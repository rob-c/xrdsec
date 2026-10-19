"""The Kerberos plumbing below the credential: DER, krb5.conf, the KDC transport, TGS checks.

The known-good bytes are in ``test_krb5_mit.py`` and the live proof in
``test_krb5_interop.py``; this file is the edges neither reaches - malformed
DER, every ``krb5.conf`` construct, a KDC that is slow, silent, truncated or
too big for UDP, and every way a TGS reply can fail its checks. The fake KDC
below is a pair of loopback sockets answering with whatever a test scripts.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import replace

import pytest

from xrdcore.errors import CredentialError
from xrdsec.der import DERError, parse
from xrdsec.krb5 import asn1, kdc, tgs
from xrdsec.krb5.asn1 import (
    EncryptedData,
    Fields,
    Key,
    fields,
    general_string,
    integer,
    kerberos_time,
    principal_name,
    tlv,
)
from xrdsec.krb5.model import Principal, Ticket, parse_principal
from xrdsec.krb5.profile import Profile, enctype_list
from xrdsec.krb5.rfc3961 import get_enctype

REALM = "EXAMPLE.ORG"
CLIENT = Principal(("jane",), REALM, 1)
SERVICE = Principal(("xrootd", "srv.example.org"), REALM, 1)
TGS_NAME = Principal(("krbtgt", REALM), REALM, 2)


# -- DER ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "value", [0, 1, 127, 128, 255, 256, 65535, 2**31 - 1, 2**32 - 1, -1, -128, -129]
)
def test_integers_are_minimal_twos_complement(value):
    encoded = integer(value)
    element, _ = parse(encoded)
    assert int.from_bytes(element.value, "big", signed=True) == value
    # Minimal: no leading byte that the next byte's sign bit makes redundant.
    if len(element.value) > 1:
        first, second = element.value[0], element.value[1]
        assert not (first == 0 and second < 0x80) and not (first == 0xFF and second >= 0x80)


def test_long_lengths_use_the_long_form():
    assert tlv(0x04, b"x" * 200)[:3] == b"\x04\x81\xc8"
    assert tlv(0x04, b"x" * 300)[:4] == b"\x04\x82\x01\x2c"


def test_time_and_flags_round_trip():
    stamp = 1_790_000_123
    assert asn1.read_time(parse(kerberos_time(stamp))[0]) == stamp
    assert asn1.read_flags(parse(asn1.kerberos_flags(0x40810000))[0]) == 0x40810000
    # A short BIT STRING (another encoder trimming trailing zero bytes) still reads.
    assert asn1.read_flags(parse(b"\x03\x02\x00\x40")[0]) == 0x40000000


@pytest.mark.parametrize(
    "der",
    [
        b"\x18\x0f" + b"2026x9291845172",  # not ending in Z
        b"\x18\x05" + b"2026Z",  # too short
        b"\x04\x0f" + b"20260929184517Z",  # not a GeneralizedTime
        b"\x18\x0f" + b"20261399184517Z",  # month 13
    ],
)
def test_a_malformed_time_is_refused(der):
    with pytest.raises(DERError, match="KerberosTime"):
        asn1.read_time(parse(der)[0])


def test_malformed_flags_and_strings_are_refused():
    with pytest.raises(DERError, match="KerberosFlags"):
        asn1.read_flags(parse(b"\x03\x00")[0])
    with pytest.raises(DERError, match="GeneralString"):
        asn1.read_string(parse(b"\x04\x01x")[0])
    with pytest.raises(DERError, match="OCTET STRING"):
        asn1.read_octets(parse(b"\x1b\x01x")[0])


def test_fields_insist_on_der_order_and_single_values():
    with pytest.raises(DERError, match="not a SEQUENCE"):
        Fields(parse(b"\x04\x00")[0], "thing")
    backwards = asn1.sequence(tlv(0xA1, integer(1)), tlv(0xA0, integer(0)))
    with pytest.raises(DERError, match="out of order"):
        Fields(parse(backwards)[0], "thing")
    primitive = asn1.sequence(tlv(0x80, b"\x01"))
    with pytest.raises(DERError, match="out of order"):
        Fields(parse(primitive)[0], "thing")
    doubled = asn1.sequence(tlv(0xA0, integer(1) + integer(2)))
    with pytest.raises(DERError, match="more than one value"):
        Fields(parse(doubled)[0], "thing")
    view = Fields(parse(fields((0, integer(5))))[0], "thing")
    assert view.optional(3) is None and view.time(3, default=7) == 7
    with pytest.raises(DERError, match=r"lacks its required field \[1\]"):
        view.get(1)


def test_a_principal_name_round_trips_and_a_bad_one_is_refused():
    element = parse(principal_name(SERVICE))[0]
    assert asn1.read_principal_name(element, REALM) == SERVICE
    bad = fields((0, integer(1)), (1, general_string("flat")))
    with pytest.raises(DERError, match="not a SEQUENCE"):
        asn1.read_principal_name(parse(bad)[0], REALM)


def test_encrypted_data_keeps_its_kvno():
    sealed = EncryptedData(18, b"cipher", kvno=3)
    assert asn1.read_encrypted_data(parse(sealed.encode())[0]) == sealed
    assert asn1.read_encrypted_data(parse(EncryptedData(18, b"c").encode())[0]).kvno is None


def _ticket_der(server: Principal = SERVICE, vno: int = 5) -> bytes:
    body = fields(
        (0, integer(vno)),
        (1, general_string(server.realm)),
        (2, principal_name(server)),
        (3, EncryptedData(18, b"opaque", 2).encode()),
    )
    return tlv(asn1.APP_TICKET, body)


def test_a_ticket_decodes_its_outer_fields():
    info = asn1.decode_ticket(_ticket_der())
    assert info.server == SERVICE and info.enc_part == EncryptedData(18, b"opaque", 2)


def test_a_ticket_that_is_not_one_is_refused():
    with pytest.raises(DERError, match="Ticket version 4"):
        asn1.decode_ticket(_ticket_der(vno=4))
    with pytest.raises(DERError, match="expected Ticket"):
        asn1.decode_ticket(b"\x62\x00")
    with pytest.raises(DERError, match="trailing data"):
        asn1.decode_ticket(_ticket_der() + b"\x00")


def _krb_error(code: int, text: str | None = "", server: Principal = SERVICE) -> bytes:
    body = fields(
        (0, integer(5)),
        (1, integer(30)),
        (4, kerberos_time(1_790_000_000)),
        (5, integer(0)),
        (6, integer(code)),
        (9, general_string(server.realm)),
        (10, principal_name(server)),
        (11, None if text is None else general_string(text)),
    )
    return tlv(asn1.APP_KRB_ERROR, body)


def test_a_krb_error_decodes():
    error = asn1.decode_krb_error(_krb_error(7, "LOOKING_UP_SERVER"))
    assert (error.code, error.realm, error.text, error.server_time) == (
        7,
        REALM,
        "LOOKING_UP_SERVER",
        1_790_000_000,
    )
    assert error.server.same_name(SERVICE)
    assert asn1.decode_krb_error(_krb_error(60, None)).text == ""


# -- a TGS reply, built here the way a KDC builds one -------------------------


def _tgt(enctype: int = 18) -> Ticket:
    return Ticket(
        client=CLIENT,
        server=TGS_NAME,
        enctype=enctype,
        auth_time=1,
        start_time=1,
        end_time=int(time.time()) + 3600,
        renew_till=0,
        flags=0x40E00000,
        der=_ticket_der(TGS_NAME),
        key=get_enctype(enctype).random_key(),
    )


def _enc_part(nonce: int, server: Principal, key: Key, tag: int, renew: bool) -> bytes:
    body = fields(
        (0, key.encode()),
        (1, asn1.sequence()),  # last-req: empty
        (2, integer(nonce)),
        (4, asn1.kerberos_flags(0x00A10000)),
        (5, kerberos_time(1_790_000_000)),
        (7, kerberos_time(1_790_036_000)),
        (8, kerberos_time(1_790_086_400) if renew else None),
        (9, general_string(server.realm)),
        (10, principal_name(server)),
    )
    return tlv(tag, body)


def _reply(tgt: Ticket, nonce: int, **overrides) -> bytes:
    """A TGS-REP for ``tgt``; keyword overrides break exactly one thing."""
    server = overrides.get("reply_server", SERVICE)
    key = overrides.get("key", Key(18, bytes(range(32))))
    part = _enc_part(
        nonce,
        server,
        key,
        overrides.get("tag", asn1.APP_ENC_TGS_REP_PART),
        overrides.get("renew", True),
    )
    etype = overrides.get("etype", tgt.enctype)
    sealed = get_enctype(tgt.enctype).encrypt(tgt.key, overrides.get("usage", 8), part)
    client = overrides.get("client", tgt.client)
    body = fields(
        (0, integer(5)),
        (1, integer(13)),
        (3, general_string(client.realm)),
        (4, principal_name(client)),
        (5, _ticket_der(overrides.get("ticket_server", server))),
        (6, EncryptedData(etype, sealed).encode()),
    )
    return tlv(asn1.APP_TGS_REP, body)


def _ask(tgt: Ticket, server: Principal = SERVICE, **overrides) -> Ticket:
    def send(profile, realm, request):
        assert realm == REALM
        return overrides.pop("raw", None) or _reply(tgt, 42, **overrides)

    hooks = tgs.TgsHooks(send=send, nonce=42)
    return tgs.tgs_exchange(tgt, tgs.TgsRequest(server, (18,)), Profile(), hooks)


def test_a_well_formed_reply_yields_the_ticket_and_its_key():
    tgt = _tgt()
    ticket = _ask(tgt)
    assert ticket.server.same_name(SERVICE) and ticket.client == CLIENT
    assert ticket.key == bytes(range(32)) and ticket.enctype == 18
    assert (ticket.auth_time, ticket.start_time, ticket.end_time) == (
        1_790_000_000,
        1_790_000_000,  # no starttime: it is the authtime
        1_790_036_000,
    )
    assert ticket.renew_till == 1_790_086_400 and ticket.flags == 0x00A10000


def test_the_as_rep_tag_on_the_encrypted_part_is_accepted_too():
    """RFC 4120 section 5.4.2: some KDCs send EncASRepPart in a TGS-REP."""
    ticket = _ask(_tgt(), tag=asn1.APP_ENC_AS_REP_PART, renew=False)
    assert ticket.renew_till == 0


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"etype": 17}, "reply sealed with enctype 17"),
        ({"usage": 9}, "integrity check failed"),
        ({"reply_server": Principal(("xrootd", "other"), REALM, 1)}, "asked for xrootd/srv"),
        ({"ticket_server": Principal(("xrootd", "other"), REALM, 1)}, "asked for xrootd/srv"),
        ({"client": Principal(("mallory",), REALM, 1)}, "the ticket is for mallory"),
        ({"key": Key(23, bytes(16))}, "enctype 23 is not supported"),
        ({"key": Key(18, bytes(5))}, "session key for xrootd/srv.* is 5 bytes"),
        ({"tag": 0x62}, "expected EncTGSRepPart"),
        ({"raw": b"\x6d\x03\x30\x01\x00"}, "unusable"),
    ],
)
def test_a_reply_that_fails_any_check_is_refused(overrides, message):
    with pytest.raises(CredentialError, match=message):
        _ask(_tgt(), **overrides)


@pytest.mark.parametrize(
    "code, text, message",
    [
        (7, "", "the KDC has no principal xrootd/srv.example.org@EXAMPLE.ORG"),
        (32, "", "your ticket-granting ticket has expired; run kinit"),
        (37, "", "clock here and the KDC's differ"),
        (14, "", "share no encryption type"),
        (99, "WHATEVER", r"the KDC refused the request for .* \(KDC error 99: WHATEVER\)"),
    ],
)
def test_kdc_errors_become_sentences(code, text, message):
    with pytest.raises(CredentialError, match=message):
        _ask(_tgt(), raw=_krb_error(code, text))


def test_cross_realm_is_refused_before_the_kdc_is_asked():
    other = Principal(("xrootd", "srv.other.org"), "OTHER.ORG", 1)
    with pytest.raises(CredentialError, match="cross-realm authentication is not supported"):
        # The production entry point: refused before any network is touched.
        tgs.request_ticket(_tgt(), other, Profile(), etypes=[18])


def _no_network(profile: Profile, realm: str, request: bytes) -> bytes:
    pytest.fail("the KDC was asked")


def test_a_tgt_with_a_legacy_session_key_is_refused():
    with pytest.raises(CredentialError, match="cannot be used: Kerberos enctype 23"):
        tgs.tgs_exchange(
            replace(_tgt(), enctype=23),
            tgs.TgsRequest(SERVICE, (18,)),
            Profile(),
            tgs.TgsHooks(send=_no_network),
        )


def test_the_request_carries_what_the_kdc_needs():
    """The body the checksum covers, the TGT, and the authenticator under usage 7."""
    tgt = _tgt(20)
    sent: list[bytes] = []

    def send(profile, realm, request):
        sent.append(request)
        return _reply(tgt, 42)

    tgs.tgs_exchange(
        tgt,
        tgs.TgsRequest(SERVICE, (20, 18)),
        Profile(),
        tgs.TgsHooks(send=send, nonce=42, clock=lambda: 5.5),
    )
    request = Fields(parse(parse(sent[0])[0].value)[0], "TGS-REQ")
    body = Fields(request.get(4), "body")
    assert body.integer(7) == 42 and body.time(5) == tgt.end_time
    (pa,) = request.get(3).children()
    ap_req = Fields(parse(parse(Fields(pa, "PA").octets(2))[0].value)[0], "AP-REQ")
    assert tlv(ap_req.get(3).tag, ap_req.get(3).value) == tgt.der
    sealed = asn1.read_encrypted_data(ap_req.get(4))
    plain = get_enctype(20).decrypt(tgt.key, 7, sealed.cipher)
    auth = Fields(parse(parse(plain)[0].value)[0], "Authenticator")
    assert (auth.time(5), auth.integer(4)) == (5, 500000)
    checksum = Fields(auth.get(3), "Checksum")
    body_der = tlv(request.get(4).tag, request.get(4).value)
    assert checksum.octets(1) == get_enctype(20).checksum(tgt.key, 6, body_der)


# -- krb5.conf ---------------------------------------------------------------

KRB5_CONF = """\
# a comment
; another
[libdefaults]
  default_realm = EXAMPLE.ORG
  dns_lookup_kdc = false
  default_ccache_name = "FILE:/tmp/krb5cc_\\"q\\"\\t"
  forwardable* = true

[realms]
  EXAMPLE.ORG = {
     kdc = kdc1.example.org:88
     kdc = kdc2.example.org  tcp/kdc3.example.org
     admin_server = kdc1.example.org
     nested = {
        deep = value
     }
  }*
  OTHER.ORG = {
     kdc = kdc.other.org
  }

[domain_realm]
  .example.org = EXAMPLE.ORG
  special.example.org = OTHER.ORG
  example.net = EXAMPLE.ORG

[realms]
  THIRD.ORG = {
     kdc = kdc.third.org
  }
stray line with no equals
}
"""


def test_a_krb5_conf_parses_into_realms_and_kdcs():
    profile = Profile.parse(KRB5_CONF)
    assert profile.default_realm == "EXAMPLE.ORG"
    assert profile.kdcs("EXAMPLE.ORG") == [
        "kdc1.example.org:88",
        "kdc2.example.org",
        "tcp/kdc3.example.org",
    ]
    assert profile.kdcs("THIRD.ORG") == ["kdc.third.org"]  # a section named twice is merged
    assert profile.kdcs("NOWHERE") == []
    assert profile.values("realms", "EXAMPLE.ORG", "nested", "deep") == ["value"]


def test_a_krb5_conf_value_is_unquoted_and_read_as_a_flag():
    profile = Profile.parse(KRB5_CONF)
    assert profile.libdefault("default_ccache_name") == 'FILE:/tmp/krb5cc_"q"\t'
    assert profile.flag("forwardable", False) is True  # the "final" asterisk is ignored
    assert profile.flag("dns_lookup_kdc", True) is False
    assert profile.flag("absent", True) is True
    assert profile.first("libdefaults", "absent", default="x") == "x"


@pytest.mark.parametrize(
    "host, realm",
    [
        ("srv.example.org", "EXAMPLE.ORG"),
        ("SRV.Example.Org.", "EXAMPLE.ORG"),
        ("special.example.org", "OTHER.ORG"),
        ("a.b.example.org", "EXAMPLE.ORG"),
        ("example.net", "EXAMPLE.ORG"),
        ("x.example.net", ""),  # "example.net" maps the host itself, not its subdomains
        ("example.org", ""),  # ".example.org" maps hosts in the domain, not the domain
        ("elsewhere.com", ""),
    ],
)
def test_domain_realm_follows_mits_order(host, realm):
    assert Profile.parse(KRB5_CONF).realm_for_host(host) == realm


def test_include_and_includedir_are_followed(tmp_path):
    confd = tmp_path / "krb5.conf.d"
    confd.mkdir()
    (confd / "realm.conf").write_text("[realms]\n A.ORG = {\n  kdc = a\n }\n")
    (confd / "plain_name-1").write_text("[libdefaults]\n default_realm = A.ORG\n")
    (confd / "ignored.rpmsave").write_text("[libdefaults]\n default_realm = WRONG\n")
    extra = tmp_path / "extra.conf"
    main = tmp_path / "krb5.conf"
    extra.write_text(f"include {main}\n[libdefaults]\n rdns = false\n")  # a cycle, cut
    main.write_text(
        f"includedir {confd}\ninclude {extra}\ninclude {tmp_path / 'missing'}\n"
        f"includedir {tmp_path / 'nodir'}\nmodule something:/x\n"
        "[libdefaults]\n udp_preference_limit = 1\n"
    )
    profile = Profile.load(str(main))
    assert profile.kdcs("A.ORG") == ["a"]
    assert profile.values("libdefaults", "default_realm") == ["A.ORG"]
    assert profile.libdefault("rdns") == "false"
    assert profile.libdefault("udp_preference_limit") == "1"


def test_include_counts_after_a_section_and_after_a_tab(tmp_path):
    """MIT reads ``include``/``includedir`` at the start of any line, with any blank after."""
    confd = tmp_path / "inc"
    confd.mkdir()
    (confd / "realm.conf").write_text("[realms]\n EX.ORG = {\n  kdc = 127.0.0.1:1\n }\n")
    (tmp_path / "one").write_text("[libdefaults]\n rdns = false\n")
    (tmp_path / "two").write_text("[libdefaults]\n dns_lookup_kdc = false\n")
    main = tmp_path / "krb5.conf"
    main.write_text(
        "[libdefaults]\n default_realm = EX.ORG\n"
        f"includedir\t{confd}\n"
        f"include   {tmp_path / 'one'}  \n"
        # The file carries on in its own section after an include.
        " udp_preference_limit = 1\n"
        "[realms]\n OTHER = {\n"
        f"include {tmp_path / 'two'}\n"  # even inside a block
        "  kdc = other\n }\n"
        # Not at the start of the line, or a longer word: an ordinary relation.
        f" include {tmp_path / 'missing'}\n"
        "[x]\n includes = 1\nmodule = m\n"  # ``module`` counts only before a section
    )
    profile = Profile.load(str(main))
    assert profile.kdcs("EX.ORG") == ["127.0.0.1:1"]
    assert profile.libdefault("rdns") == "false"
    assert profile.libdefault("dns_lookup_kdc") == "false"
    assert profile.libdefault("udp_preference_limit") == "1"
    assert profile.kdcs("OTHER") == ["other"]
    assert profile.values("x", "includes") == ["1"] and profile.values("x", "module") == ["m"]


def test_krb5_config_is_a_colon_separated_list_and_etc_is_the_default(tmp_path, monkeypatch):
    first, second = tmp_path / "a", tmp_path / "b"
    first.write_text("[libdefaults]\n default_realm = FIRST\n")
    second.write_text("[libdefaults]\n default_realm = SECOND\n ticket_lifetime = 1h\n")
    monkeypatch.setenv("KRB5_CONFIG", f"{first}::{second}")
    profile = Profile.load()
    assert profile.default_realm == "FIRST" and profile.libdefault("ticket_lifetime") == "1h"
    monkeypatch.delenv("KRB5_CONFIG")
    from xrdsec.krb5 import profile as module

    monkeypatch.setattr(module, "DEFAULT_CONFIG", str(second))
    assert Profile.load().default_realm == "SECOND"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("aes256-cts-hmac-sha1-96 aes128-cts", [18, 17]),
        ("aes256-sha2,aes128-sha2", [20, 19]),
        ("DEFAULT -aes128-cts-hmac-sha1-96", [20, 18, 19]),
        ("aes aes256-cts", [17, 20, 19, 18]),  # a repeat moves to the end, as MIT's does
        ("des-cbc-crc rc4-hmac camellia256-cts", []),
        ("aes-sha1 +aes-sha2", [18, 17, 20, 19]),
    ],
)
def test_enctype_lists_read_the_way_mit_reads_them(text, expected):
    assert enctype_list(text) == expected


# -- the KDC transport -------------------------------------------------------


@pytest.mark.parametrize(
    "entry, expected",
    [
        ("kdc.example.org", ("kdc.example.org", 88, "")),
        ("kdc.example.org:750", ("kdc.example.org", 750, "")),
        ("TCP/kdc.example.org:750", ("kdc.example.org", 750, "tcp")),
        ("udp/kdc.example.org", ("kdc.example.org", 88, "udp")),
        ("[::1]:8888", ("::1", 8888, "")),
        ("[::1]", ("::1", 88, "")),
        ("::1", ("::1", 88, "")),
        ("https://kdcproxy.example.org/KdcProxy", None),
        ("xyz/kdc.example.org", None),
        ("kdc.example.org:port", None),
        (":88", None),
    ],
)
def test_kdc_entries_parse(entry, expected):
    found = kdc.parse_kdc(entry)
    assert (found if found is None else (found.host, found.port, found.transport)) == expected


def test_a_kdc_address_prints_the_way_krb5_conf_writes_it():
    assert str(kdc.KdcAddress("h", 88, "tcp")) == "tcp/h:88"
    assert str(kdc.KdcAddress("h", 750, "")) == "h:750"


class FakeKdc:
    """A KDC on loopback, UDP and TCP on one port, answering as ``respond`` says.

    ``respond(request, transport)`` returns the reply, or ``None`` to say
    nothing (UDP) or hang up (TCP). Every request is kept in :attr:`seen`.
    """

    def __init__(self, respond) -> None:
        self.respond = respond
        self.seen: list[tuple[str, bytes]] = []
        self.tcp = socket.create_server(("127.0.0.1", 0))
        self.port = self.tcp.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", self.port))
        self.tcp.settimeout(0.1)
        self.udp.settimeout(0.1)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.udp.recvfrom(65535)
            except OSError:
                pass
            else:
                self.seen.append(("udp", data))
                reply = self.respond(data, "udp")
                if reply is not None:
                    self.udp.sendto(reply, peer)
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                continue
            with conn:
                self._tcp_one(conn)

    def _tcp_one(self, conn: socket.socket) -> None:
        conn.settimeout(2)
        size = struct.unpack(">I", conn.recv(4))[0]
        data = b""
        while len(data) < size:
            data += conn.recv(size - len(data))
        self.seen.append(("tcp", data))
        reply = self.respond(data, "tcp")
        if reply is not None:
            conn.sendall(reply)

    def profile(self, *entries: str, extra: str = "") -> Profile:
        kdcs = "\n".join(f"  kdc = {entry.format(port=self.port)}" for entry in entries)
        return Profile.parse(f"[libdefaults]\n{extra}\n[realms]\n R = {{\n{kdcs}\n }}\n")

    def close(self) -> None:
        self._stop.set()
        self._thread.join(2)
        self.tcp.close()
        self.udp.close()


@pytest.fixture
def fake_kdc():
    made: list[FakeKdc] = []

    def make(respond) -> FakeKdc:
        made.append(FakeKdc(respond))
        return made[-1]

    yield make
    for each in made:
        each.close()


def _realm_r(*kdcs: str) -> Profile:
    """A profile whose realm ``R`` lists ``kdcs``, in order."""
    lines = "".join(f"  kdc = {entry}\n" for entry in kdcs)
    return Profile.parse(f"[realms]\n R = {{\n{lines} }}\n")


def _framed(reply: bytes) -> bytes:
    return len(reply).to_bytes(4, "big") + reply


TOO_BIG = _krb_error(kdc.KRB_ERR_RESPONSE_TOO_BIG, "", TGS_NAME)


def test_udp_is_tried_first(fake_kdc):
    server = fake_kdc(lambda data, transport: b"reply:" + data)
    assert kdc.exchange(server.profile("127.0.0.1:{port}"), "R", b"hello") == b"reply:hello"
    assert server.seen == [("udp", b"hello")]


def test_too_big_for_udp_moves_to_tcp(fake_kdc):
    server = fake_kdc(
        lambda data, transport: TOO_BIG if transport == "udp" else _framed(b"big reply")
    )
    assert kdc.exchange(server.profile("127.0.0.1:{port}"), "R", b"req") == b"big reply"
    assert [transport for transport, _ in server.seen] == ["udp", "tcp"]


def test_a_udp_only_kdc_is_not_asked_over_tcp(fake_kdc):
    server = fake_kdc(lambda data, transport: TOO_BIG)
    assert kdc.exchange(server.profile("udp/127.0.0.1:{port}"), "R", b"req") == TOO_BIG
    assert [transport for transport, _ in server.seen] == ["udp"]


@pytest.mark.parametrize(
    "entry, extra",
    [("tcp/127.0.0.1:{port}", ""), ("127.0.0.1:{port}", "udp_preference_limit = 1")],
)
def test_tcp_only_and_large_requests_go_straight_to_tcp(fake_kdc, entry, extra):
    server = fake_kdc(lambda data, transport: _framed(b"tcp reply"))
    assert kdc.exchange(server.profile(entry, extra=extra), "R", b"req") == b"tcp reply"
    assert [transport for transport, _ in server.seen] == ["tcp"]


def test_other_errors_and_malformed_errors_are_left_to_the_caller(fake_kdc):
    other = _krb_error(7)
    server = fake_kdc(lambda data, transport: other)
    assert kdc.exchange(server.profile("127.0.0.1:{port}"), "R", b"req") == other
    broken = bytes([asn1.APP_KRB_ERROR]) + b"\x01\x00"
    server = fake_kdc(lambda data, transport: broken)
    assert kdc.exchange(server.profile("127.0.0.1:{port}"), "R", b"req") == broken


def test_a_silent_kdc_is_skipped_for_the_next(fake_kdc):
    silent = fake_kdc(lambda data, transport: None)
    answering = fake_kdc(lambda data, transport: b"second")
    profile = _realm_r(f"127.0.0.1:{silent.port}", f"127.0.0.1:{answering.port}")
    assert kdc.exchange(profile, "R", b"req", timeout=0.3) == b"second"


def test_when_no_kdc_answers_every_attempt_is_listed(fake_kdc):
    silent = fake_kdc(lambda data, transport: None)
    hangs_up = fake_kdc(lambda data, transport: None)
    profile = _realm_r(f"127.0.0.1:{silent.port}", f"tcp/127.0.0.1:{hangs_up.port}")
    with pytest.raises(
        CredentialError, match=r"no KDC for realm R answered \(127.*; tcp/127.*closed"
    ):
        kdc.exchange(profile, "R", b"req", timeout=0.3)


def test_an_absurd_tcp_length_is_refused(fake_kdc):
    server = fake_kdc(lambda data, transport: (kdc.MAX_REPLY + 1).to_bytes(4, "big"))
    with pytest.raises(CredentialError, match="announced a"):
        kdc.exchange(server.profile("tcp/127.0.0.1:{port}"), "R", b"req")


def test_a_realm_with_no_kdc_listed_says_how_to_add_one():
    profile = Profile.parse("[realms]\n R = {\n kdc = https://proxy/KdcProxy\n }\n")
    with pytest.raises(CredentialError, match=r"lists no usable KDC for realm 'R'.*kdc = <host>"):
        kdc.exchange(profile, "R", b"req")


# -- principals --------------------------------------------------------------


@pytest.mark.parametrize(
    "text, default, expected",
    [
        ("xrootd/host@REALM", "", Principal(("xrootd", "host"), "REALM", 1)),
        ("jane", "DEF", Principal(("jane",), "DEF", 1)),
        (r"a\/b@R", "", Principal(("a/b",), "R", 1)),
        (r"a\@b/c@R@S", "", Principal(("a@b", "c"), "R@S", 1)),
        ("trailing\\", "", Principal(("trailing",), "", 1)),
    ],
)
def test_principals_parse_the_way_krb5_parse_name_does(text, default, expected):
    assert parse_principal(text, default) == expected


def test_same_name_ignores_the_name_type():
    assert Principal(("a",), "R", 1).same_name(Principal(("a",), "R", 2))
    assert not Principal(("a",), "R", 1).same_name(Principal(("a",), "S", 1))
