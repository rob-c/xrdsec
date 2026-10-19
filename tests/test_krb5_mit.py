"""The Kerberos client against bytes MIT krb5 and XRootD produced.

``tests/_krb5_mit.py`` holds a capture from a throwaway MIT realm (for
``aes256-cts-hmac-sha1-96`` and ``aes256-cts-hmac-sha384-192``): MIT
``kinit``'s credential cache, MIT ``kvno``'s TGS-REQ, the real KDC's reply
to a TGS-REQ this client sent, and the AP-REQ and KRB-CRED the official
``xrdcp`` sent a real ``xrootd -exptkn``. Every test here reads one of those
and either opens it with this client's cryptography, or rebuilds it with
this client's encoder and compares bytes. Neither side of any comparison is
this package checking itself.
"""

from __future__ import annotations

import struct

import pytest

from xrdsec.der import parse, parse_all, read_integer
from xrdsec.krb5 import asn1, tgs
from xrdsec.krb5.asn1 import Fields, Key, read_encrypted_data, tlv
from xrdsec.krb5.ccache import read_ccache
from xrdsec.krb5.model import Principal, Ticket
from xrdsec.krb5.profile import Profile
from xrdsec.krb5.rfc3961 import get_enctype

from tests._krb5_mit import CAPTURED, SERVICE_PASSWORD

REALM = "XRD.TEST"
SERVICE = Principal(("xrootd", "localhost"), REALM, 1)
ENCTYPES = sorted(int(number) for number in CAPTURED)


def data(enctype: int, name: str) -> bytes:
    return bytes.fromhex(CAPTURED[str(enctype)][name])


def cache(tmp_path, enctype: int, name: str) -> tuple[Principal, list[Ticket]]:
    path = tmp_path / name
    path.write_bytes(data(enctype, name))
    return read_ccache(str(path))


def body_of(der: bytes, tag: int) -> Fields:
    """The fields of an ``[APPLICATION n] SEQUENCE``."""
    outer, _ = parse(der)
    assert outer.tag == tag
    return Fields(parse(outer.value)[0], hex(tag))


def whole(element) -> bytes:
    return tlv(element.tag, element.value)


def open_ticket(enctype: int, ticket_der: bytes) -> Fields:
    """EncTicketPart, decrypted with the service key MIT put in its keytab (usage 2)."""
    info = asn1.decode_ticket(ticket_der)
    key = data(enctype, "service_key")
    plain = get_enctype(info.enc_part.etype).decrypt(key, 2, info.enc_part.cipher)
    return body_of(plain, 0x63)


@pytest.fixture(params=ENCTYPES)
def enctype(request: pytest.FixtureRequest) -> int:
    return int(request.param)


# -- the credential cache MIT kinit wrote -----------------------------------


def test_mits_cache_reads_back_with_its_session_key(tmp_path, enctype):
    default, found = cache(tmp_path, enctype, "tgt_ccache")
    assert str(default) == f"jane@{REALM}"
    # kinit also stores configuration pseudo-entries (fast_avail, pa_type):
    # they are metadata, not tickets, and must not be offered as either.
    assert [str(t.server) for t in found] == [f"krbtgt/{REALM}@{REALM}"]
    tgt = found[0]
    assert tgt.enctype == enctype and len(tgt.key) == 32
    assert tgt.forwardable  # kinit -f


def test_mits_service_ticket_opens_with_the_keytab_key_and_holds_the_cached_key(tmp_path, enctype):
    """The session key in MIT's cache is the one inside the ticket MIT's KDC issued."""
    _, found = cache(tmp_path, enctype, "service_ccache")
    service = next(t for t in found if t.server.same_name(SERVICE))
    part = open_ticket(enctype, service.der)
    key = asn1.read_key(part.get(1))
    assert (key.enctype, key.value) == (service.enctype, service.key)
    assert asn1.read_principal_name(part.get(3), part.string(2)).same_name(service.client)


def test_the_keytab_key_is_the_password_run_through_string_to_key(enctype):
    """MIT's salt is the realm and the components, concatenated."""
    salt = f"{REALM}xrootdlocalhost".encode()
    derived = get_enctype(enctype).string_to_key(SERVICE_PASSWORD.encode(), salt)
    assert derived == data(enctype, "service_key")


# -- MIT kvno's TGS-REQ -----------------------------------------------------


def _mit_tgs_req(enctype: int):
    request = body_of(data(enctype, "mit_tgs_req"), asn1.APP_TGS_REQ)
    padata = [Fields(pa, "PA-DATA") for pa in parse_all(request.get(3).value)]
    ap_req = next(pa.octets(2) for pa in padata if pa.integer(1) == tgs.PA_TGS_REQ)
    return request, body_of(ap_req, asn1.APP_AP_REQ)


def test_mits_tgs_authenticator_opens_under_the_tgt_session_key(tmp_path, enctype):
    _, (tgt,) = cache(tmp_path, enctype, "tgt_ccache")
    _, ap_req = _mit_tgs_req(enctype)
    sealed = read_encrypted_data(ap_req.get(4))
    plain = get_enctype(sealed.etype).decrypt(tgt.key, tgs.USAGE_TGS_REQ_AUTH, sealed.cipher)
    authenticator = body_of(plain, asn1.APP_AUTHENTICATOR)
    assert authenticator.string(1) == REALM


def test_mits_request_body_checksum_verifies_and_the_authenticator_re_encodes_identically(
    tmp_path, enctype
):
    """Both halves of PA-TGS-REQ: the keyed checksum (usage 6) and the DER around it."""
    _, (tgt,) = cache(tmp_path, enctype, "tgt_ccache")
    request, ap_req = _mit_tgs_req(enctype)
    sealed = read_encrypted_data(ap_req.get(4))
    plain = get_enctype(sealed.etype).decrypt(tgt.key, tgs.USAGE_TGS_REQ_AUTH, sealed.cipher)
    auth = body_of(plain, asn1.APP_AUTHENTICATOR)
    checksum = Fields(auth.get(3), "Checksum")
    body = whole(request.get(4))
    session = get_enctype(tgt.enctype)
    assert checksum.integer(0) == session.checksum_type
    assert session.checksum(tgt.key, tgs.USAGE_TGS_REQ_CKSUM, body) == checksum.octets(1)
    rebuilt = asn1.encode_authenticator(
        tgt.client,
        auth.time(5),
        auth.integer(4),
        checksum=(checksum.integer(0), checksum.octets(1)),
        subkey=asn1.read_key(auth.get(6)),
    )
    assert rebuilt == plain


def test_mits_request_body_re_encodes_identically(enctype):
    """KDC-REQ-BODY from the same field values is byte-for-byte what MIT sent."""
    request, _ = _mit_tgs_req(enctype)
    body = Fields(request.get(4), "KDC-REQ-BODY")
    etypes = [read_integer(e) for e in body.get(8).children()]
    rebuilt = asn1.encode_req_body(
        options=asn1.read_flags(body.get(0)),
        server=asn1.read_principal_name(body.get(3), body.string(2)),
        till=body.time(5),
        nonce=body.integer(7),
        etypes=etypes,
    )
    assert rebuilt == whole(request.get(4))


def test_mits_ap_req_ticket_is_the_tgt_from_the_cache(tmp_path, enctype):
    _, (tgt,) = cache(tmp_path, enctype, "tgt_ccache")
    _, ap_req = _mit_tgs_req(enctype)
    assert whole(ap_req.get(3)) == tgt.der


# -- this client's TGS-REQ, answered by the real KDC -------------------------


def test_the_real_kdcs_reply_to_our_request_replays_into_a_working_ticket(tmp_path, enctype):
    """Our request, sent once to MIT's KDC; its reply decrypts, checks, and yields a ticket
    whose session key is the one inside the ticket - as the service will see it."""
    _, (tgt,) = cache(tmp_path, enctype, "tgt_ccache")
    sent: list[bytes] = []

    def send(profile, realm, request):
        sent.append(request)
        return data(enctype, "kdc_tgs_rep")

    clock = float(CAPTURED[str(enctype)]["our_clock"])
    hooks = tgs.TgsHooks(clock=lambda: clock, send=send, nonce=12345678)
    ticket = tgs.tgs_exchange(tgt, tgs.TgsRequest(SERVICE, (enctype,)), Profile(), hooks)
    assert ticket.server.same_name(SERVICE) and ticket.client == tgt.client
    part = open_ticket(enctype, ticket.der)
    assert asn1.read_key(part.get(1)).value == ticket.key
    # The request is ours; only the confounders differ from the one the KDC accepted.
    ours, captured = (body_of(r, asn1.APP_TGS_REQ) for r in (sent[0], data(enctype, "our_tgs_req")))
    assert whole(ours.get(4)) == whole(captured.get(4))


def test_a_replayed_reply_with_another_nonce_is_refused(tmp_path, enctype):
    from xrdcore.errors import CredentialError

    _, (tgt,) = cache(tmp_path, enctype, "tgt_ccache")
    with pytest.raises(CredentialError, match="nonce does not match"):
        tgs.tgs_exchange(
            tgt,
            tgs.TgsRequest(SERVICE, (enctype,)),
            Profile(),
            tgs.TgsHooks(send=lambda *a: data(enctype, "kdc_tgs_rep"), nonce=87654321),
        )


def test_a_reply_for_another_service_is_refused(tmp_path, enctype):
    from xrdcore.errors import CredentialError

    _, (tgt,) = cache(tmp_path, enctype, "tgt_ccache")
    other = Principal(("xrootd", "elsewhere"), REALM, 1)
    with pytest.raises(CredentialError, match="asked for xrootd/elsewhere"):
        tgs.tgs_exchange(
            tgt,
            tgs.TgsRequest(other, (enctype,)),
            Profile(),
            tgs.TgsHooks(send=lambda *a: data(enctype, "kdc_tgs_rep"), nonce=12345678),
        )


def test_a_reply_under_the_wrong_key_fails_integrity(tmp_path, enctype):
    from dataclasses import replace

    from xrdcore.errors import CredentialError

    _, (tgt,) = cache(tmp_path, enctype, "tgt_ccache")
    forged = replace(tgt, key=bytes(32))
    with pytest.raises(CredentialError, match="integrity check failed"):
        tgs.tgs_exchange(
            forged,
            tgs.TgsRequest(SERVICE, (enctype,)),
            Profile(),
            tgs.TgsHooks(send=lambda *a: data(enctype, "kdc_tgs_rep"), nonce=12345678),
        )


# -- what the official xrdcp sent the real server ----------------------------


def _xrdcp_session_ticket(tmp_path, enctype: int) -> Ticket:
    _, found = cache(tmp_path, enctype, "service_ccache")
    return next(t for t in found if t.server.same_name(SERVICE))


def test_our_ap_req_is_xrdcps_ap_req_but_for_the_confounder(tmp_path, enctype):
    """Same options, same ticket, and - opened - the same authenticator, byte for byte."""
    service = _xrdcp_session_ticket(tmp_path, enctype)
    theirs = body_of(data(enctype, "xrdcp_ap_req"), asn1.APP_AP_REQ)
    sealed = read_encrypted_data(theirs.get(4))
    cipher = get_enctype(sealed.etype)
    their_auth = cipher.decrypt(service.key, tgs.USAGE_AP_REQ_AUTH, sealed.cipher)
    fields = body_of(their_auth, asn1.APP_AUTHENTICATOR)
    when = fields.time(5) + fields.integer(4) / 1_000_000

    ours = body_of(tgs.build_ap_req(service, clock=lambda: when), asn1.APP_AP_REQ)
    for number in (0, 1, 2, 3):  # pvno, msg-type, ap-options (use-session-key), ticket
        assert whole(ours.get(number)) == whole(theirs.get(number))
    mine = read_encrypted_data(ours.get(4))
    assert (mine.etype, mine.kvno) == (sealed.etype, sealed.kvno)
    assert cipher.decrypt(service.key, tgs.USAGE_AP_REQ_AUTH, mine.cipher) == their_auth


def test_our_krb_cred_is_xrdcps_krb_cred_but_for_the_confounder(tmp_path, enctype):
    """The forwarded TGT, as MIT's krb5_fwd_tgt_creds packaged it for -exptkn."""
    service = _xrdcp_session_ticket(tmp_path, enctype)
    theirs = body_of(data(enctype, "xrdcp_krb_cred"), asn1.APP_KRB_CRED)
    sealed = read_encrypted_data(theirs.get(3))
    cipher = get_enctype(sealed.etype)
    their_part = cipher.decrypt(service.key, tgs.USAGE_KRB_CRED, sealed.cipher)
    part = body_of(their_part, asn1.APP_ENC_KRB_CRED_PART)
    (info_element,) = part.get(0).children()
    info = Fields(info_element, "KrbCredInfo")
    key = asn1.read_key(info.get(0))
    (ticket_element,) = theirs.get(2).children()
    forwarded = Ticket(
        client=asn1.read_principal_name(info.get(2), info.string(1)),
        server=asn1.read_principal_name(info.get(9), info.string(8)),
        enctype=key.enctype,
        auth_time=info.time(4),
        start_time=info.time(5),
        end_time=info.time(6),
        renew_till=info.time(7),
        flags=asn1.read_flags(info.get(3)),
        der=whole(ticket_element),
        key=key.value,
    )
    when = part.time(2) + part.integer(3) / 1_000_000
    ours = body_of(tgs.build_krb_cred(forwarded, service, clock=lambda: when), asn1.APP_KRB_CRED)
    for number in (0, 1, 2):  # pvno, msg-type, tickets
        assert whole(ours.get(number)) == whole(theirs.get(number))
    mine = read_encrypted_data(ours.get(3))
    assert cipher.decrypt(service.key, tgs.USAGE_KRB_CRED, mine.cipher) == their_part


def test_key_repr_never_shows_the_key():
    assert "value" not in repr(Key(18, b"\x01" * 32))


# -- a cache that records the KDC's clock as ahead of or behind this one ------


def _skewed(tmp_path, enctype: int, name: str, seconds: int, micros: int):
    """MIT's cache with its DeltaTime header tag (all zeros as captured) set."""
    raw = bytearray(data(enctype, name))
    assert raw[:8] == bytes.fromhex("0504000c00010008")  # version 4, one tag: DeltaTime
    raw[8:16] = struct.pack(">ii", seconds, micros)
    path = tmp_path / name
    path.write_bytes(bytes(raw))
    return read_ccache(str(path))[1]


def test_the_ap_req_authenticator_uses_the_kdcs_clock_as_kinit_measured_it(tmp_path, enctype):
    """A host 299.75 s fast still sends xrdcp's authenticator, as MIT's kdc_timesync does."""
    service = next(
        t
        for t in _skewed(tmp_path, enctype, "service_ccache", -300, 250_000)
        if t.server.same_name(SERVICE)
    )
    assert service.kdc_offset == -299.75
    theirs = body_of(data(enctype, "xrdcp_ap_req"), asn1.APP_AP_REQ)
    sealed = read_encrypted_data(theirs.get(4))
    cipher = get_enctype(sealed.etype)
    their_auth = cipher.decrypt(service.key, tgs.USAGE_AP_REQ_AUTH, sealed.cipher)
    fields = body_of(their_auth, asn1.APP_AUTHENTICATOR)
    when = fields.time(5) + fields.integer(4) / 1_000_000

    ours = body_of(tgs.build_ap_req(service, clock=lambda: when + 299.75), asn1.APP_AP_REQ)
    mine = read_encrypted_data(ours.get(4))
    assert cipher.decrypt(service.key, tgs.USAGE_AP_REQ_AUTH, mine.cipher) == their_auth


def test_the_tgs_authenticator_uses_the_kdcs_clock_and_the_ticket_keeps_it(tmp_path, enctype):
    (tgt,) = _skewed(tmp_path, enctype, "tgt_ccache", 3600, 0)
    sent: list[bytes] = []

    def send(profile, realm, request):
        sent.append(request)
        return data(enctype, "kdc_tgs_rep")

    clock = float(CAPTURED[str(enctype)]["our_clock"])
    ticket = tgs.tgs_exchange(
        tgt,
        tgs.TgsRequest(SERVICE, (enctype,)),
        Profile(),
        tgs.TgsHooks(clock=lambda: clock - 3600, send=send, nonce=12345678),
    )
    assert ticket.kdc_offset == 3600
    request = body_of(sent[0], asn1.APP_TGS_REQ)
    padata = [Fields(pa, "PA-DATA") for pa in parse_all(request.get(3).value)]
    ap_req = body_of(next(pa.octets(2) for pa in padata if pa.integer(1) == 1), asn1.APP_AP_REQ)
    sealed = read_encrypted_data(ap_req.get(4))
    plain = get_enctype(sealed.etype).decrypt(tgt.key, tgs.USAGE_TGS_REQ_AUTH, sealed.cipher)
    authenticator = body_of(plain, asn1.APP_AUTHENTICATOR)
    assert (authenticator.time(5), authenticator.integer(4)) == tgs._split_time(clock)
