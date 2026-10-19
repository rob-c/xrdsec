"""The portable client's front door: service tickets from a cache, and the messages built from them.

The caches are written with :func:`xrdsec.testing.krb5.write_ccache`; the
cache *reader* is checked against an independent encoder in
``test_krb5_ccache.py``. The KDC is stood in for by monkeypatching
:func:`xrdsec.krb5.client.request_ticket` - what a real one does with the
requests is xrdclient's interoperability suite's business, and what a fake
one on a socket does is ``test_krb5_protocol.py``'s.
"""

from __future__ import annotations

import struct
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from xrdcore.errors import CredentialError
from xrdsec.der import parse
from xrdsec.krb5 import asn1, client, tgs
from xrdsec.krb5.asn1 import Fields
from xrdsec.krb5.ccache import CCACHE_VERSION_4, marshal_principal, marshal_ticket
from xrdsec.krb5.model import TKT_FLG_FORWARDABLE, Principal, Ticket
from xrdsec.krb5.profile import Profile
from xrdsec.krb5.rfc3961 import get_enctype
from xrdsec.testing.krb5 import make_ticket, recording_tgs, write_ccache

REALM = "EXAMPLE.ORG"
JANE = Principal(("jane",), REALM, 1)
TGS = Principal(("krbtgt", REALM), REALM, 2)
SERVICE = "xrootd/srv.example.org@EXAMPLE.ORG"
KEY = bytes(range(32))


@pytest.fixture(autouse=True)
def _realm(tmp_path, monkeypatch):
    """A ``krb5.conf`` naming only the default realm, so no test reads the machine's."""
    conf = tmp_path / "krb5.conf"
    conf.write_text(f"[libdefaults]\n default_realm = {REALM}\n")
    monkeypatch.setenv("KRB5_CONFIG", str(conf))


def _service(host: str = "srv.example.org", *, lifetime: float = 36000.0) -> Ticket:
    """A service ticket for ``xrootd/<host>`` with ``lifetime`` seconds left."""
    return make_ticket(JANE, Principal(("xrootd", host), REALM, 1), lifetime=lifetime)


def _use(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *tickets: Ticket) -> str:
    """A FILE cache holding ``tickets`` (principal jane), made the default; its path."""
    path = write_ccache(tmp_path / "krb5cc_test", tickets, default=JANE)
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{path}")
    return path


@pytest.fixture
def tgt_only(tmp_path, monkeypatch):
    """A default cache holding a forwardable TGT and nothing else."""
    return _use(tmp_path, monkeypatch, make_ticket(JANE, TGS))


@pytest.fixture
def kdc(monkeypatch):
    """A stand-in for the TGS exchange that records what it was asked."""
    asked: list[dict[str, Any]] = []
    monkeypatch.setattr(client, "request_ticket", recording_tgs(asked))
    return asked


# -- tickets() and inspect_cache(): the klist-style views ----------------------------------


def test_tickets_returns_only_the_live_ones(tmp_path):
    path = write_ccache(
        tmp_path / "mixed", [make_ticket(JANE, TGS, lifetime=-60), _service(lifetime=600)]
    )
    assert [str(t.server) for t in client.tickets(path)] == [SERVICE]


def test_tickets_reads_the_default_cache(tgt_only):
    assert [t.is_tgt for t in client.tickets()] == [True]


def test_tickets_is_quiet_about_a_cache_that_is_not_there(tmp_path, monkeypatch):
    assert client.tickets(str(tmp_path / "absent")) == []
    junk = tmp_path / "junk"
    junk.write_bytes(b"\x05\x04nonsense")
    assert client.tickets(str(junk)) == []
    monkeypatch.setenv("KRB5CCNAME", "API:")
    assert client.tickets() == []


def test_inspect_cache_names_the_principal_and_the_latest_expiry(tmp_path, monkeypatch):
    tgt = make_ticket(JANE, TGS, lifetime=3600)
    stale = _service(lifetime=-60)
    path = write_ccache(tmp_path / "cc", [stale, tgt])
    before = Path(path).read_bytes()
    info = client.inspect_cache(f"FILE:{path}")
    assert info == client.CacheInfo(f"FILE:{path}", f"jane@{REALM}", tgt.end_time)
    assert Path(path).read_bytes() == before  # read-only
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{path}")
    assert client.inspect_cache().name == f"FILE:{path}"


def test_inspect_cache_of_an_empty_cache_has_no_expiry(tmp_path):
    path = write_ccache(tmp_path / "empty", [], default=JANE)
    assert client.inspect_cache(path).expires_at == 0


def test_inspect_cache_says_which_cache_is_missing_or_unreadable(tmp_path):
    with pytest.raises(FileNotFoundError):
        client.inspect_cache(f"FILE:{tmp_path / 'absent'}")
    (tmp_path / "dir").mkdir()
    with pytest.raises(CredentialError, match="is unreadable"):
        client.inspect_cache(f"FILE:{tmp_path / 'dir'}")
    junk = tmp_path / "junk"
    junk.write_bytes(b"\x09\x09garbage")
    with pytest.raises(CredentialError, match="is unreadable"):
        client.inspect_cache(str(junk))
    with pytest.raises(CredentialError, match="macOS API: cache"):
        client.inspect_cache("API:ABCD")


# -- which service, which enctypes ------------------------------------------------------


def test_the_realm_comes_from_the_name_the_domain_map_or_the_default():
    profile = Profile.parse("[domain_realm]\n .mapped.org = MAPPED.ORG\n")

    def target(name: str, host: str) -> str:
        return str(client.target_principal(name, host, profile, REALM))

    assert target("xrootd/a.mapped.org@NAMED", "x") == "xrootd/a.mapped.org@NAMED"
    assert target("xrootd/a.mapped.org", "x") == "xrootd/a.mapped.org@MAPPED.ORG"
    assert target("xrootd/b.mapped.org", "b.mapped.org") == "xrootd/b.mapped.org@MAPPED.ORG"
    assert target("xrootd/unmapped.net", "unmapped.net") == f"xrootd/unmapped.net@{REALM}"
    assert target("host", "c.mapped.org") == "host@MAPPED.ORG"  # one component: the host decides
    assert str(client.target_principal("xrootd/unmapped.net", "", profile)) == (
        "xrootd/unmapped.net"
    )


@pytest.mark.parametrize(
    "libdefaults, expected",
    [
        ("", [18, 17, 20, 19]),
        ("default_tgs_enctypes = aes256-sha2", [20]),
        ("permitted_enctypes = aes128-cts aes256-cts", [17, 18]),
        ("default_tgs_enctypes = rc4-hmac\n permitted_enctypes = aes256-cts", [18]),
        ("default_tgs_enctypes = des-cbc-crc", [18, 17, 20, 19]),
    ],
)
def test_the_enctypes_asked_for_follow_krb5_conf(libdefaults, expected):
    assert client.request_enctypes(Profile.parse(f"[libdefaults]\n {libdefaults}\n")) == expected


# -- service_credentials(): the login path ------------------------------------------------


def _login(*, forward: bool = False) -> client.ServiceCredentials | None:
    """A login to :data:`SERVICE` from the default cache, forwarding if asked."""
    return client.service_credentials(SERVICE, "srv.example.org", forward=forward)


def test_no_cache_is_no_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{tmp_path / 'absent'}")
    assert _login() is None


def test_an_empty_cache_is_no_credentials(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    assert _login() is None


def test_an_expired_cache_says_whose_tickets_expired_and_how_long_ago(tmp_path, monkeypatch):
    path = _use(tmp_path, monkeypatch, make_ticket(JANE, TGS, lifetime=-2460))
    with pytest.raises(CredentialError) as info:
        _login()
    assert str(info.value) == (
        f"the Kerberos tickets for jane@{REALM} in {path} expired 41 minutes ago; run kinit"
    )


@pytest.mark.parametrize("content", [None, b"\x09\x09garbage"])
def test_an_unreadable_cache_is_an_error_not_a_silence(monkeypatch, tmp_path, content):
    path = tmp_path / "bad"
    if content is None:
        path.mkdir()  # exists, but reading it fails
    else:
        path.write_bytes(content)
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{path}")
    with pytest.raises(CredentialError, match="is unreadable"):
        _login()


def test_a_cached_service_ticket_is_used_without_asking_the_kdc(tmp_path, monkeypatch, kdc):
    held = _service()
    _use(tmp_path, monkeypatch, make_ticket(JANE, TGS), held)
    found = _login()
    assert found is not None and kdc == []
    assert str(found.target) == SERVICE
    assert found.ticket == held and found.forward is None


def test_with_only_a_tgt_the_kdc_is_asked_once_per_process(tgt_only, kdc):
    first = _login()
    second = _login()
    assert first is not None and second is not None
    assert len(kdc) == 1
    assert str(kdc[0]["server"]) == SERVICE
    assert kdc[0]["etypes"] == [18, 17, 20, 19] and kdc[0]["options"] == 0
    assert kdc[0]["tgt"].key == KEY


def test_the_realm_is_completed_before_the_kdc_is_asked(tgt_only, kdc):
    found = client.service_credentials("xrootd/srv.example.org", "srv.example.org")
    assert found is not None and str(found.target) == SERVICE


def test_clear_cache_forgets_the_fetched_tickets(tgt_only, kdc):
    _login()
    client.clear_cache()
    _login()
    assert len(kdc) == 2


def test_a_remembered_ticket_about_to_expire_is_fetched_again(tgt_only, kdc):
    _login()
    slot = next(iter(client._FETCHED))
    client._FETCHED[slot] = replace(client._FETCHED[slot], end_time=int(time.time()) + 30)
    _login()
    assert len(kdc) == 2


def test_no_tgt_and_no_service_ticket_says_kinit(monkeypatch, tmp_path, kdc):
    _use(tmp_path, monkeypatch, make_ticket(JANE, Principal(("host", "elsewhere"), REALM)))
    with pytest.raises(CredentialError, match=r"no live ticket-granting ticket for EXAMPLE\.ORG"):
        _login()


def test_a_tgt_without_a_session_key_is_passed_over(monkeypatch, tmp_path, kdc):
    _use(tmp_path, monkeypatch, make_ticket(JANE, TGS, key=b""))
    with pytest.raises(CredentialError, match="no live ticket-granting ticket"):
        _login()


def test_forwarding_fetches_a_forwarded_tgt(tgt_only, kdc):
    found = _login(forward=True)
    assert found is not None and found.forward is not None
    _service_request, forwarded = kdc
    assert forwarded["server"].components == ("krbtgt", REALM)
    assert forwarded["options"] == tgs.KDC_OPT_FORWARDED | tgs.KDC_OPT_FORWARDABLE


def test_forwarding_with_a_tgt_that_cannot_be_forwarded_says_kinit_f(monkeypatch, tmp_path, kdc):
    _use(tmp_path, monkeypatch, make_ticket(JANE, TGS, flags=0))
    with pytest.raises(CredentialError, match=r"is not forwardable; run kinit -f"):
        _login(forward=True)


def test_a_ticket_fetched_for_a_file_cache_is_not_written_back(tgt_only, kdc):
    before = Path(tgt_only).read_bytes()
    _login()
    assert Path(tgt_only).read_bytes() == before


def test_a_session_key_of_the_wrong_length_is_a_credential_error(monkeypatch, tmp_path):
    """A damaged cache must say so as a CredentialError, not escape as a ValueError."""
    _use(tmp_path, monkeypatch, make_ticket(JANE, TGS, key=b"short"))
    with pytest.raises(CredentialError, match="session key is 5 bytes, not 32"):
        _login()


# -- the messages built from a service ticket ------------------------------------------


def _session(enctype: int = 18) -> Ticket:
    """A service ticket with a real session key of ``enctype``."""
    return make_ticket(
        JANE,
        Principal(("xrootd", "srv.example.org"), REALM, 1),
        enctype=enctype,
        key=get_enctype(enctype).random_key(),
    )


def _open(blob: bytes, tag: int) -> Fields:
    """The fields of an ``[APPLICATION tag]`` message."""
    outer, _ = parse(blob)
    assert outer.tag == tag
    return Fields(parse(outer.value)[0], hex(tag))


@pytest.mark.parametrize("enctype", [17, 18, 19, 20])
def test_the_ap_req_is_what_krb5_mk_req_extended_sends(enctype):
    session = _session(enctype)
    ap_req = _open(tgs.build_ap_req(session), asn1.APP_AP_REQ)
    assert asn1.read_flags(ap_req.get(2)) == tgs.AP_OPTS_USE_SESSION_KEY
    sealed = asn1.read_encrypted_data(ap_req.get(4))
    plain = get_enctype(enctype).decrypt(session.key, tgs.USAGE_AP_REQ_AUTH, sealed.cipher)
    authenticator = Fields(parse(parse(plain)[0].value)[0], "Authenticator")
    assert authenticator.string(1) == REALM
    assert authenticator.optional(3) is None  # no checksum, as krb5_mk_req_extended sends
    assert abs(authenticator.time(5) - time.time()) < 5


def test_a_krb_cred_carries_the_forwarded_tgt_under_the_session_key():
    session = _session()
    forwarded = replace(_session(), server=TGS)
    krb_cred = _open(tgs.build_krb_cred(forwarded, session), asn1.APP_KRB_CRED)
    sealed = asn1.read_encrypted_data(krb_cred.get(3))
    plain = get_enctype(18).decrypt(session.key, tgs.USAGE_KRB_CRED, sealed.cipher)
    part = Fields(parse(parse(plain)[0].value)[0], "EncKrbCredPart")
    (info,) = part.get(0).children()
    assert asn1.read_key(Fields(info, "KrbCredInfo").get(0)).value == forwarded.key


def test_the_testing_cache_writer_writes_what_the_reader_reads(tmp_path):
    """``write_ccache`` is ``marshal_ticket`` behind a version 4 header, no tags."""
    ticket = make_ticket(JANE, TGS)
    path = write_ccache(tmp_path / "cc", [ticket])
    expected = struct.pack(">HH", CCACHE_VERSION_4, 0) + marshal_principal(JANE)
    assert Path(path).read_bytes() == expected + marshal_ticket(ticket)
    assert ticket.forwardable and ticket.flags == TKT_FLG_FORWARDABLE


def test_the_package_names_its_modules_and_loads_them_on_demand():
    import xrdsec.krb5

    assert dir(xrdsec.krb5) == sorted(xrdsec.krb5.__all__)
    assert xrdsec.krb5.client is client
    with pytest.raises(AttributeError, match="no attribute 'nonexistent'"):
        _ = xrdsec.krb5.nonexistent
