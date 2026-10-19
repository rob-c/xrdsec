"""The ``"globus"`` profile: ``globus_gsi_proxy_sign_req``, as xgfalclient signed it.

xgfalclient's ``crypto.proxy.sign_request`` (GridFTP, SRM and gridsite
delegation) is the reference; each test pins one rule of it, field by field:
the subject and serial, the string type of the new ``CN``, the extensions,
the policy, the validity window and what a GT2 legacy signer begets. The
rules every profile shares (expired signers, foreign keys, path lengths,
forbidden extensions) are ``test_proxies.py``'s.
"""

from __future__ import annotations

import dataclasses
import hashlib
import time
from pathlib import Path

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization

from xrdsec import proxies
from xrdsec.delegation import ProxyRequest, parse_proxy_request
from xrdsec.der import TAG_PRINTABLE_STRING, parse_one
from xrdsec.proxies import issue_proxy
from xrdsec.testing.pki import create_pki
from xrdsec.testing.proxygrid import Grid, build_grid, key, usage
from xrdsec.voms import VOMS_AC_OID
from xrdsec.x509 import (
    INHERIT_ALL_OID,
    KEY_USAGE_OID,
    LIMITED_PROXY_OID,
    PROXY_CERT_INFO_OID,
    ProxyCredential,
    certificate_fields,
    extensions_of,
    legacy_proxy_kind,
    proxy_policy,
)

MOMENT = float(int(time.time()))


@pytest.fixture
def grid(tmp_path: Path) -> Grid:
    return build_grid(tmp_path / "grid")


@pytest.fixture
def user(grid: Grid) -> ProxyCredential:
    return grid.credential()


def _request(private) -> ProxyRequest:
    """A PKCS#10 request for ``private``'s key; Globus ignores its subject."""
    built = cx509.CertificateSigningRequestBuilder().subject_name(
        cx509.Name.from_rfc4514_string("CN=proxy")
    )
    built = built.add_extension(usage(), critical=True)
    return parse_proxy_request(
        built.sign(private, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    )


def _key_serial(request: ProxyRequest) -> int:
    """``proxy_serial`` in xgfalclient: the first four bytes of the key's SHA-1."""
    return int.from_bytes(hashlib.sha1(request.spki).digest()[:4], "big")


def _extensions(certificate) -> dict[str, tuple[bool, bytes]]:
    return {ext.oid: (ext.critical, ext.value) for ext in extensions_of(certificate.der)}


def _last_cn_tag(certificate) -> int:
    subject = parse_one(certificate_fields(certificate.der)["subject"])
    return subject.children()[-1].children()[0].children()[1].tag


def test_the_profile_is_listed():
    assert "globus" in proxies.PROFILES
    assert proxies._PROFILES["globus"].voms is False


def test_the_proxy_is_named_after_its_key(user):
    request = _request(key(5))
    issued = issue_proxy(user, request, profile="globus", now=MOMENT)
    serial = _key_serial(request)
    assert issued.serial == serial
    assert issued.subject.rdns == (*user.chain[0].subject.rdns, ("CN", str(serial)))
    assert issued.issuer == user.chain[0].subject
    assert _last_cn_tag(issued) == TAG_PRINTABLE_STRING
    # The issuer's RDNs are copied byte for byte, as a verifier compares them.
    signer = certificate_fields(user.chain[0].der)["subject"]
    assert certificate_fields(issued.der)["issuer"] == signer


def test_the_extensions_are_key_usage_and_proxy_cert_info_only(user):
    issued = issue_proxy(user, _request(key(5)), profile="globus")
    extensions = _extensions(issued)
    assert set(extensions) == {KEY_USAGE_OID, PROXY_CERT_INFO_OID}
    assert extensions[KEY_USAGE_OID] == (True, bytes.fromhex("030205a0"))
    assert extensions[PROXY_CERT_INFO_OID][0] is True
    assert proxy_policy(extensions) == INHERIT_ALL_OID


def test_validity_is_backdated_five_minutes_and_bounded_by_the_chain(user):
    issued = issue_proxy(user, _request(key(5)), profile="globus", now=MOMENT)
    assert issued.not_before == max(MOMENT - 300, user.chain[0].not_before)
    assert issued.not_after == min(link.not_after for link in user.chain)
    shorter = issue_proxy(user, _request(key(5)), profile="globus", now=MOMENT, lifetime=60)
    assert shorter.not_after == MOMENT + 60


@pytest.mark.parametrize("asked", [None, False, True])
def test_limitation_is_imposed_on_request_and_never_lifted(user, asked):
    rfc = issue_proxy(user, _request(key(5)), profile="globus", limited=asked)
    expected = LIMITED_PROXY_OID if asked else INHERIT_ALL_OID
    assert proxy_policy(_extensions(rfc)) == expected
    limited = ProxyCredential(
        chain=(issue_proxy(user, _request(key(6)), profile="globus", limited=True), *user.chain),
        key=key(6),
    )
    child = issue_proxy(limited, _request(key(7)), profile="globus", limited=asked)
    assert proxy_policy(_extensions(child)) == LIMITED_PROXY_OID


def test_no_voms_ac_is_carried_forward(grid, user):
    voms = proxies.create_proxy(user, voms_acs=[grid.make_ac()])
    assert VOMS_AC_OID in _extensions(voms.certificate)
    issued = issue_proxy(voms, _request(key(6)), profile="globus")
    assert VOMS_AC_OID not in _extensions(issued)
    rfc = issue_proxy(voms, _request(key(6)), profile="rfc3820")
    assert VOMS_AC_OID in _extensions(rfc)  # the default profile does carry it


@pytest.mark.parametrize(("kind", "child_name"), [("legacy", "proxy"), ("limited", None)])
def test_a_legacy_signer_begets_a_legacy_child(tmp_path, kind, child_name):
    pki = create_pki(tmp_path / "pki")
    signer = pki.credential(pki.proxy("legacy", path=tmp_path / "legacy"))
    assert legacy_proxy_kind(signer.chain[0].subject, signer.chain[0].issuer) == "proxy"
    limited = kind == "limited"
    child = issue_proxy(signer, _request(key(5)), profile="globus", limited=limited)
    expected = "limited proxy" if limited else child_name
    assert child.subject.rdns[-1] == ("CN", expected)
    assert PROXY_CERT_INFO_OID not in _extensions(child)
    assert child.serial == _key_serial(_request(key(5)))


def test_an_rfc_signer_never_begets_a_legacy_child(user):
    rfc = ProxyCredential(
        chain=(issue_proxy(user, _request(key(6)), profile="globus"), *user.chain), key=key(6)
    )
    child = issue_proxy(rfc, _request(key(7)), profile="globus")
    assert PROXY_CERT_INFO_OID in _extensions(child)
    assert child.subject.rdns[:-1] == rfc.chain[0].subject.rdns


def test_a_bare_key_is_certified_like_a_request(user):
    request = _request(key(5))
    from_spki = issue_proxy(user, request.spki, profile="globus", now=MOMENT)
    assert from_spki.serial == _key_serial(request)


def test_an_unsigned_request_is_refused(user):
    good = _request(key(5))
    forged = dataclasses.replace(good, der=good.der[:-1] + bytes([good.der[-1] ^ 1]))
    with pytest.raises(proxies.ProxyError, match="not signed"):
        issue_proxy(user, forged, profile="globus")


def test_a_stronger_digest_can_be_asked_for_and_sha1_cannot(user):
    """``digest`` reaches the signature: SHA-384 when a peer asks, never SHA-1."""
    strong = issue_proxy(user, _request(key(5)), profile="globus", digest="sha384")
    signed = cx509.load_der_x509_certificate(strong.der)
    assert isinstance(signed.signature_hash_algorithm, hashes.SHA384)
    with pytest.raises(proxies.ProxyError, match="unsupported digest"):
        issue_proxy(user, _request(key(5)), profile="globus", digest="sha1")
