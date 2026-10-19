"""Globus delegation's request side: making a request, signing one, splitting a DER chain.

:func:`~xrdsec.delegation.make_proxy_request`,
:func:`~xrdsec.delegation.sign_globus_request` and
:func:`~xrdsec.x509.split_der_certificates` moved here from xgfalclient's
``crypto/proxy.py`` and ``crypto/x509.py`` in 0.4.0, for GSI delegation
(:mod:`xrdsec.gsi.gss`); these are their cases, ported.
"""

from __future__ import annotations

import time

import pytest

from xrdsec import der, rsa
from xrdsec.delegation import (
    DelegationError,
    ProxyRequest,
    make_proxy_request,
    parse_proxy_request,
    sign_globus_request,
)
from xrdsec.proxies import NOT_BEFORE_SKEW
from xrdsec.testing.pki import PKI, test_key
from xrdsec.x509 import (
    LIMITED_PROXY_OID,
    ProxyCredential,
    certificate_data,
    proxy_policy,
    split_der_certificates,
)


def key(slot: int) -> rsa.RSAPrivateKey:
    """Frozen key ``slot`` as xrdsec's RSA view."""
    return rsa.RSAPrivateKey.from_cryptography(test_key(slot))


def sign(
    request: bytes | ProxyRequest,
    credential: ProxyCredential,
    *,
    lifetime: float | None = None,
    limited: bool | None = None,
    now: float | None = None,
) -> bytes:
    """``sign_globus_request`` with ``credential``'s chain and key."""
    chain = [link.der for link in credential.chain]
    return sign_globus_request(
        request, chain, credential.key, lifetime=lifetime, limited=limited, now=now
    )


def test_a_request_round_trips() -> None:
    request = parse_proxy_request(make_proxy_request(key(5), (("CN", "delegated"),)))
    assert request.verify() and request.public_key == key(5).public
    assert str(request.subject) == "/CN=delegated"
    assert str(parse_proxy_request(make_proxy_request(key(5))).subject) == "/CN=proxy"


def test_a_globus_proxy_is_issued_below_the_signer(pki: PKI) -> None:
    credential = pki.credential()
    now = time.time()
    request = make_proxy_request(key(6))
    proxy = certificate_data(sign(request, credential, lifetime=60, now=now))
    issuer = credential.certificate
    assert proxy.issuer.rdns == issuer.subject.rdns
    assert proxy.subject.rdns[:-1] == issuer.subject.rdns
    assert proxy.subject.cn == str(proxy.serial)
    assert proxy.not_before == int(now - NOT_BEFORE_SKEW)
    assert proxy.not_after == int(now + 60)
    assert proxy.public_key == key(6).public
    unlimited = certificate_data(sign(parse_proxy_request(request), credential))
    assert unlimited.not_after == min(link.not_after for link in credential.chain)
    limited = certificate_data(sign(request, credential, limited=True))
    assert proxy_policy(limited.extension_values) == LIMITED_PROXY_OID


def test_limited_proxies_only_beget_limited(pki: PKI) -> None:
    limited = pki.credential(pki.proxy("limited"))
    child = certificate_data(sign(make_proxy_request(key(6)), limited, limited=False))
    assert proxy_policy(child.extension_values) == LIMITED_PROXY_OID


def test_a_legacy_signer_begets_a_legacy_proxy(pki: PKI) -> None:
    legacy = pki.credential(pki.proxy("legacy"))
    child = certificate_data(sign(make_proxy_request(key(6)), legacy))
    assert child.subject.cn == "proxy" and proxy_policy(child.extension_values) is None
    limited = certificate_data(sign(make_proxy_request(key(6)), legacy, limited=True))
    assert limited.subject.cn == "limited proxy"


def test_every_refusal_is_a_delegation_error(pki: PKI) -> None:
    credential = pki.credential()
    good = der.parse_one(make_proxy_request(key(5))).children()
    forged = der.sequence(good[0].encoded, good[1].encoded, der.bit_string(b"\x00" * 256))
    with pytest.raises(DelegationError, match="does not verify"):
        sign(forged, credential)
    with pytest.raises(DelegationError, match="not a PKCS#10"):
        sign(der.sequence(der.integer(1)), credential)
    with pytest.raises(DelegationError):
        sign_globus_request(make_proxy_request(key(6)), [b"\x30\x03\x02\x01\x00"], credential.key)
    with pytest.raises(DelegationError, match="lifetime must be positive"):
        sign(make_proxy_request(key(6)), credential, lifetime=0)


def test_consecutive_der_certificates_are_split(pki: PKI) -> None:
    credential = pki.credential()
    chain = b"".join(link.der for link in credential.chain)
    split = split_der_certificates(chain)
    assert [link.der for link in split] == [link.der for link in credential.chain]
    assert split_der_certificates(b"") == []
    with pytest.raises(der.DERError):
        split_der_certificates(b"\x30\x05\x00")
