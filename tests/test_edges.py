"""Edges of the ported primitives that the ported suites leave unexercised."""

from __future__ import annotations

import calendar
import ssl
import time

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from xrdsec import der, rsa, userproxy, x509
from xrdsec.aes import CTR
from xrdsec.testing.pki import test_key


def test_ctr_is_a_continuous_stream():
    key, iv = bytes(range(16)), bytes(16)
    whole = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(b"x" * 37)
    stream = CTR(key, iv)
    assert stream.update(b"x" * 5) + stream.update(b"x" * 32) == whole
    with pytest.raises(ValueError, match="16 bytes"):
        CTR(key, b"short")


def test_der_builders_round_trip():
    assert der.parse_one(der.octet_string(b"ab")).value == b"ab"
    when = calendar.timegm((2026, 7, 31, 12, 0, 0))
    assert der.decode_time(der.parse_one(der.utc_time(when))) == when
    assert der.decode_time(der.parse_one(der.generalized_time(when))) == when
    assert der.parse_one(der.validity_time(when)).tag == der.TAG_UTC_TIME
    assert der.parse_one(der.validity_time(calendar.timegm((2051, 1, 1, 0, 0, 0)))).tag == (
        der.TAG_GENERALIZED_TIME
    )
    with pytest.raises(der.DERError, match="trailing"):
        der.parse_one(der.octet_string(b"") + b"\x00")
    with pytest.raises(der.DERError, match="two arcs"):
        der.encode_oid("1")


def test_user_proxy_refusals():
    with pytest.raises(ValueError, match="needs the user certificate"):
        userproxy.user_proxy((), rsa.RSAPrivateKey.from_cryptography(test_key(0)))


def test_an_expired_user_certificate_makes_no_proxy(pki):
    user = pki.user_credential
    with pytest.raises(ValueError, match="expired"):
        userproxy.user_proxy(user.chain, user.key, now=user.certificate.not_after + 1)


def test_names_fall_back_to_utf8():
    encoded = x509.encode_name((("CN", "Jané"),))
    assert x509.decode_name(encoded).cn == "Jané"


def test_key_usage_bounds():
    with pytest.raises(ValueError):
        x509.key_usage()
    with pytest.raises(ValueError):
        x509.key_usage(8)


def test_issuer_hashes_and_non_canonical_strings(pki):
    ca = x509.parse_certificate(pki.ca_signer.der)
    assert x509.issuer_hashes(pki.user_credential.certificate) == x509.name_hashes(
        ca.subject.encoded()
    )
    # An attribute value of a type OpenSSL does not fold (an OCTET STRING) is hashed as written.
    odd = der.sequence(der.set_of(der.sequence(der.oid("2.5.4.3"), der.octet_string(b"x"))))
    assert len(x509.name_hashes(odd)[0]) == 8


def test_signature_algorithm_identifiers():
    assert der.parse_one(x509.signature_algorithm("sha256")).children()[1].tag == der.TAG_NULL


def test_a_private_key_without_primes_cannot_be_encoded():
    numbers = test_key(0).private_numbers()
    public = numbers.public_numbers
    bare = rsa.RSAPrivateKey(public.n, public.e, numbers.d)
    with pytest.raises(ValueError, match="primes"):
        rsa.private_key_der(bare)


def test_moment_is_truncated():
    from xrdsec.delegation import _moment

    assert _moment(time.time()).microsecond == 0


def test_extension_and_key_info_builders(pki):
    assert x509.parse_extension(x509.extension("2.5.29.15", x509.key_usage(0, 2))).critical is False
    critical = x509.parse_extension(x509.extension("2.5.29.15", x509.key_usage(0), critical=True))
    assert critical.critical is True and critical.oid == "2.5.29.15"
    assert x509.key_usage(0, 2) == bytes.fromhex("030205a0")
    user = x509.certificate_data(pki.user_credential.certificate.der)
    assert user.public_key is not None
    assert x509.public_key_info(user.public_key) == user.spki
    assert der.parse_one(der.explicit(0, der.integer(2))).tag == 0xA0


def test_no_default_proxy_presents_nothing(tmp_path, monkeypatch):
    from xrdsec import credentials, tls

    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp_path))
    context = tls.client_context(present_default=True)
    assert context.verify_mode == ssl.CERT_REQUIRED
