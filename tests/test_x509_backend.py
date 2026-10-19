"""The X.509 decoder is ``cryptography``'s; the legacy DER path is a fallback only.

Ported from xrdclient's ``tests/test_rebased_backends.py`` when the X.509
code moved here: a well-formed certificate must never reach the hand-written
DER parser, and a certificate whose public key ``cryptography`` cannot load
(an algorithm it does not know, a broken encoding) still yields its subject,
issuer and validity, with no RSA view.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from xrdsec import x509 as certificates
from xrdsec.testing.rawpki import make_certificate, name, throwaway_key


def test_normal_certificates_are_parsed_by_cryptography(monkeypatch):
    key = throwaway_key(0)
    subject = name(("2.5.4.3", "library certificate"))
    der = make_certificate(subject, subject, key.public, key)

    def forbidden(*arguments):
        raise AssertionError("a normal certificate must not use legacy parsing")

    monkeypatch.setattr(certificates, "_legacy_certificate_data", forbidden)
    monkeypatch.setattr(certificates, "certificate_fields", forbidden)
    monkeypatch.setattr(certificates, "parse_one", forbidden)
    result = certificates.certificate_data(der)
    assert result.subject.cn == "library certificate"
    assert result.der == der and result.public_key == key.public
    assert result.signature and result.tbs and result.spki


def _ec_certificate() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "EC root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2040, 1, 1, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_real_ec_certificates_keep_the_existing_non_rsa_view():
    result = certificates.certificate_data(_ec_certificate())
    assert result.subject.cn == "EC root" and result.public_key is None


@pytest.mark.parametrize(
    "error", [ValueError("unreadable key"), UnsupportedAlgorithm("unknown key")]
)
def test_an_unusable_public_key_does_not_lose_certificate_metadata(monkeypatch, error):
    cert = x509.load_der_x509_certificate(_ec_certificate())

    def unusable():
        raise error

    view = SimpleNamespace(
        subject=cert.subject,
        issuer=cert.issuer,
        extensions=cert.extensions,
        serial_number=cert.serial_number,
        not_valid_before_utc=cert.not_valid_before_utc,
        not_valid_after_utc=cert.not_valid_after_utc,
        public_key=unusable,
        signature=cert.signature,
        tbs_certificate_bytes=cert.tbs_certificate_bytes,
        signature_algorithm_oid=cert.signature_algorithm_oid,
    )
    monkeypatch.setattr(x509, "load_der_x509_certificate", lambda data: view)
    result = certificates.certificate_data(_ec_certificate())
    assert result.subject.cn == "EC root" and result.public_key is None
