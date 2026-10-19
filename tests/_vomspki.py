"""The VOMS test installation: a proxy carrying an AC, its CA directory and vomsdir.

Shared by the VOMS decoding, policy and diagnostics tests. :func:`_fixture`
mints a user, a proxy and a VOMS server under one throwaway CA, writes the
files a grid installation would hold, and returns them with the raw
material a test needs to forge a variation; :func:`_ac` is the AC builder
with the knobs those tests turn.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, TypedDict

from xrdsec.rsa import RSAPrivateKey
from xrdsec.testing.rawpki import (
    PROXY_CERT_INFO,
    PROXY_CERT_INFO_OID,
    make_certificate,
    name,
    oid,
    pem,
    private_key_pem,
    sequence,
    throwaway_key,
    tlv,
)
from xrdsec.testing.voms import ACSpec, Attribute, make_ac
from xrdsec.voms import VOMS_AC_OID, VOMSEntry
from xrdsec.x509 import Certificate, ProxyCredential, load_proxy, parse_certificate

SHA1 = "1.2.840.113549.1.1.5"
SHA256 = "1.2.840.113549.1.1.11"
SHA384 = "1.2.840.113549.1.1.12"
SHA512 = "1.2.840.113549.1.1.13"
RSA_PSS = "1.2.840.113549.1.1.10"
MGF1 = "1.2.840.113549.1.1.8"
ECDSA_SHA256 = "1.2.840.10045.4.3.2"
EC_PUBLIC_KEY = "1.2.840.10045.2.1"
P256 = "1.2.840.10045.3.1.7"
ED25519 = "1.3.101.112"
DIGEST_SHA256 = "2.16.840.1.101.3.4.2.1"
NULL = tlv(0x05, b"")


class Facts(TypedDict):
    """The raw material behind a :func:`_fixture` installation."""

    ca_name: bytes
    user_name: bytes
    voms_name: bytes
    voms_der: bytes
    voms_key: RSAPrivateKey
    ca_der: bytes
    ca_key: RSAPrivateKey
    user_key: RSAPrivateKey


#: A proxy, its CA directory, its vomsdir and the material they were made from.
Installation = tuple[ProxyCredential, Path, Path, Facts]


def _algorithm(value: str = SHA256, parameters: bytes = NULL) -> bytes:
    return sequence(oid(value), parameters)


def _general_names(encoded_name: bytes) -> bytes:
    return sequence(tlv(0xA4, encoded_name))


def _gentime(when: float) -> bytes:
    return tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(when)).encode())


def _extension(key: str, value: bytes, critical: bool = False) -> bytes:
    flag = tlv(0x01, b"\xff") if critical else b""
    return sequence(oid(key), flag, tlv(0x04, value))


def _fqans(fqan: str | None) -> tuple[str, ...] | None:
    """One FQAN as ``ACSpec.fqans``: ``None`` - no attribute at all - and ``""`` - no values."""
    if fqan is None:
        return None
    return (fqan,) if fqan else ()


def _ac(
    user_name: bytes,
    user_serial: int,
    voms_name: bytes,
    voms_der: bytes,
    voms_key: RSAPrivateKey,
    *,
    version: int = 1,
    fqan: str | None = "/atlas/Role=production/Capability=NULL",
    uri: str = "voms.example:15000",
    not_before: float | None = None,
    not_after: float | None = None,
    holder_serial: int | None = None,
    issuer_name: bytes | None = None,
    inner_algorithm: str = SHA256,
    outer_algorithm: str = SHA256,
    signature_key: RSAPrivateKey | None = None,
    signature_digest: str = "sha256",
    algorithm_parameters: bytes = NULL,
    signature_function: Callable[[bytes], bytes] | None = None,
    embedded: tuple[bytes, ...] | None = None,
    extra_extensions: Iterable[bytes] = (),
    generic: bool = False,
) -> bytes:
    """One AC through the shared builder, :func:`xrdsec.testing.voms.make_ac`.

    The keywords are the knobs these tests turn, mapped onto ``ACSpec``; the
    algorithm identifiers and the signature are always given explicitly, so
    a test can make them disagree with the key, or with each other.
    """
    signer = signature_key or voms_key

    def sign(tbs: bytes) -> bytes:
        return signer.sign(tbs, digest=signature_digest)

    spec = ACSpec(
        version=version,
        fqans=_fqans(fqan),
        uri=uri,
        not_before=not_before or None,
        not_after=not_after or None,
        issuer_name=issuer_name or voms_name,
        embedded=embedded,
        extensions=tuple(extra_extensions),
        attributes=(Attribute("nickname", "alice", "atlas"),) if generic else (),
        algorithm=_algorithm(inner_algorithm, algorithm_parameters),
        outer_algorithm=_algorithm(outer_algorithm, algorithm_parameters),
        sign=signature_function or sign,
    )
    holder = (user_name, holder_serial or user_serial)
    return make_ac(holder, voms_der, voms_key.to_cryptography(), spec)


def _fixture(
    tmp_path: Path,
    *,
    ac_options: Mapping[str, Any] | None = None,
    acs: Iterable[bytes] | None = None,
    parent_carrier: bool = False,
    voms_ski: bytes | None = None,
    voms_spki: bytes | None = None,
) -> Installation:
    tmp_path.mkdir(parents=True, exist_ok=True)
    ca_key, user_key, proxy_key, voms_key = (throwaway_key(slot) for slot in range(1, 5))
    ca_name = name(("0.9.2342.19200300.100.1.25", "org"), ("2.5.4.3", "Grid CA"))
    user_name = name(
        ("0.9.2342.19200300.100.1.25", "org"),
        ("0.9.2342.19200300.100.1.25", "example"),
        ("2.5.4.3", "Alice"),
    )
    voms_name = name(("0.9.2342.19200300.100.1.25", "org"), ("2.5.4.3", "voms.example"))
    ca_der = make_certificate(ca_name, ca_name, ca_key.public, ca_key, serial=1)
    user_der = make_certificate(user_name, ca_name, user_key.public, ca_key, serial=2)
    voms_extensions = (
        (("1.2.3", tlv(0x05, b"")), ("2.5.29.14", voms_ski)) if voms_ski is not None else ()
    )
    voms_der = make_certificate(
        voms_name,
        ca_name,
        voms_key.public,
        ca_key,
        serial=3,
        extensions=voms_extensions,
        subject_spki=voms_spki,
    )
    options = dict(ac_options or {})
    built = acs or [_ac(user_name, 2, voms_name, voms_der, voms_key, **options)]
    acseq = sequence(sequence(*built))
    parent_name = name(
        ("0.9.2342.19200300.100.1.25", "org"),
        ("0.9.2342.19200300.100.1.25", "example"),
        ("2.5.4.3", "Alice"),
        ("2.5.4.3", "1234"),
    )
    voms_extension = ((VOMS_AC_OID, acseq),)
    if parent_carrier:
        parent_der = make_certificate(
            parent_name,
            user_name,
            proxy_key.public,
            user_key,
            serial=4,
            extensions=(*voms_extension, (PROXY_CERT_INFO_OID, PROXY_CERT_INFO)),
        )
        leaf_key = throwaway_key(5)
        leaf_name = name(
            ("0.9.2342.19200300.100.1.25", "org"),
            ("0.9.2342.19200300.100.1.25", "example"),
            ("2.5.4.3", "Alice"),
            ("2.5.4.3", "1234"),
            ("2.5.4.3", "5678"),
        )
        proxy_der = make_certificate(
            leaf_name,
            parent_name,
            leaf_key.public,
            proxy_key,
            serial=5,
            extensions=((PROXY_CERT_INFO_OID, PROXY_CERT_INFO),),
        )
        key = leaf_key
        between = pem("CERTIFICATE", parent_der)
    else:
        proxy_der = make_certificate(
            parent_name,
            user_name,
            proxy_key.public,
            user_key,
            serial=4,
            extensions=(*voms_extension, (PROXY_CERT_INFO_OID, PROXY_CERT_INFO)),
        )
        key = proxy_key
        between = b""
    proxy_path = tmp_path / "x509up"
    proxy_path.write_bytes(
        pem("CERTIFICATE", proxy_der)
        + private_key_pem(key)
        + between
        + pem("CERTIFICATE", user_der)
        + pem("CERTIFICATE", ca_der)
    )
    ca_dir = tmp_path / "certificates"
    ca_dir.mkdir()
    (ca_dir / "12345678.0").write_bytes(pem("CERTIFICATE", ca_der))
    voms_dir = tmp_path / "vomsdir" / "atlas"
    voms_dir.mkdir(parents=True)
    proxy = load_proxy(str(proxy_path))
    # Names are deliberately taken from the parser, pinning the LSC rendering.
    parsed_voms = load_proxy_from_der(voms_der)
    (voms_dir / "voms.example.lsc").write_text(
        f"# trusted server\n{parsed_voms.subject}\n{parsed_voms.issuer}\n"
    )
    facts: Facts = {
        "ca_name": ca_name,
        "user_name": user_name,
        "voms_name": voms_name,
        "voms_der": voms_der,
        "voms_key": voms_key,
        "ca_der": ca_der,
        "ca_key": ca_key,
        "user_key": user_key,
    }
    return proxy, ca_dir, voms_dir.parent, facts


def load_proxy_from_der(der: bytes) -> Certificate:
    return parse_certificate(der)


def _embedded_signer(entry: VOMSEntry) -> Certificate:
    """The VOMS server certificate an AC carries, in this package's own model.

    ``VOMSEntry`` types it as the read-only view both clients share; the
    chains made here are this package's, so the dataclass (which a test can
    ``replace``) is what is really there.
    """
    signer = entry._embedded[0]
    assert isinstance(signer, Certificate)
    return signer
