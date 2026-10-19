"""One signature check for every algorithm a grid PKI signs with.

Certificates, certificate requests and VOMS attribute certificates are all
``SEQUENCE { body, AlgorithmIdentifier, BIT STRING }``: the signature covers
the body exactly as written, and the ``AlgorithmIdentifier`` says how. What
differs between them is only where the signer's public key comes from, so
everything that checks a signature here goes through :func:`verify_signature`
with the signer's ``SubjectPublicKeyInfo`` and lets ``cryptography`` do the
arithmetic - RSA PKCS#1 v1.5 and RSASSA-PSS, ECDSA on any named curve
``cryptography`` knows, Ed25519 and Ed448.

What stays here is the *policy*: which ``AlgorithmIdentifier`` values are
accepted and with what parameters. That is deliberately narrower than
"whatever OpenSSL would do" - MD5 and SHA-1-with-ECDSA are refused, PSS
parameters must be DER and name a SHA-2 or SHA-1 hash - because a signature
algorithm the client does not recognise must fail closed, not fall through
to a guess.

Why not ``Certificate.verify_directly_issued_by``: it requires the issuer
field and the issuer's subject to be *byte-identical*, including each
attribute's string type. OpenSSL - and so every XRootD server - compares the
canonical forms instead, so a CA whose subject is a ``PrintableString`` and
whose certificates carry it as ``UTF8String`` is valid to the far end. The
callers here match names the forgiving way and then check only the signature.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from asn1crypto import algos
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from .der import TAG_NULL, TAG_SEQUENCE, DERError, Element, encode, parse

__all__ = [
    "ECDSA_DIGESTS",
    "ED448_OID",
    "ED25519_OID",
    "RSA_PKCS1_DIGESTS",
    "RSA_PSS_OID",
    "PSSParameters",
    "SignatureAlgorithmError",
    "null_parameters",
    "pss_hash",
    "pss_parameters",
    "signature_label",
    "verify_signature",
]

#: ``sha*WithRSAEncryption``: PKCS#1 v1.5 over the named hash.
RSA_PKCS1_DIGESTS = {
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}
#: ``ecdsa-with-SHA*`` (RFC 5758): ECDSA over the named hash, on the key's curve.
ECDSA_DIGESTS = {
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
}
#: ``id-RSASSA-PSS``: the hash, mask and salt are in the parameters.
RSA_PSS_OID = "1.2.840.113549.1.1.10"
#: ``id-Ed25519`` / ``id-Ed448`` (RFC 8410): parameters must be absent.
ED25519_OID = "1.3.101.112"
ED448_OID = "1.3.101.113"

#: Every hash any accepted scheme may name. SHA-1 stays for verifying the
#: older certificates and PSS defaults still in circulation; MD5 never did.
_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

#: A verifier raises ``InvalidSignature`` (or ``TypeError`` for the wrong
#: kind of key) and returns nothing when the signature is good.
_Verifier = Callable[[Any, bytes, bytes], None]


class SignatureAlgorithmError(DERError):
    """The ``AlgorithmIdentifier`` is not one this client verifies.

    Distinct from a signature that is simply wrong: a caller reporting why
    something is untrusted says "unsupported algorithm" for this and "bad
    signature" for ``False``.
    """


@dataclass(frozen=True, slots=True)
class PSSParameters:
    """``RSASSA-PSS-params`` with RFC 4055's defaults: SHA-1, MGF1-SHA-1, salt 20."""

    digest: str = "sha1"
    mgf_digest: str = "sha1"
    salt_length: int = 20


def null_parameters(parameters: list[Element]) -> bool:
    """Absent, or a single empty ``NULL`` - the two spellings RSA allows."""
    return not parameters or (
        len(parameters) == 1 and parameters[0].tag == TAG_NULL and not parameters[0].value
    )


def pss_parameters(parameters: list[Element]) -> PSSParameters | None:
    """The PSS configuration, or ``None`` if the parameters are not strict DER we accept."""
    if not parameters:
        return PSSParameters()
    if len(parameters) != 1 or parameters[0].tag != TAG_SEQUENCE:
        return None
    try:
        # DER fields must be unique, ordered, and known. asn1crypto accepts
        # some BER schema leftovers, so enforce that input policy explicitly.
        if not _pss_fields_valid(parameters[0]):
            return None
        encoded = encode(parameters[0].tag, parameters[0].value)
        config = algos.RSASSAPSSParams.load(encoded, strict=True).native
        return _pss_config(config)
    except (ValueError, TypeError, KeyError):
        return None


def _pss_fields_valid(element: Element) -> bool:
    """Whether the PSS parameter fields are in strictly increasing ``[0]``..``[3]`` order.

    DER forbids repeated or out-of-order fields; ``asn1crypto`` would decode
    some of those anyway, and two decoders reading different parameters from
    one signature is how algorithm confusion starts.
    """
    tags = [field.tag for field in element.children()]
    return tags == sorted(set(tags)) and all(tag in range(0xA0, 0xA4) for tag in tags)


def _pss_config(config: dict[str, Any]) -> PSSParameters | None:
    """Turn decoded ``RSASSA-PSS-params`` into :class:`PSSParameters`, or ``None`` to refuse.

    The mask generator must be MGF1 (the only one RFC 8017 defines), both
    hashes must be ours with absent parameters, and the trailer must be the
    ``0xBC`` one; anything else is refused rather than half-honoured.
    """
    digest = pss_hash(config["hash_algorithm"])
    mgf = config["mask_gen_algorithm"]
    if set(mgf) != {"algorithm", "parameters"} or mgf["algorithm"] != "mgf1":
        return None
    mgf_digest = pss_hash(mgf["parameters"])
    salt_length = config["salt_length"]
    if digest is None or mgf_digest is None or salt_length < 0:
        return None
    if config["trailer_field"] != "trailer_field_bc":
        return None
    return PSSParameters(digest, mgf_digest, salt_length)


def pss_hash(algorithm: dict[str, Any]) -> str | None:
    """A PSS hash or MGF1 hash, only when it is one of ours with no parameters."""
    if set(algorithm) != {"algorithm", "parameters"}:
        return None
    digest = algorithm["algorithm"]
    if digest not in _HASHES or algorithm["parameters"] is not None:
        return None
    return str(digest)


# ---------------------------------------------------------------------------
# One verifier per scheme. Each refuses the wrong kind of key with TypeError,
# which verify_signature reports as a signature that does not verify.
# ---------------------------------------------------------------------------


def _pkcs1(digest: str) -> _Verifier:
    """A verifier for RSA PKCS#1 v1.5 over ``digest``."""

    def check(key: Any, signature: bytes, data: bytes) -> None:
        """Raise unless ``signature`` is ``key``'s PKCS#1 v1.5 signature over ``data``."""
        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError("not an RSA key")
        key.verify(signature, data, padding.PKCS1v15(), _HASHES[digest]())

    return check


def _pss(config: PSSParameters) -> _Verifier:
    """A verifier for RSASSA-PSS with exactly the hash, MGF1 hash and salt length given."""

    def check(key: Any, signature: bytes, data: bytes) -> None:
        """Raise unless ``signature`` is ``key``'s PSS signature with the configured parameters.

        The salt length is fixed to the one the parameters declare, not
        auto-detected, so a signature made under different parameters fails.
        """
        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError("not an RSA key")
        mask = padding.MGF1(_HASHES[config.mgf_digest]())
        scheme = padding.PSS(mgf=mask, salt_length=config.salt_length)
        key.verify(signature, data, scheme, _HASHES[config.digest]())

    return check


def _ecdsa(digest: str) -> _Verifier:
    """A verifier for ECDSA over ``digest``, on whatever named curve the key uses."""

    def check(key: Any, signature: bytes, data: bytes) -> None:
        """Raise unless ``signature`` (DER ``ECDSA-Sig-Value``) is ``key``'s over ``data``."""
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("not an EC key")
        key.verify(signature, data, ec.ECDSA(_HASHES[digest]()))

    return check


def _eddsa(kind: type[Any]) -> _Verifier:
    """A verifier for pure EdDSA with a public key of type ``kind``."""

    def check(key: Any, signature: bytes, data: bytes) -> None:
        """Raise unless ``signature`` is ``key``'s EdDSA signature over ``data`` (no prehash)."""
        if not isinstance(key, kind):
            raise TypeError(f"not an {kind.__name__}")
        key.verify(signature, data)

    return check


#: EdDSA OIDs to the label a report uses and the public-key type that must match.
_EDDSA = {
    ED25519_OID: ("ed25519", ed25519.Ed25519PublicKey),
    ED448_OID: ("ed448", ed448.Ed448PublicKey),
}


#: A scheme is its report label and the verifier that enforces it.
_Scheme = tuple[str, _Verifier]


def _pkcs1_scheme(algorithm: str, parameters: list[Element]) -> _Scheme | None:
    """The PKCS#1 v1.5 scheme for ``algorithm``, if it is one with NULL or absent parameters."""
    digest = RSA_PKCS1_DIGESTS.get(algorithm)
    return (digest, _pkcs1(digest)) if digest and null_parameters(parameters) else None


def _ecdsa_scheme(algorithm: str, parameters: list[Element]) -> _Scheme | None:
    """The ECDSA scheme for ``algorithm``, if it is one and has no parameters (RFC 5758)."""
    digest = ECDSA_DIGESTS.get(algorithm)
    return (digest, _ecdsa(digest)) if digest and not parameters else None


def _eddsa_scheme(algorithm: str, parameters: list[Element]) -> _Scheme | None:
    """The EdDSA scheme for ``algorithm``, if it is one and has no parameters (RFC 8410)."""
    eddsa = _EDDSA.get(algorithm)
    return (eddsa[0], _eddsa(eddsa[1])) if eddsa and not parameters else None


def _pss_scheme(algorithm: str, parameters: list[Element]) -> _Scheme | None:
    """The PSS scheme, if ``algorithm`` is ``id-RSASSA-PSS`` with acceptable parameters."""
    config = pss_parameters(parameters) if algorithm == RSA_PSS_OID else None
    return ("rsassa-pss", _pss(config)) if config else None


def _scheme(algorithm: str, parameters: list[Element]) -> _Scheme:
    """The label and the verifier for one ``AlgorithmIdentifier``.

    The label is what a diagnostic calls the algorithm: the hash name for the
    PKCS#1 and ECDSA families (which is what reports have always said),
    ``rsassa-pss``, ``ed25519`` or ``ed448`` otherwise. Each family checks
    its own parameter rule - RSA PKCS#1 takes ``NULL`` or nothing, ECDSA and
    EdDSA nothing at all, PSS a strict ``RSASSA-PSS-params``.
    """
    for family in (_pkcs1_scheme, _ecdsa_scheme, _eddsa_scheme, _pss_scheme):
        found = family(algorithm, parameters)
        if found is not None:
            return found
    raise SignatureAlgorithmError(f"unsupported signature algorithm {algorithm}")


def signature_label(algorithm: str, parameters: list[Element]) -> str | None:
    """What a report calls this signature algorithm; ``None`` if it is not accepted."""
    try:
        return _scheme(algorithm, parameters)[0]
    except SignatureAlgorithmError:
        return None


def verify_signature(
    spki_der: bytes,
    algorithm_oid: str,
    params: bytes | None,
    signature: bytes,
    data: bytes,
) -> bool:
    """Whether the key in ``spki_der`` signed ``data`` under the given algorithm.

    ``params`` is the DER of the ``AlgorithmIdentifier``'s parameters, or
    ``None`` when the field is absent (which is not the same as ``NULL``:
    ECDSA and EdDSA require absence, RSA accepts either). Raises
    :class:`SignatureAlgorithmError` for an algorithm or parameter set this
    client does not accept; returns ``False`` for a key that cannot be
    loaded, a key of the wrong kind for the algorithm, or a signature that
    does not verify.
    """
    try:
        parameters = [] if params is None else [_single(params)]
    except DERError as exc:
        raise SignatureAlgorithmError(f"malformed signature parameters: {exc}") from exc
    _label, check = _scheme(algorithm_oid, parameters)
    try:
        check(serialization.load_der_public_key(spki_der), signature, data)
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm):
        return False
    return True


def _single(data: bytes) -> Element:
    """Parse ``data`` as exactly one element; trailing bytes are a ``DERError``."""
    element, end = parse(data)
    if end != len(data):
        raise DERError(f"{len(data) - end} trailing bytes after the parameters")
    return element
