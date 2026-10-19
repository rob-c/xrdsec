"""What a proxy is, in ``voms-proxy-info``'s terms: :func:`describe_proxy`.

Re-exported by :mod:`xrdsec.proxies`. The answer is a
:class:`ProxyInfo` - plain values, ready for a report - built from a
certificate chain alone, so a chain from a file, from a GSI peer or from
:func:`~xrdsec.proxies.create_proxy` is described the same way and
no private key is needed.

The wording of :attr:`ProxyInfo.kind` and :attr:`ProxyInfo.key_usage` is the
VOMS clients' (``voms-proxy-info``'s ``type`` and ``key usage`` lines), so a
script that greps their output keeps working against ``xrd-proxy info``. The
VOMS attribute certificates are *decoded*, not validated: describing a proxy
makes no trust decision (``voms-proxy-info`` does not either); call
:func:`~xrdsec.voms.validate_voms` for one.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from .delegation import KEY_USAGE_OID, proxy_path_length
from .der import DERError, parse_one
from .voms import VOMSEntry, inspect_voms
from .x509 import (
    INDEPENDENT_OID,
    INHERIT_ALL_OID,
    LEGACY_PROXY_OID,
    LIMITED_PROXY_OID,
    PROXY_CERT_INFO_OID,
    Certificate,
    ProxyCredential,
    certificate_fields,
    extensions_of,
    legacy_proxy_kind,
    proxy_identity,
    proxy_policy,
)

__all__ = ["ProxyInfo", "describe_proxy"]

#: ``keyUsage`` bit names in bit order (RFC 5280 4.2.1.3), as OpenSSL and
#: ``voms-proxy-info`` print them.
_KEY_USAGE_NAMES = (
    "Digital Signature",
    "Non Repudiation",
    "Key Encipherment",
    "Data Encipherment",
    "Key Agreement",
    "Certificate Sign",
    "CRL Sign",
    "Encipher Only",
    "Decipher Only",
)

#: The proxy policy languages by the word ``voms-proxy-info`` uses for them;
#: any other language is a "restricted" proxy (its rights are in a policy
#: this client does not interpret).
_POLICY_WORDS = {
    INHERIT_ALL_OID: "impersonation",
    LIMITED_PROXY_OID: "limited",
    INDEPENDENT_OID: "independent",
}


@dataclass(frozen=True, slots=True)
class ProxyInfo:
    """A description of one credential chain, as ``voms-proxy-info -all`` gives it.

    Names are in OpenSSL's slash form (``/DC=org/CN=Jane``). Times are
    seconds since the epoch. Nothing here is secret; :meth:`as_dict` is
    what ``xrd-proxy info --json`` reports.
    """

    #: The leaf certificate's subject and issuer.
    subject: str
    issuer: str
    #: The user behind the chain (:func:`~xrdsec.x509.proxy_identity`).
    identity: str
    #: ``voms-proxy-info``'s ``type``: ``"RFC3820 compliant impersonation
    #: proxy"``, ``"full legacy globus proxy"``, ``"end entity credential"``...
    kind: str
    #: Whether the leaf is a proxy at all, and whether it is a limited one.
    is_proxy: bool
    limited: bool
    #: The leaf's ``pCPathLenConstraint``; ``None`` is unlimited (or not a proxy).
    path_length: int | None
    #: The leaf key's size in bits (RSA modulus, EC curve); ``0`` if unknown.
    strength: int
    key_usage: tuple[str, ...]
    #: The leaf's ``notBefore``, and the earliest ``notAfter`` in the chain -
    #: a proxy is unusable once anything above it has expired.
    not_before: float
    not_after: float
    #: Seconds of validity left when described, never negative.
    time_left: float
    #: Every VOMS AC in the chain, decoded but not validated.
    voms: tuple[VOMSEntry, ...]
    #: The file the chain came from, when it came from one.
    path: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Plain JSON-ready values, the VOMS ACs reduced to what ``-all`` prints."""
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "identity": self.identity,
            "type": self.kind,
            "is_proxy": self.is_proxy,
            "limited": self.limited,
            "path_length": self.path_length,
            "strength": self.strength,
            "key_usage": list(self.key_usage),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "time_left": self.time_left,
            "path": self.path,
            "voms": [_voms_dict(entry) for entry in self.voms],
        }


def describe_proxy(
    chain: Sequence[Certificate] | ProxyCredential, *, path: str = "", now: float | None = None
) -> ProxyInfo:
    """Describe ``chain`` (leaf first), or a credential's chain; see :class:`ProxyInfo`.

    ``path`` is recorded as given (the file the chain was read from). ``now``
    pins the clock for :attr:`ProxyInfo.time_left`. Raises
    :class:`ValueError` for an empty chain; damaged extensions are described
    as best they can be rather than refused - inspecting a broken proxy is
    how one finds out why it is broken.
    """
    links = tuple(chain.chain if isinstance(chain, ProxyCredential) else chain)
    if not links:
        raise ValueError("there is no certificate to describe")
    leaf = links[0]
    extensions = {ext.oid: ext for ext in extensions_of(leaf.der)}
    not_after = min(link.not_after for link in links)
    moment = time.time() if now is None else now
    kind, limited = _kind(leaf, extensions)
    info = extensions.get(PROXY_CERT_INFO_OID) or extensions.get(LEGACY_PROXY_OID)
    usage = extensions.get(KEY_USAGE_OID)
    return ProxyInfo(
        subject=str(leaf.subject),
        issuer=str(leaf.issuer),
        identity=str(proxy_identity(links)),
        kind=kind,
        is_proxy=kind != _END_ENTITY,
        limited=limited,
        path_length=_path_length(info),
        strength=_strength(leaf),
        key_usage=_key_usage(usage.value) if usage is not None else (),
        not_before=leaf.not_before,
        not_after=not_after,
        time_left=max(0.0, not_after - moment),
        voms=inspect_voms(links).entries,
        path=path,
    )


#: ``voms-proxy-info``'s word for a certificate that is not a proxy.
_END_ENTITY = "end entity credential"


def _kind(leaf: Certificate, extensions: dict[str, Any]) -> tuple[str, bool]:
    """``voms-proxy-info``'s ``type`` line for ``leaf``, and whether it is limited.

    An RFC 3820 ``ProxyCertInfo`` first, then the pre-RFC Globus extension
    ("Proxy draft"), then GT2's naming; anything else is an end-entity
    certificate.
    """
    values = {oid: (ext.critical, ext.value) for oid, ext in extensions.items()}
    policy = proxy_policy(values)
    if policy is not None:
        word = _POLICY_WORDS.get(policy, "restricted")
        style = "RFC3820" if PROXY_CERT_INFO_OID in extensions else "Proxy draft (pre-RFC)"
        return f"{style} compliant {word} proxy", policy == LIMITED_PROXY_OID
    legacy = legacy_proxy_kind(leaf.subject, leaf.issuer)
    if legacy is not None:
        limited = legacy == "limited proxy"
        return ("limited" if limited else "full") + " legacy globus proxy", limited
    return _END_ENTITY, False


def _path_length(info: Any) -> int | None:
    """The proxy's own path-length constraint, ``None`` if absent or unreadable."""
    if info is None:
        return None
    try:
        return proxy_path_length(info)
    except (DERError, ValueError, IndexError):
        return None


def _strength(leaf: Certificate) -> int:
    """The leaf key's size in bits: RSA modulus or EC curve; ``0`` for anything else."""
    try:
        key = serialization.load_der_public_key(certificate_fields(leaf.der)["spki"])
    except (DERError, ValueError, IndexError, UnsupportedAlgorithm):
        return 0
    if isinstance(key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey | dsa.DSAPublicKey):
        return key.key_size
    return 0


def _key_usage(value: bytes) -> tuple[str, ...]:
    """The names of the bits set in a ``keyUsage`` BIT STRING value.

    Bit 0 is the most significant bit of the first content octet (after the
    "unused bits" octet), as X.680 numbers a named BIT STRING.
    """
    try:
        bits = parse_one(value).value[1:]
    except DERError:
        return ()
    return tuple(
        name
        for index, name in enumerate(_KEY_USAGE_NAMES)
        if index // 8 < len(bits) and bits[index // 8] & (0x80 >> (index % 8))
    )


def _voms_dict(entry: VOMSEntry) -> dict[str, Any]:
    """One AC as ``voms-proxy-info -all`` shows it: VO, issuer, FQANs, validity, URI."""
    return {
        "vo": entry.vo,
        "holder": str(entry.holder),
        "issuer": str(entry.issuer),
        "fqans": list(entry.fqans),
        "not_before": entry.not_before,
        "not_after": entry.not_after,
        "uri": entry.uri,
        "status": entry.status.value,
    }
