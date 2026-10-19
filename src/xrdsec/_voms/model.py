"""The VOMS data model: OIDs, the certificate protocol, statuses and results.

Everything the other ``_voms`` modules build or return is defined here, and
nothing here does any work beyond describing itself, so this module sits at
the bottom of the import graph: :mod:`.ac` constructs :class:`VOMSEntry` and
:class:`VOMSAttribute` while decoding, :mod:`.policy` assigns a
:class:`VOMSStatus` to each entry, and :mod:`.diagnostics` records
:class:`VOMSDiagnostic` messages. The public names are re-exported by
:mod:`xrdsec.voms`, which is where callers should import them from.

The ``remaining()`` and ``message`` helpers stay with the types they describe;
the plain-language explanation of each status (:func:`_status_message`) is
here rather than in :mod:`.diagnostics` because the result types are the only
callers.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Protocol

from ..rsa import RSAPublicKey
from ..x509 import Name

# The 1.3.6.1.4.1.8005 arc is INFN's private enterprise number; VOMS defined
# these under it before any standard AC profile existed.

#: The proxy-certificate extension whose value is ``SEQUENCE { SEQUENCE OF AC }``.
VOMS_AC_OID = "1.3.6.1.4.1.8005.100.100.5"
#: The AC attribute type holding the VO's policy authority and the FQAN list.
VOMS_FQAN_OID = "1.3.6.1.4.1.8005.100.100.4"
#: The AC extension embedding the VOMS server's signing certificate chain.
VOMS_CERTS_OID = "1.3.6.1.4.1.8005.100.100.10"
#: The AC extension carrying VOMS "generic attributes" (name/value/qualifier).
VOMS_ATTRIBUTES_OID = "1.3.6.1.4.1.8005.100.100.11"
_AKI_OID = "2.5.29.35"  # authorityKeyIdentifier (RFC 5280 4.2.1.1)
_SKI_OID = "2.5.29.14"  # subjectKeyIdentifier, read from the signer certificate
_TARGETS_OID = "2.5.29.55"  # targetInformation (RFC 5755 4.3.2)
_NO_REV_AVAIL_OID = "2.5.29.56"  # noRevAvail (RFC 5755 4.3.6)
#: Extensions an AC may mark critical without being refused as ``EXTENSION``.
_KNOWN_AC_EXTENSIONS = {
    VOMS_CERTS_OID,
    VOMS_ATTRIBUTES_OID,
    _AKI_OID,
    _TARGETS_OID,
    _NO_REV_AVAIL_OID,
}

#: Most links followed from a VOMS signer to a CA: real chains are two or
#: three deep, and the bound turns a cross-signing loop into a diagnostic.
_MAX_CHAIN_DEPTH = 8
#: Most ACs decoded from one proxy; each costs a signature check and file
#: reads, so a proxy cannot buy unbounded work. One AC per VO is the norm.
_MAX_AC_ENTRIES = 32


class Certificate(Protocol):
    """Read-only certificate view shared by both clients' credential models."""

    @property
    def subject(self) -> Name:
        """The certificate's subject DN."""

    @property
    def issuer(self) -> Name:
        """The issuer DN; for a proxy, the subject of the certificate that signed it."""

    @property
    def serial(self) -> int:
        """The serial number, matched against the AC's ``Holder`` serial."""

    @property
    def not_before(self) -> float:
        """Start of validity, seconds since the epoch (UTC)."""

    @property
    def not_after(self) -> float:
        """End of validity, seconds since the epoch (UTC)."""

    @property
    def public_key(self) -> RSAPublicKey | None:
        """The RSA key if the certificate has one; signature checks use :attr:`der` instead."""

    @property
    def extensions(self) -> Mapping[str, tuple[bool, bytes]] | Sequence[str]:
        """Extension OIDs, or ``{oid: (critical, value)}`` in xgfalclient's model.

        Both shapes are accepted so one validator serves both clients;
        :func:`~xrdsec._voms.ac._certificate_extension` reads either.
        """

    @property
    def der(self) -> bytes:
        """The exact DER bytes: what anchors and legacy signer files are compared by."""

    @property
    def is_proxy(self) -> bool:
        """Whether this is an RFC 3820 (or Globus legacy) proxy, for the holder walk."""


class VOMSStatus(StrEnum):
    """The first failed AC check, or ``ok`` after the implemented checks."""

    # ``Enum``'s own ``str()`` and ``format()`` (``VOMSStatus.OK``), not
    # ``StrEnum``'s bare value: what callers and xgfalclient's diagnostics
    # have always printed for a status stays what they print.
    __str__ = Enum.__str__
    __format__ = Enum.__format__

    OK = "ok"
    UNCHECKED = "unchecked"
    NO_EXTENSION = "no_extension"
    DECODE = "decode"
    VERSION = "version"
    HOLDER = "holder"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    NO_SIGNER = "no_signer"
    SIGNATURE_ALGORITHM = "signature_algorithm"
    SIGNATURE = "signature"
    ISSUER = "issuer"
    TARGET = "target"
    UNTRUSTED = "untrusted"
    LSC = "lsc"
    EXTENSION = "extension"
    ATTRIBUTES = "attributes"


@dataclass(frozen=True, slots=True)
class VOMSDiagnostic:
    """A stable error code and an actionable, non-secret user message."""

    code: str
    message: str
    path: str = ""
    errno: int | None = None


@dataclass(frozen=True, slots=True)
class VOMSAttribute:
    """One VOMS generic attribute (name, value, qualifier)."""

    name: str
    value: str
    qualifier: str = ""


@dataclass(frozen=True, slots=True)
class VOMSEntry:
    """One VOMS attribute certificate, normally representing one VO."""

    vo: str
    uri: str
    fqans: tuple[str, ...]
    attributes: tuple[VOMSAttribute, ...]
    holder: Name
    issuer: Name
    not_before: float
    not_after: float
    carrier: int
    status: VOMSStatus = VOMSStatus.UNCHECKED
    digest: str = ""
    signer: Certificate | None = field(default=None, repr=False, compare=False)
    diagnostics: tuple[VOMSDiagnostic, ...] = ()
    # The raw material the policy checks. Private and excluded from ``repr``
    # and equality: two entries with the same claims compare equal however
    # they were encoded, and a printed entry never dumps signature bytes.
    _version: int = field(default=0, repr=False, compare=False)
    _holder_serial: int | None = field(default=None, repr=False, compare=False)
    _tbs: bytes = field(default=b"", repr=False, compare=False)
    _inner_algorithm: bytes = field(default=b"", repr=False, compare=False)
    _outer_algorithm: bytes = field(default=b"", repr=False, compare=False)
    _signature: bytes = field(default=b"", repr=False, compare=False)
    _embedded: tuple[Certificate, ...] = field(default=(), repr=False, compare=False)
    _targets: tuple[str, ...] | None = field(default=None, repr=False, compare=False)
    _aki: bytes | None = field(default=None, repr=False, compare=False)
    _unknown_critical: bool = field(default=False, repr=False, compare=False)

    @property
    def verified(self) -> bool:
        """Whether every intrinsic and configured trust check passed."""
        return self.status is VOMSStatus.OK

    def remaining(self, now: float | None = None) -> float:
        """Seconds before the AC expires."""
        return self.not_after - (time.time() if now is None else now)

    @property
    def message(self) -> str:
        """Explain a failed check without requiring knowledge of status codes."""
        return "\n".join(issue.message for issue in self.diagnostics) or _status_message(
            self.status, self.vo
        )


@dataclass(frozen=True, slots=True)
class VOMSResult:
    """All ACs found in a proxy chain and the overall verdict."""

    entries: tuple[VOMSEntry, ...]
    status: VOMSStatus

    @property
    def diagnostics(self) -> tuple[VOMSDiagnostic, ...]:
        """Detailed trust-file failures, including failures in a mixed-VO proxy."""
        return tuple(issue for entry in self.entries for issue in entry.diagnostics)

    @property
    def message(self) -> str:
        """A plain-language summary suitable for a CLI error or exception."""
        failures = [entry.message for entry in self.entries if not entry.verified]
        return "\n".join(failures) or _status_message(self.status)

    @property
    def verified(self) -> tuple[VOMSEntry, ...]:
        """The independently verified entries; a bad AC never poisons a good one."""
        return tuple(entry for entry in self.entries if entry.verified)

    @property
    def fqans(self) -> tuple[str, ...]:
        """FQANs from verified entries, in wire order with duplicates removed."""
        return _unique(fqan for entry in self.verified for fqan in entry.fqans)

    @property
    def vos(self) -> tuple[str, ...]:
        """VO names from verified entries, in wire order with duplicates removed."""
        return _unique(entry.vo for entry in self.verified if entry.vo)


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    """``values`` in first-seen order without duplicates."""
    return tuple(dict.fromkeys(values))


def _status_message(status: VOMSStatus, vo: str = "") -> str:
    """The plain-language sentence for ``status``, prefixed with the VO when known.

    Used only when no detailed diagnostic exists. Each sentence ends with what
    the user should do, because these reach people through CLI errors rather
    than through code that can inspect the status.
    """
    subject = f"VO '{vo}': " if vo else ""
    explanations = {
        VOMSStatus.OK: "VOMS validation passed.",
        VOMSStatus.UNCHECKED: "VOMS claims are decoded, not verified. Do not trust them yet.",
        VOMSStatus.NO_EXTENSION: "This proxy has no VOMS attributes. Obtain a VOMS-enabled proxy.",
        VOMSStatus.DECODE: "The VOMS attributes are damaged or malformed. Obtain a new proxy.",
        VOMSStatus.VERSION: (
            "This proxy uses an unsupported VOMS format. Obtain a new proxy or update the client."
        ),
        VOMSStatus.HOLDER: "VOMS attributes belong to a different certificate. Obtain a new proxy.",
        VOMSStatus.NOT_YET_VALID: "VOMS attributes are not valid yet. Check your computer's clock.",
        VOMSStatus.EXPIRED: "The VOMS attributes have expired. Obtain a new proxy.",
        VOMSStatus.NO_SIGNER: "The VOMS signing certificate is missing. Obtain a new proxy.",
        VOMSStatus.SIGNATURE_ALGORITHM: (
            "This proxy uses an unsupported or invalid VOMS signature. "
            "Obtain a new proxy or update the client."
        ),
        VOMSStatus.SIGNATURE: "Invalid VOMS signature. Obtain a new proxy; do not use this one.",
        VOMSStatus.ISSUER: (
            "The VO signing certificate does not match this proxy. "
            "Obtain a new proxy from your VO's service."
        ),
        VOMSStatus.TARGET: (
            "These VO permissions do not cover this server. "
            "Request a proxy for the intended service."
        ),
        VOMSStatus.UNTRUSTED: (
            "Cannot verify the VO signing certificate. "
            "Install or update the official CA certificates."
        ),
        VOMSStatus.LSC: (
            "Cannot confirm the VO signing server. Install or update your VO's official .lsc file."
        ),
        VOMSStatus.EXTENSION: (
            "This proxy needs an unsupported VOMS feature. "
            "Update the client or ask your VO administrator for a compatible proxy."
        ),
        VOMSStatus.ATTRIBUTES: (
            "This proxy has no usable VO or group membership. "
            "Request a proxy for the correct VO and group."
        ),
    }
    return subject + explanations[status]
