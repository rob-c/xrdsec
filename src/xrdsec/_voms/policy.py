"""Validating one decoded VOMS AC: the intrinsic checks, then external trust.

:func:`_validate_entry` is the per-AC pipeline the facade's ``validate_voms``
runs for every entry :mod:`.ac` decoded. It stops at the first failure, in the
order BriX uses: claims (version, critical extensions, FQANs), holder binding
through delegated proxies, validity with clock skew, signature shape, targets,
then the embedded signer chain, the signature itself (one entry point for
every algorithm, :func:`~xrdsec.signatures.verify_signature`) and the
authority key identifier. Only an AC that passes all of those is checked
against the local CA and ``vomsdir`` trust material, which :mod:`.trust` owns.

The result is a copy of the entry with ``status``, ``digest``, ``signer`` and
``diagnostics`` filled in; entries are independent, so one bad AC never
poisons a good one in the same proxy.
"""

from __future__ import annotations

import socket
from collections.abc import Sequence
from dataclasses import dataclass, replace

from ..der import TAG_OID, TAG_SEQUENCE, DERError, Element, oid_string
from ..signatures import signature_label, verify_signature
from ..x509 import certificate_fields
from .ac import _certificate_extension, _encoded, _one
from .diagnostics import _problem
from .model import _SKI_OID, Certificate, VOMSDiagnostic, VOMSEntry, VOMSStatus
from .trust import _lsc_matches, _trusted_chain


@dataclass(frozen=True, slots=True)
class _Checks:
    """What one ``validate_voms`` call checks every AC against.

    The facade resolves the defaults once - the trust directories through the
    environment and the conventional locations, ``now`` from the clock - and
    every entry in the proxy is then judged against the same frozen values, so
    two ACs in one proxy can never be checked against different clocks or
    different trust material. ``None`` for a directory means none was found;
    that is a failed trust check (``UNTRUSTED`` / ``LSC``), never a skipped one.
    """

    #: The CA certificate directory (``X509_CERT_DIR``), or ``None`` if absent.
    ca_path: str | None
    #: The ``vomsdir`` holding each VO's ``.lsc`` files, or ``None`` if absent.
    voms_dir: str | None
    #: The service the proxy is presented to, for the AC targets extension;
    #: ``None`` falls back to this machine's hostname, as BriX does.
    host: str | None
    #: The moment of validation, seconds since the epoch.
    now: float
    #: Seconds of clock skew forgiven on ``notBefore`` only: an AC minted by a
    #: server whose clock runs ahead is merely early, while ``notAfter`` is the
    #: issuer's hard limit and is honoured exactly.
    skew: int


def _validate_entry(entry: VOMSEntry, chain: Sequence[Certificate], checks: _Checks) -> VOMSEntry:
    """Run every check on one AC and return a copy carrying the verdict.

    ``chain`` is the whole proxy chain the AC was found in (the holder may be
    an ancestor of the certificate that carries it). The order matters and
    follows BriX: cheap, local, attacker-independent checks first, then the
    signature, and only then the filesystem trust material - so a forged or
    stale AC is reported for what is wrong with *it*, not for a missing
    ``vomsdir`` on the machine checking it. ``digest`` and ``signer`` are
    filled in as soon as they are known, even on failure, because
    diagnostics and xgfalclient's ``voms-proxy-info`` style output show them.
    """
    status = _intrinsic_status(entry, chain, checks.host, checks.now, checks.skew)
    if status is not VOMSStatus.OK:
        return replace(entry, status=status)
    signer_chain = _signer_chain(entry)
    if not signer_chain:
        return replace(entry, status=VOMSStatus.ISSUER)
    signer = signer_chain[0]
    signature_status, digest = _signature_status(entry, signer)
    if signature_status is not VOMSStatus.OK:
        return replace(entry, status=signature_status, digest=digest, signer=signer)
    if not _aki_matches(entry, signer):
        return replace(entry, status=VOMSStatus.ISSUER, digest=digest, signer=signer)
    diagnostics: list[VOMSDiagnostic] = []
    trust_status = _trust_status(entry, signer_chain, checks, diagnostics)
    return replace(
        entry, status=trust_status, digest=digest, signer=signer, diagnostics=tuple(diagnostics)
    )


def _signature_status(entry: VOMSEntry, signer: Certificate) -> tuple[VOMSStatus, str]:
    """Whether ``signer``'s key signed the AC, and what the algorithm is called.

    One check for every algorithm (:func:`~xrdsec.signatures.verify_signature`):
    an algorithm or parameter set it does not accept is ``SIGNATURE_ALGORITHM``,
    anything that does not verify - a wrong key type, a malformed signer, a bad
    signature - is ``SIGNATURE``.
    """
    algorithm = _signature_algorithm(entry)
    if algorithm is None:
        return VOMSStatus.SIGNATURE_ALGORITHM, ""
    oid, parameters = algorithm
    label = signature_label(oid, parameters)
    if label is None:
        return VOMSStatus.SIGNATURE_ALGORITHM, ""
    params = _encoded(parameters[0]) if parameters else None
    try:
        spki = certificate_fields(signer.der)["spki"]
        valid = verify_signature(spki, oid, params, entry._signature, entry._tbs)
    except (DERError, IndexError):  # SignatureAlgorithmError is a DERError
        valid = False
    return (VOMSStatus.OK if valid else VOMSStatus.SIGNATURE), label


def _aki_matches(entry: VOMSEntry, signer: Certificate) -> bool:
    """Whether the AC's authority key identifier names ``signer``'s key.

    RFC 5755 makes the AKI optional, and so is the signer's subject key
    identifier; with either absent there is nothing to compare and the
    subject-name match that chose ``signer`` stands. Present on both sides
    they must agree byte for byte - a mismatch means the embedded certificate
    has the right name but is not the key that signed, the shape of a
    substituted signer.
    """
    if entry._aki is None:
        return True
    ski = _certificate_extension(signer, _SKI_OID)
    if ski is None:
        return True
    try:
        return entry._aki == _one(ski).value
    except DERError:
        return False


def _external_trust_status(
    entry: VOMSEntry,
    signer_chain: Sequence[Certificate],
    ca_path: str | None,
    voms_dir: str | None,
    now: float,
) -> VOMSStatus:
    """The trust verdict alone, without diagnostics, for callers of the old helper.

    This positional shape predates :class:`_Checks`; tests in both clients
    still call it, so it stays as a thin adapter over :func:`_trust_status`.
    ``host`` and ``skew`` play no part in the trust-material checks.
    """
    checks = _Checks(ca_path=ca_path, voms_dir=voms_dir, host=None, now=now, skew=0)
    return _trust_status(entry, signer_chain, checks)


def _trust_status(
    entry: VOMSEntry,
    signer_chain: Sequence[Certificate],
    checks: _Checks,
    diagnostics: list[VOMSDiagnostic] | None = None,
) -> VOMSStatus:
    """Whether the local trust material vouches for an AC's signer.

    Two independent questions, both of which must be "yes": does the signer
    chain lead to a CA in ``ca_path`` (``UNTRUSTED`` otherwise), and does the
    VO's ``.lsc`` file - or a legacy signer certificate - in ``voms_dir`` name
    exactly this signer (``LSC`` otherwise)? The second is what stops any
    IGTF-accredited host certificate from minting ACs for any VO: the CA
    check alone only proves *someone* trustworthy signed.

    The chain's diagnostics are buffered in ``pending`` and only published on
    failure, so a successful validation never carries noise about, say, an
    unreadable spare file in the CA directory.
    """
    if checks.ca_path is None:
        _problem(
            diagnostics,
            "ca_directory_missing",
            "No CA certificate directory was found. Install your trusted CA bundle "
            "and set X509_CERT_DIR to its certificates directory.",
        )
        return VOMSStatus.UNTRUSTED
    pending: list[VOMSDiagnostic] = []
    if not _trusted_chain(signer_chain, checks.ca_path, checks.now, pending):
        if diagnostics is not None:
            diagnostics.extend(pending)
        return VOMSStatus.UNTRUSTED
    if checks.voms_dir is None:
        _problem(
            diagnostics,
            "voms_directory_missing",
            f"No VOMS trust directory was found for VO '{entry.vo}'. Install the VO's official "
            ".lsc files and set X509_VOMS_DIR to the vomsdir directory.",
        )
        return VOMSStatus.LSC
    if not _lsc_matches(checks.voms_dir, entry.vo, signer_chain, diagnostics):
        return VOMSStatus.LSC
    return VOMSStatus.OK


def _intrinsic_status(
    entry: VOMSEntry,
    chain: Sequence[Certificate],
    host: str | None,
    now: float,
    skew: int,
) -> VOMSStatus:
    """The checks that need nothing but the AC and the proxy chain, in BriX order.

    Claims, holder binding, validity, signature shape, then targets: each is
    cheap and none reads a key or a file, so a structurally bad AC is turned
    away before any cryptography runs.
    """
    status = _claims_status(entry)
    if status is not VOMSStatus.OK:
        return status
    if not _holder_matches(entry, chain):
        return VOMSStatus.HOLDER
    status = _validity_status(entry, now, skew)
    if status is not VOMSStatus.OK:
        return status
    status = _signature_shape_status(entry)
    if status is not VOMSStatus.OK:
        return status
    return _target_status(entry, host)


def _claims_status(entry: VOMSEntry) -> VOMSStatus:
    """Whether the AC is a version we implement, with understood extensions and real FQANs.

    ``version`` is the INTEGER 1, meaning v2 (RFC 5755 only defines v2). An AC
    with no FQANs or no VO grants nothing and is reported rather than passed.
    """
    if entry._version != 1:
        return VOMSStatus.VERSION
    if entry._unknown_critical:
        return VOMSStatus.EXTENSION
    if not entry.fqans or not entry.vo:
        return VOMSStatus.ATTRIBUTES
    return VOMSStatus.OK


def _validity_status(entry: VOMSEntry, now: float, skew: int) -> VOMSStatus:
    """Whether ``now`` is inside ``[notBefore - skew, notAfter]``."""
    if entry.not_before > now + skew:
        return VOMSStatus.NOT_YET_VALID
    if entry.not_after < now:
        return VOMSStatus.EXPIRED
    return VOMSStatus.OK


def _signature_shape_status(entry: VOMSEntry) -> VOMSStatus:
    """Whether the AC carries a signer chain and consistent algorithm identifiers.

    VOMS always embeds its signing certificate (the ``...100.100.10``
    extension); without it there is no key to verify against, since nothing
    here looks signers up elsewhere. The inner ``signature`` field and the
    outer ``signatureAlgorithm`` must be byte-identical (RFC 5755): otherwise
    the algorithm the signature was verified under is not the one the signer
    committed to inside the signed bytes.
    """
    if not entry._embedded:
        return VOMSStatus.NO_SIGNER
    if entry._inner_algorithm != entry._outer_algorithm:
        return VOMSStatus.SIGNATURE_ALGORITHM
    return VOMSStatus.OK


def _target_status(entry: VOMSEntry, host: str | None) -> VOMSStatus:
    """Whether the AC's targets extension, if any, names the service being contacted.

    An absent or empty targets list means "valid everywhere". ``host`` falls back
    to this machine's name, the right answer for a server validating a client's
    proxy; a client checking its own proxy for a remote service passes that
    service's name.
    """
    targets = entry._targets
    wanted = (host or socket.gethostname()).lower().rstrip(".")
    if targets is not None and targets and wanted not in targets:
        return VOMSStatus.TARGET
    return VOMSStatus.OK


def _holder_matches(entry: VOMSEntry, chain: Sequence[Certificate]) -> bool:
    """Whether the AC belongs to the proxy chain it was found in.

    VOMS binds the AC to the user's end-entity certificate by issuer and serial,
    but the AC is usually carried by a proxy (or a proxy of a proxy) derived
    from it. The walk starts at the carrying certificate and climbs through
    proxy parents until a certificate matches or a non-proxy is reached; the
    ``seen`` set ends the walk on a cyclic chain. Without this, an AC copied
    from one user's proxy into another's would carry the first user's groups.
    """
    if not entry.holder or entry._holder_serial is None or entry.carrier >= len(chain):
        return False
    current = chain[entry.carrier]
    seen: set[bytes] = set()
    while current.der not in seen:
        seen.add(current.der)
        if _is_holder(entry, current):
            return True
        if not current.is_proxy:
            break
        parent = _proxy_parent(current, chain)
        if parent is None:
            break
        current = parent
    return False


def _is_holder(entry: VOMSEntry, certificate: Certificate) -> bool:
    """Whether ``certificate`` is the one the AC's ``Holder.baseCertificateID`` names.

    The serial must match exactly; the name may be either the certificate's
    issuer (what RFC 5755 ``IssuerSerial`` means) or its subject, a deliberate
    tolerance for servers that filled the field with the holder's own DN.
    """
    return entry._holder_serial == certificate.serial and entry.holder in (
        certificate.subject,
        certificate.issuer,
    )


def _proxy_parent(certificate: Certificate, chain: Sequence[Certificate]) -> Certificate | None:
    """The certificate in ``chain`` that issued proxy ``certificate``, if present.

    A proxy's issuer is its parent's subject (RFC 3820); the parent itself is
    excluded so a self-issued certificate cannot be its own parent.
    """
    return next(
        (
            candidate
            for candidate in chain
            if candidate.der != certificate.der and candidate.subject == certificate.issuer
        ),
        None,
    )


def _signer_chain(entry: VOMSEntry) -> tuple[Certificate, ...]:
    """The embedded certificates with the AC's issuer moved to the front.

    The signer is found by subject name among the embedded certificates; the
    rest keep their order and serve as intermediates for :mod:`.trust`. An
    empty result means no embedded certificate claims to be the issuer.
    """
    for index, certificate in enumerate(entry._embedded):
        if certificate.subject == entry.issuer:
            return (certificate, *entry._embedded[:index], *entry._embedded[index + 1 :])
    return ()


def _signature_algorithm(entry: VOMSEntry) -> tuple[str, list[Element]] | None:
    """The outer ``signatureAlgorithm`` as ``(oid, parameters)``, or ``None`` if malformed."""
    try:
        return _algorithm_identifier(_one(entry._outer_algorithm))
    except (DERError, IndexError):
        return None


def _signature_digest(entry: VOMSEntry) -> str | None:
    """The human-readable name of the AC's signature algorithm, or ``None``."""
    algorithm = _signature_algorithm(entry)
    if algorithm is None:
        return None
    return signature_label(*algorithm)


def _algorithm_identifier(element: Element) -> tuple[str, list[Element]]:
    """Split an ``AlgorithmIdentifier ::= SEQUENCE { OID, parameters OPTIONAL }``.

    At most one parameters element is allowed; anything else is a
    ``DERError`` rather than a parameter set silently ignored, since RSA-PSS
    security depends on the parameters being the ones that were checked.
    """
    if element.tag != TAG_SEQUENCE:
        raise DERError("signature algorithm has no OID")
    parts = element.children()
    if not 1 <= len(parts) <= 2 or parts[0].tag != TAG_OID:
        raise DERError("signature algorithm has no OID")
    return oid_string(parts[0]), parts[1:]
