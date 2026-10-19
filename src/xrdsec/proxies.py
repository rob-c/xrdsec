"""One X.509 proxy issuer for every tool that makes proxies, with named profiles.

A proxy certificate (RFC 3820) is a certificate a *user* signs: its subject is
the signer's plus one more ``CN``, it carries a critical ``ProxyCertInfo``
saying what rights it inherits, and it lives no longer than the chain above it.
Grid software issues them in four places - ``voms-proxy-init`` from a user
certificate, a GSI client answering a server's delegation request, an ARC
client delegating to a compute element, and ``xrdgsiproxy`` - and each project
grew its own issuer with its own small differences. This module is the one
implementation; the differences are kept as named **profiles**:

``"rfc3820"`` (the default)
    What ``voms-proxy-init`` and ``grid-proxy-init`` make: subject
    ``<issuer>/CN=<serial>`` with a random 31-bit serial, a critical
    ``keyUsage`` (digitalSignature, keyEncipherment), a critical
    ``ProxyCertInfo`` (inheritAll, or Globus' limited language), validity
    backdated five minutes for clock skew, and the VOMS attribute
    certificates of the signer's chain carried forward.
``"arc"``
    ARC's delegation profile (what ``xrdarc.proxy`` issued): the same shape
    with a 63-bit serial. ARC's own C++ reuses the *issuer's* serial number
    for every proxy, which RFC 3820 section 3.3 forbids; a random one is used
    instead, as the Python ARC client always did.
``"xrootd"``
    ``XrdCryptosslX509SignProxyReq`` and ``XrdCryptosslX509CreateProxy``:
    validity from *now* (no backdating), every extension of the signer copied
    (:func:`~xrdsec.delegation._inherited` says which are not), and,
    for a delegation request, the subject and serial the request names.
``"globus"``
    ``globus_gsi_proxy_sign_req``, what GridFTP, SRM and gridsite peers
    expect from a delegation: subject ``<issuer>/CN=<serial>`` with the
    serial taken from the first four bytes of the certified key's SHA-1, a
    critical ``keyUsage`` and ``ProxyCertInfo``, validity backdated five
    minutes - and no VOMS ACs carried forward. A GT2 legacy signer gets a GT2
    child (``CN=proxy``, no ``ProxyCertInfo``), as Globus keeps a chain in
    one proxy style.
``"globus-legacy"``
    A pre-RFC Globus Toolkit 2 proxy: ``CN=proxy`` or ``CN=limited proxy``,
    no ``ProxyCertInfo``, serial from the key's SHA-1. Only for talking to
    software that predates 2004; OpenSSL does not recognise these as proxies.

Rules every profile obeys, because a verifier enforces them and a proxy that
breaks one is useless at best: a limited signer only issues limited proxies
(``limited=False`` cannot lift it); a signer's ``pCPathLenConstraint`` is
carried down one smaller, and a signer at ``0`` cannot issue at all; validity
never starts before the signer's nor ends after the earliest expiry in its
chain; RFC 3820 sections 3.5-3.7 forbid alternative names and ``cA=TRUE``, so
``extra_extensions`` cannot add them; and a request's proof of possession is
checked before its key is certified.

Where to start reading: :func:`issue_proxy` (a certificate for somebody
else's key - a delegation) and :func:`create_proxy` (a fresh key and its
proxy - what ``voms-proxy-init`` does). Files and inspection are re-exported
here from :mod:`._proxyfiles` (:func:`load_credential`, :func:`write_proxy`)
and :mod:`._proxyinfo` (:func:`describe_proxy`). The certificate itself is
built by :func:`~xrdsec.delegation.issue_certificate`, which is also
xgfalclient's ``build_certificate``; :func:`~xrdsec.delegation.\
sign_proxy_request` and :func:`~xrdsec.userproxy.user_proxy` are
thin profiles of :func:`issue_proxy`.
"""

from __future__ import annotations

import datetime
import hashlib
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

from ._proxyfiles import load_credential, write_proxy
from ._proxyinfo import ProxyInfo, describe_proxy
from .delegation import (
    ISSUER_ALT_NAME_OID,
    KEY_USAGE_OID,
    SUBJECT_ALT_NAME_OID,
    VOMS_AC_OID,
    DelegationError,
    ProxyRequest,
    _check_request,
    _holds_key,
    _inherited,
    _library_key,
    issue_certificate,
    proxy_cert_info_extension,
    proxy_path_length,
)
from .der import (
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_OCTET_STRING,
    TAG_SEQUENCE,
    encode_oid,
    parse,
    parse_one,
    printable_string,
    raw_children,
    sequence,
    set_of,
    tlv,
)
from .rsa import RSAPrivateKey
from .x509 import (
    INHERIT_ALL_OID,
    LEGACY_PROXY_OID,
    LIMITED_PROXY_OID,
    PROXY_CERT_INFO_OID,
    Certificate,
    Extension,
    ProxyCredential,
    certificate_fields,
    extensions_of,
    legacy_proxy_kind,
    parse_certificate,
    parse_extension,
    proxy_policy,
)

__all__ = [
    "DEFAULT_LIFETIME",
    "NOT_BEFORE_SKEW",
    "PROFILES",
    "ProfileName",
    "ProxyError",
    "ProxyInfo",
    "create_proxy",
    "describe_proxy",
    "issue_proxy",
    "load_credential",
    "voms_extension",
    "write_proxy",
]

#: The profile names :func:`issue_proxy` and :func:`create_proxy` accept.
ProfileName = Literal["rfc3820", "arc", "xrootd", "globus", "globus-legacy"]
PROFILES: tuple[ProfileName, ...] = ("rfc3820", "arc", "xrootd", "globus", "globus-legacy")

#: How long :func:`create_proxy` makes a proxy last: ``voms-proxy-init``'s
#: default, and ``XrdSecgsi``'s for the proxy it makes in memory.
DEFAULT_LIFETIME = datetime.timedelta(hours=12)
#: How far back a proxy's validity starts, for a peer whose clock is behind
#: ours: five minutes, the allowance Globus, VOMS and ARC all use.
NOT_BEFORE_SKEW = 300.0

#: Issuing fails for the same reasons whether the key came in a delegation
#: request or was made here, so the error is the delegation module's: one
#: ``except`` covers both, and existing callers keep catching what they did.
ProxyError = DelegationError

BASIC_CONSTRAINTS_OID = "2.5.29.19"
#: ``commonName``: the attribute a proxy appends to its issuer's subject.
_CN_OID = "2.5.4.3"
#: Most ACs one VOMS extension may hold; the decoder refuses more
#: (:data:`xrdsec._voms.model._MAX_AC_ENTRIES`), so none are written.
_MAX_ACS = 32
#: RSA keys below this are refused outright by current OpenSSL security
#: levels, so a proxy with one would be issued only to fail its first handshake.
_MIN_RSA_BITS = 1024
#: The curves an EC proxy key may use, by ``bits``.
_CURVES: dict[int, type[ec.EllipticCurve]] = {
    256: ec.SECP256R1,
    384: ec.SECP384R1,
    521: ec.SECP521R1,
}

#: A critical ``keyUsage`` of digitalSignature and keyEncipherment (bits 0
#: and 2: ``05 a0`` is "5 unused bits, 1010 0000"). What a proxy needs to
#: sign a GSI exchange and further proxies, and what the stock tools give
#: one; keyCertSign must not be set on a proxy (RFC 3820 section 3.7).
_KEY_USAGE = sequence(
    encode_oid(KEY_USAGE_OID),
    tlv(TAG_BOOLEAN, b"\xff"),
    tlv(TAG_OCTET_STRING, tlv(TAG_BIT_STRING, b"\x05\xa0")),
)


@dataclass(frozen=True, slots=True)
class _Profile:
    """How one profile differs from the others; see the module docstring."""

    #: Width of the random serial (and so of the ``CN``); ``0`` derives the
    #: serial from the certified key, as Globus does.
    serial_bits: int
    #: The default backdating of ``notBefore``, in seconds.
    skew: float
    #: GT2 naming (``CN=proxy``) and no ``ProxyCertInfo``.
    legacy: bool = False
    #: XrdCrypto's rules: the signer's extensions are copied, and a delegation
    #: request names the proxy (subject and serial) itself.
    xrdcrypto: bool = False
    #: Whether the chain's VOMS ACs are carried forward (``copy_voms`` can
    #: only turn this off, never on).
    voms: bool = True
    #: Whether a GT2 legacy signer gets a GT2 child, keeping one proxy style
    #: per chain, as Globus does.
    follow_legacy: bool = False


_PROFILES: dict[str, _Profile] = {
    "rfc3820": _Profile(serial_bits=31, skew=NOT_BEFORE_SKEW),
    "arc": _Profile(serial_bits=63, skew=NOT_BEFORE_SKEW),
    "xrootd": _Profile(serial_bits=31, skew=0.0, xrdcrypto=True),
    "globus": _Profile(serial_bits=0, skew=NOT_BEFORE_SKEW, voms=False, follow_legacy=True),
    "globus-legacy": _Profile(serial_bits=0, skew=NOT_BEFORE_SKEW, legacy=True),
}

#: The signing key as ``cryptography`` holds it (the type the builder takes).
_LibraryKey = _rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


@dataclass(frozen=True, slots=True)
class _Issue:
    """Everything one issuance has established before a byte is written.

    Built and checked by :func:`_prepare`; the step functions read it, so
    each of them takes one argument instead of the dozen facts it needs.
    """

    profile: _Profile
    #: The signing certificate (``signer.chain[0]``) and its whole chain.
    certificate: Certificate
    chain: tuple[Certificate, ...]
    key: _LibraryKey
    #: The key to certify, as ``SubjectPublicKeyInfo`` DER.
    spki: bytes
    #: The delegation request the key came in, if it came in one.
    request: ProxyRequest | None
    moment: float
    limited: bool
    #: The new proxy's own ``pCPathLenConstraint``; ``None`` is unlimited.
    depth: int | None
    #: Whether the new proxy is a GT2 legacy one (no ``ProxyCertInfo``).
    legacy: bool


def issue_proxy(
    signer: ProxyCredential,
    public_key_spki: bytes | ProxyRequest,
    *,
    profile: ProfileName = "rfc3820",
    lifetime: datetime.timedelta | float | None = None,
    limited: bool | None = None,
    path_length: int | None = None,
    extra_extensions: Sequence[bytes] = (),
    copy_voms: bool = True,
    now: float | None = None,
    not_before_skew: float | None = None,
    digest: str = "sha256",
) -> Certificate:
    """A proxy certificate for ``public_key_spki``, issued by ``signer``.

    ``signer`` is the issuing credential: a user certificate and its key, or
    a proxy and its key (``chain[0]`` signs; the rest of the chain bounds the
    validity and may carry VOMS ACs). ``public_key_spki`` is the key to
    certify - ``SubjectPublicKeyInfo`` DER, or a parsed PKCS#10
    :class:`~xrdsec.delegation.ProxyRequest`, whose signature is
    checked first and which, under ``profile="xrootd"``, also names the proxy.

    ``lifetime`` (a :class:`~datetime.timedelta` or seconds) can only shorten
    the proxy below the chain's earliest expiry; ``None`` runs to it.
    ``limited=True`` imposes Globus' limited policy; ``None`` and ``False``
    inherit the signer's. ``path_length`` caps further delegation below the
    new proxy (it can only tighten the signer's own). ``extra_extensions``
    are DER ``Extension``\\ s appended as given; a VOMS AC extension among
    them replaces the one ``copy_voms`` would carry forward. ``now`` and
    ``not_before_skew`` (seconds; the profile's default when ``None``) pin
    the clock, for tests and for peers with known skew. ``digest`` is the
    signature's hash (``sha256``, ``sha384`` or ``sha512``; SHA-1 is
    refused), for a peer that asks for a stronger one than the default.

    Returns the parsed certificate; its DER is
    :attr:`~xrdsec.x509.Certificate.der`. Raises :class:`ProxyError`
    (a :class:`ValueError`) for every refusal: an unknown profile, an expired
    signer, a key that is not the signer's, a request that fails its checks,
    a path length that forbids issuing, or an extension RFC 3820 forbids.
    """
    plan = _PROFILES.get(profile)
    if plan is None:
        raise ProxyError(f"unknown proxy profile {profile!r}; use one of {', '.join(PROFILES)}")
    issue = _prepare(signer, public_key_spki, plan, (limited, path_length, now))
    extensions = _extensions(issue, extra_extensions, copy_voms)
    subject, serial = _naming(issue)
    not_before, not_after = _validity(issue, lifetime, not_before_skew)
    try:
        der = issue_certificate(
            subject=subject,
            issuer=certificate_fields(issue.certificate.der)["subject"],
            public_key=issue.spki,
            signer=issue.key,
            not_before=not_before,
            not_after=not_after,
            serial=serial,
            extensions=extensions,
            digest=digest,
        )
    except ValueError as exc:  # e.g. a request's CN=0: X.509 serials must be positive
        raise ProxyError(f"cannot issue the proxy: {exc}") from exc
    return parse_certificate(der)


def create_proxy(
    signer: ProxyCredential,
    *,
    lifetime: datetime.timedelta | float = DEFAULT_LIFETIME,
    key_type: Literal["rsa", "ec"] = "rsa",
    bits: int | None = None,
    limited: bool = False,
    voms_acs: Sequence[bytes] = (),
    profile: ProfileName = "rfc3820",
    path_length: int | None = None,
    now: float | None = None,
) -> ProxyCredential:
    """A new proxy credential - fresh key, its certificate, ``signer``'s chain - in memory.

    What ``voms-proxy-init`` and ``grid-proxy-init`` do, minus the file:
    nothing here touches the disk (:func:`write_proxy` does that, when it is
    wanted), so a proxy can be made, used and dropped without a private key
    ever being written anywhere.

    ``key_type`` is ``"rsa"`` (``bits`` default 2048) or ``"ec"`` (``bits``
    names the curve: 256, 384 or 521; default 256). GSI's XRootD login can
    only use an RSA proxy; HTTPS and delegation take either. ``voms_acs``
    are DER attribute certificates (from :func:`xrdsec.voms_client.fetch_ac`)
    for the new proxy's VOMS extension; without them, ACs already in
    ``signer``'s chain are carried forward. The other options are
    :func:`issue_proxy`'s. Raises :class:`ProxyError` as it does, and
    :class:`ValueError` for an unusable key size.
    """
    key, spki = _new_key(key_type, bits)
    extras = (voms_extension(voms_acs),) if voms_acs else ()
    certificate = issue_proxy(
        signer,
        spki,
        profile=profile,
        lifetime=lifetime,
        limited=limited,
        path_length=path_length,
        extra_extensions=extras,
        now=now,
    )
    return ProxyCredential(chain=(certificate, *signer.chain), key=key)


def voms_extension(acs: Sequence[bytes]) -> bytes:
    """The VOMS AC extension holding ``acs``, as a complete DER ``Extension``.

    ``Extension { 1.3.6.1.4.1.8005.100.100.5, non-critical,
    OCTET STRING { SEQUENCE { SEQUENCE OF AttributeCertificate } } }`` - the
    doubly wrapped sequence is what ``voms-proxy-init`` writes and what
    :func:`~xrdsec.voms.inspect_voms` reads. Non-critical, as VOMS
    writes it: software that does not know VOMS must still accept the proxy.
    Each AC must be one DER ``SEQUENCE`` (it is not otherwise checked here;
    :func:`~xrdsec.voms.validate_voms` judges it in the proxy).
    Raises :class:`ValueError` for none, too many, or a malformed one.
    """
    if not acs or len(acs) > _MAX_ACS:
        raise ValueError(f"a VOMS extension holds 1 to {_MAX_ACS} attribute certificates")
    for ac in acs:
        # parse_one refuses trailing bytes, so two ACs glued together, or an
        # AC with junk after it, cannot pass as one.
        if parse_one(ac).tag != TAG_SEQUENCE:
            raise ValueError("a VOMS attribute certificate must be one DER SEQUENCE")
    return sequence(
        encode_oid(VOMS_AC_OID),
        tlv(TAG_OCTET_STRING, sequence(sequence(*acs))),
    )


# ---------------------------------------------------------------------------
# What is being issued, checked before anything is built
# ---------------------------------------------------------------------------


def _prepare(
    signer: ProxyCredential,
    material: bytes | ProxyRequest,
    plan: _Profile,
    options: tuple[bool | None, int | None, float | None],
) -> _Issue:
    """Check that ``signer`` may issue for ``material`` now; the facts, as an :class:`_Issue`.

    The order of the checks is the order the old XrdCrypto-profile issuer
    made them in, so the first refusal a caller sees is unchanged: the
    signer's dates, its key, the request, then the path length.
    ``options`` is ``(limited, path_length, now)`` from :func:`issue_proxy`.
    """
    limited, path_length, now = options
    if not signer.chain:
        raise ProxyError("the signing credential holds no certificate")
    certificate = signer.chain[0]
    moment = time.time() if now is None else now
    if min(link.not_after for link in signer.chain) <= moment:
        raise ProxyError(f"the signing credential {certificate.subject} has expired")
    # Refuses, by name, a key of a type no proxy can be signed with (DSA,
    # Ed25519); an RSA key may be the client's own view or cryptography's.
    key = _library_key(signer.key)
    if not _holds_key(certificate, key):
        raise ProxyError("the private key does not belong to the signing credential")
    spki, request = _certified(material, plan, certificate)
    legacy = plan.legacy or (plan.follow_legacy and _is_legacy_signer(certificate))
    return _Issue(
        profile=plan,
        certificate=certificate,
        chain=tuple(signer.chain),
        key=key,
        spki=spki,
        request=request,
        moment=moment,
        limited=bool(limited) or _is_limited(certificate),
        depth=_child_depth(certificate, path_length, legacy),
        legacy=legacy,
    )


def _public_spki(key: _LibraryKey) -> bytes:
    """The ``SubjectPublicKeyInfo`` DER of ``key``'s public half."""
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _certified(
    material: bytes | ProxyRequest, plan: _Profile, signer: Certificate
) -> tuple[bytes, ProxyRequest | None]:
    """The key to certify, and the request it came in (if any), once the request is checked.

    Under XrdCrypto's profile the request must also be for the signer's own
    name plus one ``CN`` (:func:`~xrdsec.delegation._check_request`);
    the other profiles name the proxy themselves and ignore the request's
    subject (ARC sends an empty one), so only its proof of possession
    matters. A bare SPKI is the caller's own key and is taken as given.
    """
    if not isinstance(material, ProxyRequest):
        return bytes(material), None
    if plan.xrdcrypto:
        _check_request(material, signer)
    elif not material.verify():
        raise ProxyError("the proxy request is not signed by the key it carries")
    return material.spki, material


def _extension_map(certificate: Certificate) -> dict[str, tuple[bool, bytes]]:
    """``{oid: (critical, value)}`` for ``certificate``, as :func:`proxy_policy` reads it."""
    return {ext.oid: (ext.critical, ext.value) for ext in extensions_of(certificate.der)}


def _is_limited(certificate: Certificate) -> bool:
    """Whether ``certificate`` is a limited proxy, by policy or (GT2) by name.

    A limited proxy may only issue limited proxies; Globus, VOMS and ARC all
    enforce this on the issuing side, and the GridFTP servers that honour
    limitation would otherwise be handed a way around it.
    """
    if legacy_proxy_kind(certificate.subject, certificate.issuer) == "limited proxy":
        return True
    return proxy_policy(_extension_map(certificate)) == LIMITED_PROXY_OID


def _is_legacy_signer(certificate: Certificate) -> bool:
    """Whether ``certificate`` is a GT2 legacy proxy: named as one, with no proxy extension."""
    if legacy_proxy_kind(certificate.subject, certificate.issuer) is None:
        return False
    return not _signer_depth(certificate)[0]


def _signer_depth(certificate: Certificate) -> tuple[bool, int | None]:
    """Whether the signer has a proxy extension, and the path length it allows.

    The second value is ``None`` for no constraint - including for a signer
    with no proxy extension at all (a user certificate, a GT2 proxy).
    """
    for extension in extensions_of(certificate.der):
        if extension.oid in (PROXY_CERT_INFO_OID, LEGACY_PROXY_OID):
            return True, proxy_path_length(extension)
    return False, None


def _child_depth(certificate: Certificate, requested: int | None, legacy: bool) -> int | None:
    """The new proxy's ``pCPathLenConstraint``, once :func:`_refuse_depth` allows one.

    RFC 3820 section 4.1.4: the constraint counts the proxies that may
    follow, so the child of a signer allowing ``n`` allows at most ``n - 1``.
    ``requested`` may tighten that, never loosen it.
    """
    styled, signer = _signer_depth(certificate)
    _refuse_depth(requested, legacy, styled, signer)
    allowed = None if signer is None else signer - 1
    if requested is None or (allowed is not None and allowed < requested):
        return allowed
    return requested


def _refuse_depth(requested: int | None, legacy: bool, styled: bool, signer: int | None) -> None:
    """Refuse a path length that cannot be issued.

    A negative request is meaningless; a signer at ``0`` may not issue at
    all. A GT2 legacy proxy has nowhere to write a constraint, so it is
    refused under a signer that has a proxy extension (``styled``: it would
    silently drop the signer's limit, and mixes proxy styles in one chain)
    and when a constraint is asked for.
    """
    if requested is not None and requested < 0:
        raise ProxyError(f"a proxy path length cannot be negative: {requested}")
    if legacy and (styled or requested is not None):
        raise ProxyError(
            "a legacy (GT2) proxy cannot carry a path length, so it is not issued "
            "below an RFC 3820 proxy or with path_length set"
        )
    if signer is not None and signer < 1:
        raise ProxyError("the signing proxy's path length forbids further delegation")


# ---------------------------------------------------------------------------
# What goes into the certificate
# ---------------------------------------------------------------------------


def _extensions(issue: _Issue, extras: Sequence[bytes], copy_voms: bool) -> list[bytes]:
    """The new proxy's extensions, in order: the profile's own, then ``extras``.

    A VOMS extension among ``extras`` replaces the carried one rather than
    duplicating it. Every OID may appear once (RFC 5280 section 4.2).
    """
    checked = [_checked_extra(raw) for raw in extras]
    keep_voms = (
        copy_voms and issue.profile.voms and not any(ext.oid == VOMS_AC_OID for ext in checked)
    )
    final = [*_profile_extensions(issue, keep_voms), *(ext.der for ext in checked)]
    _check_unique(final)
    return final


def _profile_extensions(issue: _Issue, keep_voms: bool) -> list[bytes]:
    """The extensions the profile itself writes.

    The order is part of the golden tests: XrdCrypto's profile writes the
    copied signer extensions (its own VOMS AC among them, in place) then
    ``ProxyCertInfo``; the others write ``keyUsage``, ``ProxyCertInfo``
    (unless legacy), then the VOMS ACs carried forward from the chain.
    """
    policy = LIMITED_PROXY_OID if issue.limited else INHERIT_ALL_OID
    if issue.profile.xrdcrypto:
        copied, _ = _inherited(issue.certificate, voms=keep_voms)
        return [*copied, proxy_cert_info_extension(policy, issue.depth)]
    own = [_KEY_USAGE]
    if not issue.legacy:
        own.append(proxy_cert_info_extension(policy, issue.depth))
    if keep_voms:
        own.extend(_nearest_voms(issue.chain))
    return own


def _checked_extra(raw: bytes) -> Extension:
    """One caller-supplied extension, refused if RFC 3820 forbids it on a proxy.

    The profile writes ``ProxyCertInfo`` itself (a second one would be an
    ambiguity verifiers resolve differently); sections 3.5 and 3.6 forbid
    ``subjectAltName`` and ``issuerAltName``; section 3.7 forbids ``cA=TRUE``.
    """
    extension = parse_extension(raw)
    if extension.oid in (PROXY_CERT_INFO_OID, LEGACY_PROXY_OID):
        raise ProxyError("the profile writes the ProxyCertInfo extension itself")
    if extension.oid in (SUBJECT_ALT_NAME_OID, ISSUER_ALT_NAME_OID):
        raise ProxyError("RFC 3820 forbids alternative names on a proxy certificate")
    if extension.oid == BASIC_CONSTRAINTS_OID and _asserts_ca(extension.value):
        raise ProxyError("a proxy certificate cannot be a CA (basicConstraints cA=TRUE)")
    return extension


def _asserts_ca(value: bytes) -> bool:
    """Whether a ``basicConstraints`` value says ``cA=TRUE``.

    ``BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }``: DER
    omits a FALSE default, so ``cA`` is present only when it is TRUE - but a
    non-DER ``FALSE`` (``01 01 00``) is read as false, not as present.
    """
    members = parse(value)[0].children()
    return bool(members) and members[0].tag == TAG_BOOLEAN and members[0].value != b"\x00"


def _nearest_voms(chain: Sequence[Certificate]) -> list[bytes]:
    """The VOMS AC extension nearest the leaf of ``chain``, as ``[der]``; ``[]`` if none.

    Copied to the new proxy as ``voms-proxy-init`` places it and as XRootD's
    delegation does: storage reached through a delegated proxy often reads
    VOMS attributes only from the end of the chain it was handed. The AC
    stays valid on the new proxy, because its holder is the end-entity
    certificate, which is still in the chain.
    """
    for certificate in chain:
        for extension in extensions_of(certificate.der):
            if extension.oid == VOMS_AC_OID:
                return [extension.der]
    return []


def _check_unique(extensions: Sequence[bytes]) -> None:
    """Refuse a certificate that would carry one extension twice (RFC 5280 4.2)."""
    seen: set[str] = set()
    for raw in extensions:
        oid = parse_extension(raw).oid
        if oid in seen:
            raise ProxyError(f"the extension {oid} would appear twice in the proxy")
        seen.add(oid)


def _naming(issue: _Issue) -> tuple[bytes, int]:
    """The new proxy's subject (DER) and serial number, per the profile.

    RFC 3820 section 3.4: the issuer's subject plus one ``CN``. The serial
    must be unique among the issuer's proxies (section 3.3), which a random
    number of 31 or 63 bits is; the same number is the ``CN``, so the name
    is unique too. XrdCrypto takes both from the request, whose subject
    :func:`_certified` has checked; GT2 names every proxy ``proxy``.
    """
    issuer = certificate_fields(issue.certificate.der)["subject"]
    if issue.legacy:
        cn = "limited proxy" if issue.limited else "proxy"
        return _below(issuer, cn), _key_serial(issue.spki)
    if issue.request is not None and issue.profile.xrdcrypto:
        return issue.request.subject_der, issue.request.serial
    if issue.profile.serial_bits == 0:
        serial = _key_serial(issue.spki)
    else:
        serial = secrets.randbits(issue.profile.serial_bits) | 1
    return _below(issuer, str(serial)), serial


def _below(subject: bytes, common_name: str) -> bytes:
    """``subject`` (DER) with one more RDN, ``CN=<common_name>``.

    The issuer's RDNs are copied as encoded: a verifier compares the proxy's
    subject prefix with its issuer's name byte for byte, and re-encoding a
    ``PrintableString`` as ``UTF8String`` would break the match. The new CN
    is a ``PrintableString``, as Globus and VOMS write it.
    """
    rdn = set_of(sequence(encode_oid(_CN_OID), printable_string(common_name)))
    return sequence(*raw_children(subject), rdn)


def _key_serial(spki: bytes) -> int:
    """Globus' serial: the first four bytes of the key's SHA-1, never zero.

    SHA-1 is a name here, not a signature, so its weakness does not matter;
    it makes the serial unique per key without any state.
    """
    return int.from_bytes(hashlib.sha1(spki, usedforsecurity=False).digest()[:4], "big") or 1


def _validity(
    issue: _Issue, lifetime: datetime.timedelta | float | None, skew: float | None
) -> tuple[float, float]:
    """``notBefore`` and ``notAfter`` for the new proxy.

    Backdated by the profile's skew, but never before the signer's own
    ``notBefore`` (a proxy valid before its issuer fails verification); ends
    at the chain's earliest expiry, or sooner when ``lifetime`` says so.
    """
    backdate = issue.profile.skew if skew is None else skew
    if backdate < 0:
        raise ProxyError(f"not_before_skew cannot be negative: {backdate}")
    not_before = max(issue.moment - backdate, issue.certificate.not_before)
    not_after = min(link.not_after for link in issue.chain)
    if lifetime is not None:
        seconds = (
            lifetime.total_seconds()
            if isinstance(lifetime, datetime.timedelta)
            else float(lifetime)
        )
        if seconds <= 0:
            raise ProxyError(f"a proxy lifetime must be positive, not {seconds:g} seconds")
        not_after = min(not_after, issue.moment + seconds)
    return not_before, not_after


def _new_key(key_type: str, bits: int | None) -> tuple[object, bytes]:
    """A fresh private key for a proxy, as a credential holds it, and its SPKI.

    RSA keys are returned as :class:`~xrdsec.rsa.RSAPrivateKey`
    (what GSI signs with); EC keys as ``cryptography``'s object.
    """
    if key_type == "rsa":
        size = 2048 if bits is None else bits
        if size < _MIN_RSA_BITS:
            raise ValueError(f"an RSA proxy key needs at least {_MIN_RSA_BITS} bits, not {size}")
        key = RSAPrivateKey.generate(size)
        return key, _public_spki(key.to_cryptography())
    if key_type == "ec":
        curve = _CURVES.get(256 if bits is None else bits)
        if curve is None:
            raise ValueError(f"an EC proxy key is 256, 384 or 521 bits, not {bits}")
        library = ec.generate_private_key(curve())
        return library, _public_spki(library)
    raise ValueError(f"unknown proxy key type {key_type!r}; use 'rsa' or 'ec'")
