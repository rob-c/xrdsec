"""X.509 proxy delegation: sign the proxy request a GSI server sends.

When a client delegates, the *server* makes a key pair and sends the public
half as a PKCS#10 certificate request whose subject is the client proxy's
subject plus one ``CN=<serial>``. The client signs it with its proxy's private
key, producing an RFC 3820 proxy one link further down the chain, and sends
back just that certificate; the server already holds the rest of the chain
and the private key, so it ends up with a complete proxy of its own - and the
client's private key never leaves the client.

The certificate written here follows ``XrdCryptosslX509SignProxyReq``, the
function the stock client uses:

* version 3, serial number taken from the request's last ``CN``;
* subject from the request, issuer the signing proxy's subject;
* valid from now until the signing proxy expires, never beyond;
* every extension of the signing proxy copied as written (key usage, basic
  constraints, ...) except its ``ProxyCertInfo``, which is replaced by a
  critical ``ProxyCertInfo`` with the ``inheritAll`` policy;
* ``sha256WithRSAEncryption`` - or, signed by an EC proxy,
  ``ecdsa-with-SHA256``.

The signer may be an RFC 3820 proxy, a pre-RFC Globus (GT3/GT4) proxy with
the ``1.3.6.1.4.1.3536.1.222`` extension, or a GT2 legacy proxy known only by
its ``CN=proxy`` name; what is issued is always an RFC 3820 proxy, which is
what XrdCrypto issues too.

The certificate itself is assembled and signed by ``cryptography``'s
``CertificateBuilder`` (:func:`issue_certificate`), with every extension
passed through as the bytes the signer carries. The decision of
*what* goes in it is :mod:`xrdsec.proxies`' ``"xrootd"`` profile -
:func:`sign_proxy_request` is a thin call into
:func:`~xrdsec.proxies.issue_proxy` - while this module keeps the
pieces both share: the PKCS#10 parser, XrdCrypto's request and extension
rules (:func:`_check_request`, :func:`_inherited`) and the builder.

Four places deliberately differ from XrdCrypto. A limited signer issues a
limited proxy (XrdCrypto writes inheritAll whatever the signer was, which
would let a delegation lift the limitation). The request's own signature
is checked, so what gets signed is a key the requester holds. A path-length
constraint is carried down the chain as :rfc:`3820` has it - one less than the
signer's - so a signer whose constraint is already ``0`` refuses instead of
issuing a proxy no verifier would accept. And the signer's subject and
authority *key identifiers* are not copied: they describe the signer's key,
and on the new certificate they send ``openssl verify`` looking for an issuer
that does not exist (a proxy XrdCl delegates fails ``openssl verify`` for
exactly that reason; one delegated from here passes).
"""

from __future__ import annotations

import datetime
import re
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cryptography import x509 as _x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import ObjectIdentifier

from .der import (
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_SEQUENCE,
    DERError,
    Element,
    bit_string,
    encode,
    encode_integer,
    encode_oid,
    explicit,
    integer,
    oid_string,
    parse,
    raw_children,
    read_integer,
    sequence,
)
from .rsa import RSAPrivateKey, RSAPublicKey, pem_blocks, public_key_from_bitstring
from .x509 import (
    INHERIT_ALL_OID,
    LEGACY_PROXY_OID,
    PROXY_CERT_INFO_OID,
    Certificate,
    Extension,
    Name,
    certificate_fields,
    decode_name,
    encode_name,
    extensions_of,
    parse_extension,
    public_key_info,
    signature_algorithm,
    verify_signed,
)

__all__ = [
    "DelegationError",
    "ProxyRequest",
    "SigningKey",
    "issue_certificate",
    "load_proxy_request",
    "make_proxy_request",
    "parse_proxy_request",
    "proxy_cert_info_extension",
    "proxy_path_length",
    "sign_globus_request",
    "sign_proxy_request",
]

#: ``pkcs-9-at-extensionRequest``: where a PKCS#10 request carries extensions.
EXTENSION_REQUEST_OID = "1.2.840.113549.1.9.14"
KEY_USAGE_OID = "2.5.29.15"
#: Key identifiers name *one* key; copied onto a certificate for another key
#: they point path building at the wrong issuer, so they are not copied.
_KEY_IDENTIFIER_OIDS = ("2.5.29.14", "2.5.29.35")
SUBJECT_ALT_NAME_OID = "2.5.29.17"
ISSUER_ALT_NAME_OID = "2.5.29.18"
#: What :func:`_inherited` never copies from a signer (see its docstring).
_NOT_COPIED = (*_KEY_IDENTIFIER_OIDS, ISSUER_ALT_NAME_OID, SUBJECT_ALT_NAME_OID)
#: The VOMS AC extension (``xrdsec.voms.VOMS_AC_OID``), spelled
#: out so this module does not import the VOMS package.
VOMS_AC_OID = "1.3.6.1.4.1.8005.100.100.5"
SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11"

_SERIAL_CN = re.compile(r"-?[0-9]{1,20}")

#: What can sign a certificate here: the client's RSA view, or a
#: ``cryptography`` RSA or EC private key (an EC proxy signs ECDSA).
SigningKey = RSAPrivateKey | _rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

#: The hashes a certificate is signed over; ``cryptography`` signs no SHA-1.
_DIGESTS: dict[str, type[hashes.SHA256 | hashes.SHA384 | hashes.SHA512]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class DelegationError(ValueError):
    """The request cannot, or must not, be signed."""


@dataclass(frozen=True, slots=True)
class ProxyRequest:
    """A decoded PKCS#10 certificate request, as a GSI server sends it."""

    subject: Name
    subject_der: bytes
    spki: bytes
    #: The requested key when it is RSA (all a GSI server sends); ``None`` for
    #: any other algorithm, which :attr:`spki` still carries in full.
    public_key: RSAPublicKey | None
    extensions: tuple[Extension, ...]
    der: bytes

    @property
    def serial(self) -> int:
        """The serial the last ``CN`` names, as the unsigned 32-bit value XrdCrypto uses."""
        kind, value = self.subject.rdns[-1] if self.subject.rdns else ("", "")
        if kind != "CN" or not _SERIAL_CN.fullmatch(value):
            raise DelegationError(f"the request's subject does not end in CN=<serial>: {value!r}")
        return int(value) % (1 << 32)

    def verify(self) -> bool:
        """Whether the request is signed by the key it asks to be certified."""
        return verify_signed(self.der, self.spki)


def load_proxy_request(data: bytes | str) -> ProxyRequest:
    """Parse a ``CERTIFICATE REQUEST`` from PEM (what XrdCrypto sends) or raw DER."""
    der = next(
        (body for label, body in pem_blocks(data) if label.endswith("CERTIFICATE REQUEST")),
        None,
    )
    if der is None:
        der = data if isinstance(data, bytes) else data.encode("latin-1")
    try:
        return parse_proxy_request(der)
    except DERError as exc:
        raise DelegationError(f"unreadable proxy request: {exc}") from exc


def parse_proxy_request(der: bytes) -> ProxyRequest:
    """Decode one DER PKCS#10 ``CertificationRequest``, of any key type.

    The parser both clients share: :func:`load_proxy_request` here (an
    XRootD GSI server's request), and xgfalclient's ``parse_request`` (a
    GridFTP, SRM or gridsite delegation service's). Its proof of possession
    is :meth:`ProxyRequest.verify`, which checks whatever algorithm the
    request is signed with. Anything malformed raises
    :class:`~xrdsec.der.DERError`.
    """
    try:
        top = parse(der)[0].children()
        if len(top) != 3 or top[0].tag != TAG_SEQUENCE or top[2].tag != TAG_BIT_STRING:
            raise DERError("not a PKCS#10 certificate request")
        return _parse_request(der)
    except DERError:
        raise
    except (ValueError, IndexError) as exc:
        raise DERError(f"not a PKCS#10 certificate request: {exc}") from exc


def _parse_request(der: bytes) -> ProxyRequest:
    """Decode a PKCS#10 ``CertificationRequest`` (RFC 2986) far enough to sign it.

    Only ``certificationRequestInfo`` is unpacked: version, subject,
    ``subjectPKInfo`` and the optional ``[0] attributes``. The SPKI is kept as
    the exact DER the requester sent, because it is both what gets certified
    and what the request's own signature is checked against; ``cryptography``
    loads it once here purely to refuse key types it could not certify later.
    """
    info = raw_children(der)[0]
    fields = raw_children(info)
    if len(fields) < 3 or parse(fields[0])[0].tag != TAG_INTEGER:
        raise DERError("CertificationRequestInfo needs a version, a subject and a key")
    spki = parse(fields[2])[0].children()
    if len(spki) != 2 or spki[1].tag != TAG_BIT_STRING:
        raise DERError("the request's key is not a SubjectPublicKeyInfo")
    try:
        key = serialization.load_der_public_key(fields[2])
    except UnsupportedAlgorithm as exc:
        raise DERError(f"the request's key is of an unsupported type: {exc}") from exc
    return ProxyRequest(
        subject=decode_name(fields[1]),
        subject_der=fields[1],
        spki=fields[2],
        public_key=public_key_from_bitstring(spki[1])
        if isinstance(key, _rsa.RSAPublicKey)
        else None,
        extensions=tuple(_requested_extensions(fields[3:])),
        der=der,
    )


def _requested_extensions(extras: list[bytes]) -> list[Extension]:
    """The extensions inside the ``[0] attributes`` of a request, if any."""
    out: list[Extension] = []
    for extra in extras:
        if extra[0] != 0xA0:
            continue
        for attribute in parse(extra)[0].children():
            parts = attribute.children()
            if len(parts) == 2 and oid_string(parts[0]) == EXTENSION_REQUEST_OID:
                out.extend(_extension_list(parts[1]))
    return out


def _extension_list(values: Element) -> list[Extension]:
    """``SET OF Extensions``: each value is itself a ``SEQUENCE OF Extension``."""
    return [
        parse_extension(raw)
        for value in values.children()
        for raw in raw_children(encode(value.tag, value.value))
    ]


def proxy_path_length(extension: Extension) -> int | None:
    """The ``pCPathLenConstraint`` of a ProxyCertInfo extension; ``None`` if unlimited.

    Reads both the RFC 3820 layout (constraint first) and the pre-RFC Globus
    one (policy first, constraint in an explicit ``[1]``).
    """
    for part in parse(extension.value)[0].children():
        if part.tag == TAG_INTEGER:
            return read_integer(part)
        if part.tag == 0xA1:
            return read_integer(part.children()[0])
    return None


def _check_request(request: ProxyRequest, signer: Certificate) -> None:
    """Refuse a request this proxy must not sign, before any signing happens.

    The subject must be the signer's subject plus exactly one RDN (the
    ``CN=<serial>`` RFC 3820 requires), so a server cannot obtain a proxy with
    a name of its choosing. The request must be self-signed by the key it
    carries - XrdCrypto skips this - so the certified key is one the server
    actually holds. And it must carry extensions: every stock server request
    does, and one without is refused rather than guessed at.
    """
    if request.subject.rdns[:-1] != signer.subject.rdns:
        raise DelegationError(
            f"the request is for {request.subject}, which is not {signer.subject}/CN=<serial>"
        )
    if not request.verify():
        raise DelegationError("the proxy request is not signed by the key it carries")
    if not request.extensions:
        raise DelegationError("the proxy request carries no extensions")


def _inherited(signer: Certificate, *, voms: bool = True) -> tuple[list[bytes], int | None]:
    """The signer's extensions to copy, and its proxy path-length constraint.

    XrdCrypto's rule, for both of its issuers (delegation and
    ``xrdgsiproxy``): every extension of the signer goes onto the new proxy
    as written, except the few that describe the signer alone - its
    ``ProxyCertInfo`` (replaced), its key identifiers (see the module
    docstring) and its ``issuerAltName`` (RFC 3820 section 3.6 forbids one
    on a proxy). A ``subjectAltName`` is skipped on an end-entity signer, as
    ``xrdgsiproxy`` skips it (user certificates often carry an e-mail
    address), but refused on a proxy signer, which RFC 3820 section 3.5 says
    must not have had one. ``voms=False`` leaves the VOMS AC extension
    behind. Raises :class:`DelegationError` for a signer with no
    ``keyUsage``: every stock proxy has one, and some verifiers insist.
    """
    copied: list[bytes] = []
    depth: int | None = None
    usage = False
    for extension in extensions_of(signer.der):
        if extension.oid == SUBJECT_ALT_NAME_OID and signer.is_proxy:
            raise DelegationError("the signing proxy carries a subjectAltName; refusing")
        if extension.oid in (PROXY_CERT_INFO_OID, LEGACY_PROXY_OID):
            depth = proxy_path_length(extension)
            continue
        if extension.oid in _NOT_COPIED or (extension.oid == VOMS_AC_OID and not voms):
            continue
        usage = usage or extension.oid == KEY_USAGE_OID
        copied.append(extension.der)
    if not usage:
        raise DelegationError("the signing proxy has no keyUsage extension")
    return copied, depth


def _proxy_cert_info(depth: int | None) -> bytes:
    """A critical inheritAll ProxyCertInfo one step below a signer constrained to ``depth``.

    ``depth`` is the *signer's* ``pCPathLenConstraint`` (``None``: unlimited);
    the new proxy gets one less, and a signer at ``0`` may not delegate at
    all. What ``XrdCryptosslX509SignProxyReq`` writes for an unrestricted
    signer; :func:`xrdsec.proxies.issue_proxy` makes the same
    decision (and the limited case) itself, and the golden test in
    ``tests/test_delegation.py`` rebuilds the original XrdCrypto certificate
    with this.
    """
    if depth is not None and depth < 1:
        raise DelegationError("the signing proxy's path length forbids further delegation")
    return proxy_cert_info_extension(INHERIT_ALL_OID, None if depth is None else depth - 1)


def proxy_cert_info_extension(policy: str, path_length: int | None) -> bytes:
    """A critical RFC 3820 ``ProxyCertInfo`` extension, as DER.

    ``ProxyCertInfo ::= SEQUENCE { pCPathLenConstraint INTEGER OPTIONAL,
    proxyPolicy SEQUENCE { policyLanguage OID, policy OCTET STRING OPTIONAL } }``
    - the policy *body* is never written, because the three languages used
    in practice (inheritAll, independent, Globus' limited) take none.
    ``path_length`` is this proxy's own constraint; ``None`` leaves further
    delegation unbounded, as ``voms-proxy-init`` and ``grid-proxy-init`` do.
    """
    body = sequence(encode_oid(policy))
    value = sequence(body) if path_length is None else sequence(encode_integer(path_length), body)
    return sequence(
        encode_oid(PROXY_CERT_INFO_OID),
        encode(TAG_BOOLEAN, b"\xff"),
        encode(TAG_OCTET_STRING, value),
    )


def sign_proxy_request(
    request: ProxyRequest,
    signer: Certificate,
    key: SigningKey,
    *,
    now: float | None = None,
) -> Certificate:
    """Issue the proxy ``request`` asks for, signed by ``signer`` with ``key``.

    ``signer`` is the client's own proxy - the first certificate of the proxy
    file - and ``key`` its private key: RSA (signing ``sha256WithRSAEncryption``)
    or EC (``ecdsa-with-SHA256``). Raises :class:`DelegationError` when the
    request is malformed, is not for this proxy, or the proxy cannot sign.

    This is the ``"xrootd"`` profile of :func:`xrdsec.proxies.issue_proxy`,
    the one proxy issuer every client shares; the certificate is
    byte-for-byte what ``XrdCryptosslX509SignProxyReq`` writes
    (``tests/test_delegation.py`` pins it against the hand-assembled DER),
    except that a *limited* signer issues a limited proxy instead of an
    unrestricted one.
    """
    # Imported here, not at the top: ``proxies`` is built on this module
    # (the request parser and the certificate builder), so a module-level
    # import would be a cycle.
    from .proxies import issue_proxy
    from .x509 import ProxyCredential

    return issue_proxy(
        ProxyCredential(chain=(signer,), key=key), request, profile="xrootd", now=now
    )


def make_proxy_request(
    key: RSAPrivateKey, rdns: Sequence[tuple[str, str]] = (("CN", "proxy"),)
) -> bytes:
    """A signed PKCS#10 request for ``key``: what a delegation *target* sends.

    The client is the signer and never sends one; the acceptor side of GSI
    (:class:`xrdsec.gsi.gss.SecurityContext` with ``server_side=True``, which
    the in-process GridFTP, LFC and dcap fakes run) and gridsite delegation
    services do. The RFC 2986 ``CertificationRequest``:
    ``certificationRequestInfo`` (version 0, a subject the signer ignores -
    Globus names the proxy itself - the SPKI, and an empty ``[0]`` attribute
    set), signed SHA-256 with ``key`` as proof of possession. Moved here from
    xgfalclient's ``crypto.proxy.make_request`` in 0.4.0.
    """
    info = sequence(
        integer(0),
        encode_name(rdns),
        public_key_info(key.public),
        explicit(0, b""),
    )
    return sequence(
        info, signature_algorithm("sha256"), bit_string(key.sign(info, digest="sha256"))
    )


def sign_globus_request(
    request: bytes | ProxyRequest,
    chain: Sequence[bytes],
    key: object,
    *,
    lifetime: float | None = None,
    limited: bool | None = None,
    digest: str = "sha256",
    now: float | None = None,
) -> bytes:
    """Sign ``request`` as Globus' ``globus_gsi_proxy_sign_req`` would; the DER certificate.

    ``chain`` is the signing credential's certificates as DER, leaf (the
    signer) first, and ``key`` the leaf's private key: an RSA key in either
    form, or an EC key. This is the ``"globus"`` profile of
    :func:`xrdsec.proxies.issue_proxy`, which GSI delegation
    (:mod:`xrdsec.gsi.gss`) and gridsite delegation both need:

    * ``lifetime`` (seconds) can only shorten the proxy; it never outlives
      any link of ``chain``;
    * ``limited=None`` inherits the signer's limitation; ``False`` cannot
      lift it, ``True`` imposes it;
    * a legacy (GT2) signer gets a legacy child (``CN=proxy``), anything
      else an RFC 3820 one.

    The request's own signature is checked first: signing a key whose
    holder has not proved possession would hand a credential to whoever
    forged the request. Every refusal - an unreadable or unproven request,
    an expired chain, a key that is not the signer's, a path length that
    forbids delegating, SHA-1 as ``digest`` - is a :class:`DelegationError`.
    """
    # Imported here for the reason sign_proxy_request gives: proxies builds on us.
    from .proxies import issue_proxy
    from .x509 import ProxyCredential, parse_certificate

    try:
        parsed = parse_proxy_request(request) if isinstance(request, bytes) else request
        signer = ProxyCredential(chain=tuple(parse_certificate(der) for der in chain), key=key)
    except DERError as exc:
        raise DelegationError(str(exc)) from exc
    if not parsed.verify():
        raise DelegationError("the certificate request's signature does not verify")
    issued = issue_proxy(
        signer,
        parsed,
        profile="globus",
        lifetime=lifetime,
        limited=limited,
        now=now,
        digest=digest,
    )
    return issued.der


def _library_key(key: object) -> _rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    """The signer as a ``cryptography`` private key, whichever form the caller holds.

    Raises :class:`DelegationError` for anything that is neither, so a DSA or
    Ed25519 key fails with a sentence rather than deep inside the builder.
    """
    if isinstance(key, RSAPrivateKey):
        return key.to_cryptography()
    if isinstance(key, _rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        return key
    raise DelegationError(f"cannot sign a proxy with a {type(key).__name__}")


def _holds_key(signer: Certificate, key: PrivateKeyTypes) -> bool:
    """Whether ``key`` is the private half of the key ``signer`` certifies."""
    try:
        public = serialization.load_der_public_key(certificate_fields(signer.der)["spki"])
    except (DERError, ValueError, IndexError, UnsupportedAlgorithm):
        return False
    return bool(public == key.public_key())


def issue_certificate(
    *,
    subject: bytes,
    issuer: bytes,
    public_key: bytes,
    signer: SigningKey,
    not_before: float,
    not_after: float,
    serial: int | None = None,
    extensions: Sequence[bytes] = (),
    digest: str = "sha256",
) -> bytes:
    """Sign a version 3 certificate and return its DER.

    The building block under every :mod:`xrdsec.proxies` profile and the
    test PKI, with the keyword interface xgfalclient's ``build_certificate``
    had, so every proxy is issued through one implementation. ``subject`` and ``issuer`` are
    DER ``Name``s, re-emitted with each attribute's original string type;
    ``public_key`` is the certified key's ``SubjectPublicKeyInfo`` DER;
    ``extensions`` are DER ``Extension``s, written in the order given with
    their values untouched (``cryptography`` would otherwise re-encode the
    ones it understands). Times are truncated to whole seconds. ``serial``
    defaults to a random positive 63-bit number. The signature is
    PKCS#1 v1.5 for an RSA ``signer`` and ECDSA for an EC one, over
    ``digest``.

    Raises :class:`ValueError` (a :class:`~xrdsec.der.DERError` for
    malformed DER) when an input cannot go into a certificate.
    """
    algorithm = _DIGESTS.get(digest.lower().replace("-", ""))
    if algorithm is None:
        raise ValueError(f"unsupported digest {digest!r} for a certificate signature")
    builder = (
        _x509.CertificateBuilder()
        .subject_name(_library_name(subject))
        .issuer_name(_library_name(issuer))
        .public_key(_certified_key(public_key))
        .serial_number(secrets.randbits(63) | 1 if serial is None else serial)
        .not_valid_before(_moment(not_before))
        .not_valid_after(_moment(not_after))
    )
    for raw in extensions:
        extension = parse_extension(raw)
        value = _x509.UnrecognizedExtension(ObjectIdentifier(extension.oid), extension.value)
        builder = builder.add_extension(value, critical=extension.critical)
    certificate = builder.sign(_library_key(signer), algorithm())
    return certificate.public_bytes(serialization.Encoding.DER)


def _moment(when: float) -> datetime.datetime:
    """A timestamp as an aware UTC ``datetime``, truncated to whole seconds.

    X.509 times have one-second resolution. Truncating, rather than rounding,
    means ``notBefore`` can never land in the future, where a strict verifier
    would see a not-yet-valid proxy.
    """
    return datetime.datetime.fromtimestamp(int(when), datetime.UTC)


def _certified_key(spki: bytes) -> Any:
    """Load the SubjectPublicKeyInfo to certify; an unknown algorithm is a ``DERError``."""
    try:
        return serialization.load_der_public_key(spki)
    except UnsupportedAlgorithm as exc:
        raise DERError(f"cannot certify this kind of key: {exc}") from exc


def _library_name(der: bytes) -> _x509.Name:
    """A DER ``Name`` as ``cryptography``'s, each value keeping its string type.

    The type matters: an issuer written as ``UTF8String`` where the signer's
    subject is a ``PrintableString`` is a different name to a byte-wise
    comparison, and some verifiers compare that way.
    """
    rdns = []
    for rdn in parse(der)[0].children():
        attributes = []
        for attribute in rdn.children():
            kind, value = attribute.children()
            attributes.append(
                _x509.NameAttribute(
                    ObjectIdentifier(oid_string(kind)),
                    _string(value),
                    _type=_ASN1Type(value.tag),
                )
            )
        rdns.append(_x509.RelativeDistinguishedName(attributes))
    return _x509.Name(rdns)


#: How each DirectoryString type's bytes read as text; the rest are 8-bit.
_STRING_CODECS = {0x0C: "utf-8", 0x1C: "utf-32-be", 0x1E: "utf-16-be"}


def _string(element: Element) -> str:
    """The text of a DirectoryString value, decoded per its ASN.1 string type.

    ``BMPString`` is UTF-16BE and ``UniversalString`` UTF-32BE; Printable, IA5,
    Teletex and the rest are read as Latin-1, which round-trips every byte and
    so re-encodes the name exactly as the signer wrote it.
    """
    return element.value.decode(_STRING_CODECS.get(element.tag, "latin-1"))
