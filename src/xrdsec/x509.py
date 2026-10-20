"""Library-backed X.509 inspection and RFC 3820 proxy compatibility.

GSI needs less of X.509 than it first appears: the handshake echoes the
proxy chain to the server verbatim, and the *server* validates it. What the
client genuinely needs is to look at the material it is about to offer — is
this a proxy, whose is it, and has it expired — so that a stale proxy is a
sentence rather than a 3010 from the far end an hour into a job.

So this reads certificates. It does not build paths for the login itself:
trust in the *client* is the endpoint's decision. The pieces here that do
check signatures (:func:`verify_signed`) serve X.509 delegation, where the
client is about to hand a server a credential and so has to know which server
it is talking to - see :mod:`xrdsec.trust`.

The proxy rules, briefly, because they explain most of the code below. An
RFC 3820 proxy certificate is issued by an end-entity certificate (or by
another proxy) rather than a CA, and is recognised by:

* its subject: the issuer's subject plus exactly one more ``CN`` (section
  3.4) - conventionally a random serial number, so ``.../CN=Jane
  Doe/CN=1234567890``;
* a critical ``ProxyCertInfo`` extension, ``id-pe-proxyCertInfo``
  (section 3.8), holding an optional path-length limit and a
  ``ProxyPolicy`` whose language OID says what rights the proxy carries:
  ``id-ppl-inheritAll`` (all of the issuer's), ``id-ppl-independent``
  (none), or a site-specific language such as Globus's "limited proxy"
  (no job submission);
* no ``cA`` in Basic Constraints and no subject or issuer alternative
  names (the rest of RFC 3820 section 3).

Two older generations are still met on the grid and are read too: Globus
GT2 "legacy" proxies, marked only by a final ``CN=proxy`` or ``CN=limited
proxy`` (:func:`legacy_proxy_kind`), and the pre-RFC GT3 draft proxies, which
carry the same information under Globus's own extension OID
(:data:`LEGACY_PROXY_OID`). XrdCl's GSI plug-in (XrdSecgsi) and gfal2
disagree on how strictly to apply these rules; where they differ the
function says which reading it gives, and xgfalclient builds gfal2's on top
of the same primitives.

Decoding goes through ``cryptography`` (:func:`certificate_data`), with a
bounded DER fallback (:func:`_legacy_certificate_data`) for certificates a
strict parser refuses but a user still needs diagnosed. Shared with
xgfalclient, whose condition-coverage run covers this module too.
"""

from __future__ import annotations

import base64
import contextlib
import textwrap
import time
import warnings
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, TypeVar, cast

from cryptography import x509 as _x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.utils import CryptographyDeprecationWarning

from .credentials import default_proxy_path
from .der import (
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SET,
    DERError,
    Element,
    bit_string,
    encode,
    integer,
    null,
    oid,
    oid_string,
    parse,
    parse_one,
    printable_string,
    raw_children,
    read_integer,
    sequence,
    set_of,
    tlv,
    utf8_string,
)
from .der import (
    decode_time as _decode_time,
)
from .rsa import RSAPublicKey, pem_blocks, public_key_from_bitstring
from .signatures import RSA_PKCS1_DIGESTS, SignatureAlgorithmError, verify_signature

__all__ = [
    "ATTRIBUTE_NAMES",
    "ATTRIBUTE_OIDS",
    "AUTHORITY_KEY_ID_OID",
    "BASIC_CONSTRAINTS_OID",
    "INDEPENDENT_OID",
    "INHERIT_ALL_OID",
    "KEY_USAGE_OID",
    "LEGACY_PROXY_OID",
    "LIMITED_PROXY_OID",
    "PROXY_CERT_INFO_OID",
    "SUBJECT_ALT_NAME_OID",
    "SUBJECT_KEY_ID_OID",
    "Certificate",
    "Extension",
    "Name",
    "ProxyCredential",
    "certificate_fields",
    "certificates_in",
    "credential_key",
    "decode_name",
    "default_proxy_path",
    "encode_name",
    "extension",
    "extensions_of",
    "is_proxy_certificate",
    "issuer_hashes",
    "key_usage",
    "legacy_proxy_kind",
    "load_certificates",
    "load_proxy",
    "name_from_element",
    "name_hashes",
    "parse_certificate",
    "parse_extension",
    "pem_encode",
    "policy_language",
    "proxy_identity",
    "proxy_policy",
    "public_key_info",
    "read_credential_files",
    "signature_algorithm",
    "signature_digest",
    "signed_by",
    "split_der_certificates",
    "tbs_extensions",
    "verify_issued",
    "verify_signed",
]

#: The short names OpenSSL prints for the attribute types that appear in
#: grid subjects. Anything else is rendered by its OID, which is honest.
ATTRIBUTE_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}

#: The reverse map, for building a DER name from OpenSSL-style short names.
ATTRIBUTE_OIDS = {short: dotted for dotted, short in ATTRIBUTE_NAMES.items()}

#: ``id-pe-proxyCertInfo`` (RFC 3820 section 3.8): the presence of this
#: extension is what makes a certificate an RFC 3820 proxy.
PROXY_CERT_INFO_OID = "1.3.6.1.5.5.7.1.14"
#: The pre-RFC Globus "legacy" proxy extension, still seen in the wild.
LEGACY_PROXY_OID = "1.3.6.1.4.1.3536.1.222"
#: Proxy policy languages: full impersonation (``id-ppl-inheritAll``), an
#: independent identity (``id-ppl-independent``), and Globus' limited proxy.
INHERIT_ALL_OID = "1.3.6.1.5.5.7.21.1"
INDEPENDENT_OID = "1.3.6.1.5.5.7.21.2"
LIMITED_PROXY_OID = "1.3.6.1.4.1.3536.1.1.1.9"
#: The last ``CN`` a Globus GT2 proxy appends to its issuer's subject, which
#: is all that marks one: it predates every proxy extension.
_GT2_PROXY_NAMES = ("proxy", "limited proxy")


def pem_encode(label: str, der: bytes) -> bytes:
    """``der`` as one PEM block labelled ``label``, 64 base64 characters a line."""
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode("ascii")


@dataclass(frozen=True, slots=True)
class Name:
    """A distinguished name: ``(type, value)`` pairs plus the DER they came from."""

    rdns: tuple[tuple[str, str], ...] = ()
    der: bytes = field(default=b"", compare=False, repr=False)

    @property
    def cn(self) -> str:
        """The *last* ``CN``, or ``""``: the most specific, which for a proxy
        is the proxy's own serial rather than the user's name."""
        common = [value for key, value in self.rdns if key == "CN"]
        return common[-1] if common else ""

    def get(self, key: str) -> list[str]:
        """Every value of attribute ``key`` (a short name such as ``DC``), in order."""
        return [value for name, value in self.rdns if name == key]

    def __str__(self) -> str:
        """OpenSSL's one-line form: ``/DC=org/DC=example/CN=Jane Doe``."""
        return "".join(f"/{key}={value}" for key, value in self.rdns)

    def __bool__(self) -> bool:
        """False for the empty name, which X.509 allows as a subject."""
        return bool(self.rdns)

    def encoded(self) -> bytes:
        """The DER the name was read from, else a fresh encoding of :attr:`rdns`.

        The original bytes are preferred because a signature and a CA hash
        cover them exactly; a re-encoding can differ (string types, multi-
        valued RDNs) and so fail to match.
        """
        return self.der or encode_name(self.rdns)


def encode_name(rdns: Sequence[tuple[str, str]]) -> bytes:
    """A ``Name`` from ``(type, value)`` pairs, one attribute per RDN."""
    parts = []
    for key, value in rdns:
        kind = ATTRIBUTE_OIDS.get(key, key)
        parts.append(set_of(sequence(oid(kind), _attribute_value(kind, value))))
    return sequence(*parts)


#: Attributes RFC 4519 types as IA5String: domainComponent and emailAddress.
_IA5_ATTRIBUTES = ("0.9.2342.19200300.100.1.25", "1.2.840.113549.1.9.1")


def _attribute_value(kind: str, value: str) -> bytes:
    """``value`` in the string type RFC 5280 expects for attribute ``kind``.

    PrintableString where the characters allow - the type grid CAs issue
    names in - else UTF8String; IA5String for the two attributes defined
    that way.
    """
    if kind in _IA5_ATTRIBUTES:
        return tlv(0x16, value.encode("ascii"))
    if _printable(value):
        return printable_string(value)
    return utf8_string(value)


def _printable(value: str) -> bool:
    """Whether ``value`` fits X.680's PrintableString alphabet (and is non-empty)."""
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")
    return bool(value) and all(char in allowed for char in value)


def name_from_element(element: Element) -> Name:
    """A parsed DER ``Name`` as a :class:`Name`, multi-valued RDNs flattened.

    An attribute that is not an ``(OID, value)`` pair is skipped: this is
    for display and comparison, and one garbled attribute should not hide
    the rest of a subject from a user diagnosing their proxy.
    """
    rdns: list[tuple[str, str]] = []
    for rdn in element.children():
        for attribute in rdn.children():
            parts = attribute.children()
            if len(parts) != 2:
                continue
            key = oid_string(parts[0])
            rdns.append((ATTRIBUTE_NAMES.get(key, key), _decode_string(parts[1])))
    return Name(tuple(rdns), element.encoded)


def _decode_string(element: Element) -> str:
    """DirectoryString in any of the encodings certificates actually use."""
    if element.tag == 0x1E:  # BMPString: UTF-16BE
        return element.value.decode("utf-16-be", "replace")
    return element.value.decode("utf-8", "replace")


@dataclass(frozen=True, slots=True)
class Certificate:
    """One X.509 certificate, decoded far enough to be useful."""

    subject: Name
    issuer: Name
    serial: int
    not_before: float
    not_after: float
    public_key: RSAPublicKey | None
    extensions: tuple[str, ...] = ()
    der: bytes = field(default=b"", repr=False)

    @property
    def is_proxy(self) -> bool:
        """True for an RFC 3820 proxy or a Globus legacy proxy."""
        if PROXY_CERT_INFO_OID in self.extensions or LEGACY_PROXY_OID in self.extensions:
            return True
        # A proxy always appends a CN to its issuer's subject; a CA-issued
        # end-entity certificate does not.
        return bool(self.subject.rdns) and self.subject.rdns[:-1] == self.issuer.rdns

    @property
    def is_anchor(self) -> bool:
        """True for a self-signed certificate: a trust anchor, not a link.

        A CA that signed itself is where verification *stops*, which is why a
        verifier keeps its own copy and never takes one from the wire.
        """
        return self.subject == self.issuer

    @property
    def expired(self) -> bool:
        """Whether ``notAfter`` has passed; ``notBefore`` is not checked here."""
        return self.not_after <= time.time()

    def remaining(self) -> float:
        """Seconds of validity left; negative once expired."""
        return self.not_after - time.time()

    def pem(self) -> bytes:
        """The certificate back as a PEM block."""
        return pem_encode("CERTIFICATE", self.der)

    def __str__(self) -> str:
        """The subject in OpenSSL's slash form, as ``voms-proxy-info`` prints it."""
        return str(self.subject)


def parse_certificate(der: bytes) -> Certificate:
    """Decode one DER certificate.

    VOMS attribute certificates embed their signing chain as consecutive DER
    certificates rather than PEM, so callers need the single-certificate
    decoder as well as :func:`load_certificates`.
    """
    data = certificate_data(der)
    return Certificate(
        data.subject,
        data.issuer,
        data.serial,
        data.not_before,
        data.not_after,
        data.public_key,
        data.extensions,
        data.der,
    )


@dataclass(frozen=True, slots=True)
class CertificateData(Certificate):
    """One decoded view for both clients; compatibility facades keep their types."""

    extension_values: dict[str, tuple[bool, bytes]] = field(default_factory=dict, repr=False)
    tbs: bytes = field(default=b"", repr=False)
    signature: bytes = field(default=b"", repr=False)
    signature_oid: str = ""
    spki: bytes = field(default=b"", repr=False)


#: cryptography's deprecation of a zero or negative serial, which RFC 5280
#: forbids and several IGTF CAs still carry - in their own serial, or as the
#: issuer serial an Authority Key Identifier names. Every grid client loads
#: those CAs, so every command printed the warning three times.
SERIAL_WARNING = r"Parsed a serial number which wasn't positive"


def quiet_serial_warning() -> None:
    """Ignore :data:`SERIAL_WARNING` when it is raised from this package's own calls.

    Installed once, at import: ``warnings.catch_warnings`` around each load
    would swap the process's filters under other threads. Scoped to the one
    message and to ``xrdsec`` modules, so the same warning from a caller's
    own code still shows. When ``cryptography`` refuses such certificates
    outright, :func:`certificate_data`'s ``ValueError`` fallback reads them.
    """
    warnings.filterwarnings(
        "ignore",
        message=SERIAL_WARNING,
        category=CryptographyDeprecationWarning,
        module=r"xrdsec\.",
    )


quiet_serial_warning()


def _library_name(name: _x509.Name) -> Name:
    """A ``cryptography`` name as a :class:`Name`, keeping its original DER."""
    return Name(
        tuple(
            (ATTRIBUTE_NAMES.get(a.oid.dotted_string, a.oid.dotted_string), str(a.value))
            for a in name
        ),
        name.public_bytes(),
    )


def certificate_data(der: bytes) -> CertificateData:
    """Decode normal certificates through cryptography, preserving original DER.

    Legacy inspection APIs also accept incomplete names/keys that a strict
    X.509 loader refuses. Their bounded compatibility decoder is shared here;
    this function does not establish trust or validate a certificate path.
    """
    try:
        cert = _x509.load_der_x509_certificate(der)
        extensions = {
            e.oid.dotted_string: (e.critical, e.value.public_bytes()) for e in cert.extensions
        }
    except (ValueError, _x509.DuplicateExtension):
        # A duplicated extension is malformed X.509, but still a certificate
        # to inspect; the bounded decoder below reads it.
        return _legacy_certificate_data(der)
    # Key types ``cryptography`` cannot load (unusual curves, broken
    # parameters) fall back as well: the certificate is still worth showing.
    try:
        public = cert.public_key()
        numbers = public.public_numbers() if isinstance(public, _rsa.RSAPublicKey) else None
        key = RSAPublicKey(numbers.n, numbers.e) if numbers is not None else None
        spki = public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except (ValueError, UnsupportedAlgorithm):
        return _legacy_certificate_data(der)
    return CertificateData(
        _library_name(cert.subject),
        _library_name(cert.issuer),
        cert.serial_number,
        cert.not_valid_before_utc.timestamp(),
        cert.not_valid_after_utc.timestamp(),
        key,
        tuple(extensions),
        bytes(der),
        extensions,
        cert.tbs_certificate_bytes,
        cert.signature,
        cert.signature_algorithm_oid.dotted_string,
        spki,
    )


def tbs_extensions(fields: list[Element]) -> dict[str, tuple[bool, bytes]]:
    """The ``[3] EXPLICIT Extensions`` among a TBSCertificate's trailing fields.

    ``OID -> (critical, extnValue)``; a duplicated OID - one of the defects
    the fallback exists to tolerate (see :func:`certificate_data`) - keeps
    the last occurrence.
    """
    found: dict[str, tuple[bool, bytes]] = {}
    for extra in fields:
        if extra.tag != 0xA3:
            continue
        for extension in extra.children()[0].children():
            parts = extension.children()
            if parts and parts[-1].tag == TAG_OCTET_STRING:
                critical = (
                    len(parts) == 3 and parts[1].tag == TAG_BOOLEAN and parts[1].value != b"\x00"
                )
                found[oid_string(parts[0])] = (critical, parts[-1].value)
    return found


def _legacy_certificate_data(der: bytes) -> CertificateData:
    """Decode a certificate with this package's own DER reader.

    The RFC 5280 layout is ``SEQUENCE { tbsCertificate, signatureAlgorithm,
    signatureValue }``, and the TBS is ``[0] version`` (optional, hence
    ``index``), serial, signature, issuer, validity, subject,
    subjectPublicKeyInfo, then optional unique IDs and ``[3]`` extensions.
    Only the structure is checked - nothing here establishes trust.
    """
    top = parse_one(der).children()
    if len(top) != 3 or top[0].tag != 0x30 or top[2].tag != TAG_BIT_STRING:
        raise DERError("not an X.509 certificate")
    fields = top[0].children()
    index = 1 if fields and fields[0].tag == 0xA0 else 0
    if len(fields) < index + 6:
        raise DERError("certificate body is missing required fields")
    validity = fields[index + 3].children()
    if len(validity) != 2:
        raise DERError("certificate validity is not a pair of times")
    spki = fields[index + 5]
    key = _certificate_key(spki)
    extensions = tbs_extensions(fields[index + 6 :])
    return CertificateData(
        name_from_element(fields[index + 4]),
        name_from_element(fields[index + 2]),
        read_integer(fields[index]) if fields[index].tag == TAG_INTEGER else 0,
        _decode_time(validity[0]),
        _decode_time(validity[1]),
        key,
        tuple(extensions),
        bytes(der),
        extensions,
        top[0].encoded,
        top[2].value[1:],  # BIT STRING: skip the unused-bits octet
        oid_string(top[1].children()[0]),
        spki.encoded,
    )


def _certificate_key(spki: Element) -> RSAPublicKey | None:
    """The RSA key in a ``SubjectPublicKeyInfo``; ``None`` for any other or a broken one."""
    parts = spki.children()
    key: RSAPublicKey | None = None
    if len(parts) == 2 and parts[1].tag == TAG_BIT_STRING:
        with contextlib.suppress(DERError):
            key = public_key_from_bitstring(parts[1])
    return key


_View = TypeVar("_View")


def certificates_in(data: bytes | str, parse: Callable[[bytes], _View]) -> list[_View]:
    """Every ``CERTIFICATE`` block in ``data``, in file order, decoded by ``parse``.

    A block that will not parse is skipped rather than fatal: proxy files
    routinely carry a CA certificate this reader has no opinion about, and
    losing the whole chain over one of them would be the wrong trade.

    ``parse`` is the certificate view to build; a client with a view of its
    own (gfal2's proxy rules) passes that, and so reads PEM through this one
    loop.
    """
    out: list[_View] = []
    for label, der in pem_blocks(data):
        if label != "CERTIFICATE":
            continue
        try:
            out.append(parse(der))
        except (DERError, ValueError):
            continue
    return out


def load_certificates(data: bytes | str) -> list[Certificate]:
    """Every ``CERTIFICATE`` block in ``data``, in file order; see :func:`certificates_in`."""
    return certificates_in(data, parse_certificate)


def split_der_certificates(data: bytes) -> list[CertificateData]:
    """Consecutive DER certificates with no framing between them, in order.

    Globus delegation and VOMS ACs carry chains this way: each certificate's
    own outer TLV header is what finds the next. Trailing bytes that are not
    a whole certificate raise :class:`~xrdsec.der.DERError`, which is how
    the GSI acceptor tells that more of a chain is still to come. (Until
    0.4.0 this was xgfalclient's, in its ``crypto.x509``.)
    """
    out: list[CertificateData] = []
    pos = 0
    while pos < len(data):
        # Only the outer TLV's extent is read here; certificate_data decodes
        # the certificate itself, once.
        _, end = parse(data, pos)
        out.append(certificate_data(data[pos:end]))
        pos = end
    return out


@dataclass(frozen=True, slots=True)
class ProxyCredential:
    """A loaded GSI proxy: the chain as PEM, its key, and what it says."""

    chain: tuple[Certificate, ...]
    #: An :class:`~xrdsec.rsa.RSAPrivateKey` for an RSA proxy - all
    #: GSI itself can use - or the ``cryptography`` key object for any other
    #: type (an EC proxy can still sign a delegated proxy). Typed loosely to
    #: keep the import one-way.
    key: object
    path: str = ""

    @property
    def certificate(self) -> Certificate:
        """The end-entity certificate — the proxy itself, first in the file."""
        return self.chain[0]

    @property
    def subject(self) -> Name:
        """The proxy's own subject, proxy ``CN`` included; see :attr:`identity`."""
        return self.certificate.subject

    @property
    def identity(self) -> str:
        """The user behind the proxy; see :func:`proxy_identity`."""
        return str(proxy_identity(self.chain))

    @property
    def expired(self) -> bool:
        """Whether *any* certificate in the chain has expired.

        Any, not just the first: a proxy cannot outlive its issuer, and a
        server that checks the chain would refuse it on the issuer's date.
        """
        return any(certificate.expired for certificate in self.chain)

    def remaining(self) -> float:
        """Seconds until the first certificate in the chain expires."""
        return min(certificate.remaining() for certificate in self.chain)

    def pem(self) -> bytes:
        """The chain as concatenated PEM, which is what GSI puts on the wire.

        The trust anchor is left out. Some tools write the CA into the proxy
        file beside the certificates it signed, and a server handed a chain
        that carries its own anchor refuses the login as inconsistent - it
        looks anchors up in its certificate directory by hash, so one arriving
        over the wire is neither needed nor believed. A file holding nothing
        but an anchor is sent as it is, so the server can say so itself.
        """
        chain = [link for link in self.chain if not link.is_anchor] or list(self.chain)
        return b"".join(certificate.pem() for certificate in chain)

    def to_pem(self, with_key: bool = True) -> bytes:
        """The credential as a proxy file holds it: certificate, key, then the chain.

        That order - the proxy, its unencrypted key, the certificates above
        it - is what ``voms-proxy-init`` and ``grid-proxy-init`` write and
        what every reader of ``/tmp/x509up_u<uid>`` (OpenSSL's
        ``load_cert_chain`` included) expects. RSA keys are written as
        PKCS#1 ``RSA PRIVATE KEY``, EC keys as SEC1 ``EC PRIVATE KEY``: the
        traditional forms older grid software still insists on. Trust
        anchors are left out, as :meth:`pem` leaves them out.
        ``with_key=False`` gives the public chain alone, in the same order.

        The result holds a private key in the clear: it belongs in a ``0600``
        file (:func:`xrdsec.proxies.write_proxy`) or a pipe, never
        in a log.
        """
        rest = [link for link in self.chain[1:] if not link.is_anchor]
        key = _private_key_pem(self.key) if with_key else b""
        return self.certificate.pem() + key + b"".join(link.pem() for link in rest)

    def __repr__(self) -> str:
        """Subject only: a repr ends up in logs and tracebacks, the key must not."""
        return f"ProxyCredential(subject={str(self.subject)!r}, key=<redacted>)"


def _private_key_pem(key: object) -> bytes:
    """``key`` as unencrypted traditional PEM (PKCS#1 for RSA, SEC1 for EC).

    Any other key ``cryptography`` holds is written as PKCS#8, the only form
    it has; nothing in this package makes such a proxy, but a loaded one is
    written back as it can be rather than refused.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    from .rsa import RSAPrivateKey, private_key_pem

    if isinstance(key, RSAPrivateKey):
        return private_key_pem(key)
    traditional = isinstance(key, _rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey)
    # ``ProxyCredential.key`` is typed loosely to keep the imports one-way;
    # whatever else it holds is a ``cryptography`` key, the only other kind loaded.
    library = cast("PrivateKeyTypes", key)
    return library.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL
        if traditional
        else serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def is_proxy_certificate(certificate: Certificate) -> bool:
    """Whether ``certificate`` is a proxy by the strict, Globus reading.

    It carries a ``ProxyCertInfo`` (RFC 3820's or the pre-RFC Globus one), or
    it is named as a GT2 proxy (:func:`legacy_proxy_kind`). Unlike
    :attr:`Certificate.is_proxy` this does not accept "any extra ``CN`` under
    the issuer", so a user certificate whose CA's name happens to prefix its
    own is not mistaken for a proxy.
    """
    if PROXY_CERT_INFO_OID in certificate.extensions or LEGACY_PROXY_OID in certificate.extensions:
        return True
    return legacy_proxy_kind(certificate.subject, certificate.issuer) is not None


def proxy_identity(chain: Sequence[Certificate]) -> Name:
    """The user behind a proxy chain: the subject of its end-entity certificate.

    When the leaf is recognisably a proxy (:func:`is_proxy_certificate`) and
    the end-entity certificate is in the chain - as every proxy file and
    every GSI login has it - that subject is the answer, exactly. Otherwise
    (a bare delegated certificate, or a leaf whose proxy extension was lost,
    which XrdCl's loose reading still treats as a proxy) the leaf's subject
    is stripped of its trailing proxy CNs: numeric ones (RFC 3820; XrdCrypto
    may write a negative number) and GT2's ``proxy`` and ``limited proxy``,
    as many as there are - the older rule, which xgfalclient's shared-core
    tests pin. ``voms-proxy-info``'s ``identity`` line,
    :attr:`ProxyCredential.identity` and
    :func:`~xrdsec.proxies.describe_proxy` all use this one rule.
    """
    if not chain:
        return Name(())
    if is_proxy_certificate(chain[0]):
        end_entity = next((c for c in chain if not is_proxy_certificate(c)), None)
        if end_entity is not None:
            return end_entity.subject
    return _stripped(chain[0].subject)


def _stripped(subject: Name) -> Name:
    """``subject`` without its trailing proxy CNs (see :func:`_proxy_common_name`)."""
    rdns = list(subject.rdns)
    while rdns and rdns[-1][0] == "CN" and _proxy_common_name(rdns[-1][1]):
        rdns.pop()
    return Name(tuple(rdns))


def _proxy_common_name(value: str) -> bool:
    """Whether a ``CN`` value is one a proxy appends: a (signed) number, or a GT2 name."""
    return value.removeprefix("-").isdigit() or value in _GT2_PROXY_NAMES


def read_credential_files(cert_path: str, key_path: str | None = None) -> tuple[bytes, bytes]:
    """The bytes of a certificate file and of the file holding its private key.

    ``key_path`` names a separate key file (``usercert.pem``/``userkey.pem``);
    left out, or the same file, the key is in the certificate file, as a
    proxy carries it - and the file is read once.

    Every credential loader goes through this and :func:`credential_key`:
    :func:`load_proxy` here, and a client's own loader whose certificate view
    differs.
    """
    with open(cert_path, "rb") as handle:
        cert_data = handle.read()
    if not key_path or key_path == cert_path:
        return cert_data, cert_data
    with open(key_path, "rb") as handle:
        return cert_data, handle.read()


def credential_key(data: bytes | str) -> object:
    """The private key in ``data``, as a credential holds it.

    An :class:`~xrdsec.rsa.RSAPrivateKey` when it is RSA and the
    ``cryptography`` key otherwise (an EC proxy can still sign a delegated
    proxy), so a caller that needs RSA (GSI) can say "the key is not RSA"
    rather than "the file is unreadable". Raises
    :class:`~xrdsec.der.DERError` when there is no usable key.
    """
    from .rsa import RSAPrivateKey, load_library_key

    key: object = load_library_key(data)
    if isinstance(key, _rsa.RSAPrivateKey):
        key = RSAPrivateKey.from_cryptography(key)
    return key


def load_proxy(path: str, key_path: str | None = None) -> ProxyCredential:
    """Load a combined proxy file: certificate, private key, issuer chain.

    ``key_path`` reads the key from a file of its own instead (see
    :func:`read_credential_files`); :func:`credential_key` says what type the
    key is.
    """
    data, key_data = read_credential_files(path, key_path)
    chain = load_certificates(data)
    if not chain:
        raise DERError(f"no certificate in {path}")
    return ProxyCredential(chain=tuple(chain), key=credential_key(key_data), path=path)


# ---------------------------------------------------------------------------
# Proxy introspection, as GSI and gfal2 define it
# ---------------------------------------------------------------------------


def proxy_policy(extensions: Mapping[str, tuple[bool, bytes]]) -> str | None:
    """The proxy policy language a certificate's ``ProxyCertInfo`` names.

    ``extensions`` maps an extension OID to ``(critical, value)``, as
    :class:`CertificateData` carries them. ``None`` is a certificate with no
    ``ProxyCertInfo`` - RFC 3820's or the draft-era Globus one - at all; an
    extension too garbled to name a policy is ``""``, still a proxy but one
    whose rights nobody can read.
    """
    for extension in (PROXY_CERT_INFO_OID, LEGACY_PROXY_OID):
        found = extensions.get(extension)
        if found is not None:
            return policy_language(found[1])
    return None


def policy_language(value: bytes) -> str:
    """The policy language OID inside a ``ProxyCertInfo``; ``""`` if unreadable.

    Both layouts end with the ``ProxyPolicy`` sequence, whose first member is
    the language: RFC 3820's (path length first) and the draft's.
    """
    try:
        info = parse_one(value).children()
        policy = info[-1].children()
        return oid_string(policy[0])
    except (DERError, IndexError):
        return ""


def legacy_proxy_kind(subject: Name, issuer: Name) -> str | None:
    """``"proxy"`` or ``"limited proxy"`` for a Globus GT2 proxy's name, else ``None``.

    A GT2 proxy is known by its name alone: its issuer's subject plus one
    ``CN=proxy`` (or ``CN=limited proxy``). This is the strict, Globus
    reading gfal2 uses; :attr:`Certificate.is_proxy` is XrdCl's looser one
    (any appended ``CN``), which also accepts an RFC proxy whose extension
    has been lost. Whether the certificate also carries a proxy extension
    is the caller's question - see :func:`proxy_policy`.
    """
    if not subject.rdns:
        return None
    kind, value = subject.rdns[-1]
    if kind != "CN" or value not in _GT2_PROXY_NAMES:
        return None
    return value if subject.rdns[:-1] == issuer.rdns else None


def signed_by(tbs: bytes, signature_oid: str, signature: bytes, key: RSAPublicKey | bytes) -> bool:
    """Whether ``key`` made ``signature`` over ``tbs`` with ``signature_oid``.

    The decoded form of :func:`verify_signed`, for a certificate view that has
    already split itself up. ``key`` is an :class:`RSAPublicKey` or any
    ``SubjectPublicKeyInfo`` DER (EC and EdDSA included); an algorithm this
    client does not accept is a signature that does not verify.
    """
    spki = key.der() if isinstance(key, RSAPublicKey) else key
    try:
        return verify_signature(spki, signature_oid, None, signature, tbs)
    except SignatureAlgorithmError:
        return False


# ---------------------------------------------------------------------------
# The raw structure, for signing and verifying
# ---------------------------------------------------------------------------

#: ``sha*WithRSAEncryption`` - the hash each PKCS#1 signature OID names.
_SIGNATURE_DIGESTS = RSA_PKCS1_DIGESTS


@dataclass(frozen=True, slots=True)
class Extension:
    """One certificate extension: what it is, and its bytes as written."""

    oid: str
    critical: bool
    value: bytes
    der: bytes = field(default=b"", repr=False)


def decode_name(der: bytes) -> Name:
    """A DER ``Name`` as a :class:`Name`."""
    return name_from_element(parse_one(der))


# The string types OpenSSL folds to lower-case UTF-8 before hashing a name
# (``ASN1_MASK_CANON``), with how each one's bytes read as text.
_CANON_STRINGS = {
    0x0C: "utf-8",  # UTF8String
    0x13: "latin-1",  # PrintableString
    0x14: "latin-1",  # T61String: OpenSSL reads it as Latin-1
    0x16: "latin-1",  # IA5String
    0x1A: "latin-1",  # VisibleString
    0x1C: "utf-32-be",  # UniversalString
    0x1E: "utf-16-be",  # BMPString
}
_ASCII_SPACE = b" \t\n\v\f\r"


def _canonical_value(tag: int, value: bytes) -> bytes:
    """One attribute value as OpenSSL's ``asn1_string_canon`` leaves it.

    Leading and trailing space goes, each run of inner space becomes one, and
    ASCII letters are lowered; bytes above 0x7F pass through untouched.
    """
    encoding = _CANON_STRINGS.get(tag)
    if encoding is None:
        return encode(tag, value)
    text = value.decode(encoding, "replace").encode("utf-8").strip(_ASCII_SPACE)
    out = bytearray()
    spaced = False
    for byte in text:
        if byte < 0x80 and byte in _ASCII_SPACE:
            if not spaced:
                out.append(0x20)
            spaced = True
            continue
        spaced = False
        out.append(byte + 0x20 if 0x41 <= byte <= 0x5A else byte)
    return encode(0x0C, bytes(out))


def name_hashes(name_der: bytes) -> tuple[str, str]:
    """``openssl x509 -subject_hash`` and ``-subject_hash_old`` of a DER ``Name``.

    These are the file names a CA directory knows a certificate authority by
    (``<hash>.0``), and what GSI uses to say which authority stands behind a
    certificate: the new hash is SHA-1 over the canonical form of the name,
    the old one MD5 over its DER, each as the first four bytes read
    little-endian.
    """
    import hashlib

    # OpenSSL's X509_NAME canonical encoding: each RDN's attributes with
    # canonicalised values, the SET re-encoded with sorted members, and
    # the RDNs concatenated *without* the outer SEQUENCE header.
    canonical = bytearray()
    for rdn in raw_children(name_der):
        entries = []
        for attribute in raw_children(rdn):
            oid, value = parse(attribute)[0].children()
            entries.append(
                sequence(encode(oid.tag, oid.value), _canonical_value(value.tag, value.value))
            )
        canonical += encode(TAG_SET, b"".join(sorted(entries)))

    def short(digest: bytes) -> str:
        """The first four digest bytes, little-endian, as eight hex digits."""
        return f"{int.from_bytes(digest[:4], 'little'):08x}"

    return short(hashlib.sha1(bytes(canonical)).digest()), short(hashlib.md5(name_der).digest())


def issuer_hashes(certificate: Certificate) -> tuple[str, str]:
    """:func:`name_hashes` of the authority that signed ``certificate``."""
    return name_hashes(certificate_fields(certificate.der)["issuer"])


def certificate_fields(der: bytes) -> dict[str, bytes]:
    """The parts of a certificate a signer copies, each exactly as written.

    Keys: ``issuer``, ``subject``, ``spki`` and - when present -
    ``extensions`` (the inner ``SEQUENCE OF Extension``).
    """
    tbs = raw_children(der)[0]
    fields = raw_children(tbs)
    index = 1 if fields and fields[0][0] == 0xA0 else 0
    if len(fields) < index + 6:
        raise DERError("certificate body is missing required fields")
    out = {
        "issuer": fields[index + 2],
        "subject": fields[index + 4],
        "spki": fields[index + 5],
    }
    for extra in fields[index + 6 :]:
        if extra[0] == 0xA3:
            out["extensions"] = raw_children(extra)[0]
    return out


def extensions_of(der: bytes) -> list[Extension]:
    """Every extension of the certificate in ``der``, in order."""
    block = certificate_fields(der).get("extensions")
    return [parse_extension(raw) for raw in raw_children(block)] if block else []


def parse_extension(raw: bytes) -> Extension:
    """One DER ``Extension``: ``SEQUENCE { OID, BOOLEAN DEFAULT FALSE, OCTET STRING }``."""
    parts = parse(raw)[0].children()
    if len(parts) not in (2, 3) or parts[0].tag != TAG_OID or parts[-1].tag != TAG_OCTET_STRING:
        raise DERError("malformed certificate extension")
    critical = len(parts) == 3 and parts[1].tag == TAG_BOOLEAN and parts[1].value != b"\x00"
    return Extension(oid_string(parts[0]), critical, parts[-1].value, raw)


def signature_digest(algorithm: str) -> str:
    """The hash behind a ``sha*WithRSAEncryption`` OID; refuses anything else.

    Only the RSA PKCS#1 family maps to a bare hash name; what
    :func:`verify_signed` accepts is wider (see
    :mod:`xrdsec.signatures`).
    """
    digest = _SIGNATURE_DIGESTS.get(algorithm)
    if digest is None:
        raise DERError(f"unsupported signature algorithm {algorithm}")
    return digest


def verify_signed(der: bytes, key: RSAPublicKey | bytes) -> bool:
    """Whether ``key`` signed the certificate or certificate request in ``der``.

    Both are ``SEQUENCE { body, AlgorithmIdentifier, BIT STRING }`` and both
    are signed over the body exactly as written, so one function serves both.
    ``key`` is an :class:`RSAPublicKey` or - for any algorithm, EC and EdDSA
    included - the signer's ``SubjectPublicKeyInfo`` DER. An algorithm this
    client does not accept is a signature that does not verify.
    """
    try:
        body, algorithm, signature = raw_children(der)[:3]
        identifier = parse_one(algorithm).children()
        kind = oid_string(identifier[0])
        bits = parse(signature)[0]
    except (DERError, ValueError, IndexError):
        return False
    if bits.tag != TAG_BIT_STRING or bits.value[:1] != b"\x00" or len(identifier) > 2:
        return False
    params = identifier[1].encoded if len(identifier) == 2 else None
    spki = key.der() if isinstance(key, RSAPublicKey) else key
    try:
        return verify_signature(spki, kind, params, bits.value[1:], body)
    except SignatureAlgorithmError:
        return False


class _Encoded(Protocol):
    """Anything that carries a certificate's DER - both clients' certificate views do."""

    @property
    def der(self) -> bytes:
        """The certificate exactly as encoded."""


def verify_issued(certificate: _Encoded, issuer: _Encoded) -> bool:
    """Whether ``issuer``'s key - RSA, EC or EdDSA - signed ``certificate``.

    Only the signature: whether the names chain, and whether ``issuer`` may
    issue at all, are the caller's questions (see
    :mod:`xrdsec.trust`), because the name comparison a grid PKI
    needs is OpenSSL's canonical one, not byte equality.
    """
    try:
        spki = certificate_fields(issuer.der)["spki"]
    except (DERError, ValueError, IndexError):
        return False
    return verify_signed(certificate.der, spki)


# ---------------------------------------------------------------------------
# Building blocks for certificates and requests
# ---------------------------------------------------------------------------

#: RFC 5280 extension OIDs a builder needs by number.
KEY_USAGE_OID = "2.5.29.15"
BASIC_CONSTRAINTS_OID = "2.5.29.19"
SUBJECT_ALT_NAME_OID = "2.5.29.17"
SUBJECT_KEY_ID_OID = "2.5.29.14"
AUTHORITY_KEY_ID_OID = "2.5.29.35"

#: ``sha*WithRSAEncryption`` (RFC 4055 / PKCS #1), for the RSA-only
#: :func:`signature_algorithm`; certificate *issuing* goes through
#: ``cryptography``, which picks the algorithm from the signer's key itself.
_SIGNATURE_OIDS = {
    "sha1": "1.2.840.113549.1.1.5",
    "sha256": "1.2.840.113549.1.1.11",
    "sha384": "1.2.840.113549.1.1.12",
    "sha512": "1.2.840.113549.1.1.13",
}
_RSA_OID = "1.2.840.113549.1.1.1"


def extension(extension_oid: str, value: bytes, critical: bool = False) -> bytes:
    """One RFC 5280 ``Extension``: ``SEQUENCE { extnID, critical, extnValue }``.

    ``value`` is the DER of the extension's own structure; it is wrapped in
    the OCTET STRING ``extnValue`` requires. A non-critical extension omits
    the BOOLEAN altogether, because DER forbids encoding a DEFAULT value
    (``critical`` defaults to FALSE) and strict parsers reject it.
    """
    parts = [oid(extension_oid)]
    if critical:
        parts.append(tlv(TAG_BOOLEAN, b"\xff"))
    parts.append(tlv(TAG_OCTET_STRING, value))
    return sequence(*parts)


def key_usage(*bits: int) -> bytes:
    """A KeyUsage BIT STRING from bit numbers (0 = digitalSignature).

    Bit 0 is the most significant bit of the first content octet (X.690
    numbers named bits from the left). Only bits 0-7 are supported, which
    covers every usage a proxy or test CA needs (digitalSignature=0,
    keyEncipherment=2, keyCertSign=5, cRLSign=6). DER drops trailing zero
    bits, which the "unused bits" octet counts.
    """
    if not bits or not all(0 <= bit <= 7 for bit in bits):
        raise ValueError("key usage bits must be between 0 and 7")
    value = 0
    for bit in bits:
        value |= 1 << (7 - bit)
    return tlv(TAG_BIT_STRING, bytes([7 - max(bits), value]))


def public_key_info(key: RSAPublicKey) -> bytes:
    """``SubjectPublicKeyInfo`` for an RSA key, with RFC 3279's explicit ``NULL``."""
    return sequence(
        sequence(oid(_RSA_OID), null()),
        bit_string(sequence(integer(key.n), integer(key.e))),
    )


def signature_algorithm(digest: str) -> bytes:
    """The ``sha*WithRSAEncryption`` ``AlgorithmIdentifier`` for ``digest``."""
    return sequence(oid(_SIGNATURE_OIDS[digest]), null())
