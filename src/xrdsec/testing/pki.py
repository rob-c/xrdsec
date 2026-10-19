"""A throwaway grid PKI, minted in process: CA, host, user, proxies and CRLs.

This is the one test PKI for every client on the stack - xrdsec's own suite,
xrdclient's, xgfalclient's and xrdarc's. Every
certificate is made at run time with today's validity, so nothing in any
repository expires. The CA directory is laid out the way ``X509_CERT_DIR``
is - ``<subject hash>.0`` files, with the hash computed exactly as OpenSSL
computes it - so a context built with ``capath=`` trusts it just as it would
``/etc/grid-security/certificates``::

    >>> pki = create_pki(tmp_path)
    >>> server = pki.server_context()          # host cert, asks for and checks a client
    >>> os.environ.update(pki.environment())   # X509_USER_PROXY, X509_CERT_DIR
    >>> pki.proxy("limited", lifetime=600)     # another proxy file, beside the PKI

What lives here, from the bottom up:

* :func:`test_key` / :func:`test_key_pem` - eight *fixed* RSA keys
  (:mod:`._keys` says why they are frozen and which slot is for what), as
  ``cryptography`` keys and as PKCS#1 PEM;
* :func:`subject_hash` - OpenSSL's ``X509_NAME_hash``, the CA file name;
* :func:`ca_certificate`, :func:`host_certificate`, :func:`user_certificate`
  and :func:`proxy_certificate` - the four builders, each returning DER, for
  a test that needs one certificate rather than a whole PKI;
* :class:`BasePKI` / :class:`PKI` - the files on disk (CA directory with an
  IGTF signing policy, host and user credentials, a default proxy, CRLs on
  request) and TLS contexts over them.

:class:`BasePKI` is generic in how it *presents* what it minted: :class:`PKI`
hands out ``cryptography`` certificates and keys and loads proxies with
:func:`xrdsec.x509.load_proxy`, while a client with types of its own
(xgfalclient's ``Certificate``/``Credential``) subclasses it with three hooks
- and may rename the entities through the ``*_SUBJECT`` class attributes. The
minting, the file layout and the contexts exist once, here.

Certificates are signed with :func:`xrdsec.delegation.issue_certificate`
(``cryptography``'s builder underneath), so a proxy minted here is laid out
the way :mod:`xrdsec.proxies` lays one out; the Globus proxy rules
(lifetime capped by the issuer chain, limited begets limited, a GT2 issuer
begets a GT2 child) are restated in :func:`proxy_certificate` rather than
borrowed from the issuer, so a bug in the issuer does not quietly
become a bug in the fixture that tests it.

Stability: this module is public test API, versioned with the package. Keys
are written ``0600`` because globus and voms tools refuse a readable private
key or proxy.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import os
import ssl
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Generic, Protocol, Self, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..delegation import issue_certificate
from ..der import (
    boolean,
    oid,
    parse_one,
    printable_string,
    sequence,
    set_of,
    tlv,
)
from ..x509 import (
    INHERIT_ALL_OID,
    LIMITED_PROXY_OID,
    PROXY_CERT_INFO_OID,
    CertificateData,
    ProxyCredential,
    certificate_data,
    encode_name,
    legacy_proxy_kind,
    load_proxy,
    name_hashes,
    pem_encode,
    proxy_policy,
)
from ._keys import KEYS

__all__ = [
    "ALLOW_PROXY_CERTS",
    "BACKDATE",
    "DAY",
    "DEFAULT_HOSTS",
    "KEYS",
    "PKI",
    "BasePKI",
    "HoldsChain",
    "PrivateKey",
    "Rdns",
    "Signer",
    "ca_certificate",
    "create_pki",
    "host_certificate",
    "key_pem",
    "proxy_certificate",
    "subject_hash",
    "test_key",
    "test_key_pem",
    "user_certificate",
]

#: Seconds in a day, for certificate lifetimes.
DAY = 86400.0
#: OpenSSL's ``X509_V_FLAG_ALLOW_PROXY_CERTS``, as a plain ``int``.
ALLOW_PROXY_CERTS = int(ssl.VERIFY_ALLOW_PROXY_CERTS)
#: How far back a proxy's ``notBefore`` is set, as Globus does, so a peer
#: whose clock runs a little behind does not see a not-yet-valid proxy.
BACKDATE = 300.0
#: The names a host certificate covers by default: every way a test dials
#: a loopback server. Python's ``ssl`` matches only ``subjectAltName``.
DEFAULT_HOSTS = ("localhost", "127.0.0.1", "::1")

#: A distinguished name as ``(short name, value)`` pairs, most significant
#: first - ``(("DC", "org"), ("CN", "Jane"))`` - as
#: :func:`xrdsec.x509.encode_name` takes it.
Rdns = tuple[tuple[str, str], ...]
#: The private keys the PKI signs with: RSA (the frozen test keys) or EC.
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

# X.509 extension OIDs (RFC 5280 section 4.2.1).
_BASIC_CONSTRAINTS = "2.5.29.19"
_KEY_USAGE = "2.5.29.15"
_SUBJECT_ALT_NAME = "2.5.29.17"
_SUBJECT_KEY_ID = "2.5.29.14"
_AUTHORITY_KEY_ID = "2.5.29.35"
_COMMON_NAME = "2.5.4.3"

# Parsed keys by slot. Keys are immutable, so sharing them between tests and
# threads is safe; the lock only guarantees ``test_key(n) is test_key(n)``
# even when two xdist-free threads race to parse a slot first.
_KEY_CACHE: dict[int, rsa.RSAPrivateKey] = {}
_KEY_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def test_key(slot: int) -> rsa.RSAPrivateKey:
    """Frozen key number ``slot`` (0-7) as a ``cryptography`` key, parsed once.

    The same object comes back for the same slot for the life of the
    process. ``IndexError`` past the last slot, as for any sequence; a test
    that needs a key nobody else uses should add a slot to :mod:`._keys`
    rather than generate one, so the suite stays fast and repeatable.
    """
    with _KEY_LOCK:
        found = _KEY_CACHE.get(slot)
        if found is None:
            loaded = serialization.load_pem_private_key(KEYS[slot].encode("ascii"), None)
            assert isinstance(loaded, rsa.RSAPrivateKey)  # every slot is RSA by construction
            found = _KEY_CACHE[slot] = loaded
        return found


def test_key_pem(slot: int) -> bytes:
    """Frozen key ``slot`` as PKCS#1 ``RSA PRIVATE KEY`` PEM, the form a proxy file carries.

    The committed text itself, so it is byte-for-byte stable; use it where a
    file or an API wants PEM rather than a key object.
    """
    return KEYS[slot].encode("ascii")


# Helpers, not tests: stop pytest collecting them from test modules that import them.
test_key.__dict__["__test__"] = False
test_key_pem.__dict__["__test__"] = False


def key_pem(key: PrivateKey) -> bytes:
    """``key`` as unencrypted "traditional" PEM: ``RSA PRIVATE KEY`` or ``EC PRIVATE KEY``.

    The traditional (PKCS#1 / SEC 1) forms rather than PKCS#8 because that is
    what ``grid-proxy-init`` and ``voms-proxy-init`` write into a proxy file,
    and some older readers accept nothing else.
    """
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _spki(key: PrivateKey) -> bytes:
    """The ``SubjectPublicKeyInfo`` DER of ``key``'s public half."""
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


# ---------------------------------------------------------------------------
# Names and extensions
# ---------------------------------------------------------------------------


def subject_hash(name_der: bytes) -> str:
    """OpenSSL's ``X509_NAME_hash`` of a DER name: the file name in a CA directory.

    The "new" (OpenSSL >= 1.0) hash that ``c_rehash`` and ``openssl x509
    -subject_hash`` print, which is what lets ``capath=`` find the CA. It is
    the library's own :func:`~xrdsec.x509.name_hashes`; the test
    suites pin it against the ``openssl`` binary where one is installed.
    """
    return name_hashes(name_der)[0]


def _extension(extension_oid: str, value: bytes, *, critical: bool = False) -> bytes:
    """One DER ``Extension``; the criticality flag only when set (DER omits a DEFAULT)."""
    flag = boolean(True) if critical else b""
    return sequence(oid(extension_oid), flag, tlv(0x04, value))


def _key_usage(*bits: int) -> bytes:
    """A critical ``keyUsage`` extension with the named bits (0 = digitalSignature).

    Bit 0 is the most significant bit of the first content octet (X.690);
    DER drops trailing zero bits, which the leading "unused bits" octet
    counts. Only bits 0-7 are needed by anything minted here.
    """
    value = 0
    for bit in bits:
        value |= 1 << (7 - bit)
    return _extension(_KEY_USAGE, tlv(0x03, bytes([7 - max(bits), value])), critical=True)


def _san(hosts: Sequence[str]) -> bytes:
    """A ``subjectAltName``: ``iPAddress`` (``[7]``) for literals, else ``dNSName`` (``[2]``).

    Python's ``ssl`` matches a host name only against these entries, never
    the CN, so every name a test connects to must be listed.
    """
    names = []
    for host in hosts:
        try:
            names.append(tlv(0x87, ipaddress.ip_address(host).packed))
        except ValueError:
            names.append(tlv(0x82, host.encode("ascii")))
    return _extension(_SUBJECT_ALT_NAME, sequence(*names))


def _key_id(key: PrivateKey) -> bytes:
    """RFC 5280 method 1: the SHA-1 of the subjectPublicKey BIT STRING's contents."""
    bits = parse_one(_spki(key)).children()[1].value
    return hashlib.sha1(bits[1:]).digest()  # [1:]: past the unused-bits octet


def _key_ids(subject: PrivateKey, issuer: PrivateKey) -> list[bytes]:
    """Subject and authority key identifiers, which OpenSSL 3's chain building wants."""
    return [
        _extension(_SUBJECT_KEY_ID, tlv(0x04, _key_id(subject))),
        _extension(_AUTHORITY_KEY_ID, sequence(tlv(0x80, _key_id(issuer)))),
    ]


def _with_cn(name_der: bytes, common_name: str) -> bytes:
    """``name_der`` with one more RDN, ``CN=<common_name>`` (RFC 3820 section 3.4).

    The issuer's RDNs are copied as encoded, byte for byte: a validator
    compares the proxy's subject prefix with its issuer's name, and a
    re-encoding that changed a string type would break the match. The new
    CN is a PrintableString, as Globus writes it.
    """
    rdns = parse_one(name_der).children()
    extra = set_of(sequence(oid(_COMMON_NAME), printable_string(common_name)))
    return sequence(*(rdn.encoded for rdn in rdns), extra)


# ---------------------------------------------------------------------------
# Certificate builders
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Signer:
    """A certificate chain (DER, leaf first) and the private key of its leaf.

    What every builder below signs *with*: the CA for host and user
    certificates, the user (or a proxy) for proxies. ``chain`` beyond the
    leaf matters only for proxies, whose lifetime it caps and which a proxy
    file carries after the key.
    """

    chain: tuple[bytes, ...]
    key: PrivateKey

    @property
    def der(self) -> bytes:
        """The leaf certificate: the one whose key signs."""
        return self.chain[0]

    @property
    def leaf(self) -> CertificateData:
        """The leaf, decoded by the library."""
        return certificate_data(self.der)


def ca_certificate(rdns: Rdns, key: PrivateKey, *, lifetime: float = 7 * DAY) -> bytes:
    """A self-signed grid CA certificate (DER), valid from an hour ago for ``lifetime``.

    Critical ``basicConstraints`` CA and ``keyCertSign``/``cRLSign`` usage,
    as every IGTF CA carries, plus key identifiers.
    """
    name, now = encode_name(rdns), time.time()
    return issue_certificate(
        subject=name,
        issuer=name,
        public_key=_spki(key),
        signer=key,
        not_before=now - 3600,
        not_after=now + lifetime,
        extensions=[
            _extension(_BASIC_CONSTRAINTS, sequence(boolean(True)), critical=True),
            _key_usage(5, 6),
            *_key_ids(key, key),
        ],
    )


def _end_entity(
    rdns: Rdns, key: PrivateKey, ca: Signer, extensions: list[bytes], lifetime: float
) -> bytes:
    """An end-entity certificate for ``key`` signed by ``ca``; the host and user builders' core.

    ``digitalSignature``/``keyEncipherment`` usage (what TLS client and
    server authentication both need with RSA) and key identifiers are
    added to ``extensions``. The certificate never outlives its CA.
    """
    now = time.time()
    return issue_certificate(
        subject=encode_name(rdns),
        issuer=ca.leaf.subject.encoded(),
        public_key=_spki(key),
        signer=ca.key,
        not_before=now - 3600,
        not_after=min(now + lifetime, ca.leaf.not_after),
        extensions=[_key_usage(0, 2), *extensions, *_key_ids(key, ca.key)],
    )


def host_certificate(
    rdns: Rdns,
    key: PrivateKey,
    ca: Signer,
    *,
    hosts: Sequence[str] = DEFAULT_HOSTS,
    lifetime: float = 7 * DAY,
) -> bytes:
    """A host (service) certificate (DER) whose ``subjectAltName`` covers ``hosts``."""
    return _end_entity(rdns, key, ca, [_san(hosts)], lifetime)


def user_certificate(
    rdns: Rdns, key: PrivateKey, ca: Signer, *, lifetime: float = 7 * DAY
) -> bytes:
    """A user certificate (DER): what ``usercert.pem`` holds and what proxies are made from."""
    return _end_entity(rdns, key, ca, [], lifetime)


def _is_limited(leaf: CertificateData, legacy: bool) -> bool:
    """Whether ``leaf`` is a limited proxy, by either generation's marking."""
    if legacy:
        return leaf.subject.cn == "limited proxy"
    return proxy_policy(leaf.extension_values) == LIMITED_PROXY_OID


def _proxy_shape(issuer: Signer, kind: str, serial: int) -> tuple[bytes, list[bytes]]:
    """The subject and extensions of a proxy of ``issuer``: Globus's rules.

    * ``legacy`` asks for a pre-RFC (GT2) proxy: ``CN=proxy``, no extensions;
    * a GT2 issuer always gets a GT2 child, whatever ``kind`` says, because
      Globus keeps a chain in one proxy style;
    * otherwise an RFC 3820 proxy named ``CN=<serial>`` with a critical
      ``ProxyCertInfo``, limited if asked or if the issuer is (a limited
      proxy only begets limited ones), and the critical
      ``digitalSignature``/``keyEncipherment`` usage Globus gives every proxy.
    """
    leaf = issuer.leaf
    if kind == "legacy":
        return _with_cn(leaf.subject.encoded(), "proxy"), []
    legacy = proxy_policy(leaf.extension_values) is None and (
        legacy_proxy_kind(leaf.subject, leaf.issuer) is not None
    )
    limited = kind == "limited" or _is_limited(leaf, legacy)
    usage = _key_usage(0, 2)
    if legacy:
        name = "limited proxy" if limited else "proxy"
        return _with_cn(leaf.subject.encoded(), name), [usage]
    policy = sequence(sequence(oid(LIMITED_PROXY_OID if limited else INHERIT_ALL_OID)))
    info = _extension(PROXY_CERT_INFO_OID, policy, critical=True)
    return _with_cn(leaf.subject.encoded(), str(serial)), [usage, info]


def proxy_certificate(
    key: PrivateKey,
    issuer: Signer,
    *,
    kind: str = "rfc",
    lifetime: float = 12 * 3600,
    extensions: Sequence[bytes] = (),
) -> bytes:
    """A proxy certificate (DER) for ``key``, signed by ``issuer``.

    ``kind`` is ``rfc`` (RFC 3820, inherit-all policy), ``limited`` (Globus's
    limited-proxy policy) or ``legacy`` (pre-RFC GT2); see
    :func:`_proxy_shape` for how the issuer's own kind wins. The lifetime is
    cut to the issuer chain's - a proxy cannot outlive anything it was made
    from - and the start is back-dated :data:`BACKDATE` seconds against
    clock skew. The serial is the first four bytes of the SHA-1 of the new
    key, as ``globus_gsi_proxy_sign_req`` numbers (and names) a proxy.
    ``extensions`` (DER ``Extension`` s) are appended - a VOMS AC extension,
    say (:func:`xrdsec.testing.voms.ac_extension`). ``ValueError`` for an
    unknown ``kind``.
    """
    if kind not in ("rfc", "limited", "legacy"):
        raise ValueError(f"unknown proxy kind {kind!r}: rfc, limited or legacy")
    now, spki = time.time(), _spki(key)
    serial = int.from_bytes(hashlib.sha1(spki).digest()[:4], "big")
    subject, shape = _proxy_shape(issuer, kind, serial)
    expires = min(certificate_data(link).not_after for link in issuer.chain)
    return issue_certificate(
        subject=subject,
        issuer=issuer.leaf.subject.encoded(),
        public_key=spki,
        signer=issuer.key,
        not_before=now - BACKDATE,
        not_after=min(expires, now + lifetime),
        serial=serial,
        extensions=[*shape, *extensions],
    )


def _pem(der: bytes) -> bytes:
    """One certificate as a PEM block."""
    return pem_encode("CERTIFICATE", der)


def _write(path: Path, data: bytes, mode: int = 0o644) -> Path:
    """Write ``data`` and set ``mode`` (after writing, whatever the umask); ``path``."""
    path.write_bytes(data)
    os.chmod(path, mode)
    return path


# ---------------------------------------------------------------------------
# The PKI on disk
# ---------------------------------------------------------------------------


class _Link(Protocol):
    """Anything that carries its certificate's DER (both clients' certificate views do)."""

    @property
    def der(self) -> bytes:
        """The certificate's DER."""
        ...


class HoldsChain(Protocol):
    """A loaded credential of either client: a chain of certificates and a key.

    xrdsec's :class:`~xrdsec.x509.ProxyCredential` and
    xgfalclient's ``Credential`` both qualify, so either can be handed to
    :meth:`BasePKI.proxy` as the issuer of a proxy-of-a-proxy.
    """

    @property
    def chain(self) -> Sequence[_Link]:
        """The certificates, leaf first."""
        ...

    @property
    def key(self) -> object:
        """The leaf's private key: a ``cryptography`` key or the clients' RSA view."""
        ...


def _as_signer(issuer: Signer | HoldsChain) -> Signer:
    """``issuer`` as a :class:`Signer`, converting a client's loaded credential.

    The clients' RSA key view converts with its ``to_cryptography()``; a
    key of any other type is refused (``TypeError``) here rather than deep
    inside the certificate builder.
    """
    if isinstance(issuer, Signer):
        return issuer
    key = issuer.key
    convert = getattr(key, "to_cryptography", None)
    if convert is not None:
        key = convert()
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise TypeError(f"cannot sign a proxy with a {type(key).__name__}")
    return Signer(tuple(link.der for link in issuer.chain), key)


#: How a :class:`BasePKI` subclass presents a certificate, a key and a loaded credential.
CertT = TypeVar("CertT")
KeyT = TypeVar("KeyT")
CredT = TypeVar("CredT")


class BasePKI(Generic[CertT, KeyT, CredT]):
    """Files and objects for one throwaway grid PKI rooted at ``directory``.

    Made by :meth:`create` (or :func:`create_pki`); constructing one writes
    the files. Layout under ``directory``: ``ca.pem``, ``certificates/``
    (the CA directory: ``<hash>.0`` and ``<hash>.signing_policy``),
    ``hostcert.pem``/``hostkey.pem``, ``usercert.pem``/``userkey.pem`` (the
    grid-security names) and ``x509up_rfc`` - the default proxy, an RFC 3820
    proxy of the user signed with key slot 3. The ``*_path`` attributes name
    those files.

    Subclasses choose the *view*: :meth:`_certificate_view`,
    :meth:`_key_view` and :meth:`_load_credential` turn the minted DER, the
    ``cryptography`` keys and a file on disk into whatever types their test
    suite works with, and the ``*_SUBJECT`` class attributes name the
    entities. Everything else - minting, layout, contexts, CRLs - is shared.
    """

    #: The CA's subject.
    CA_SUBJECT: ClassVar[Rdns] = (("DC", "org"), ("DC", "xrdsec"), ("CN", "xrdsec Test CA"))
    #: The user's subject: what a server sees as the client's identity.
    USER_SUBJECT: ClassVar[Rdns] = (
        ("DC", "org"),
        ("DC", "xrdsec"),
        ("OU", "People"),
        ("CN", "Test User"),
    )
    #: The RDNs a host certificate's subject starts with; ``CN=<host_cn>`` follows.
    HOST_PREFIX: ClassVar[Rdns] = (("DC", "org"), ("DC", "xrdsec"))

    def __init__(self, directory: Path, ca: Signer, host: Signer, user: Signer) -> None:
        """Write the CA directory, host and user credentials and the default proxy."""
        self.directory = directory
        self._ca, self._host, self._user = ca, host, user
        self.ca: CertT = self._certificate_view(ca.der)
        self.host: CertT = self._certificate_view(host.der)
        self.user: CertT = self._certificate_view(user.der)
        self.ca_key: KeyT = self._key_view(ca.key)
        self.host_key: KeyT = self._key_view(host.key)
        self.user_key: KeyT = self._key_view(user.key)
        self.ca_dir = directory / "certificates"
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        #: The CA's subject hash: its file name (``<hash>.0``) in :attr:`ca_dir`.
        self.ca_hash = subject_hash(ca.leaf.subject.encoded())
        self.ca_file = _write(directory / "ca.pem", _pem(ca.der))
        _write(self.ca_dir / f"{self.ca_hash}.0", _pem(ca.der))
        # Globus refuses a CA without an IGTF signing policy beside it.
        _write(self.ca_dir / f"{self.ca_hash}.signing_policy", self.signing_policy())
        self.host_cert_path = _write(directory / "hostcert.pem", _pem(host.der))
        self.host_key_path = _write(directory / "hostkey.pem", key_pem(host.key), 0o600)
        self.user_cert_path = _write(directory / "usercert.pem", _pem(user.der))
        self.user_key_path = _write(directory / "userkey.pem", key_pem(user.key), 0o600)
        self.proxy_path = self.proxy()

    @classmethod
    def create(
        cls,
        directory: Path | str,
        *,
        hosts: Sequence[str] = DEFAULT_HOSTS,
        host_cn: str = "host/localhost",
        lifetime: float = 7 * DAY,
        key_slots: tuple[int, int, int] = (0, 1, 2),
    ) -> Self:
        """Mint a CA, a host certificate for ``hosts`` and a user certificate, and write them.

        ``key_slots`` picks the frozen keys for the CA, host and user; a
        second, distinct PKI needs different ones, or its CA would be the
        same CA. The host's subject is :attr:`HOST_PREFIX` plus
        ``CN=<host_cn>`` (globus's ``host/<name>`` form by default).
        ``directory`` is created if missing.
        """
        base = Path(directory)
        base.mkdir(parents=True, exist_ok=True)
        ca_key, host_key, user_key = (test_key(slot) for slot in key_slots)
        ca = Signer((ca_certificate(cls.CA_SUBJECT, ca_key, lifetime=lifetime),), ca_key)
        host_rdns = (*cls.HOST_PREFIX, ("CN", host_cn))
        host = host_certificate(host_rdns, host_key, ca, hosts=hosts, lifetime=lifetime)
        user = user_certificate(cls.USER_SUBJECT, user_key, ca, lifetime=lifetime)
        return cls(base, ca, Signer((host, ca.der), host_key), Signer((user, ca.der), user_key))

    # -- views (what a subclass overrides) ------------------------------------------------

    def _certificate_view(self, der: bytes) -> CertT:
        """Present one minted certificate (DER) as this suite's certificate type."""
        raise NotImplementedError

    def _key_view(self, key: PrivateKey) -> KeyT:
        """Present one minted private key as this suite's key type."""
        raise NotImplementedError

    def _load_credential(self, cert_path: str, key_path: str | None) -> CredT:
        """Load a credential file (or certificate and key pair) as this suite's credential type.

        Loading goes through a client's own credential loader, so it also
        checks that the file is one a client accepts.
        """
        raise NotImplementedError

    # -- the raw material -----------------------------------------------------------------

    @property
    def ca_signer(self) -> Signer:
        """The CA as a :class:`Signer`, for minting further certificates under it."""
        return self._ca

    @property
    def host_signer(self) -> Signer:
        """The host credential as a :class:`Signer` (chain: host, CA)."""
        return self._host

    @property
    def user_signer(self) -> Signer:
        """The user credential as a :class:`Signer` (chain: user, CA): what signs proxies."""
        return self._user

    def signing_policy(self) -> bytes:
        """The CA's ``.signing_policy``: it may sign anything under its own DC prefix."""
        subject = self._ca.leaf.subject
        prefix = "".join(f"/{key}={value}" for key, value in subject.rdns if key == "DC")
        return (
            f"access_id_CA X509 '{subject}'\n"
            "pos_rights globus CA:sign\n"
            f"cond_subjects globus '\"{prefix}/*\"'\n"
        ).encode()

    # -- credentials ----------------------------------------------------------------------

    @property
    def user_credential(self) -> CredT:
        """The user's end-entity credential (``usercert.pem`` and ``userkey.pem``), loaded."""
        return self._load_credential(str(self.user_cert_path), str(self.user_key_path))

    def proxy(
        self,
        kind: str = "rfc",
        *,
        lifetime: float = 12 * 3600,
        path: Path | None = None,
        key_slot: int = 3,
        issuer: Signer | HoldsChain | None = None,
    ) -> Path:
        """Write a proxy file (certificate, key, chain); ``kind`` is rfc, limited or legacy.

        ``issuer`` signs it (default: the user); passing a loaded proxy
        credential - either client's type - makes a proxy of a proxy. See
        :func:`proxy_certificate` for the rules. The file is in the order
        globus writes ``x509up_u<uid>``: proxy certificate, its key, then
        the issuer chain without the self-signed CA. ``path`` defaults to
        ``x509up_<kind>`` beside the PKI.
        """
        signer = self._user if issuer is None else _as_signer(issuer)
        key = test_key(key_slot)
        body = _pem(proxy_certificate(key, signer, kind=kind, lifetime=lifetime)) + key_pem(key)
        body += b"".join(_pem(link) for link in signer.chain if not _self_signed(link))
        return _write(path or self.directory / f"x509up_{kind}", body, 0o600)

    def credential(self, path: Path | None = None) -> CredT:
        """Load a proxy file (default: :attr:`proxy_path`) through the client's loader."""
        return self._load_credential(str(path or self.proxy_path), None)

    # -- revocation -----------------------------------------------------------------------

    def crl(self, revoked: Iterable[int] = (), *, lifetime: float = DAY) -> bytes:
        """A CRL (PEM) from the CA revoking the certificates with serials ``revoked``.

        Valid from an hour ago for ``lifetime``, with the authority key
        identifier OpenSSL uses to match a CRL to its CA. Empty ``revoked``
        is a clean CRL - what a CA directory with CRL checking switched on
        needs for *every* CA, or verification fails closed.
        """
        now = datetime.datetime.now(datetime.UTC)
        ca = x509.load_der_x509_certificate(self._ca.der)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca.subject)
            .last_update(now - datetime.timedelta(hours=1))
            .next_update(now + datetime.timedelta(seconds=lifetime))
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca.key.public_key()),
                critical=False,
            )
        )
        for serial in revoked:
            entry = x509.RevokedCertificateBuilder().serial_number(serial)
            builder = builder.add_revoked_certificate(entry.revocation_date(now).build())
        return builder.sign(self._ca.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def install_crl(self, revoked: Iterable[int] = ()) -> Path:
        """Write :meth:`crl` into the CA directory as ``<hash>.r0``, where OpenSSL looks."""
        return _write(self.ca_dir / f"{self.ca_hash}.r0", self.crl(revoked))

    # -- TLS contexts ---------------------------------------------------------------------

    def server_context(self, *, require_client: bool = True) -> ssl.SSLContext:
        """A server context presenting the host certificate.

        With ``require_client`` the server asks for, and verifies, a client
        certificate, proxies included (OpenSSL rejects a proxy certificate
        unless ``X509_V_FLAG_ALLOW_PROXY_CERTS`` is set).
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.host_cert_path), str(self.host_key_path))
        context.load_verify_locations(cafile=str(self.ca_file))
        context.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_NONE
        context.verify_flags |= ssl.VERIFY_ALLOW_PROXY_CERTS
        return context

    def client_context(
        self,
        *,
        proxy: Path | None = None,
        anonymous: bool = False,
        check_hostname: bool = True,
    ) -> ssl.SSLContext:
        """A client context presenting a proxy (default: :attr:`proxy_path`) and trusting the CA.

        The proxy file holds certificate, key and chain, so it is passed as
        both; ``anonymous`` presents nothing at all, for a server that must
        cope without a client certificate. Host-name checking stays on unless
        ``check_hostname`` is false - the host certificate's
        ``subjectAltName`` covers the ``hosts`` it was made for, but a GSI
        peer is named by its certificate, not its host (the GSI code checks
        it after the handshake, as :func:`xrdsec.gsi.gss.check_host`).

        Unlike :func:`xrdsec.tls.client_context`, every call builds a fresh,
        uncached context, which a test may change (cap the TLS version, load
        a different credential) without touching any other test's. Test
        suites whose lint bans building contexts by hand get theirs here.
        """
        context = ssl.create_default_context(cafile=str(self.ca_file))
        context.check_hostname = check_hostname
        if not anonymous:
            credential = str(proxy or self.proxy_path)
            context.load_cert_chain(credential, credential)
        return context

    def environment(self) -> dict[str, str]:
        """Variables that point a client at this PKI's proxy and CA directory."""
        return {"X509_USER_PROXY": str(self.proxy_path), "X509_CERT_DIR": str(self.ca_dir)}

    def __repr__(self) -> str:
        """Where it lives and whose CA it is; never any key material."""
        return f"{type(self).__name__}({str(self.directory)!r}, ca={str(self._ca.leaf.subject)!r})"


def _self_signed(der: bytes) -> bool:
    """Subject equals issuer: a trust anchor, which a proxy file leaves out."""
    data = certificate_data(der)
    return data.subject.rdns == data.issuer.rdns


class PKI(BasePKI[x509.Certificate, PrivateKey, ProxyCredential]):
    """The plain view of the test PKI: ``cryptography`` objects and the library's loader.

    :attr:`ca`, :attr:`host` and :attr:`user` are ``cryptography``
    certificates, the ``*_key`` attributes ``cryptography`` private keys,
    and :meth:`credential` returns :class:`~xrdsec.x509.ProxyCredential`
    as :func:`~xrdsec.x509.load_proxy` reads it.
    """

    def _certificate_view(self, der: bytes) -> x509.Certificate:
        """A ``cryptography`` certificate."""
        return x509.load_der_x509_certificate(der)

    def _key_view(self, key: PrivateKey) -> PrivateKey:
        """The ``cryptography`` key itself."""
        return key

    def _load_credential(self, cert_path: str, key_path: str | None) -> ProxyCredential:
        """Through :func:`xrdsec.x509.load_proxy`, as a client loads its proxy."""
        return load_proxy(cert_path, key_path)


def create_pki(
    directory: Path | str,
    *,
    hosts: Sequence[str] = DEFAULT_HOSTS,
    host_cn: str = "host/localhost",
    lifetime: float = 7 * DAY,
    key_slots: tuple[int, int, int] = (0, 1, 2),
) -> PKI:
    """Mint and write a :class:`PKI`; see :meth:`BasePKI.create`."""
    return PKI.create(
        directory, hosts=hosts, host_cn=host_cn, lifetime=lifetime, key_slots=key_slots
    )
