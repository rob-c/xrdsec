"""Hand-assembled certificates and requests: the *low-level* test PKI.

Fixture files checked into a repository expire, drift, and are impossible
to review, so every test gets a chain that is valid *today*, built in
process. :mod:`xrdsec.testing.pki` builds well-formed material and exists to
make malformed material impossible; this module is its opposite.
:func:`make_certificate` signs a hand-assembled TBSCertificate, so a test can
give it an SPKI the key does not match, an extension in any shape, or a name
``cryptography`` would refuse; :func:`make_request` does the same for a
PKCS#10 request (what a delegating GSI server asks for); :func:`proxy_chain`
writes a user-plus-proxy PEM chain from the frozen keys. The DER writers are
:mod:`xrdsec.der`'s, re-exported under the short names the tests use.

It was a private helper of xrdsec's and xrdclient's suites, one identical
copy each; both now import it from here (0.4.0). Public test API, versioned
with the package; nothing here is imported by the library.
"""

from __future__ import annotations

import base64
import time

from xrdsec.der import bit_string as bitstring
from xrdsec.der import integer, oid, sequence, tlv
from xrdsec.der import set_of as setof
from xrdsec.der import utc_time as utctime
from xrdsec.der import utf8_string as utf8
from xrdsec.rsa import RSAPrivateKey, RSAPublicKey
from xrdsec.rsa import private_key_pem as private_key_pem
from xrdsec.testing.pki import KEYS, test_key
from xrdsec.x509 import pem_encode as pem

__all__ = [
    "bitstring",
    "integer",
    "oid",
    "pem",
    "private_key_pem",
    "sequence",
    "setof",
    "tlv",
    "utctime",
    "utf8",
]

#: The RFC 2409 first Oakley group. A real group, small enough that a pure
#: Python ``pow`` over it is instant.
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
DH_GENERATOR = 2

SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11"
RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1"
PROXY_CERT_INFO_OID = "1.3.6.1.5.5.7.1.14"


def name(*pairs: tuple[str, str]) -> bytes:
    """A distinguished name from ``(OID, value)`` pairs, in order."""
    return sequence(*(setof(sequence(oid(key), utf8(value))) for key, value in pairs))


def public_key_info(key: RSAPublicKey) -> bytes:
    """The RSA ``SubjectPublicKeyInfo``: the library's own encoding of it."""
    return key.der()


def make_certificate(
    subject: bytes,
    issuer: bytes,
    subject_key: RSAPublicKey,
    signer: RSAPrivateKey,
    *,
    serial: int = 1,
    not_before: float | None = None,
    not_after: float | None = None,
    extensions: tuple[tuple[str, bytes], ...] = (),
    subject_spki: bytes | None = None,
) -> bytes:
    """A signed X.509 v3 certificate, as DER."""
    now = time.time()
    algorithm = sequence(oid(SHA256_WITH_RSA_OID), tlv(0x05, b""))
    encoded = [
        tlv(0xA3, sequence(*(sequence(oid(key), tlv(0x04, body)) for key, body in extensions)))
    ]
    tbs = sequence(
        tlv(0xA0, integer(2)),
        integer(serial),
        algorithm,
        issuer,
        sequence(
            utctime(now - 3600 if not_before is None else not_before),
            utctime(now + 43200 if not_after is None else not_after),
        ),
        subject,
        subject_spki if subject_spki is not None else public_key_info(subject_key),
        *(encoded if extensions else []),
    )
    return sequence(tbs, algorithm, bitstring(signer.sign(tbs, digest="sha256")))


#: ``ProxyCertInfo`` with an unlimited path length and the ``inheritAll``
#: policy — what ``grid-proxy-init`` writes.
PROXY_CERT_INFO = sequence(sequence(oid("1.3.6.1.5.5.7.21.1")))


def proxy_chain(
    key: RSAPrivateKey,
    *,
    identity: tuple[tuple[str, str], ...] = (
        ("0.9.2342.19200300.100.1.25", "org"),
        ("0.9.2342.19200300.100.1.25", "example"),
        ("2.5.4.3", "Jane Doe"),
    ),
    proxy_cn: str = "1234567890",
    not_after: float | None = None,
    key_usage: bool = False,
) -> bytes:
    """A three-certificate proxy file: proxy, key, user certificate, CA.

    The proxy shares ``key`` with nothing else; the user and CA certificates
    carry their own so the chain is structurally what a real one is. Returns
    the combined PEM that ``$X509_USER_PROXY`` points at. ``key_usage``
    gives the proxy the ``keyUsage`` extension a proxy must carry to sign a
    delegated one, as every proxy a grid tool writes does.
    """
    ca_key = _cached_key(1)
    user_key = _cached_key(2)
    ca_name = name(("0.9.2342.19200300.100.1.25", "org"), ("2.5.4.3", "Example CA"))
    user_name = name(*identity)
    proxy_name = name(*identity, ("2.5.4.3", proxy_cn))

    ca = make_certificate(ca_name, ca_name, ca_key.public, ca_key, serial=1)
    user = make_certificate(user_name, ca_name, user_key.public, ca_key, serial=2)
    proxy = make_certificate(
        proxy_name,
        user_name,
        key.public,
        user_key,
        serial=3,
        not_after=not_after,
        extensions=(
            *((("2.5.29.15", bytes.fromhex("030205a0")),) if key_usage else ()),
            (PROXY_CERT_INFO_OID, PROXY_CERT_INFO),
        ),
    )
    return (
        pem("CERTIFICATE", proxy)
        + private_key_pem(key)
        + pem("CERTIFICATE", user)
        + pem("CERTIFICATE", ca)
    )


def pkcs8_pem(key: RSAPrivateKey) -> bytes:
    """The same key wrapped as unencrypted PKCS#8 ``PRIVATE KEY``."""
    inner = private_key_pem(key)
    der = base64.b64decode(b"".join(inner.splitlines()[1:-1]))
    return pem(
        "PRIVATE KEY",
        sequence(
            integer(0),
            sequence(oid(RSA_ENCRYPTION_OID), tlv(0x05, b"")),
            tlv(0x04, der),
        ),
    )


def dh_parameters_pem() -> bytes:
    """``DH PARAMETERS`` over the Oakley group, as a server would send them."""
    return pem("DH PARAMETERS", sequence(integer(DH_PRIME), integer(DH_GENERATOR)))


_KEYS: dict[int, RSAPrivateKey] = {}


def _cached_key(slot: int) -> RSAPrivateKey:
    """Frozen key ``slot`` of :mod:`xrdsec.testing.pki`, as the client's RSA view.

    2048-bit because ``ssl`` refuses anything smaller, and frozen because
    generating keys in every test would make the suite slow and
    unrepeatable; slots past the last wrap round. Converted once per process.
    """
    if slot not in _KEYS:
        _KEYS[slot] = RSAPrivateKey.from_cryptography(test_key(slot % len(KEYS)))
    return _KEYS[slot]


def throwaway_key(slot: int = 0) -> RSAPrivateKey:
    """Frozen RSA key ``slot`` (2048-bit, the client's view); the same one for the same slot."""
    return _cached_key(slot)


#: ``pkcs-9-at-extensionRequest``, where a PKCS#10 request carries extensions.
EXTENSION_REQUEST_OID = "1.2.840.113549.1.9.14"


def extension(key: str, body: bytes, *, critical: bool = False) -> bytes:
    """One DER ``Extension``, the criticality flag written only when set."""
    flag = tlv(0x01, b"\xff") if critical else b""
    return sequence(oid(key), flag, tlv(0x04, body))


#: ``basicConstraints`` ``cA:TRUE``, critical: what makes a certificate an
#: issuer to a path validator, and what every grid CA carries.
CA_CONSTRAINTS = extension("2.5.29.19", sequence(tlv(0x01, b"\xff")), critical=True)


def make_request(
    subject: bytes,
    key: RSAPrivateKey,
    *,
    extensions: tuple[bytes, ...] = (),
    signer: RSAPrivateKey | None = None,
    attributes: bytes | None = None,
) -> bytes:
    """A PKCS#10 certificate request, as DER - what a GSI server delegating asks for.

    ``extensions`` are encoded :func:`extension` values, carried in an
    ``extensionRequest`` attribute; ``signer`` defaults to ``key`` itself and
    exists so a test can make a request whose signature does not match.
    """
    if attributes is None:
        requested = setof(sequence(*extensions))
        attributes = sequence(oid(EXTENSION_REQUEST_OID), requested) if extensions else b""
    info = sequence(integer(0), subject, public_key_info(key.public), tlv(0xA0, attributes))
    algorithm = sequence(oid(SHA256_WITH_RSA_OID), tlv(0x05, b""))
    return sequence(info, algorithm, bitstring((signer or key).sign(info, digest="sha256")))


def make_certificate_with(
    subject: bytes,
    issuer: bytes,
    subject_key: RSAPublicKey,
    signer: RSAPrivateKey,
    extensions: tuple[bytes, ...],
    *,
    serial: int = 1,
    not_before: float | None = None,
    not_after: float | None = None,
) -> bytes:
    """Like :func:`make_certificate`, with extensions given already encoded."""
    now = time.time()
    algorithm = sequence(oid(SHA256_WITH_RSA_OID), tlv(0x05, b""))
    tbs = sequence(
        tlv(0xA0, integer(2)),
        integer(serial),
        algorithm,
        issuer,
        sequence(
            utctime(now - 3600 if not_before is None else not_before),
            utctime(now + 43200 if not_after is None else not_after),
        ),
        subject,
        public_key_info(subject_key),
        *([tlv(0xA3, sequence(*extensions))] if extensions else []),
    )
    return sequence(tbs, algorithm, bitstring(signer.sign(tbs, digest="sha256")))
