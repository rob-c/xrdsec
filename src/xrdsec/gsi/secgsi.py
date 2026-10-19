"""XrdSecgsi: XRootD's ``gsi`` authentication protocol, client side.

The wire format is XrdSut's bucket buffer: the NUL-terminated name ``"gsi"``,
a big-endian step code, then type-length-value buckets terminated by a zero
type. The handshake is two rounds, three with delegation:

1. **kXGC_certreq** - the client names its crypto module, its version, the
   hashes of the CA that issued *its own* certificate (``new.0|old.0``, the
   names that CA has in a certificate directory - the server loads it by them
   to verify the chain it will be sent), its options (whether it will
   delegate) and a random tag, with a nested message holding the tag the
   *server* must sign.
2. **kXGS_cert** - the server answers with its certificate, its
   Diffie-Hellman public blob, a random tag of its own, and the message
   digests it supports.
3. **kXGC_cert** - the client agrees an AES-128 session key over that group,
   picks a digest from the server's list (``sha256`` where offered, else
   ``sha1`` - dCache's doors offer ``sha1:md5`` alone), signs the server's
   tag with the proxy's private key (proof of possession), and returns its
   own public value plus the proxy chain, encrypted under the session key.
4. **kXGS_pxyreq** / **kXGC_sigpxy** - only when the client offered to
   delegate: the server sends a certificate request for a key pair it made,
   and the client signs it into a proxy one link below its own
   (:func:`xrdsec.delegation.sign_proxy_request`). The client's private key
   never leaves the client.

Which Diffie-Hellman the exchange uses is the server's version's to decide,
as it is for the stock client. From ``XrdSecgsiVersDHsigned`` (10400) each
side *signs* its DH blob with its private key - the server's is checked
against the key in its certificate - the shared secret keeps its leading
zeros, and every encrypted buffer starts with a fresh IV. Older servers get
the original unsigned exchange. Delegation needs the signed one: a server
refuses to take a proxy over an exchange it cannot attribute, and so does
this client, which in addition checks the server's certificate against the
CA directory and the host name (:mod:`xrdsec.trust`) before it signs
anything for it.

Every login - not only a delegating one - first makes the server prove who
it is, as ``XrdSecgsi`` clients do: before the proxy chain is sent, the
certificate in ``kXGS_cert`` must chain to a CA in the certificate directory
and name the host that was dialled, or match one of the patterns in
``$XrdSecGSISRVNAMES`` (comma-separated, ``*`` and ``?`` wildcards; for a
server whose certificate carries an alias). A client may turn that off for a
broken test setup by building :class:`SecgsiClient` without a
:class:`ServerCheck`; delegation still checks, and still refuses an
unverified server.

The DH arithmetic stays on Python integers rather than ``cryptography``'s
``dh`` module on purpose: ``cryptography`` 50 deprecated finite-field DH
(``CryptographyDeprecationWarning``, "support will be removed in a future
release"), and GSI cannot follow it to elliptic curves - the group is the
server's. The checks OpenSSL's ``DH_check_pub_key`` makes are made here
instead (:func:`check_group`): a prime of at least :data:`MIN_DH_BITS`, and a
peer value strictly between 1 and ``p - 1``, so a server - or anyone in the
middle of an unsigned exchange - cannot force a shared secret of 1 or
``p - 1``. Current ``xrootd`` sends a 3072-bit group; anything under
:data:`WEAK_DH_BITS` is used, with a warning, because old servers may.

Every refusal is a :class:`xrdcore.errors.CredentialError` - the class
xrdclient's ``errors.CredentialError`` is. Until 0.4.0 this was xrdclient's
``auth/gsi.py``; xrdclient keeps only the adapter to its
``kXR_auth`` framework (where the credential comes from, configuration, the
prompt). The server side, for tests, is :class:`xrdsec.testing.gsi.SecgsiServer`.

Translated from go-hep ``xrootd/xrdproto/auth/gsi`` and ``XrdSecgsi``.
"""

from __future__ import annotations

import binascii
import fnmatch
import os
import struct
from dataclasses import dataclass

from xrdcore.errors import CredentialError
from xrdcore.log import get_logger

from ..aes import cbc_decrypt, cbc_encrypt
from ..credentials import read_private_file
from ..delegation import DelegationError, load_proxy_request, sign_proxy_request
from ..der import DERError, parse, read_integer
from ..rsa import RSAPrivateKey, RSAPublicKey, load_private_key, pem_blocks
from ..trust import TrustError, verify_server
from ..x509 import ProxyCredential, issuer_hashes, load_certificates

__all__ = [
    "BUCKET_CIPHER",
    "BUCKET_CIPHER_ALG",
    "BUCKET_CLNT_OPTS",
    "BUCKET_CRYPTOMOD",
    "BUCKET_ISSUER_HASH",
    "BUCKET_MAIN",
    "BUCKET_MD_ALG",
    "BUCKET_MESSAGE",
    "BUCKET_PUK",
    "BUCKET_RTAG",
    "BUCKET_SIGNED_RTAG",
    "BUCKET_VERSION",
    "BUCKET_X509",
    "BUCKET_X509_REQ",
    "MIN_DH_BITS",
    "STEP_CLIENT_CERT",
    "STEP_CLIENT_CERTREQ",
    "STEP_CLIENT_SIGPXY",
    "STEP_SERVER_CERT",
    "STEP_SERVER_PXYREQ",
    "WEAK_DH_BITS",
    "Bucket",
    "Delegation",
    "PeerPublic",
    "SecgsiClient",
    "ServerCheck",
    "Session",
    "answer_certificate",
    "answer_proxy_request",
    "build_cert_response",
    "build_certreq",
    "check_group",
    "check_server",
    "choose_digest",
    "client_ca_hashes",
    "decode_message",
    "encode_message",
    "encode_public_blob",
    "find_bucket",
    "parse_dh_parameters",
    "parse_peer_blob",
    "read_proxy",
    "seal",
    "server_names",
    "session_key",
    "unseal",
]

_log = get_logger(__name__)

# -- steps: server messages are kXGS_*, client messages kXGC_* --------------
# XrdSecgsi's step codes, sent as the big-endian word after ``"gsi\0"``.
# :meth:`SecgsiClient.step` dispatches on them and refuses a step it does
# not expect, so a message from the wrong round is never misread as another.
STEP_SERVER_INIT = 2000
STEP_SERVER_CERT = 2001
STEP_SERVER_PXYREQ = 2002
STEP_CLIENT_CERTREQ = 1000
STEP_CLIENT_CERT = 1001
STEP_CLIENT_SIGPXY = 1002

# -- XrdSutBucket type codes -----------------------------------------------
# Only the types this client reads or writes; ``BUCKET_NONE`` terminates a
# message. A bucket of a type not listed here is carried and ignored.
BUCKET_NONE = 0
BUCKET_CRYPTOMOD = 3000
BUCKET_MAIN = 3001
BUCKET_PUK = 3004
BUCKET_CIPHER = 3005
BUCKET_RTAG = 3006
BUCKET_SIGNED_RTAG = 3007
BUCKET_USER = 3008
BUCKET_MESSAGE = 3011
BUCKET_VERSION = 3014
BUCKET_CLNT_OPTS = 3019
BUCKET_X509 = 3022
BUCKET_ISSUER_HASH = 3023
BUCKET_X509_REQ = 3024
BUCKET_CIPHER_ALG = 3025
BUCKET_MD_ALG = 3026

#: Advertised to a server older than signed DH: the original exchange.
VERSION_UNSIGNED_DH = 10300
#: ``XrdSecgsiVersDHsigned``: advertised to - and by - a server that signs its
#: DH blob, which selects the signed exchange on both ends. The client claims
#: no later version, so a newer server expects the random tag signed raw, as
#: this client signs it.
VERSION_SIGNED_DH = 10400
#: A stock client's default options (``kOptsCreatePxy``), with delegation off.
CLIENT_OPTS_DEFAULT = 0x80
#: ``kOptsDlgPxy | kOptsSigReq``: "ask me for a delegated proxy, I will sign
#: the request" - what ``XrdSecGSIDELEGPROXY=1`` adds.
CLIENT_OPTS_DELEGATE = 0x01 | 0x04
#: ``gNoPadTag``: a crypto module name ending in it cannot pad a DH secret.
NOPAD = "nopad"
#: ``EVP_MAX_IV_LENGTH``: the IV the signed exchange puts before each buffer.
IV_LEN = 16
#: What the stock client tells a server whose proxy request it will not sign.
REFUSAL = "Not allowed to sign proxy requests"
#: AES-128: the session key is the leading 16 bytes of the DH shared secret.
SESSION_KEY_LEN = 16
#: Length of the random tags each side sends for the other to sign.
RTAG_LEN = 8

_NAME = b"gsi\x00"
_BPUB = b"---BPUB---"
#: The reference encoder drops the final dash when it writes the closing
#: delimiter, so matching on nine bytes is what actually parses.
_EPUB = b"---EPUB--"


@dataclass(frozen=True, slots=True)
class Bucket:
    """One type-length-value element of a GSI message."""

    type: int
    data: bytes

    def __repr__(self) -> str:
        """Type and length only: a bucket may hold a private key or a session secret."""
        return f"Bucket(type={self.type}, len={len(self.data)})"


def encode_message(step: int, buckets: list[Bucket] | tuple[Bucket, ...]) -> bytes:
    """``"gsi\\0"``, the step, the buckets, the terminator.

    Each bucket is a big-endian ``(type, length)`` pair of 32-bit words and
    then its bytes - the layout of a serialized ``XrdSutBuffer``.
    """
    out = bytearray(_NAME)
    out += struct.pack(">I", step)
    for bucket in buckets:
        out += struct.pack(">II", bucket.type, len(bucket.data))
        out += bucket.data
    out += struct.pack(">I", BUCKET_NONE)
    return bytes(out)


def decode_message(data: bytes) -> tuple[int, list[Bucket]]:
    """Split a GSI message into its step code and buckets.

    Everything here comes from the network, so each length is checked
    against what is left before it is trusted, and a short or lying buffer
    is a :class:`~xrdcore.errors.CredentialError`, never an
    :class:`IndexError`. Bytes after the terminator are ignored.
    """
    end = data.find(b"\x00")
    if end < 0:
        raise CredentialError("GSI message has no protocol name")
    pos = end + 1
    if pos + 4 > len(data):
        raise CredentialError("GSI message is too short for a step code")
    (step,) = struct.unpack_from(">I", data, pos)
    pos += 4
    buckets: list[Bucket] = []
    while pos + 4 <= len(data):
        (kind,) = struct.unpack_from(">I", data, pos)
        pos += 4
        if kind == BUCKET_NONE:
            break
        if pos + 4 > len(data):
            raise CredentialError(f"GSI bucket {kind} has a truncated length")
        (length,) = struct.unpack_from(">I", data, pos)
        pos += 4
        if length > len(data) - pos:
            raise CredentialError(
                f"GSI bucket {kind} claims {length} bytes, {len(data) - pos} available"
            )
        buckets.append(Bucket(kind, data[pos : pos + length]))
        pos += length
    return step, buckets


def find_bucket(data: bytes, kind: int) -> bytes | None:
    """The first bucket of type ``kind``, or ``None``.

    An undecodable message is treated as having no such bucket: callers ask
    for a bucket because they need it, and its absence is the error they
    report, with a sentence that says which bucket was missing.
    """
    try:
        _step, buckets = decode_message(data)
    except CredentialError:
        return None
    for bucket in buckets:
        if bucket.type == kind:
            return bucket.data
    return None


# ---------------------------------------------------------------------------
# Diffie-Hellman over the server's group
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PeerPublic:
    """The server's DH blob: PEM parameters, the group, and its public value."""

    params_pem: bytes
    p: int
    g: int
    public: int


def parse_dh_parameters(pem: bytes) -> tuple[int, int]:
    """The prime and generator from a ``DH PARAMETERS`` PEM block."""
    blocks = [der for label, der in pem_blocks(pem) if label.endswith("PARAMETERS")]
    if not blocks:
        raise CredentialError("no PEM block in the server's DH parameters")
    try:
        element, _ = parse(blocks[0])
        fields = element.children()
        if len(fields) < 2:
            raise DERError("DHParameter needs a prime and a base")
        return read_integer(fields[0]), read_integer(fields[1])
    except DERError as exc:
        raise CredentialError(f"unreadable DH parameters: {exc}") from exc


def parse_peer_blob(blob: bytes) -> PeerPublic:
    """Split ``<PEM params>---BPUB---<hex>---EPUB---`` into its parts."""
    start = blob.find(_BPUB)
    end = blob.find(_EPUB, start + len(_BPUB) if start >= 0 else 0)
    if start < 0 or end <= start + len(_BPUB):
        raise CredentialError("malformed GSI DH public blob")
    params = blob[:start]
    try:
        public = int(blob[start + len(_BPUB) : end].strip(), 16)
    except ValueError as exc:
        raise CredentialError("the DH public value is not hexadecimal") from exc
    prime, generator = parse_dh_parameters(params)
    return PeerPublic(params_pem=bytes(params), p=prime, g=generator, public=public)


def encode_public_blob(params_pem: bytes, public: int) -> bytes:
    """The client's blob: the server's parameters echoed, then our public value."""
    hexed = binascii.hexlify(public.to_bytes((public.bit_length() + 7) // 8, "big")).upper()
    return params_pem + _BPUB + hexed + b"---EPUB---"


#: The smallest DH prime accepted at all - OpenSSL's and ``cryptography``'s
#: floor too. A 512-bit discrete log is within reach of a university cluster.
MIN_DH_BITS = 512
#: Below this a group is used, with a warning: ``xrootd`` itself sends 3072
#: bits, but older servers and other implementations may send less, and
#: refusing them would end GSI logins to them altogether.
WEAK_DH_BITS = 2048

#: The weak prime sizes already warned about, so a busy process says it once.
_WARNED_BITS: set[int] = set()


def check_group(peer: PeerPublic) -> None:
    """Refuse a DH group or peer value no honest server sends.

    The checks OpenSSL's ``DH_check_pub_key`` makes, which a raw ``pow``
    does not: the prime must be odd and at least :data:`MIN_DH_BITS` long,
    the generator and the peer's public value strictly between 1 and
    ``p - 1``. A public value of 0, 1 or ``p - 1`` (or ``p`` and above)
    would pin the shared secret to a value anyone can compute, and with the
    unsigned exchange there is nothing else to stop a man in the middle from
    sending one. Raises :class:`~xrdcore.errors.CredentialError`.
    """
    bits = peer.p.bit_length()
    if bits < MIN_DH_BITS:
        raise CredentialError(
            f"the server's Diffie-Hellman prime is {bits} bits; "
            f"fewer than {MIN_DH_BITS} is not secure and is refused"
        )
    if not peer.p & 1 or not 1 < peer.g < peer.p - 1:
        raise CredentialError("the server's Diffie-Hellman group is malformed")
    if not 1 < peer.public < peer.p - 1:
        raise CredentialError(
            "the server's Diffie-Hellman public value is out of range "
            "(it must lie strictly between 1 and p-1)"
        )
    if bits < WEAK_DH_BITS and bits not in _WARNED_BITS:
        _WARNED_BITS.add(bits)
        _log.warning(
            "the GSI server's Diffie-Hellman group is only %d bits (%d or more is "
            "recommended); the login goes ahead, but the server should be upgraded",
            bits,
            WEAK_DH_BITS,
        )


def session_key(
    peer: PeerPublic, private: int, length: int = SESSION_KEY_LEN, *, padded: bool = False
) -> bytes:
    """The leading ``length`` bytes of the DH shared secret.

    XrdSecgsi's unsigned path takes the secret's *minimal* big-endian form —
    leading zeros stripped, as OpenSSL's ``DH_compute_key`` returns it — and
    uses its first bytes directly, with no KDF. The signed path, when both
    ends can, keeps the secret at the full width of the prime
    (``EVP_PKEY_CTX_set_dh_pad``), leading zeros and all. The group and
    the peer's value are checked first (:func:`check_group`).
    """
    check_group(peer)
    secret = pow(peer.public, private, peer.p)
    if not 1 < secret < peer.p - 1:
        # Only a peer value of small order gets here - a group whose ``p`` is
        # not the safe prime it claims to be. Refused for the same reason.
        raise CredentialError("the Diffie-Hellman exchange produced a degenerate secret")
    width = peer.p.bit_length() if padded else secret.bit_length()
    raw = secret.to_bytes((width + 7) // 8, "big")
    if len(raw) < length:
        raise CredentialError(f"DH shared secret is {len(raw)} bytes, need {length}")
    return raw[:length]


# ---------------------------------------------------------------------------
# The two client rounds
# ---------------------------------------------------------------------------


def build_certreq(
    *,
    cryptomod: str = "ssl",
    version: int = VERSION_UNSIGNED_DH,
    issuer_hash: str = "",
    options: int = CLIENT_OPTS_DEFAULT,
    rtag: bytes,
) -> bytes:
    """The first client message, ``kXGC_certreq``. No cryptography involved."""
    inner = encode_message(STEP_CLIENT_CERTREQ, [Bucket(BUCKET_RTAG, rtag)])
    return encode_message(
        STEP_CLIENT_CERTREQ,
        [
            Bucket(BUCKET_CRYPTOMOD, (cryptomod or "ssl").encode("ascii")),
            Bucket(BUCKET_VERSION, struct.pack(">I", version)),
            Bucket(BUCKET_ISSUER_HASH, issuer_hash.encode("ascii")),
            Bucket(BUCKET_CLNT_OPTS, struct.pack(">I", options)),
            Bucket(BUCKET_MAIN, inner),
        ],
    )


@dataclass(frozen=True, slots=True)
class Session:
    """What the certificate round leaves for a delegation round after it."""

    key: bytes
    use_iv: bool
    server_pem: bytes = b""


def seal(key: bytes, plain: bytes, *, use_iv: bool, iv: bytes | None = None) -> bytes:
    """AES-CBC under the session key; the signed exchange prefixes a fresh IV."""
    if not use_iv:
        return cbc_encrypt(key, plain)
    vector = iv if iv is not None else os.urandom(IV_LEN)
    return vector + cbc_encrypt(key, plain, vector)


def unseal(key: bytes, data: bytes, *, use_iv: bool) -> bytes:
    """The inverse of :func:`seal`."""
    try:
        if not use_iv:
            return cbc_decrypt(key, data)
        return cbc_decrypt(key, data[IV_LEN:], data[:IV_LEN])
    except ValueError as exc:
        raise CredentialError(f"cannot decrypt the server's GSI message: {exc}") from exc


def _server_key(server_pem: bytes | None) -> RSAPublicKey:
    """The RSA key in the server's leaf certificate, which signed its DH blob."""
    certificates = load_certificates(server_pem or b"")
    key = certificates[0].public_key if certificates else None
    if key is None:
        raise CredentialError("the server signed its DH parameters but sent no RSA certificate")
    return key


def _unsign(blob: bytes, server_pem: bytes | None) -> bytes:
    """The server's DH blob, recovered with the key in its certificate."""
    try:
        return _server_key(server_pem).decrypt_public(blob)
    except ValueError as exc:
        raise CredentialError(
            "the server's DH parameters are not signed by its certificate's key"
        ) from exc


def _peer_blob(challenge: bytes) -> tuple[bytes, bool]:
    """The server's DH blob, and whether it came signed."""
    signed = find_bucket(challenge, BUCKET_CIPHER)
    if signed is not None:
        return _unsign(signed, find_bucket(challenge, BUCKET_X509)), True
    blob = find_bucket(challenge, BUCKET_PUK)
    if blob is None:
        raise CredentialError("the server's GSI challenge carries no DH public key")
    return blob, False


def _signed_tag(message: bytes | None, key: RSAPrivateKey) -> list[Bucket]:
    """Proof of possession: raw PKCS#1 v1.5 over the tag the server sent, if it sent one."""
    tag = find_bucket(message, BUCKET_RTAG) if message is not None else None
    return [Bucket(BUCKET_SIGNED_RTAG, key.sign(tag))] if tag else []


#: The message digests this client can sign with, most preferred first.
CLIENT_DIGESTS = ("sha256", "sha1")


def choose_digest(offered: bytes | None) -> bytes:
    """The digest to answer ``kXGS_cert`` with: ours, the first the server lists.

    The server says what it accepts in the challenge's ``kXRS_md_alg`` bucket
    (``sha256`` from a current xrootd, ``sha1:md5`` from dCache and older
    xrootd) and refuses a reply naming anything else. A server that sends no
    list predates the choice and gets ``sha256``, which is what this client
    always said before it read the list.
    """
    if not offered:
        return CLIENT_DIGESTS[0].encode()
    names = [name.strip().lower() for name in offered.decode("ascii", "replace").split(":")]
    for digest in CLIENT_DIGESTS:
        if digest in names:
            return digest.encode()
    raise CredentialError(
        f"the server's GSI accepts only the digests {':'.join(names)}, "
        f"and this client signs with {':'.join(CLIENT_DIGESTS)}"
    )


def client_ca_hashes(proxy: ProxyCredential) -> str:
    """``new.0|old.0``: the CA-directory names of the authority behind ``proxy``.

    That authority signed the end-entity certificate - the first link in the
    chain that is neither a proxy nor an anchor. Empty when the chain has
    no such link, or it cannot be read far enough to hash.
    """
    for certificate in proxy.chain:
        if certificate.is_proxy or certificate.is_anchor:
            continue
        try:
            new, old = issuer_hashes(certificate)
        except (DERError, ValueError, IndexError):
            return ""
        return f"{new}.0|{old}.0"
    return ""


def _outer_cert(
    blob: bytes, key: RSAPrivateKey, signed: bool, main: bytes, digest: bytes = b"sha256"
) -> list[Bucket]:
    """The cleartext buckets of ``kXGC_cert`` around the sealed ``main`` buffer.

    ``blob`` is our DH public blob (:func:`encode_public_blob`). In the signed
    exchange it travels encrypted with the proxy's private key - "signed" in
    XrdSecgsi's sense, recoverable with the public key sent beside it - and
    the cipher name carries ``#16`` to say every buffer is prefixed by an IV;
    the unsigned exchange sends the blob in the clear under the bare name.
    The digest is the one :func:`choose_digest` picked from the server's list.
    """
    if signed:
        agreement = [
            Bucket(BUCKET_CIPHER, key.encrypt_private(blob)),
            Bucket(BUCKET_PUK, key.public.pem()),
            Bucket(BUCKET_CIPHER_ALG, b"aes-128-cbc#%d" % IV_LEN),
        ]
    else:
        agreement = [Bucket(BUCKET_PUK, blob), Bucket(BUCKET_CIPHER_ALG, b"aes-128-cbc")]
    return [
        Bucket(BUCKET_CRYPTOMOD, b"ssl"),
        *agreement,
        Bucket(BUCKET_MD_ALG, digest),
        Bucket(BUCKET_MAIN, main),
    ]


def answer_certificate(
    challenge: bytes,
    chain_pem: bytes,
    key: RSAPrivateKey,
    *,
    private: int | None = None,
    rtag: bytes | None = None,
    iv: bytes | None = None,
    padded: bool = True,
) -> tuple[bytes, Session]:
    """Answer ``kXGS_cert`` with ``kXGC_cert``, in whichever DH the server chose.

    Returns the message and the :class:`Session` a delegation round needs.
    ``private``, ``rtag`` and ``iv`` are injectable so the encoding can be
    pinned by a test; leave them unset in production and they are drawn from
    :func:`os.urandom`. ``padded=False`` is for a server whose crypto module
    says ``nopad``.
    """
    blob, signed = _peer_blob(challenge)
    peer = parse_peer_blob(blob)
    digest = choose_digest(find_bucket(challenge, BUCKET_MD_ALG))
    if private is None:
        # A private exponent in [2, p-2]; the group is the server's choice.
        private = 2 + int.from_bytes(os.urandom((peer.p.bit_length() + 7) // 8), "big") % (
            peer.p - 3
        )
    secret = session_key(peer, private, padded=signed and padded)

    # The sealed part: our chain, our signature over the server's tag (proof
    # we hold the proxy's key), and a fresh tag of our own for the server's
    # next message. Only this part is secret; the DH value travels outside it.
    inner = [
        Bucket(BUCKET_X509, chain_pem),
        *_signed_tag(find_bucket(challenge, BUCKET_MAIN), key),
        Bucket(BUCKET_RTAG, rtag if rtag is not None else os.urandom(RTAG_LEN)),
    ]
    main = seal(secret, encode_message(STEP_CLIENT_CERT, inner), use_iv=signed, iv=iv)
    # Our public value g^x mod p, in the server's own parameters' framing.
    blob_out = encode_public_blob(peer.params_pem, pow(peer.g, private, peer.p))
    outer = _outer_cert(blob_out, key, signed, main, digest)
    server_pem = find_bucket(challenge, BUCKET_X509) or b""
    return encode_message(STEP_CLIENT_CERT, outer), Session(secret, signed, server_pem)


def build_cert_response(
    challenge: bytes,
    chain_pem: bytes,
    key: RSAPrivateKey,
    *,
    private: int | None = None,
    rtag: bytes | None = None,
) -> bytes:
    """Answer ``kXGS_cert`` with ``kXGC_cert``: :func:`answer_certificate`'s message alone."""
    return answer_certificate(challenge, chain_pem, key, private=private, rtag=rtag)[0]


def _delegated(plain: bytes, proxy: ProxyCredential, key: RSAPrivateKey) -> Bucket:
    """The signed proxy for the server's request, or the reason there is none."""
    request = find_bucket(plain, BUCKET_X509_REQ)
    if request is None:
        return Bucket(BUCKET_MESSAGE, b"bucket with proxy request missing")
    try:
        issued = sign_proxy_request(load_proxy_request(request), proxy.certificate, key)
    except DelegationError as exc:
        _log.warning("not delegating the X.509 proxy: %s", exc)
        return Bucket(BUCKET_MESSAGE, f"problems signing the request: {exc}".encode())
    _log.debug("delegated a proxy for %s until %s", issued.subject, issued.not_after)
    return Bucket(BUCKET_X509, issued.pem())


def answer_proxy_request(
    challenge: bytes,
    session: Session,
    proxy: ProxyCredential,
    key: RSAPrivateKey,
    *,
    allowed: bool,
    iv: bytes | None = None,
) -> bytes:
    """Answer ``kXGS_pxyreq`` with ``kXGC_sigpxy``.

    With ``allowed`` the request is signed into a proxy below ``proxy``;
    without, the server is told so in words - the stock client's answer, which
    lets the login finish with nothing delegated.
    """
    main = find_bucket(challenge, BUCKET_MAIN)
    if main is None:
        raise CredentialError("the server's proxy request has no main buffer")
    plain = unseal(session.key, main, use_iv=session.use_iv)
    # A refusal is still a well-formed reply, signed like any other, so the
    # server ends the login normally rather than on a protocol error.
    answer = _delegated(plain, proxy, key) if allowed else Bucket(BUCKET_MESSAGE, REFUSAL.encode())
    inner = [answer, *_signed_tag(plain, key)]
    sealed = seal(
        session.key, encode_message(STEP_CLIENT_SIGPXY, inner), use_iv=session.use_iv, iv=iv
    )
    return encode_message(
        STEP_CLIENT_SIGPXY, [Bucket(BUCKET_CRYPTOMOD, b"ssl"), Bucket(BUCKET_MAIN, sealed)]
    )


def read_proxy(path: str, *, named: bool = True) -> ProxyCredential:
    """Load the proxy at ``path`` once it is shown to be this user's alone.

    :func:`xrdsec.x509.load_proxy` reads any file it is pointed
    at, which is right for inspecting one; a proxy about to be *used* is
    read through :func:`xrdsec.credentials.read_private_file`:
    a regular file, owned by the effective uid, mode ``0600`` or tighter -
    what ``voms-proxy-init`` writes and ``XrdSecgsi`` expects. ``named=False``
    is for the default location, a predictable name, where a symbolic link
    is not followed (``predictable=True``).
    Raises :class:`~xrdcore.errors.InsecureCredentialError` (a
    :class:`PermissionError`) for a file that fails those checks, and
    :class:`ValueError` for one that is not a proxy.
    """
    data = read_private_file(path, kind="X.509 proxy", predictable=not named)
    chain = load_certificates(data)
    if not chain:
        raise DERError(f"no certificate in {path}")
    return ProxyCredential(chain=tuple(chain), key=load_private_key(data), path=path)


@dataclass(frozen=True, slots=True)
class Delegation:
    """Whether, and to whom, the proxy may be delegated."""

    wanted: bool = False
    host: str = ""
    ca_path: str | None = None


@dataclass(frozen=True, slots=True)
class ServerCheck:
    """Who a GSI server must prove to be before the proxy chain is sent to it.

    ``host`` is the name that was dialled; ``names`` are the extra patterns
    ``$XrdSecGSISRVNAMES`` allows - shell wildcards matched against the host
    name in the server certificate's ``CN`` - for a server whose certificate
    carries an alias rather than the name it is reached by. ``bypass`` is
    how the client's user turns the check off (xrdclient's
    ``XRD_GSI_VERIFY_SERVER=0``), named in the refusal when given.
    """

    host: str
    ca_path: str | None = None
    names: tuple[str, ...] = ()
    bypass: str = ""


#: The stock client's variable, mixed case as XRootD spells it.
_SRVNAMES_VARIABLE = "XrdSecGSISRVNAMES"


def server_names() -> tuple[str, ...]:
    """The patterns in ``$XrdSecGSISRVNAMES``, the stock client's variable."""
    raw = os.environ.get(_SRVNAMES_VARIABLE, "")
    return tuple(name.strip().lower() for name in raw.split(",") if name.strip())


def _expected_name(chain_pem: bytes, check: ServerCheck) -> str:
    """The name the certificate must carry: the host, or an alias a pattern allows.

    A certificate whose ``CN`` (``host/<name>`` or ``<name>``) matches one of
    ``check.names`` is held to that name instead, so the chain and the
    validity checks still apply in full - only the name is widened.
    """
    certificates = load_certificates(chain_pem) if check.names else []
    if certificates:
        alias = certificates[0].subject.cn.lower().rsplit("/", 1)[-1]
        if any(fnmatch.fnmatchcase(alias, pattern) for pattern in check.names):
            return alias
    return check.host


def check_server(chain_pem: bytes, check: ServerCheck) -> None:
    """Refuse a server whose certificate does not establish that it is ``check.host``.

    The login-time check ``XrdSecgsi`` makes: the certificate must chain to a
    CA in ``check.ca_path`` (:func:`xrdsec.trust.verify_server`),
    be current, and name the host - or an alias ``check.names`` allows.
    Raises :class:`~xrdcore.errors.CredentialError` saying which check failed
    and how to get past a setup that cannot pass it.
    """
    try:
        verify_server(chain_pem, _expected_name(chain_pem, check), check.ca_path)
    except TrustError as exc:
        bypass = f"; on a test setup only, {check.bypass} skips the check" if check.bypass else ""
        raise CredentialError(
            f"the GSI server {check.host} did not prove its identity: {exc}. "
            "Check $X509_CERT_DIR holds its CA; for a certificate issued to another "
            f"name, list that name in $XrdSecGSISRVNAMES{bypass}"
        ) from exc


def _modules(cryptomod: str) -> tuple[str, bool]:
    """The crypto module to name, and whether it pads a DH secret.

    The first module the server lists counts; ``nopad`` on its end says the
    server cannot pad a DH secret, which the signed exchange must then match.
    """
    module = (cryptomod or "ssl").split("|")[0] or "ssl"
    padded = not module.endswith(NOPAD)
    return (module if padded else module[: -len(NOPAD)]), padded


class SecgsiClient:
    """One XrdSecgsi login: the client's half of the exchange, round by round.

    Pure state, no I/O: :meth:`initial` makes ``kXGC_certreq``, and
    :meth:`step` answers each server message. One instance serves one login
    attempt (it keeps the exchange's session key between rounds), so it must
    not be shared between connections. xrdclient's ``GSICredential``
    subclasses it to plug it into its ``kXR_auth`` framework.
    """

    __slots__ = (
        "_may_delegate",
        "_rtag",
        "_session",
        "cryptomod",
        "delegation",
        "issuer_hash",
        "padded",
        "proxy",
        "server_check",
        "server_version",
    )

    def __init__(
        self,
        proxy: ProxyCredential,
        *,
        cryptomod: str = "ssl",
        issuer_hash: str = "",
        server_version: int = 0,
        delegation: Delegation | None = None,
        server_check: ServerCheck | None = None,
    ):
        """A login with ``proxy``, shaped by what the server's offer said.

        ``cryptomod``, ``issuer_hash`` and ``server_version`` come from the
        offer's ``c:``, ``ca:`` and ``v:`` parameters; the version alone
        selects the signed or unsigned exchange. ``delegation`` defaults to
        "do not delegate". ``server_check=None`` sends the chain to whoever
        answers - only for a test setup that cannot pass the check.
        """
        self.proxy = proxy
        self.cryptomod, self.padded = _modules(cryptomod)
        self.issuer_hash = issuer_hash
        self.server_version = server_version
        self.delegation = delegation or Delegation()
        self.server_check = server_check
        self._rtag = b""
        self._session: Session | None = None
        self._may_delegate = False

    @property
    def identity(self) -> str:
        """Who this proxy says you are, with the proxy CNs stripped."""
        return self.proxy.identity

    @property
    def signed(self) -> bool:
        """Whether the server's version makes this the signed-DH exchange."""
        return self.server_version >= VERSION_SIGNED_DH

    def initial(self) -> bytes:
        """``kXGC_certreq``: announce the module, version, our CA and options.

        Resets the per-exchange state, so an instance re-driven after a
        failed round starts clean. The random tag is the one the server must
        sign; ``nopad`` is echoed only when the signed exchange is in use,
        because only that exchange pads the secret. An expired proxy is
        refused here, before any round trip.
        """
        if self.proxy.expired:
            raise CredentialError(
                f"the X.509 proxy {self.proxy.path or '<memory>'} expired "
                f"{-self.proxy.remaining() / 3600:.1f} hours ago; renew it"
            )
        self._rtag = os.urandom(RTAG_LEN)
        self._session, self._may_delegate = None, False
        return build_certreq(
            cryptomod=self.cryptomod + ("" if self.padded or not self.signed else NOPAD),
            version=VERSION_SIGNED_DH if self.signed else VERSION_UNSIGNED_DH,
            issuer_hash=self.issuer_hash,
            options=CLIENT_OPTS_DEFAULT | (CLIENT_OPTS_DELEGATE if self._offers() else 0),
            rtag=self._rtag,
        )

    def _offers(self) -> bool:
        """Whether to offer the server a delegated proxy (wanted, and the exchange is signed)."""
        if self.delegation.wanted and not self.signed:
            _log.warning(
                "not delegating the X.509 proxy: the server runs GSI %d, "
                "which predates the signed exchange delegation needs",
                self.server_version,
            )
        return self.delegation.wanted and self.signed

    def _key(self) -> RSAPrivateKey:
        """The proxy's private key, which GSI needs to be RSA (raw PKCS#1 signing)."""
        key = self.proxy.key
        if not isinstance(key, RSAPrivateKey):
            raise CredentialError("the proxy's private key is not RSA")
        return key

    def step(self, challenge: bytes) -> bytes | None:
        """Answer ``kXGS_cert`` or ``kXGS_pxyreq``; any other step is refused.

        The server is verified *before* the reply is built, because the reply
        carries the proxy chain. Whether delegation may follow is decided
        here too: offered, and the server proven - by the login check, or by
        :meth:`_trusted` when that check was turned off.
        """
        step, _buckets = decode_message(challenge)
        if step == STEP_SERVER_CERT:
            verified = self._verify(challenge)
            message, self._session = answer_certificate(
                challenge, self.proxy.pem(), self._key(), padded=self.padded
            )
            self._may_delegate = self._offers() and (verified or self._trusted(self._session))
            return message
        if step == STEP_SERVER_PXYREQ:
            if self._session is None:
                raise CredentialError("the server asked for a proxy before the key exchange")
            return answer_proxy_request(
                challenge, self._session, self.proxy, self._key(), allowed=self._may_delegate
            )
        raise CredentialError(f"unexpected GSI step {step} from the server")

    def _verify(self, challenge: bytes) -> bool:
        """Check the server before anything is sent to it; whether a check was made."""
        if self.server_check is None:
            return False
        check_server(find_bucket(challenge, BUCKET_X509) or b"", self.server_check)
        return True

    def _trusted(self, session: Session) -> bool:
        """Whether the server proved to be the host it was dialled as."""
        try:
            verify_server(session.server_pem, self.delegation.host, self.delegation.ca_path)
        except TrustError as exc:
            _log.warning("not delegating the X.509 proxy to %s: %s", self.delegation.host, exc)
            return False
        return True
