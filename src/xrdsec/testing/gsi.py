"""The acceptor side of GSI, for in-process test servers.

Every fake grid server on the stack that speaks GSI needs the same few
server-side pieces, and before 0.4.0 each carried its own:

* **GSS acceptors** (GridFTP ``ADAT``, LFC Csec, dcap's ``enc`` tunnel):
  :func:`acceptor` builds a server-side :class:`~xrdsec.gsi.gss.SecurityContext`
  and :func:`accept_tokens` runs the token loop over whatever framing the
  protocol uses; :func:`exchange_tokens` runs both ends of it in-process, for
  a test of a GSS context itself; :func:`proxy_owner` turns the peer's proxy subject into the
  user's DN, which is what a grid-mapfile is keyed by.
* **httpg** (the SRM fake): :func:`httpg_context` shapes a server TLS
  context the way a Globus or dCache acceptor negotiates, and
  :func:`accept_httpg` runs the GSI preamble - the TLS 1.3 turn byte, then
  the client's delegation flag - before HTTP starts.
* **XrdSecgsi** (xrdclient's ``gsi`` tests): :class:`SecgsiServer` plays
  ``XrdSecgsi``'s server rounds - the ``kXGS_cert`` challenge in the signed
  or the unsigned Diffie-Hellman exchange, reading the client's
  ``kXGC_cert`` (session key, chain, proof of possession), and the
  ``kXGS_pxyreq``/``kXGC_sigpxy`` delegation round.

Nothing here is a production server: the checks are those a test needs to
catch a client that gets the protocol wrong, and a failed one raises
(:class:`~xrdsec.gsi.gss.GSIError` for GSS and httpg,
:class:`~xrdcore.errors.CredentialError` for XrdSecgsi) for the fake to turn
into whatever its protocol says on a failed login.

Public test API, versioned with the package.
"""

from __future__ import annotations

import os
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field

from xrdcore.errors import CredentialError

from ..der import integer, sequence
from ..gsi.gss import NO_DELEGATION, TURN, GSIError, SecurityContext
from ..gsi.secgsi import (
    BUCKET_CIPHER,
    BUCKET_CIPHER_ALG,
    BUCKET_MAIN,
    BUCKET_MD_ALG,
    BUCKET_PUK,
    BUCKET_RTAG,
    BUCKET_SIGNED_RTAG,
    BUCKET_X509,
    BUCKET_X509_REQ,
    STEP_CLIENT_CERT,
    STEP_CLIENT_SIGPXY,
    STEP_SERVER_CERT,
    STEP_SERVER_PXYREQ,
    Bucket,
    decode_message,
    encode_message,
    encode_public_blob,
    find_bucket,
    parse_peer_blob,
    seal,
    session_key,
    unseal,
)
from ..rsa import RSAPrivateKey, RSAPublicKey, load_public_key
from ..x509 import load_certificates, pem_encode

__all__ = [
    "MODP_2048_GENERATOR",
    "MODP_2048_PRIME",
    "SecgsiLogin",
    "SecgsiServer",
    "accept_httpg",
    "accept_tokens",
    "acceptor",
    "dh_parameters_pem",
    "exchange_tokens",
    "httpg_context",
    "proxy_owner",
]

# -- GSS -----------------------------------------------------------------------------


def acceptor(
    tls: ssl.SSLContext, *, turn: bool = True, delegation_key: RSAPrivateKey | None = None
) -> SecurityContext:
    """A server-side GSI context over ``tls`` (a server context presenting the host).

    ``turn=False`` is dCache's engine (no TLS 1.3 turn byte, as its dcap and
    SRM doors speak); ``delegation_key`` fixes the key a delegating client
    is asked to certify, sparing a 2048-bit key generation per test.
    """
    return SecurityContext(tls, server_side=True, turn=turn, delegation_key=delegation_key)


def accept_tokens(
    context: SecurityContext,
    receive: Callable[[], bytes | None],
    send: Callable[[bytes], None],
) -> bool:
    """Answer the initiator's tokens until ``context`` completes; whether it did.

    The initiator speaks first, so each round reads a token with ``receive``
    and sends the reply, if any, with ``send``; the acceptor completes on the
    client's delegation flag (or its delegated proxy), which needs no answer.
    ``receive`` returning ``None`` means the client gave up (LFC's
    ``HANDSHAKE_ERROR``): the loop stops and the result is ``False``.
    :class:`~xrdsec.gsi.gss.GSIError` from a bad token propagates.
    """
    while not context.complete:
        token = receive()
        if token is None:
            return False
        reply = context.step(token)
        if reply:
            send(reply)
    return True


def exchange_tokens(
    initiator: SecurityContext, responder: SecurityContext, *, rounds: int = 20
) -> list[bytes]:
    """Ferry tokens between two in-process contexts until both are done; the responder's tokens.

    For a test holding both ends (no socket): the initiator speaks first and
    the loop stops once both report completion *and* nothing is left in
    flight - the last token matters even then, because under TLS 1.3 the
    responder's final token carries session tickets, and an initiator that
    drops it has lost records from the stream. The responder's tokens are
    returned in order, so a test can look for the TLS 1.3 turn. Raises
    :class:`~xrdsec.gsi.gss.GSIError` if the exchange has not converged
    after ``rounds`` round trips, or for a bad token from either side.
    """
    sent: list[bytes] = []
    token = initiator.step()
    for _ in range(rounds):
        token = responder.step(token)
        sent.append(token)
        token = initiator.step(token)
        if initiator.complete and responder.complete and not token:
            return sent
    raise GSIError(f"the GSI exchange did not converge in {rounds} rounds")


def proxy_owner(subject: str) -> str:
    """The end-entity DN of a proxy: drop every ``CN=<serial>``/``CN=proxy`` tail.

    ``subject`` is in Globus's slash form. RFC 3820 proxies append a numeric
    ``CN``, legacy Globus proxies ``CN=proxy`` or ``CN=limited proxy``, and
    a proxy of a proxy appends another, so every such tail is removed; a
    grid-mapfile is keyed by the user's own DN. At least ``/<first RDN>`` is
    always kept, so a certificate whose DN is only a ``CN`` survives.
    """
    parts = subject.split("/")
    while len(parts) > 2 and (
        parts[-1] in ("CN=proxy", "CN=limited proxy")
        or (parts[-1].startswith("CN=") and parts[-1][3:].isdigit())
    ):
        parts.pop()
    return "/".join(parts)


# -- httpg ---------------------------------------------------------------------------


def httpg_context(tls: ssl.SSLContext, *, turn: bool = False) -> ssl.SSLContext:
    """Shape server context ``tls`` (in place, and returned) the way an httpg acceptor talks.

    globus-gssapi (CGSI-gSOAP's GSI) runs the handshake as TLS 1.2 token
    ping-pong: under TLS 1.3 its initiator waits for a server token after
    its own Finished and then misreads session tickets as data. So the
    context is capped at TLS 1.2, unless ``turn`` asks for TLS 1.3 the way a
    Globus acceptor does it - a NUL turn byte after the handshake, and no
    session tickets. Do not share one context between servers with
    different ``turn`` settings.
    """
    if turn:
        tls.num_tickets = 0
    else:
        tls.maximum_version = ssl.TLSVersion.TLSv1_2
    return tls


def accept_httpg(sock: ssl.SSLSocket, *, turn: bool = False) -> None:
    """The acceptor's GSI preamble on a TLS socket: turn byte, then the delegation flag.

    The turn is sent only when ``turn`` is set and TLS 1.3 was negotiated.
    SRM never needs a delegated credential, so only ``0`` is accepted: a
    client that tries to delegate (or sends anything else, or nothing) gets
    :class:`~xrdsec.gsi.gss.GSIError`, and the fake hangs up.
    """
    if turn and sock.version() == "TLSv1.3":
        sock.sendall(TURN)  # globus-gssapi's TLS 1.3 "your turn" token
    flag = sock.recv(1)
    if flag != NO_DELEGATION:
        raise GSIError(f"unexpected GSI delegation flag {flag!r}")


# -- XrdSecgsi -----------------------------------------------------------------------

#: RFC 3526's 2048-bit MODP group (group 14): a safe prime of the size
#: :data:`~xrdsec.gsi.secgsi.WEAK_DH_BITS` asks for, so a client talking to
#: :class:`SecgsiServer` sees no weak-group warning.
MODP_2048_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
#: The group's generator.
MODP_2048_GENERATOR = 2


def dh_parameters_pem(prime: int = MODP_2048_PRIME, generator: int = MODP_2048_GENERATOR) -> bytes:
    """A ``DH PARAMETERS`` PEM block, as an ``xrootd`` server sends its group."""
    return pem_encode("DH PARAMETERS", sequence(integer(prime), integer(generator)))


@dataclass(frozen=True, slots=True)
class SecgsiLogin:
    """What :meth:`SecgsiServer.read_certificate` learned from the client's ``kXGC_cert``.

    ``key`` is the agreed session key and ``use_iv`` whether the exchange
    was the signed one (every sealed buffer then starts with an IV);
    ``plain`` is the decrypted inner message, ``chain_pem`` the client's
    proxy chain from it, and ``client_tag`` the tag the client asks the
    server's next message to carry signed.
    """

    key: bytes
    use_iv: bool
    plain: bytes
    chain_pem: bytes
    client_tag: bytes

    def client_key(self) -> RSAPublicKey:
        """The public key of the client's leaf certificate, which signs its tags."""
        return _leaf_key(self.chain_pem)


def _leaf_key(chain_pem: bytes) -> RSAPublicKey:
    """The RSA key of the first certificate in ``chain_pem``; ``CredentialError`` if none."""
    certificates = load_certificates(chain_pem)
    key = certificates[0].public_key if certificates else None
    if key is None:
        raise CredentialError("the client sent no RSA certificate")
    return key


def _random_private(prime: int) -> int:
    """A private exponent in ``[2, p - 2]``."""
    return 2 + int.from_bytes(os.urandom((prime.bit_length() + 7) // 8), "big") % (prime - 3)


@dataclass
class SecgsiServer:
    """``XrdSecgsi``'s server rounds, enough to log a client in and take a delegation.

    ``certificate_pem`` is the chain the server presents (leaf first) and
    ``key`` the leaf's private key, which signs the DH blob in the signed
    exchange (``version`` 10400 and later). ``prime``/``generator`` are the
    group (RFC 3526 group 14 by default) and ``private`` this server's
    exponent (random unless a test pins it). ``digests`` is the
    ``kXRS_md_alg`` list offered: ``sha256:sha1`` from current xrootd,
    ``sha1:md5`` from dCache.

    Usage, one login::

        server = SecgsiServer(host_pem, host_key)
        reply = client.step(server.challenge(tag=b"abcdEFGH"))
        login = server.read_certificate(reply, tag=b"abcdEFGH")

    Each ``read_*`` checks what a real server checks - the step code, the
    client's signature over the tag it was sent - and raises
    :class:`~xrdcore.errors.CredentialError` when the client got it wrong.
    """

    certificate_pem: bytes = b""
    key: RSAPrivateKey | None = None
    prime: int = MODP_2048_PRIME
    generator: int = MODP_2048_GENERATOR
    private: int = field(default=0)
    digests: bytes = b"sha256:sha1"

    def __post_init__(self) -> None:
        """Draw a private exponent unless one was given."""
        if not self.private:
            self.private = _random_private(self.prime)

    def public_blob(self) -> bytes:
        """``<PEM params>---BPUB---<hex g^x>---EPUB---``: this server's DH blob."""
        return encode_public_blob(
            dh_parameters_pem(self.prime, self.generator),
            pow(self.generator, self.private, self.prime),
        )

    def challenge(self, *, tag: bytes = b"abcdEFGH", signed: bool = True) -> bytes:
        """``kXGS_cert``: the DH blob (signed with :attr:`key`, or in clear), certificate, tag.

        The unsigned form is what servers before 10400 send: the blob in a
        ``kXRS_puk`` bucket, no cipher or digest lists.
        """
        inner = encode_message(STEP_SERVER_CERT, [Bucket(BUCKET_RTAG, tag)])
        if not signed:
            agreement = [Bucket(BUCKET_PUK, self.public_blob())]
        else:
            if self.key is None:
                raise CredentialError("the signed exchange needs the server's private key")
            agreement = [
                Bucket(BUCKET_CIPHER, self.key.encrypt_private(self.public_blob())),
                Bucket(BUCKET_CIPHER_ALG, b"aes-128-cbc:bf-cbc"),
                Bucket(BUCKET_MD_ALG, self.digests),
            ]
        buckets = [
            *agreement,
            Bucket(BUCKET_X509, self.certificate_pem),
            Bucket(BUCKET_MAIN, inner),
        ]
        return encode_message(STEP_SERVER_CERT, buckets)

    def read_certificate(self, response: bytes, *, tag: bytes | None = None) -> SecgsiLogin:
        """What ``ServerDoCert`` does with ``kXGC_cert``: agree the key, open the main buffer.

        The client's DH blob arrives signed with its proxy key (recovered with
        the ``kXRS_puk`` public key sent beside it) when the cipher name
        carries ``#16``, in clear otherwise. With ``tag`` the client must
        have signed it with the key of the chain it sent.
        """
        step, buckets = decode_message(response)
        if step != STEP_CLIENT_CERT:
            raise CredentialError(f"expected kXGC_cert, got step {step}")
        by_type = {bucket.type: bucket.data for bucket in buckets}
        signed = by_type.get(BUCKET_CIPHER_ALG, b"").endswith(b"#16")
        if signed:
            # The signed exchange sends the proxy's public key itself, as PEM.
            public = load_public_key(by_type.get(BUCKET_PUK, b""))
            blob = public.decrypt_public(by_type.get(BUCKET_CIPHER, b""))
        else:
            blob = by_type.get(BUCKET_PUK, b"")
        secret = session_key(parse_peer_blob(blob), self.private, padded=signed)
        plain = unseal(secret, by_type.get(BUCKET_MAIN, b""), use_iv=signed)
        login = SecgsiLogin(
            key=secret,
            use_iv=signed,
            plain=plain,
            chain_pem=find_bucket(plain, BUCKET_X509) or b"",
            client_tag=find_bucket(plain, BUCKET_RTAG) or b"",
        )
        if tag is not None:
            _check_signed(login.client_key(), tag, find_bucket(plain, BUCKET_SIGNED_RTAG))
        return login

    def proxy_request(
        self, login: SecgsiLogin, request_der: bytes | None, *, tag: bytes = b"ijklMNOP"
    ) -> bytes:
        """``kXGS_pxyreq``: the certificate request (PEM) sealed under the session key.

        ``request_der=None`` leaves the request out, which a client must
        answer with a reason rather than a proxy.
        """
        inner = [Bucket(BUCKET_RTAG, tag)]
        if request_der is not None:
            inner.append(Bucket(BUCKET_X509_REQ, pem_encode("CERTIFICATE REQUEST", request_der)))
        sealed = seal(login.key, encode_message(STEP_SERVER_PXYREQ, inner), use_iv=login.use_iv)
        return encode_message(STEP_SERVER_PXYREQ, [Bucket(BUCKET_MAIN, sealed)])

    def read_signed_proxy(
        self, login: SecgsiLogin, response: bytes, *, tag: bytes = b"ijklMNOP"
    ) -> bytes:
        """``kXGC_sigpxy``, opened: the plain inner message, its tag signature checked.

        The delegated proxy is its ``kXRS_x509`` bucket; a client that would
        not or could not sign sends a ``kXRS_message`` saying why instead.
        """
        step, buckets = decode_message(response)
        if step != STEP_CLIENT_SIGPXY:
            raise CredentialError(f"expected kXGC_sigpxy, got step {step}")
        main = next((bucket.data for bucket in buckets if bucket.type == BUCKET_MAIN), b"")
        plain = unseal(login.key, main, use_iv=login.use_iv)
        _check_signed(login.client_key(), tag, find_bucket(plain, BUCKET_SIGNED_RTAG))
        return plain


def _check_signed(key: RSAPublicKey, tag: bytes, signature: bytes | None) -> None:
    """Refuse a reply whose signature over ``tag`` is missing or not ``key``'s."""
    if signature is None or not key.verify(tag, signature):
        raise CredentialError("the client did not sign the server's random tag")
