"""The Globus GSI GSS-API mechanism: TLS carried in tokens, plus delegation.

Globus GSI is SSL/TLS in disguise. ``gss_init_sec_context`` runs a TLS
handshake whose records are handed to the application as opaque tokens, and
the application ferries them however its protocol likes - GridFTP base64s
them into ``ADAT`` commands, LFC's Csec frames them, httpg writes them
straight to a socket (:mod:`.httpg`). Once the handshake is over,
``gss_wrap`` is a TLS application-data record and ``gss_unwrap`` decrypts
one.

Three things make it GSI rather than plain TLS, and all are here:

* **the turn.** Under TLS 1.3 the client finishes the handshake first, so a
  Globus acceptor (globus-gridftp-server, CGSI-gSOAP) answers the client's
  Finished with one encrypted zero byte (:data:`TURN`), and the client sends
  nothing more until it has read it. dCache's own GSI engine (its dcap and
  SRM doors) sends no turn and reads the flag at once; ``turn=False`` speaks
  to it.
* **the delegation byte.** Then the client sends one encrypted byte: ``0``
  for no delegation, ``D`` to delegate. After ``D`` the server sends a
  certificate request, and the client answers with the proxy it has signed -
  that certificate alone (``globus_gsi_proxy_sign_req`` writes one DER
  certificate, and a Globus acceptor reads exactly one: anything after it
  would be read as the protocol's first command). The acceptor completes the
  chain from the certificates the client presented in the handshake.
* **the name check.** A GSI server certificate names its host as
  ``CN=host/fqdn`` (or ``ftp/fqdn``) as often as plain ``CN=fqdn``, which
  ``ssl``'s hostname check does not accept, so :func:`check_host` does it.

``ssl_compatible`` is Globus's ``GSS_C_GLOBUS_SSL_COMPATIBLE``: plain TLS,
complete with the handshake, no turn and no delegation byte - what a GridFTP
``PROT P`` data channel speaks. Both ends of such a channel present the
*user's* credential and accept a proxy chain from the peer, with no host name
to check; :func:`data_contexts` builds that pair of TLS contexts (it was
xgfalclient's ``plugins/gridftp/gsi.py`` until 0.4.0).

:class:`SecurityContext` is ``ssl.SSLObject`` over a pair of memory BIOs,
so it works for any transport. Its acceptor half is what the in-process test
servers run (:mod:`xrdsec.testing.gsi` has their loops), and serves anyone who
wants to host a GSI endpoint in Python.

The state machine is the part to read first: every state names what this
side is waiting for, and :meth:`SecurityContext.step` may advance through
several states on one token because TLS can deliver the end of the handshake
and the first application record together.

Until 0.4.0 this was xgfalclient's ``crypto/gsi.py``. Credentials are
duck-typed (:class:`DelegatingCredential`): xrdsec's
:class:`~xrdsec.x509.ProxyCredential` and xgfalclient's ``Credential`` both
delegate. Certificates come back as :class:`~xrdsec.x509.CertificateData`.
"""

from __future__ import annotations

import os
import ssl
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from ..delegation import DelegationError, make_proxy_request, sign_globus_request
from ..der import DERError, parse, parse_one
from ..rsa import RSAPrivateKey, private_key_pem
from ..x509 import (
    SUBJECT_ALT_NAME_OID,
    CertificateData,
    ProxyCredential,
    certificate_data,
    split_der_certificates,
)

__all__ = [
    "DELEGATE",
    "NO_DELEGATION",
    "TURN",
    "DelegatedCredential",
    "DelegatingCredential",
    "GSIError",
    "SecurityContext",
    "check_host",
    "data_contexts",
    "dns_names",
    "peer_chain_der",
]

#: The delegation flag a client sends when it keeps its credential to itself.
NO_DELEGATION = b"0"
#: The delegation flag that asks the acceptor for a proxy request to sign.
DELEGATE = b"D"
#: What a TLS 1.3 acceptor sends to hand the turn back after the handshake.
TURN = b"\x00"


class GSIError(Exception):
    """The GSI exchange failed: bad token, refused delegation, name mismatch.

    Deliberately not an errno-carrying error: each protocol wraps it with the
    code its own client reports (gfal2 says ``EACCES`` for a refused
    handshake or a name mismatch, srm-ifce ``ECOMM``).
    """


class _Encoded(Protocol):
    """A certificate that carries its DER: every certificate view on the stack does."""

    @property
    def der(self) -> bytes:
        """The certificate's DER."""
        ...


class DelegatingCredential(Protocol):
    """What a client delegates with: a chain, leaf first, and the leaf's private key.

    xrdsec's :class:`~xrdsec.x509.ProxyCredential` and xgfalclient's
    ``Credential`` both qualify; only the DER of each link and the key are
    read, by :func:`xrdsec.delegation.sign_globus_request`.
    """

    @property
    def chain(self) -> Sequence[_Encoded]:
        """The certificates, leaf (the signer) first."""
        ...

    @property
    def key(self) -> object:
        """The leaf's private key: RSA (either form) or EC."""
        ...


@dataclass(frozen=True, slots=True)
class DelegatedCredential:
    """What an acceptor ends up holding after the client delegated to it.

    ``key`` is the private key the acceptor generated for the request (it
    never left the acceptor); ``chain`` starts with the proxy the client
    signed for it, followed by the client's own chain.
    """

    key: RSAPrivateKey
    chain: tuple[CertificateData, ...]

    def credential(self) -> ProxyCredential:
        """The delegated proxy as a :class:`~xrdsec.x509.ProxyCredential`, to present onwards."""
        return ProxyCredential(chain=self.chain, key=self.key)

    def pem(self) -> bytes:
        """A proxy file: certificate, key, then the rest of the chain (Globus' order)."""
        first, *rest = self.chain
        return first.pem() + private_key_pem(self.key) + b"".join(link.pem() for link in rest)


def peer_chain_der(tls: Any) -> list[bytes]:
    """The certificates a TLS peer sent (DER, leaf first).

    Rebuilding a delegated proxy's chain from a handshake needs every
    certificate the peer presented, not just the leaf ``getpeercert`` gives.
    ``get_unverified_chain`` is a public ``SSLSocket``/``SSLObject`` method
    from Python 3.13; on 3.11 and 3.12 the same call exists only on the
    private ``_sslobj`` underneath, returns ``_ssl.Certificate`` objects
    rather than DER, and ``None`` (rather than ``[]``) when the peer sent
    nothing. Once the floor reaches 3.13 this collapses to the public call.
    (Until 0.4.0 this lived in xgfalclient's ``_compat``.)
    """
    # ``tls`` is typed ``Any`` because the fallback reaches a private attribute
    # typeshed does not describe; an ``SSLObject`` or ``SSLSocket`` is expected.
    whole = getattr(tls, "get_unverified_chain", None) or tls._sslobj.get_unverified_chain
    return [_der(link) for link in whole() or ()]


def _der(link: Any) -> bytes:
    """One chain entry as DER: bytes already (3.13+), or a ``Certificate`` to encode."""
    public_bytes = getattr(link, "public_bytes", None)
    return bytes(public_bytes(2)) if public_bytes is not None else bytes(link)  # 2 = DER


class SecurityContext:
    """One side of a GSI security context, driven by tokens.

    Client::

        ctx = SecurityContext(tls, delegate=credential)
        token = ctx.step()                  # ClientHello
        while not ctx.complete:
            token = ctx.step(send_and_receive(token))

    ``step`` takes the peer's latest token (empty to start) and returns the
    token to send back, which may be empty. ``complete`` turns true once the
    handshake, the delegation byte and any delegation are done.

    States (``_state``): ``handshake`` -> ``turn`` (TLS 1.3 client, waiting
    for the acceptor's zero byte) or ``flag`` (server, waiting for the
    delegation flag) -> ``request`` (client, waiting for the proxy request)
    or ``chain`` (server, waiting for the signed proxy) -> ``done``.

    Not thread-safe: one context belongs to one connection's I/O loop.
    """

    def __init__(
        self,
        tls: ssl.SSLContext,
        *,
        server_side: bool = False,
        server_hostname: str | None = None,
        delegate: DelegatingCredential | None = None,
        limited: bool = False,
        lifetime: float | None = None,
        delegation_key: RSAPrivateKey | None = None,
        ssl_compatible: bool = False,
        turn: bool = True,
    ) -> None:
        """Wrap ``tls`` over two memory BIOs; nothing is sent until :meth:`step`.

        ``tls`` must already hold this side's certificate and trust anchors;
        the context does not verify the peer's *name* (the TLS context's own
        hostname check is normally off for GSI) - call :meth:`check_host`
        once complete. On the client, ``delegate`` is the credential to sign
        a proxy with (``limited`` and ``lifetime``, in seconds, shape that
        proxy); on the server, ``delegation_key`` fixes the requested key
        (tests use it to avoid a 2048-bit key generation per case) and
        :attr:`delegated` holds the result. ``ssl_compatible`` and ``turn``
        are described in the module docstring.

        Public API with many callers (GridFTP, LFC, dcap and their test
        servers), hence the long keyword list rather than an options object.
        """
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self.tls = tls.wrap_bio(
            self._in, self._out, server_side=server_side, server_hostname=server_hostname
        )
        self.server_side = server_side
        self.delegate = delegate
        self.limited = limited
        self.lifetime = lifetime
        self.delegation_key = delegation_key
        self.delegated: DelegatedCredential | None = None
        self.ssl_compatible = ssl_compatible
        self.turn = turn
        self.complete = False
        self._state = "handshake"
        self._pending = b""

    # -- the handshake -------------------------------------------------------------

    def step(self, token: bytes = b"") -> bytes:
        """Consume the peer's ``token``; return what to send it next.

        Raises :class:`GSIError` for a failed handshake, an undecryptable
        record, an unexpected flag or a proxy that does not match the
        request. An empty return value is normal (the peer's turn).
        """
        if token:
            self._in.write(token)
        if self._state == "handshake":
            self._handshake()
        if self._state != "handshake":
            self._after_handshake()
        return self._out.read()

    def _handshake(self) -> None:
        """Advance the TLS handshake; when it completes, pick the GSI state that follows."""
        try:
            self.tls.do_handshake()
        except ssl.SSLWantReadError:
            return
        except ssl.SSLError as exc:
            raise GSIError(f"TLS handshake failed: {exc}") from exc
        # The turn exists only under TLS 1.3, where the client's Finished is
        # the handshake's last flight; under 1.2 the server spoke last, so the
        # client already has the turn.
        tls13 = self.turn and self.tls.version() == "TLSv1.3"
        if self.ssl_compatible:
            self._finish()
        elif self.server_side:
            if tls13:
                self.tls.write(TURN)
            self._state = "flag"
        elif tls13:
            self._state = "turn"
        else:
            self._send_flag()

    def _send_flag(self) -> None:
        """Client: send the delegation flag; without delegation the context is complete."""
        self.tls.write(NO_DELEGATION if self.delegate is None else DELEGATE)
        self._state = "request" if self.delegate is not None else "done"
        self.complete = self.delegate is None

    def _after_handshake(self) -> None:
        """Feed decrypted bytes through the post-handshake states, as far as they go.

        The ``if`` chain (not ``elif``) is deliberate: one batch of bytes can
        carry the turn and the request together, and each state consumes
        only its own prefix of ``_pending``.
        """
        self._pending += self._drain()
        if self._state == "turn":
            if not self._pending:
                return  # the acceptor has not handed the turn back yet
            self._pending = self._pending[1:]  # the TURN byte; its value is not checked
            self._send_flag()
        if self._state == "flag" and self._pending:
            self._read_flag()
        if self._state == "request" and self._pending:
            self._answer_request()
        elif self._state == "chain" and self._pending:
            self._accept_chain()

    def _read_flag(self) -> None:
        """Server: act on the client's delegation flag, the first pending byte."""
        flag, self._pending = self._pending[:1], self._pending[1:]
        if flag == DELEGATE:
            self._send_request()
        elif flag == NO_DELEGATION:
            self._finish()
        else:
            raise GSIError(f"unexpected GSI delegation flag {flag!r}")

    def _drain(self) -> bytes:
        """All plaintext the buffered records hold, possibly none.

        A close_notify (``SSLZeroReturnError``) ends the data without
        failing: a peer that closes after its last token has said all it
        will say, and the caller decides whether that was enough.
        """
        chunks = []
        while True:
            try:
                data = self.tls.read(65536)
            except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                break
            except ssl.SSLError as exc:
                raise GSIError(f"cannot decrypt GSI token: {exc}") from exc
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)

    def _finish(self) -> None:
        """Mark the context complete; only :meth:`wrap`/:meth:`unwrap` remain."""
        self._state = "done"
        self.complete = True

    # -- delegation, client side ---------------------------------------------------------

    def _answer_request(self) -> None:
        """Client: once the whole DER request is here, sign it and send the proxy.

        The request may arrive over several tokens; parsing its outer DER
        header tells whether all of it has. Anything after it stays pending.
        """
        try:
            _, end = parse(self._pending)
        except DERError:
            return  # the request has not fully arrived yet
        request, self._pending = self._pending[:end], self._pending[end:]
        delegate = self.delegate
        assert delegate is not None  # only a delegating client reaches "request"
        try:
            certificate = sign_globus_request(
                request,
                [link.der for link in delegate.chain],
                delegate.key,
                lifetime=self.lifetime,
                limited=self.limited,
            )
        except DelegationError as exc:
            raise GSIError(f"cannot sign the delegation request: {exc}") from exc
        self.tls.write(certificate)  # alone: the acceptor has the rest of the chain
        self._finish()

    # -- delegation, server side -----------------------------------------------------------

    def _send_request(self) -> None:
        """Server: ask the client to certify our (new, or given) key."""
        if self.delegation_key is None:
            self.delegation_key = RSAPrivateKey.generate(2048)
        self.tls.write(make_proxy_request(self.delegation_key))
        self._state = "chain"

    def _accept_chain(self) -> None:
        """Server: take the signed proxy, check it certifies our key, and keep it.

        The key check is what makes delegation safe for the acceptor: a
        client that answered with some other certificate would otherwise
        leave us holding a "proxy" whose key we do not have. A client that
        sends the whole chain (older Globus did) is taken as it is; one
        certificate alone is completed from the handshake, the Globus way.
        """
        try:
            chain = split_der_certificates(self._pending)
        except DERError:
            return  # more of the chain is still to come
        key = self.delegation_key
        assert key is not None  # set by _send_request before "chain"
        if chain[0].public_key != key.public:
            raise GSIError("the delegated certificate does not certify the requested key")
        if len(chain) == 1:
            chain.extend(certificate_data(der) for der in peer_chain_der(self.tls))
        self.delegated = DelegatedCredential(key, tuple(chain))
        self._pending = b""
        self._finish()

    # -- after the handshake ----------------------------------------------------------------

    def wrap(self, data: bytes) -> bytes:
        """``gss_wrap``: encrypt ``data`` into a token (one or more TLS records)."""
        self.tls.write(data)
        return self._out.read()

    def unwrap(self, token: bytes) -> bytes:
        """``gss_unwrap``: every byte of plaintext ``token`` carries.

        A token holding only part of a record yields ``b""`` now and the
        plaintext with the next token, as the TLS layer buffers it.
        """
        self._in.write(token)
        return self._drain()

    def peer_certificate(self) -> CertificateData | None:
        """The peer's end-entity certificate, or None (no handshake yet, or none sent)."""
        der = self.tls.getpeercert(binary_form=True)
        return certificate_data(der) if der else None

    def check_host(self, hostname: str) -> None:
        """Raise :class:`GSIError` unless the peer's certificate names ``hostname``."""
        certificate = self.peer_certificate()
        if certificate is None:
            raise GSIError("the peer presented no certificate")
        check_host(certificate, hostname)


def dns_names(certificate: CertificateData) -> list[str]:
    """The ``dNSName`` entries of the subjectAltName extension.

    An unparsable extension yields no names (and so falls back to the CN),
    rather than an error: the name check then fails or passes on what can
    be read.
    """
    found = certificate.extension_values.get(SUBJECT_ALT_NAME_OID)
    if found is None:
        return []
    try:
        names = parse_one(found[1]).children()
    except DERError:
        return []
    # [2] IMPLICIT IA5String is dNSName in RFC 5280's GeneralName CHOICE.
    return [name.value.decode("ascii", "replace") for name in names if name.tag == 0x82]


def _matches(pattern: str, hostname: str) -> bool:
    """RFC 6125 matching: case-insensitive, trailing dot ignored, ``*.`` one label only.

    A wildcard covers exactly the left-most label, so ``*.example.org``
    matches ``a.example.org`` but neither ``example.org`` nor
    ``a.b.example.org``; partial-label wildcards (``a*.example.org``) are
    not honoured at all.
    """
    pattern, hostname = pattern.lower().rstrip("."), hostname.lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, rest = hostname.partition(".")
        return bool(head) and rest == pattern[2:]
    return pattern == hostname


def check_host(certificate: CertificateData, hostname: str) -> None:
    """GSI's host name check: SAN DNS names, then ``CN=[host/|ftp/]fqdn``.

    Unlike RFC 6125, the CN is consulted even when DNS names are present:
    grid host certificates often name the service-prefixed host in the CN
    only, and refusing those would refuse real servers. Any prefix before
    ``/`` is dropped, not just ``host``/``ftp``. Raises :class:`GSIError` on
    mismatch.
    """
    candidates = dns_names(certificate)
    for common in certificate.subject.get("CN"):
        candidates.append(common.split("/", 1)[1] if "/" in common else common)
    if not any(_matches(candidate, hostname) for candidate in candidates):
        raise GSIError(
            f"the server certificate {certificate.subject} does not match host {hostname}"
        )


#: Built pairs by ``(cert, key, ca_path, cert mtime)``. Loading a chain and a
#: CA directory costs milliseconds per context, and a GridFTP session with
#: ``DCAU`` asks for a pair per data channel; the mtime makes a renewed proxy
#: load afresh. Entries are never evicted: a process sees few credentials.
_DATA_CONTEXTS: dict[tuple[object, ...], tuple[ssl.SSLContext, ssl.SSLContext]] = {}
#: Guards :data:`_DATA_CONTEXTS`; held while building, so two threads never both load.
_DATA_CONTEXTS_LOCK = threading.Lock()


def data_contexts(
    cert: str, key: str, ca_path: str | None
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """``(initiator, acceptor)`` TLS contexts for a GSI data channel (GridFTP ``DCAU A``).

    Both present the credential in ``cert``/``key`` (a proxy, typically)
    and verify the peer against the CA directory, proxies allowed. Host
    names mean nothing here - the peer is a person - so the caller checks
    the peer's identity after the handshake. Session tickets are off on
    the acceptor: after the handshake the stream may carry clear data, and
    a ticket arriving there would be read as file content.

    The pair is cached and shared: nothing may change a context it returns.
    """
    key_id = (cert, key, ca_path, os.stat(cert).st_mtime)
    with _DATA_CONTEXTS_LOCK:
        found = _DATA_CONTEXTS.get(key_id)
        if found is None:
            initiator = _data_context(ssl.PROTOCOL_TLS_CLIENT, cert, key, ca_path)
            acceptor = _data_context(ssl.PROTOCOL_TLS_SERVER, cert, key, ca_path)
            acceptor.num_tickets = 0
            found = _DATA_CONTEXTS[key_id] = (initiator, acceptor)
        return found


def _data_context(protocol: int, cert: str, key: str, ca_path: str | None) -> ssl.SSLContext:
    """One side of :func:`data_contexts`: mutual TLS with proxies, no host check.

    ``VERIFY_X509_STRICT`` (which Python 3.13's default contexts turn on) is
    cleared: grid CA and proxy certificates do not always meet its RFC 5280
    profile checks. With no ``ca_path`` nothing can verify the peer, and
    the handshake fails - there is no unauthenticated fallback.
    """
    context = ssl.SSLContext(protocol)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags |= ssl.VERIFY_ALLOW_PROXY_CERTS
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if ca_path:
        context.load_verify_locations(capath=ca_path)
    context.load_cert_chain(cert, key)
    return context
