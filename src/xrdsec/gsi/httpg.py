"""httpg: Globus' "HTTP over GSI", as an ``http.client`` connection.

On the wire httpg is TLS: GSI's tokens are TLS records, and globus-gssapi
writes them to the socket without the length header it adds to anything else.
The one GSI addition is the delegation flag (:data:`~.gss.NO_DELEGATION`), a
single application-data byte the client sends as soon as the handshake
completes, and which CGSI-gSOAP (StoRM, DPM) and jGlobus (dCache) servers both
read before the HTTP request. SRM is the protocol that runs over it; none of
its operations needs a delegated credential, so the flag sent here is always
``0``, as it is from gfal2's srm-ifce. Host names are checked GSI's way
(:func:`~.gss.check_host`: ``host/fqdn`` common names count) rather than with
``ssl``'s check.

A globus-gssapi acceptor that negotiated TLS 1.3 also writes a NUL "your
turn" byte (:data:`~.gss.TURN`) after the handshake, which jGlobus does not.
Rather than guess whether to wait for it, the flag is sent at once and a NUL
in front of the first status line is skipped (:class:`TurnSkippingResponse`).

What stays with the client is everything that is not GSI: pooling, the SOAP
envelope, retries and how failures are worded (xgfalclient's
``plugins/srm/transport.py``, where this code lived before 0.4.0). The
acceptor side is :func:`xrdsec.testing.gsi.accept_httpg`.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass

from ..x509 import certificate_data
from .gss import NO_DELEGATION, TURN, GSIError, check_host

__all__ = ["HTTPGConnection", "Handshake", "TurnSkippingResponse"]


class TurnSkippingResponse(http.client.HTTPResponse):
    """A reply that may be preceded by a Globus TLS 1.3 turn byte."""

    def begin(self) -> None:
        """Read the status line and headers, after the turn byte if one came first.

        Only the first reply on a connection can be preceded by it, and a
        status line never starts with NUL, so peeking before every reply is
        safe. ``begin`` reads each reply once, before anything of its body.
        """
        if self.fp.peek(1)[:1] == TURN:
            self.fp.read(1)
        super().begin()


@dataclass(frozen=True, slots=True)
class Handshake:
    """How an :class:`HTTPGConnection` opens its GSI session.

    ``tls`` is the client TLS context (the X.509 credential and the grid
    CAs; ``ssl``'s own host check must be off, since GSI's is applied
    instead); ``connect_timeout`` bounds the TCP connect and the TLS
    handshake (``None`` waits forever); ``check_name`` turns on GSI's host
    name check (a client's "insecure" option turns it off).
    """

    tls: ssl.SSLContext
    connect_timeout: float | None
    check_name: bool


class HTTPGConnection(http.client.HTTPConnection):
    """``http.client`` over GSI-flavoured TLS: handshake, name check, flag byte.

    ``http.client`` does the HTTP; only :meth:`connect` differs from a plain
    ``HTTPSConnection``. Not thread-safe, like any ``HTTPConnection``: a
    pool must give each to one caller at a time.
    """

    response_class = TurnSkippingResponse

    def __init__(
        self, host: str, port: int, handshake: Handshake, *, timeout: float | None
    ) -> None:
        """A connection to ``host:port``, opened lazily by the first request.

        ``timeout`` is the per-operation socket timeout once the session is
        up (``None`` waits forever).
        """
        super().__init__(host, port, timeout=timeout)
        self.handshake = handshake

    def connect(self) -> None:
        """TCP, the TLS handshake, GSI's name check, then the delegation flag.

        The connect timeout covers everything up to the flag; the operation
        timeout applies from then on. Any failure closes the raw socket and
        propagates (``OSError``, ``ssl.SSLError`` or
        :class:`~.gss.GSIError`), for the client to word.
        """
        handshake = self.handshake
        raw = socket.create_connection((self.host, self.port), handshake.connect_timeout)
        try:
            raw.settimeout(handshake.connect_timeout)
            sock = handshake.tls.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise
        # TLS has taken the socket over (``raw`` is detached): close that one.
        try:
            self._present(sock)
        except BaseException:
            sock.close()
            raise
        self.sock = sock

    def _present(self, sock: ssl.SSLSocket) -> None:
        """GSI's name check (unless turned off), then the delegation flag."""
        if self.handshake.check_name:
            der = sock.getpeercert(binary_form=True)
            if der is None:
                raise GSIError("the peer presented no certificate")
            check_host(certificate_data(der), self.host)
        # The GSI delegation flag: servers read it before the request.
        sock.sendall(NO_DELEGATION)
        sock.settimeout(self.timeout)
