"""A generic threaded HTTP(S) test server that in-process fakes are built on.

:class:`FakeHTTPSServer` is the plumbing every in-process HTTP fake needs and
none should have to write again: TLS applied per accepted connection (so a
client that never finishes its handshake holds up only its own thread), the
client certificate chain captured per request (:func:`peer_identity`),
HTTP/1.1 keep-alive with exact ``Content-Length`` replies, chunked and
``Content-Length`` request bodies (:func:`read_body`), a log of every request,
and fault injection - a status instead of the real answer, a delay before it,
a stall in the middle of it, a truncated body, a hang-up, or a server that
goes silent - per :class:`Fault`. What a particular service *says* is a route
table of plain functions, ``(method, path pattern) -> handler``::

    with FakeHTTPSServer(tls=pki.server_context()) as srv:
        srv.route("GET", r"/f/(?P<name>[^/]+)", lambda r: Response(200, data[r.params["name"]]))
        srv.add_fault(Fault("GET", "/f/big", truncate=10))       # dies ten bytes in
        ...                                                       # drive a client at srv.url
        srv.requests[-1].peer.identity                            # /DC=org/.../CN=Test User

:class:`~xrdsec.testing.voms.FakeVOMSServer` and xrdarc's fake A-REX are
route tables on it. A fake that must answer before a request's body is read
(``Expect: 100-continue``) or stream a body (a storage element) supplies its
own request handler instead (:attr:`FakeHTTPSServer.handler_class`) and
keeps the listener, the request log, the faults and the identities: that is
how xrdhttp's fake storage element (:mod:`xrdhttp.testing`) is built. It
lives in xrdsec rather than with the HTTP code because a client's identity is
a certificate chain, read with :mod:`xrdsec.x509`, and every fake that checks
one runs with :mod:`xrdsec.testing.pki`. What a reply *says* - byte ranges,
WebDAV ``multistatus`` - is HTTP, and its helpers are xrdhttp's
(:func:`xrdhttp.testing.ranged_reply`, :func:`xrdhttp.testing.propfind_reply`).

Threading: each connection gets a daemon thread (a leaked server cannot hang
interpreter exit); the route table, the fault list and the request log are
guarded by one lock, and handlers run *outside* it, so a handler may block
or call back into the same server over a new connection. :meth:`stop` hangs
up every open connection, as a dead server would; with
:attr:`FakeHTTPSServer.join_timeout` set it also waits for the connection
threads to finish, so nothing a handler does lands after the test moved on.

Stability: public test API, versioned with the package.
"""

from __future__ import annotations

import contextlib
import re
import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar, Self, cast

__all__ = [
    "FakeHTTPSServer",
    "Fault",
    "Listener",
    "PeerIdentity",
    "Request",
    "Response",
    "Route",
    "TLSServer",
    "hold",
    "peer_identity",
    "read_body",
]

#: The common names a proxy appends to its issuer's subject: an RFC 3820
#: serial, or GT2's ``proxy`` / ``limited proxy``.
_PROXY_CN = re.compile(r"\d+|proxy|limited proxy")


# ---------------------------------------------------------------------------
# Who is calling
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """The certificate chain a TLS client presented, as DER, leaf first.

    On Python 3.13 and later this is the whole chain the client sent
    (``SSLSocket.get_unverified_chain``); before 3.13 the standard library
    exposes only the leaf, so :attr:`chain` holds that alone. Either way
    :attr:`identity` - the end-entity name a grid service authorises - is
    right for a proxy, because a proxy's subject *is* its user's subject
    plus proxy CNs.
    """

    chain: tuple[bytes, ...]

    @property
    def certificate(self) -> bytes:
        """The leaf the client authenticated with: its proxy, or its user certificate."""
        return self.chain[0]

    @property
    def subject(self) -> str:
        """The leaf's subject in OpenSSL's slash form, proxy CNs included."""
        from ..x509 import certificate_data

        return str(certificate_data(self.certificate).subject)

    @property
    def identity(self) -> str:
        """The end-entity subject: :attr:`subject` with trailing proxy CNs removed.

        This is how A-REX, dCache and VOMS name the user behind a proxy. At
        least one RDN is always kept, so a certificate whose only RDN looks
        like a proxy CN is not reduced to nothing.
        """
        from ..x509 import Name, certificate_data

        rdns = list(certificate_data(self.certificate).subject.rdns)
        while len(rdns) > 1 and rdns[-1][0] == "CN" and _PROXY_CN.fullmatch(rdns[-1][1]):
            rdns.pop()
        return str(Name(tuple(rdns)))


def peer_identity(connection: object) -> PeerIdentity | None:
    """What the client at the far end of ``connection`` authenticated with, or ``None``.

    ``None`` for a plain socket, or a TLS one whose client sent no
    certificate (a server context with ``CERT_NONE`` never asks for one).
    """
    getter = getattr(connection, "getpeercert", None)
    leaf = getter(binary_form=True) if getter is not None else None
    if not leaf:
        return None
    unverified = getattr(connection, "get_unverified_chain", None)
    chain = unverified() if unverified is not None else None
    return PeerIdentity(tuple(bytes(link) for link in chain) if chain else (leaf,))


# ---------------------------------------------------------------------------
# Requests, responses and faults
# ---------------------------------------------------------------------------


@dataclass
class Response:
    """One answer. ``reason`` empty means the standard phrase for ``status``.

    ``Content-Length`` is always added by the server, so it must not be in
    ``headers``; a ``HEAD`` request gets the headers and no body.
    """

    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    reason: str = ""


@dataclass
class Request:
    """One request as the server read it; handlers get it and the log keeps it."""

    method: str
    #: The request target exactly as sent, query and all.
    target: str
    #: The path, percent-decoded once, without the query.
    path: str
    #: Query parameters, decoded; every value of a repeated key, in order.
    query: dict[str, list[str]]
    #: Header names and values as sent (a repeated header keeps its last value).
    headers: dict[str, str]
    body: bytes
    #: The client certificate chain, or ``None`` without TLS or a client certificate.
    peer: PeerIdentity | None = None
    #: The named groups of the route pattern that matched.
    params: dict[str, str] = field(default_factory=dict)
    #: Every header field line as sent, in order, repeats included; read it
    #: through :meth:`get_all`. :attr:`headers` stays a plain ``dict`` for
    #: the handlers written against it, which is why repeats need this too.
    header_fields: tuple[tuple[str, str], ...] = ()

    def header(self, name: str) -> str | None:
        """A header, looked up case-insensitively (HTTP names are)."""
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return None

    def get_all(self, name: str) -> list[str]:
        """Every value of header ``name``, case-insensitively, in the order sent.

        What :meth:`email.message.Message.get_all` answers, but ``[]``
        rather than ``None`` for none. A repeated field is how a client
        sends a list it did not comma-join (``Want-Digest``, several
        ``Cookie`` lines, a duplicated ``Content-Length`` a server must
        refuse - RFC 9110 section 5.3), and a test of that needs every line.
        A :class:`Request` built by hand without :attr:`header_fields` answers
        from :attr:`headers`.
        """
        wanted = name.lower()
        fields = self.header_fields or tuple(self.headers.items())
        return [value for key, value in fields if key.lower() == wanted]

    def param(self, name: str, default: str = "") -> str:
        """The first value of query parameter ``name``, else ``default``."""
        values = self.query.get(name)
        return values[0] if values else default


#: A route handler: answer the request, or return ``None`` to hang up without answering.
Handler = Callable[[Request], Response | None]


@dataclass
class Fault:
    """What to do instead of (or to) the real answer, for matching requests.

    ``method`` (``None`` for any) must equal the request method, and
    ``pattern`` (``None`` for any) must be found with :func:`re.search` in
    the decoded target, path and query. The first matching fault in
    :attr:`FakeHTTPSServer.faults` is used; it is removed once it has been
    used ``times`` times (``None``: never removed).

    In order of effect: ``delay`` seconds pass first; then ``drop`` hangs up
    without a word; then ``hold`` without ``truncate`` goes silent - no
    answer at all, the connection held open for ``hold`` seconds or until
    the client hangs up - as a hung server does; then ``status`` (unless
    ``None``) replaces the real answer with ``reason``/``body``/``headers``,
    otherwise the route answers; ``stall`` then pauses between the headers
    and the body (a server that froze mid-reply), and ``truncate`` sends only
    that many body bytes of the full promised length before closing - after
    holding the connection silent for ``hold`` seconds, if that is set.
    """

    method: str | None = None
    pattern: str | None = None
    status: int | None = 500
    reason: str = ""
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    times: int | None = 1
    drop: bool = False
    delay: float = 0.0
    stall: float = 0.0
    truncate: int | None = None
    hold: float = 0.0

    def matches(self, method: str, target: str) -> bool:
        """Whether this fault applies to ``method`` on the decoded ``target``."""
        if self.method is not None and self.method != method:
            return False
        return self.pattern is None or re.search(self.pattern, target) is not None


@dataclass(frozen=True, slots=True)
class Route:
    """One entry of the route table: ``method`` (``*`` for any) and a path regex."""

    method: str
    pattern: re.Pattern[str]
    handler: Handler


def read_body(handler: BaseHTTPRequestHandler) -> bytes:
    """The request body as sent: de-chunked (RFC 9112 section 7.1) or ``Content-Length`` bytes.

    Chunk extensions after ``;`` are ignored, and trailer fields are read
    and discarded up to the blank line, so a keep-alive connection stays in
    step for the next request. No body (neither header) is ``b""``.
    """
    headers, stream = handler.headers, handler.rfile
    if headers.get("Transfer-Encoding", "").lower() == "chunked":
        chunks: list[bytes] = []
        while size := int(stream.readline().split(b";")[0].strip() or b"0", 16):
            chunks.append(stream.read(size))
            stream.readline()  # the CRLF that ends each chunk
        while stream.readline().strip():
            pass  # trailer fields, then the final empty line
        return b"".join(chunks)
    length = int(headers.get("Content-Length") or 0)
    return stream.read(length) if length > 0 else b""


# ---------------------------------------------------------------------------
# The socket server
# ---------------------------------------------------------------------------


class TLSServer(ThreadingHTTPServer):
    """A threading HTTP server that wraps each accepted connection in ``tls`` (if set).

    TLS is applied in :meth:`finish_request`, on the connection's own
    thread, rather than by wrapping the listener, so a client that connects
    and never finishes its handshake holds up only itself. Subclasses hear
    about each live connection through :meth:`connected` and
    :meth:`disconnected`. A client hanging up mid-request is normal for a
    test server and is not reported.
    """

    allow_reuse_address = True
    daemon_threads = True
    tls: ssl.SSLContext | None = None

    def finish_request(self, request: Any, client_address: Any) -> None:
        """Handshake (when TLS is on), then serve the connection; always close what was opened."""
        if self.tls is not None:
            # The wrapper takes the descriptor over from ``request``, which is
            # left detached, so it is the wrapper that has to be closed.
            request = self.tls.wrap_socket(cast("socket.socket", request), server_side=True)
        self.connected(request)
        try:
            super().finish_request(request, client_address)
        finally:
            self.disconnected(request)
            if self.tls is not None:
                self.shutdown_request(request)

    def connected(self, connection: Any) -> None:
        """A connection is up (handshake done); the default does nothing."""

    def disconnected(self, connection: Any) -> None:
        """A connection is finished with; the default does nothing."""

    def handle_error(self, request: object, client_address: object) -> None:
        """A client that hangs up, or fails its handshake, is normal here, not a failure."""


def _endpoint(server: TLSServer) -> tuple[str, int]:
    """The bound ``(host, port)``: narrower than ``socketserver``'s address type."""
    host, port = cast("tuple[str, int]", server.server_address)[:2]
    return host, port


class Listener(TLSServer):
    """:class:`TLSServer` with a back-reference to its fake, which counts live connections.

    Public so a fake's own request handler (:attr:`FakeHTTPSServer.handler_class`)
    can name its ``server``: ``self.server.fake`` is the
    :class:`FakeHTTPSServer` it serves.
    """

    fake: FakeHTTPSServer

    def connected(self, connection: Any) -> None:
        """Count it and remember it, so :meth:`FakeHTTPSServer.stop` can hang up on it."""
        self.fake._connected(connection, True)

    def disconnected(self, connection: Any) -> None:
        """Forget it."""
        self.fake._connected(connection, False)

    def process_request(self, request: Any, client_address: Any) -> None:
        """Serve the connection on a new daemon thread that :meth:`FakeHTTPSServer.stop` can join.

        ``socketserver`` only keeps track of non-daemon threads (its
        ``block_on_close``), and a non-daemon thread leaked by a test could
        hang interpreter exit, so the thread is started here instead and
        handed to the fake before it runs: a thread registered only from
        inside itself could be missed by a ``stop`` racing its start.
        """
        thread = threading.Thread(
            target=self.process_request_thread,
            args=(request, client_address),
            name=f"{self.fake.name}-connection",
            daemon=True,
        )
        self.fake._started(thread)
        thread.start()


class _Handler(BaseHTTPRequestHandler):
    """Reads one request at a time and hands it to :meth:`FakeHTTPSServer.respond`."""

    protocol_version = "HTTP/1.1"
    server: Listener

    def version_string(self) -> str:
        """The ``Server`` header: the fake's name."""
        return self.server.fake.name

    def log_message(self, format: str, *args: object) -> None:
        """Quiet: tests read :attr:`FakeHTTPSServer.requests`, not stderr."""

    def handle_one_request(self) -> None:
        """Parse the request line and headers, then serve whatever the method is.

        Every method goes through :meth:`_serve`, so a route table can answer
        verbs ``http.server`` has never heard of (``PROPFIND``, ``MKCOL``...).
        """
        try:
            self.raw_requestline = self.rfile.readline(65537)
        except (OSError, ValueError):
            self.close_connection = True
            return
        if not self.raw_requestline or not self.parse_request():
            self.close_connection = True
            return
        self._serve()
        self.wfile.flush()

    def _serve(self) -> None:
        """Record, fault, route and answer one request."""
        fake = self.server.fake
        request = fake.record(self.command, self.path, self.headers, read_body(self), self)
        fault = fake.take_fault(request)
        if fault is not None:
            time.sleep(fault.delay)
            if fault.hold and fault.truncate is None and not fault.drop:
                hold(self.connection, fault.hold)
                self._hang_up()
                return
        reply = fake._answer(request, fault)
        if reply is None:
            self._hang_up()
            return
        self._reply(reply, fault)

    def _hang_up(self) -> None:
        """Close without answering, as a crashed or hostile server does."""
        self.close_connection = True
        with contextlib.suppress(OSError):
            self.connection.shutdown(socket.SHUT_RDWR)

    def _reply(self, reply: Response, fault: Fault | None) -> None:
        """Send ``reply``, applying the fault's stall and truncation."""
        reason = reply.reason.replace("\r", " ").replace("\n", " ") or None
        self.send_response(reply.status, reason)
        for name, value in reply.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(reply.body)))
        self.end_headers()
        if self.command != "HEAD":
            self._send_body(reply.body, fault)

    def _send_body(self, body: bytes, fault: Fault | None) -> None:
        """Write ``body``, first pausing for a stalling fault, cut short for a truncating one."""
        if fault is not None and fault.stall:
            self.wfile.flush()  # the headers reach the client; the body does not, yet
            time.sleep(fault.stall)
        cut = fault.truncate if fault is not None else None
        if cut is not None and cut < len(body):
            self.wfile.write(body[:cut])
            self.wfile.flush()
            if fault is not None and fault.hold:
                hold(self.connection, fault.hold)
            self._hang_up()
            return
        self.wfile.write(body)


def hold(connection: socket.socket, seconds: float) -> None:
    """Say nothing for up to ``seconds``, or until the client hangs up, whichever is first.

    Waiting in ``recv`` rather than sleeping: a client that gives up (or a
    :meth:`FakeHTTPSServer.stop` that shuts the connection down) ends the
    silence at once, and a client waiting for an answer sends nothing
    meanwhile. The caller hangs up afterwards.
    """
    connection.settimeout(seconds)
    with contextlib.suppress(OSError):  # the time is up, or the client went away
        connection.recv(1)


def _split(target: str) -> tuple[str, dict[str, list[str]]]:
    """The decoded path and query of a request target (origin or absolute form)."""
    parts = urllib.parse.urlsplit(target)
    query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    return urllib.parse.unquote(parts.path) or "/", query


class FakeHTTPSServer:
    """A threaded HTTP(S) server on loopback answering from a route table.

    ``tls`` is a server-side context (``pki.server_context()``); ``None``
    serves plain HTTP. ``name`` is the ``Server`` header and the thread
    name. The port is bound at construction (``port=0``: the kernel picks
    one, so parallel test workers never collide) and released by
    :meth:`stop`. Routes, faults and the request log are public and may be
    changed between two requests of a test.

    Subclasses may override :meth:`respond` to dispatch some other way; the
    fault handling, logging and wire behaviour stay. A subclass that needs
    to speak differently on the wire - answer before a body is read, stream
    one - sets :attr:`handler_class` and gets the listener, the request
    log, the faults and the identities all the same.
    """

    #: The request handler each connection gets: a
    #: :class:`http.server.BaseHTTPRequestHandler` whose ``server`` is a
    #: :class:`Listener`. The default reads each request whole, logs it with
    #: :meth:`record`, applies :meth:`take_fault` and answers from :meth:`respond`.
    handler_class: ClassVar[type[BaseHTTPRequestHandler]] = _Handler

    def __init__(
        self,
        *,
        tls: ssl.SSLContext | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        name: str = "xrdsec-fake-https",
        join_timeout: float | None = None,
    ) -> None:
        """Bind the port; nothing is served until :meth:`start`."""
        self.tls = tls
        self.name = name
        #: How long :meth:`stop` waits, in all, for connection threads to
        #: finish after hanging up on them; ``None`` (the default) does not
        #: wait. Waiting makes teardown deterministic - a handler that was
        #: mid-request cannot append to the log, touch a temporary directory
        #: or hit a ``ResourceWarning`` after the test that started it has
        #: ended - at the cost of up to this long per stop when a handler is
        #: asleep in a ``delay`` or ``stall`` fault. May be changed any time
        #: before :meth:`stop`.
        self.join_timeout = join_timeout
        #: The route table, tried in order: see :meth:`route`.
        self.routes: list[Route] = []
        #: Pending faults, tried in order: see :class:`Fault`.
        self.faults: list[Fault] = []
        #: Every request read, in arrival order.
        self.requests: list[Request] = []
        #: Connections accepted (after the TLS handshake, when there is one).
        self.connections = 0
        self._lock = threading.RLock()
        self._live: set[Any] = set()
        #: Connection threads started and not yet seen finished (pruned as new ones start).
        self._handlers: list[threading.Thread] = []
        self._httpd = Listener((host, port), self.handler_class)
        self._httpd.fake = self
        self._httpd.tls = tls
        self._thread: threading.Thread | None = None

    # -- configuration --------------------------------------------------------------------

    def route(self, method: str, pattern: str, handler: Handler) -> None:
        """Answer ``method`` (``*``: any) on paths fully matching ``pattern`` with ``handler``.

        The pattern is matched against the decoded path, without the query;
        its named groups arrive as :attr:`Request.params`. Earlier routes
        win. A path some route matches, but not for this method, is answered
        ``405`` with ``Allow``; a path none matches, ``404``.
        """
        with self._lock:
            self.routes.append(Route(method.upper(), re.compile(pattern), handler))

    def add_fault(self, fault: Fault) -> Fault:
        """Queue ``fault`` (see :class:`Fault`) and return it, so a test can inspect ``times``."""
        with self._lock:
            self.faults.append(fault)
        return fault

    # -- lifecycle ------------------------------------------------------------------------

    @property
    def address(self) -> tuple[str, int]:
        """Where the server listens."""
        return _endpoint(self._httpd)

    @property
    def port(self) -> int:
        """The bound port."""
        return self.address[1]

    @property
    def url(self) -> str:
        """``https://host:port`` (``http://`` without TLS), with no trailing slash."""
        host, port = self.address
        return f"{'https' if self.tls is not None else 'http'}://{host}:{port}"

    def start(self) -> Self:
        """Serve in a background thread. Idempotent."""
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._httpd.serve_forever, args=(0.01,), name=self.name, daemon=True
            )
            self._thread.start()
        return self

    def stop(self) -> None:
        """Stop listening and hang up on every open connection, as a dead server would.

        Then, with :attr:`join_timeout` set, wait up to that long in all for
        the connection threads; one still running after it (a handler that
        ignores the hang-up) is left to finish on its own, as without it.
        The listener is stopped first, so no new thread can start while
        the old ones are waited for.
        """
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
            self._thread = None
        with self._lock:
            live, self._live = list(self._live), set()
        for connection in live:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
        self._httpd.server_close()
        if self.join_timeout is not None:
            self._join_handlers(self.join_timeout)

    def _join_handlers(self, timeout: float) -> None:
        """Wait up to ``timeout`` seconds, shared by all of them, for the connection threads."""
        deadline = time.monotonic() + timeout
        with self._lock:
            handlers, self._handlers = self._handlers, []
        for thread in handlers:
            thread.join(max(0.0, deadline - time.monotonic()))

    def __enter__(self) -> Self:
        """Start serving; the ``with`` block is the server's lifetime."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """Stop, whether or not the block raised."""
        self.stop()

    def __repr__(self) -> str:
        """Where it listens and how much it has seen."""
        return f"{type(self).__name__}({self.url}, requests={len(self.requests)})"

    # -- dispatch -------------------------------------------------------------------------

    def respond(self, request: Request) -> Response | None:
        """The real answer to ``request``: the first matching route's, else 404/405."""
        with self._lock:
            routes = list(self.routes)
        allowed: list[str] = []
        for route in routes:
            match = route.pattern.fullmatch(request.path)
            if match is None:
                continue
            if route.method in ("*", request.method):
                request.params = {k: v for k, v in match.groupdict().items() if v is not None}
                return route.handler(request)
            allowed.append(route.method)
        if allowed:
            return Response(405, b"method not allowed", {"Allow": ", ".join(allowed)})
        return Response(404, b"not found")

    # -- what the handler thread calls ---------------------------------------------------

    def _started(self, thread: threading.Thread) -> None:
        """Remember a connection thread for :meth:`stop`, forgetting those already finished."""
        with self._lock:
            self._handlers = [t for t in self._handlers if t.is_alive()]
            self._handlers.append(thread)

    def _connected(self, connection: Any, live: bool) -> None:
        """Track open connections (and count new ones)."""
        with self._lock:
            if live:
                self.connections += 1
                self._live.add(connection)
            else:
                self._live.discard(connection)
        if live:
            self.opened(connection)

    def opened(self, connection: Any) -> None:
        """A connection is up (its TLS handshake done); the default does nothing.

        A subclass records what it needs of each connection here - its
        client certificate, say - before the first request on it is read.
        """

    def record(
        self, method: str, target: str, headers: Any, body: bytes, handler: BaseHTTPRequestHandler
    ) -> Request:
        """Build the :class:`Request` (with the client's identity) and append it to the log.

        Called by the request handler for every request it reads; a
        :attr:`handler_class` of a subclass calls it too, and may fill in
        :attr:`Request.body` later if it reads the body after logging.
        """
        path, query = _split(target)
        request = Request(
            method,
            target,
            path,
            query,
            dict(headers.items()),
            body,
            peer_identity(handler.connection),
            header_fields=tuple(headers.items()),
        )
        with self._lock:
            self.requests.append(request)
        return request

    def take_fault(self, request: Request) -> Fault | None:
        """The first fault matching ``request``, used up once (and dropped when spent).

        Called by the request handler; see :attr:`handler_class`.
        """
        target = urllib.parse.unquote(request.target)
        with self._lock:
            for candidate in self.faults:
                if candidate.matches(request.method, target):
                    self._spend(candidate)
                    return candidate
        return None

    def _spend(self, fault: Fault) -> None:
        """Count one use of ``fault``, dropping it once used up (called holding the lock)."""
        if fault.times is None:
            return
        fault.times -= 1
        if fault.times <= 0:
            self.faults.remove(fault)

    def _answer(self, request: Request, fault: Fault | None) -> Response | None:
        """The fault's answer if it has one, else :meth:`respond`'s; ``None`` to hang up."""
        if fault is not None and fault.drop:
            return None
        if fault is not None and fault.status is not None:
            return Response(fault.status, fault.body, dict(fault.headers), fault.reason)
        return self.respond(request)
