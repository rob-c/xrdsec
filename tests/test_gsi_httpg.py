"""httpg: the GSI handshake, name check and delegation flag under ``http.client``.

Ported from the GSI half of xgfalclient's ``tests/test_srm_transport.py``
(the connection class moved here from its ``plugins/srm/transport.py`` in
0.4.0), against a minimal httpg server built from :mod:`xrdsec.testing.gsi`'s
acceptor helpers - so the client and the test-server side are checked
against each other.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import TCPServer, ThreadingMixIn
from typing import Any, cast

import pytest

from xrdsec.gsi.gss import GSIError
from xrdsec.gsi.httpg import Handshake, HTTPGConnection
from xrdsec.testing.gsi import accept_httpg, httpg_context
from xrdsec.testing.pki import PKI, create_pki


class _Handler(BaseHTTPRequestHandler):
    """One httpg connection: TLS, the GSI preamble, then ``GET`` answered with the flag count."""

    protocol_version = "HTTP/1.1"
    server: _Server

    def setup(self) -> None:
        tls = self.server.tls.wrap_socket(self.request, server_side=True)
        try:
            accept_httpg(tls, turn=self.server.turn)
        except BaseException:
            tls.close()
            raise
        self.request = self.connection = tls
        super().setup()

    def finish(self) -> None:
        """Close the TLS socket too: the server closes only the one it accepted, now detached."""
        try:
            super().finish()
        finally:
            self.request.close()

    def do_GET(self) -> None:
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Quiet: the tests read replies, not stderr."""


class _Server(ThreadingMixIn, TCPServer):
    """A thread per connection; errors (a refused preamble) end only that connection."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, tls: ssl.SSLContext, *, turn: bool) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.tls = httpg_context(tls, turn=turn)
        self.turn = turn

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A client that hangs up mid-handshake is not a server failure."""


@contextlib.contextmanager
def serving(pki: PKI, *, turn: bool = False) -> Iterator[int]:
    """An httpg server on a free port, for the duration of the block."""
    server = _Server(pki.server_context(), turn=turn)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def client_tls(pki: PKI, *, ca: Path | None = None) -> ssl.SSLContext:
    """The client's context: the proxy, the CA, and ``ssl``'s host check off (GSI's own)."""
    context = ssl.create_default_context(cafile=str(ca or pki.ca_file))
    context.check_hostname = False
    context.load_cert_chain(str(pki.proxy_path))
    return context


def get(connection: HTTPGConnection) -> tuple[int, bytes]:
    """One ``GET /`` on ``connection``: the status and the body."""
    connection.request("GET", "/")
    reply = connection.getresponse()
    return reply.status, reply.read()


@pytest.mark.parametrize("turn", [False, True])
def test_a_request_over_httpg(pki: PKI, turn: bool) -> None:
    """Under TLS 1.3 a Globus acceptor's turn byte precedes the reply; it is skipped."""
    with serving(pki, turn=turn) as port:
        connection = HTTPGConnection(
            "localhost", port, Handshake(client_tls(pki), 5, check_name=True), timeout=5
        )
        assert get(connection) == (200, b"hello")
        assert get(connection) == (200, b"hello")  # the same session: no turn this time
        connection.close()


def test_the_host_name_is_checked_gsis_way(pki: PKI) -> None:
    """The host certificate's CN is ``host/localhost`` and its DNS name ``localhost``."""
    with serving(pki) as port:
        checked = HTTPGConnection(
            "127.0.0.1", port, Handshake(client_tls(pki), 5, check_name=True), timeout=5
        )
        with pytest.raises(GSIError, match=r"does not match host 127\.0\.0\.1"):
            checked.connect()
        unchecked = HTTPGConnection(
            "127.0.0.1", port, Handshake(client_tls(pki), 5, check_name=False), timeout=5
        )
        assert get(unchecked) == (200, b"hello")
        unchecked.close()


def test_an_untrusted_server_fails_the_handshake(pki: PKI, tmp_path: Path) -> None:
    other = create_pki(tmp_path / "other", key_slots=(5, 6, 7))
    with serving(pki) as port:
        connection = HTTPGConnection(
            "localhost",
            port,
            Handshake(client_tls(pki, ca=other.ca_file), 5, check_name=True),
            timeout=5,
        )
        with pytest.raises(ssl.SSLCertVerificationError):
            connection.connect()


class _Anonymous:
    """A TLS context whose peer (on an anonymous cipher suite) shows no certificate."""

    closed = False

    def wrap_socket(self, raw: socket.socket, server_hostname: str) -> _Anonymous:
        self._raw = raw  # taken over, as a real TLS socket takes over its socket
        return self

    def getpeercert(self, binary_form: bool) -> None:
        return None

    def close(self) -> None:
        """A refused peer's socket is closed: the one it took over."""
        self.closed = True
        self._raw.close()


def test_a_peer_without_a_certificate_is_refused(pki: PKI) -> None:
    anonymous = _Anonymous()
    with serving(pki) as port:
        connection = HTTPGConnection(
            "localhost",
            port,
            Handshake(cast("ssl.SSLContext", anonymous), connect_timeout=1, check_name=True),
            timeout=1,
        )
        with pytest.raises(GSIError, match="no certificate"):
            connection.connect()
    assert anonymous.closed and connection.sock is None


class _FakeTLS:
    """Just enough of an ``SSLSocket`` for the acceptor's preamble."""

    def __init__(self, version: str, flag: bytes) -> None:
        self._version, self._flag = version, flag
        self.sent = b""

    def version(self) -> str:
        return self._version

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        return self._flag[:size]


@pytest.mark.parametrize(
    ("version", "turn", "sent"),
    [("TLSv1.3", True, b"\x00"), ("TLSv1.2", True, b""), ("TLSv1.3", False, b"")],
)
def test_the_acceptor_sends_the_turn_only_under_tls13_when_asked(
    version: str, turn: bool, sent: bytes
) -> None:
    fake = _FakeTLS(version, b"0")
    accept_httpg(cast("ssl.SSLSocket", fake), turn=turn)
    assert fake.sent == sent


@pytest.mark.parametrize("flag", [b"D", b"", b"x"])
def test_the_acceptor_takes_no_delegation(flag: bytes) -> None:
    with pytest.raises(GSIError, match="unexpected GSI delegation flag"):
        accept_httpg(cast("ssl.SSLSocket", _FakeTLS("TLSv1.2", flag)))


def test_the_server_context_is_shaped_for_the_turn(pki: PKI) -> None:
    capped = httpg_context(pki.server_context())
    assert capped.maximum_version == ssl.TLSVersion.TLSv1_2
    turning = httpg_context(pki.server_context(), turn=True)
    assert turning.num_tickets == 0
    assert turning.maximum_version != ssl.TLSVersion.TLSv1_2
