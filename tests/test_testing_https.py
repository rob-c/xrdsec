"""The generic test HTTP(S) server (:mod:`xrdsec.testing.https`).

:class:`FakeHTTPSServer` is the base other projects' fakes are built on, so
its wire behaviour - routing, the request log, faults, client identities,
and a subclass's own handler - is pinned here. (Its range and WebDAV reply
helpers moved to xrdhttp's suite with the code.)
"""

from __future__ import annotations

import contextlib
import http.client
import os
import socket
import threading
import time
from collections.abc import Iterable, Iterator
from http.server import BaseHTTPRequestHandler

import pytest

from xrdsec.testing.https import (
    FakeHTTPSServer,
    Fault,
    Listener,
    PeerIdentity,
    Request,
    Response,
    peer_identity,
)
from xrdsec.testing.pki import PKI


def _echo(request: Request) -> Response:
    return Response(200, request.body, {"X-Name": request.params.get("name", "")})


@pytest.fixture
def server() -> Iterator[FakeHTTPSServer]:
    with FakeHTTPSServer() as srv:
        srv.route("GET", r"/f/(?P<name>[^/]+)", _echo)
        srv.route("PUT", r"/f/(?P<name>[^/]+)", _echo)
        srv.route("*", r"/any", lambda request: Response(204))
        yield srv


def _ask(
    srv: FakeHTTPSServer,
    method: str = "GET",
    target: str = "/f/a",
    body: bytes | Iterable[bytes] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5,
) -> tuple[int, str, dict[str, str], bytes]:
    conn = http.client.HTTPConnection(*srv.address, timeout=timeout)
    try:
        chunked = (headers or {}).get("Transfer-Encoding") == "chunked"
        conn.request(method, target, body=body, headers=headers or {}, encode_chunked=chunked)
        response = conn.getresponse()
        return response.status, response.reason, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def test_routes_params_and_the_request_log(server) -> None:
    status, _, headers, _ = _ask(server, target="/f/n%20x?a=1&a=2&b=")
    assert status == 200 and headers["X-Name"] == "n x"
    assert headers["Server"].startswith("xrdsec-fake-https")
    request = server.requests[-1]
    assert (request.method, request.path, request.target) == (
        "GET",
        "/f/n x",
        "/f/n%20x?a=1&a=2&b=",
    )
    assert request.query == {"a": ["1", "2"], "b": [""]}
    assert request.param("a") == "1" and request.param("zz", "dflt") == "dflt"
    assert request.header("HOST") is not None and request.header("missing") is None
    assert request.peer is None


def test_any_verb_reaches_the_route_table(server) -> None:
    assert _ask(server, "DELETE", "/any")[0] == 204
    assert _ask(server, "PROPFIND", "/any")[0] == 204  # any verb reaches the route table
    assert server.connections >= 2 and "requests=" in repr(server)


def test_unrouted_paths_and_methods(server) -> None:
    assert _ask(server, target="/nowhere")[0] == 404
    status, _, headers, _ = _ask(server, "DELETE", "/f/a")
    assert status == 405 and headers["Allow"] == "GET, PUT"


def test_bodies_chunked_or_not_and_head(server) -> None:
    assert _ask(server, "PUT", "/f/a", body=b"plain")[3] == b"plain"
    chunks = iter([b"one", b"two"])
    assert _ask(server, "PUT", "/f/a", body=chunks, headers={"Transfer-Encoding": "chunked"})[
        3
    ] == (b"onetwo")
    server.route("HEAD", r"/h", lambda request: Response(200, b"hidden"))
    status, _, headers, body = _ask(server, "HEAD", "/h")
    assert (status, headers["Content-Length"], body) == (200, "6", b"")


def test_chunk_trailers_are_consumed(server) -> None:
    with socket.create_connection(server.address) as sock:
        sock.sendall(
            b"PUT /f/t HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3;ext=1\r\nabc\r\n0\r\nX-Trailer: y\r\n\r\n"
            b"GET /f/u HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
    assert data.count(b"HTTP/1.1 200") == 2 and b"abc" in data
    assert [r.path for r in server.requests[-2:]] == ["/f/t", "/f/u"]


def test_faults(server) -> None:
    server.add_fault(Fault("GET", r"/f/a$", status=503, reason="Busy\r\nnow", body=b"later"))
    assert _ask(server)[:2] == (503, "Busy  now")
    assert _ask(server)[0] == 200  # used up
    sticky = server.add_fault(Fault(None, r"sticky", status=418, times=None))
    for _ in range(3):
        assert _ask(server, target="/f/sticky")[0] == 418
    assert sticky in server.faults
    server.faults.clear()
    server.add_fault(Fault("PUT", status=None, truncate=2))
    with pytest.raises(http.client.IncompleteRead):
        _ask(server, "PUT", body=b"abcdef")
    server.add_fault(Fault(status=None, drop=True))
    with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
        _ask(server)
    server.add_fault(Fault(status=None, delay=0.2, stall=0.2))
    started = time.monotonic()
    assert _ask(server, "PUT", body=b"slow")[3] == b"slow"
    assert time.monotonic() - started >= 0.4
    assert not Fault("GET").matches("PUT", "/")


def test_faults_are_tried_in_order_and_counted_down(server) -> None:
    """A fault that does not match is passed over; one with ``times=2`` survives its first use."""
    put_only = server.add_fault(Fault("PUT", status=500))
    twice = server.add_fault(Fault("GET", r"/f/a$", status=503, times=2))
    assert _ask(server)[0] == 503  # the PUT fault came first and was skipped
    assert twice.times == 1 and twice in server.faults
    assert _ask(server)[0] == 503
    assert server.faults == [put_only]  # spent, so dropped; the PUT fault is untouched
    assert _ask(server)[0] == 200


def test_a_route_may_hang_up(server) -> None:
    server.route("GET", r"/gone", lambda request: None)
    with pytest.raises((http.client.RemoteDisconnected, ConnectionError)):
        _ask(server, target="/gone")


def test_a_garbled_request_line_is_dropped(server) -> None:
    with socket.create_connection(server.address) as sock:
        sock.sendall(b"NOT HTTP AT ALL\r\n\r\n")
        assert b"400" in sock.recv(4096)


def _identity(request: Request) -> str:
    """The client certificate's identity, on a server that asks for one."""
    assert request.peer is not None
    return request.peer.identity


def test_peer_identity_over_tls(pki: PKI) -> None:
    with FakeHTTPSServer(tls=pki.server_context()) as srv:
        srv.route("GET", r"/who", lambda request: Response(200, _identity(request).encode()))
        assert srv.url.startswith("https://127.0.0.1:")
        conn = http.client.HTTPSConnection("localhost", srv.port, context=pki.client_context())
        conn.request("GET", "/who")
        assert conn.getresponse().read() == b"/DC=org/DC=xrdsec/OU=People/CN=Test User"
        conn.close()
        peer = srv.requests[-1].peer
    assert peer is not None and peer.subject.startswith(peer.identity + "/CN=")
    assert peer.certificate == peer.chain[0]


def test_a_failed_handshake_does_not_take_the_server_down(pki: PKI) -> None:
    with FakeHTTPSServer(tls=pki.server_context()) as srv:
        with socket.create_connection(srv.address) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\n\r\n")  # cleartext to a TLS port
            with contextlib.suppress(OSError):
                sock.recv(100)
        srv.route("GET", r"/", lambda request: Response(200, b"ok"))
        conn = http.client.HTTPSConnection("localhost", srv.port, context=pki.client_context())
        conn.request("GET", "/")
        assert conn.getresponse().read() == b"ok"
        conn.close()


def test_a_corrupt_tls_record_ends_only_that_connection(pki: PKI) -> None:
    """Garbage after a good handshake fails the request-line read; the server hangs up and lives.

    The bytes go out on a duplicate of the descriptor, below the TLS layer, so
    the server's decryption - not its HTTP parser - is what fails.
    """
    with FakeHTTPSServer(tls=pki.server_context()) as srv:
        srv.route("GET", r"/", lambda request: Response(200, b"ok"))
        context = pki.client_context()
        raw = socket.create_connection(srv.address, timeout=5)
        with (
            context.wrap_socket(raw, server_hostname="localhost") as tls,
            socket.socket(fileno=os.dup(tls.fileno())) as below,
        ):
            below.sendall(b"\x17\x03\x03\x00\x05junk!")  # application data, bad MAC
            with contextlib.suppress(OSError):
                while below.recv(4096):  # until the server hangs up
                    pass
        assert srv.requests == []
        conn = http.client.HTTPSConnection("localhost", srv.port, context=context)
        conn.request("GET", "/")
        assert conn.getresponse().read() == b"ok"
        conn.close()


def test_peer_identity_without_a_chain_api(pki: PKI) -> None:
    """Before Python 3.13 a server sees only the leaf; the identity is still the user's."""
    leaf = pki.credential().certificate.der

    class OldSocket:
        def getpeercert(self, binary_form: bool = False) -> bytes:
            return leaf

    found = peer_identity(OldSocket())
    assert found == PeerIdentity((leaf,))
    assert found.identity == "/DC=org/DC=xrdsec/OU=People/CN=Test User"
    assert peer_identity(object()) is None
    only_cn = PeerIdentity((pki.ca_signer.der,))
    assert only_cn.identity == only_cn.subject  # nothing that looks like a proxy CN


def test_start_is_idempotent() -> None:
    """A second ``start`` (``with`` on a started server, say) adds no second serving thread."""
    with FakeHTTPSServer(name="xrdsec-idempotent") as srv:
        assert srv.start() is srv
        names = [thread.name for thread in threading.enumerate()]
        assert names.count("xrdsec-idempotent") == 1


def test_stop_hangs_up_open_connections() -> None:
    srv = FakeHTTPSServer().start()
    srv.route("GET", r"/", lambda request: Response(200, b"x"))
    conn = http.client.HTTPConnection(*srv.address, timeout=5)
    conn.request("GET", "/")
    conn.getresponse().read()  # the connection is now idle in keep-alive
    srv.stop()
    srv.stop()  # idempotent
    with pytest.raises((http.client.HTTPException, OSError)):
        conn.request("GET", "/")
        conn.getresponse()
    conn.close()


def test_repeated_headers_are_all_kept(server: FakeHTTPSServer) -> None:
    """``headers`` keeps the last of a repeated field; ``get_all`` has every line, in order."""
    conn = http.client.HTTPConnection(*server.address, timeout=5)
    try:
        conn.putrequest("GET", "/f/a")
        conn.putheader("Want-Digest", "adler32")
        conn.putheader("Want-Digest", "md5")
        conn.putheader("want-digest", "crc32c")
        conn.endheaders()
        conn.getresponse().read()
    finally:
        conn.close()
    request = server.requests[-1]
    assert request.header("Want-Digest") == "md5"
    assert request.get_all("WANT-DIGEST") == ["adler32", "md5", "crc32c"]
    assert request.get_all("missing") == []
    assert ("Want-Digest", "adler32") in request.header_fields


def test_a_hand_built_request_answers_get_all_from_its_dict() -> None:
    request = Request("GET", "/", "/", {}, {"Accept": "a/b"}, b"")
    assert request.get_all("accept") == ["a/b"] and request.header_fields == ()


def _slow_server(release: threading.Event, done: threading.Event, join_timeout: float):
    """A server whose one route waits for ``release`` (at most 5 s), then sets ``done``."""

    def slow(request: Request) -> Response:
        release.wait(5)
        done.set()
        return Response(200, b"late")

    srv = FakeHTTPSServer(join_timeout=join_timeout).start()
    srv.route("GET", r"/slow", slow)
    return srv


def _send_without_reading(srv: FakeHTTPSServer) -> http.client.HTTPConnection:
    """A request sent and left unanswered, once its handler is known to be running."""
    conn = http.client.HTTPConnection(*srv.address, timeout=5)
    conn.request("GET", "/slow")
    deadline = time.monotonic() + 5
    while not srv.requests and time.monotonic() < deadline:
        time.sleep(0.01)
    return conn


def test_stop_joins_connection_threads_when_asked() -> None:
    """With ``join_timeout``, a handler still running at ``stop`` has finished when it returns."""
    release, done = threading.Event(), threading.Event()
    srv = _slow_server(release, done, join_timeout=10.0)
    assert _ask(srv, target="/nowhere")[0] == 404  # an earlier, finished thread is pruned
    conn = _send_without_reading(srv)
    threading.Timer(0.2, release.set).start()
    srv.stop()
    assert done.is_set()
    conn.close()


def test_stop_gives_up_on_a_handler_after_the_timeout() -> None:
    release, done = threading.Event(), threading.Event()
    srv = _slow_server(release, done, join_timeout=0.05)
    conn = _send_without_reading(srv)
    started = time.monotonic()
    srv.stop()
    assert time.monotonic() - started < 4 and not done.is_set()
    release.set()
    assert done.wait(5)
    conn.close()


# -- going silent ---------------------------------------------------------------------------


def _first_bytes(srv: FakeHTTPSServer, target: str = "/f/a") -> bytes:
    """Everything the server says to one ``GET`` before it hangs up."""
    with socket.create_connection(srv.address, timeout=5) as sock:
        sock.sendall(f"GET {target} HTTP/1.1\r\nHost: h\r\n\r\n".encode())
        out = b""
        while chunk := sock.recv(4096):
            out += chunk
        return out


def test_a_held_fault_says_nothing_until_its_time_is_up(server) -> None:
    server.add_fault(Fault("GET", status=None, hold=0.05))
    started = time.monotonic()
    assert _first_bytes(server) == b""
    assert time.monotonic() - started >= 0.05


def test_a_held_fault_with_a_truncation_goes_silent_mid_body(server) -> None:
    server.add_fault(Fault("GET", status=200, body=b"0123456789", truncate=3, hold=0.05))
    answer = _first_bytes(server)
    assert b"Content-Length: 10" in answer and answer.endswith(b"\r\n\r\n012")


# -- a subclass's own handler ---------------------------------------------------------------


class _Plain(BaseHTTPRequestHandler):
    """A handler that logs through the fake and answers every request with its own text."""

    protocol_version = "HTTP/1.1"
    server: Listener

    def log_message(self, format: str, *args: object) -> None:
        """Quiet."""

    def do_GET(self) -> None:
        fake = self.server.fake
        request = fake.record(self.command, self.path, self.headers, b"", self)
        found = fake.take_fault(request)
        body = b"faulted" if found is not None else b"plain"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _PlainServer(FakeHTTPSServer):
    handler_class = _Plain


def test_a_subclass_brings_its_own_handler() -> None:
    with _PlainServer() as srv:
        assert _ask(srv)[3] == b"plain"
        srv.add_fault(Fault("GET"))
        assert _ask(srv)[3] == b"faulted"
        assert [request.path for request in srv.requests] == ["/f/a", "/f/a"]
        assert srv.faults == []
