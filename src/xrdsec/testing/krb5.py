"""Kerberos test doubles: credential caches, a KCM daemon, and a python-gssapi stand-in.

Three things a Kerberos client's suite needs and no developer machine
reliably has:

* :func:`make_ticket` and :func:`write_ccache` - credentials, and a FILE
  cache holding them in the version 4 layout ``kinit`` writes (through
  :func:`xrdsec.krb5.ccache.marshal_ticket`, the encoder the KCM and keyring
  readers share). A test of the cache *reader* should prefer bytes some
  other encoder wrote; these are for tests of what is built on top.
* :class:`FakeKcm` - a KCM daemon in a thread: Heimdal's KCM protocol over a
  Unix socket, the protocol ``sssd-kcm`` (RHEL 9's default cache) and
  Heimdal's ``kcm`` speak and MIT's ``cc_kcm.c`` is a client of. Faithful to
  the wire format - MIT's own ``kinit``, ``klist`` and ``kvno`` run against
  it in xrdclient's interoperability tests - but with no access control by
  peer uid, which is the one thing a real daemon adds.
* :func:`fake_gssapi_module` - enough of python-gssapi for
  :mod:`xrdsec.krb5.gss`, with a toy mechanism whose tokens are readable
  strings and whose every call can be made to fail with a chosen status.
  Installed as ``sys.modules["gssapi"]`` it lets a GSS context's handshake,
  message protection and error paths be tested without a KDC.

The KCM framing: each request is a 4-byte big-endian length, then major
version 2, minor version 0, a 16-bit opcode and the op's arguments; each
reply is heim-ipc's frame (length, transport status), a 32-bit status (a
com_err code, 0 for success) and the op's results. Names are NUL-terminated
strings; principals and credentials are in the version 4 FILE ccache
layout; UUIDs are 16 bytes; integers are big-endian.

Stability: public test API, versioned with the package. Nothing here is
imported by the library itself.
"""

from __future__ import annotations

import itertools
import os
import socket
import struct
import threading
import time
import types
import uuid
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, ClassVar

from ..krb5 import ccache as _fmt
from ..krb5.model import TKT_FLG_FORWARDABLE, Principal, Ticket

__all__ = [
    "FAKE_REALM",
    "FAKE_USER",
    "KCM_OPS",
    "KRB5_CC_END",
    "KRB5_CC_IO",
    "KRB5_CC_NOSUPP",
    "KRB5_CC_NOTFOUND",
    "KRB5_FCC_INTERNAL",
    "KRB5_FCC_NOFILE",
    "FakeGssapi",
    "FakeKcm",
    "fake_gssapi_module",
    "make_ticket",
    "recording_tgs",
    "write_ccache",
]

# -- credentials and FILE caches ------------------------------------------------------


def make_ticket(
    client: Principal,
    server: Principal,
    *,
    lifetime: float = 36000.0,
    flags: int = TKT_FLG_FORWARDABLE,
    enctype: int = 18,
    key: bytes = bytes(range(32)),
) -> Ticket:
    """A credential for ``server`` with ``lifetime`` seconds left (negative: expired).

    The ticket itself is a single opaque TLV - a client never opens one -
    and the session key is fixed unless given, so a test can recognise it.
    The default flags make the ticket forwardable, as ``kinit -f`` asks.
    """
    now = int(time.time())
    return Ticket(
        client=client,
        server=server,
        enctype=enctype,
        auth_time=now - 60,
        start_time=now - 60,
        end_time=int(now + lifetime),
        renew_till=0,
        flags=flags,
        der=b"\x61\x03\x30\x01\x00",
        key=key,
    )


def write_ccache(path: Path, tickets: Iterable[Ticket], *, default: Principal | None = None) -> str:
    """A version 4 FILE cache at ``path`` holding ``tickets``; returns the path.

    ``default`` is the cache's principal, else the first ticket's client
    (an empty cache needs one named). No header tags, so no KDC offset.
    """
    held = list(tickets)
    principal = default if default is not None else held[0].client
    body = struct.pack(">HH", _fmt.CCACHE_VERSION_4, 0) + _fmt.marshal_principal(principal)
    path.write_bytes(body + b"".join(_fmt.marshal_ticket(ticket) for ticket in held))
    return str(path)


def recording_tgs(asked: list[dict[str, Any]]) -> Callable[..., Ticket]:
    """A stand-in for :func:`xrdsec.krb5.client.request_ticket` that records each request.

    Patch it over the real TGS exchange (``monkeypatch.setattr(client,
    "request_ticket", recording_tgs(asked))``) and every request a test
    triggers is appended to ``asked`` - the TGT, the service, the enctypes
    and the KDC options asked for - while the "KDC" answers with a ticket
    for that service, valid ten minutes, under an all-zero session key.
    xrdsec's and xrdclient's suites each had this fixture body verbatim.
    """

    def request_ticket(
        tgt: Ticket,
        server: Principal,
        profile: object,
        *,
        etypes: object,
        options: int = 0,
        **_: object,
    ) -> Ticket:
        """Record the request and issue the service ticket a KDC would."""
        asked.append({"tgt": tgt, "server": server, "etypes": etypes, "options": options})
        return replace(tgt, server=server, key=bytes(32), end_time=int(time.time()) + 600)

    return request_ticket


# -- the KCM daemon ---------------------------------------------------------------------

# com_err codes, from MIT's krb5.h.
KRB5_CC_END = -1765328242
KRB5_CC_NOTFOUND = -1765328243
KRB5_CC_IO = -1765328191
KRB5_FCC_NOFILE = -1765328189
KRB5_FCC_INTERNAL = -1765328188
KRB5_CC_NOSUPP = -1765328137

#: Opcodes, from Heimdal's kcm.h (and MIT's src/include/kcm.h); the last two
#: are MIT's extensions, which a ``heimdal=True`` daemon refuses.
KCM_OPS = {
    "NOOP": 0,
    "GET_NAME": 1,
    "RESOLVE": 2,
    "GEN_NEW": 3,
    "INITIALIZE": 4,
    "DESTROY": 5,
    "STORE": 6,
    "RETRIEVE": 7,
    "GET_PRINCIPAL": 8,
    "GET_CRED_UUID_LIST": 9,
    "GET_CRED_BY_UUID": 10,
    "REMOVE_CRED": 11,
    "SET_FLAGS": 12,
    "GET_CACHE_UUID_LIST": 18,
    "GET_CACHE_BY_UUID": 19,
    "GET_DEFAULT_CACHE": 20,
    "SET_DEFAULT_CACHE": 21,
    "GET_KDC_OFFSET": 22,
    "SET_KDC_OFFSET": 23,
    "GET_CRED_LIST": 13001,
    "REPLACE": 13002,
}
_NAMES = {number: name for name, number in KCM_OPS.items()}

#: The first opcode of MIT's extensions; Heimdal's daemon knows none of them.
_MIT_EXTENSIONS = 13000

#: What every op handler returns: the status, then the results.
_Answer = tuple[int, bytes]


def _new_uuid() -> bytes:
    """A fresh 16-byte UUID, the daemon's handle for a cache or a credential."""
    return uuid.uuid4().bytes


@dataclass
class _Cache:
    """One cache the daemon holds: its marshalled principal, credentials and KDC offset."""

    principal: bytes = b""
    creds: dict[bytes, bytes] = field(default_factory=dict)  # uuid -> marshalled cred
    offset: int = 0
    uuid: bytes = field(default_factory=_new_uuid)


class _Args:
    """A cursor over a request's arguments; a short read fails the op, as a daemon would."""

    def __init__(self, data: bytes) -> None:
        """Start at the first argument byte."""
        self.data, self.pos = data, 0

    def name(self) -> str:
        """A NUL-terminated cache name."""
        end = self.data.index(b"\0", self.pos)
        out, self.pos = self.data[self.pos : end].decode(), end + 1
        return out

    def take(self, count: int) -> bytes:
        """The next ``count`` bytes."""
        out, self.pos = self.data[self.pos : self.pos + count], self.pos + count
        return out

    def u32(self) -> int:
        """A big-endian unsigned 32-bit integer."""
        return int(struct.unpack(">I", self.take(4))[0])

    def i32(self) -> int:
        """A big-endian signed 32-bit integer (KDC offsets may be negative)."""
        return int(struct.unpack(">i", self.take(4))[0])

    def principal(self) -> bytes:
        """A marshalled principal, kept as the bytes it arrived as."""
        start = self.pos
        self.take(4)
        count = self.u32()
        for _ in range(count + 1):
            self.take(self.u32())
        return self.data[start : self.pos]

    def rest(self) -> bytes:
        """Everything not yet read."""
        out, self.pos = self.data[self.pos :], len(self.data)
        return out


class FakeKcm:
    """A KCM daemon on the Unix socket ``path``, serving until :meth:`stop`.

    Caches are kept in memory, ``{name: _Cache}``; :meth:`load` fills one
    from a FILE cache image. ``requests`` records every ``(op, cache name or
    "")`` served, so a test can say which ops a client used. ``fail`` maps
    an op's name to the status to answer it with, and ``raw`` to the result
    bytes to send instead (status 0), for malformed replies. ``heimdal=True``
    refuses MIT's extensions (``GET_CRED_LIST``, ``REPLACE``) with
    ``KRB5_FCC_INTERNAL``, as Heimdal's daemon does, so a client's fallback
    to the UUID walk is exercised. ``default`` is the default cache's name.
    """

    def __init__(self, path: Path, *, heimdal: bool = False, default: str = "1000") -> None:
        """Prepare the daemon; nothing listens until :meth:`start`."""
        self.path = Path(path)
        self.heimdal = heimdal
        self.default = default
        self.caches: dict[str, _Cache] = {}
        self.requests: list[tuple[str, str]] = []
        self.fail: dict[str, int] = {}
        self.raw: dict[str, bytes] = {}
        self._counter = itertools.count(1)
        self._lock = threading.Lock()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def load(self, name: str, image: bytes) -> None:
        """Fill cache ``name`` from a FILE-format (version 4) cache image, offset included."""
        reader = _fmt._Reader(image)
        if reader.u16() != _fmt.CCACHE_VERSION_4:
            raise ValueError("FakeKcm.load takes a version 4 FILE cache image")
        offset = _fmt._kdc_offset(reader.take(reader.u16()))
        start = reader.pos
        _fmt._read_principal(reader)
        cache = _Cache(principal=image[start : reader.pos], offset=int(offset))
        while not reader.exhausted:
            begin = reader.pos
            _fmt._read_entry(reader, _fmt.CCACHE_VERSION_4, 0.0)
            cache.creds[_new_uuid()] = image[begin : reader.pos]
        self.caches[name] = cache

    def put(
        self,
        name: str,
        principal: Principal | None,
        tickets: Iterable[Ticket] = (),
        *,
        offset: int = 0,
    ) -> None:
        """Make cache ``name`` hold ``tickets`` for ``principal``, with KDC ``offset``.

        ``principal=None`` is a cache that exists but was never initialised -
        Heimdal answers ``GET_PRINCIPAL`` for one with status 0 and nothing.
        The credentials' UUIDs are their positions, so a test can name one.
        """
        cache = _Cache(principal=b"" if principal is None else _fmt.marshal_principal(principal))
        cache.offset = offset
        for number, ticket in enumerate(tickets):
            cache.creds[number.to_bytes(16, "big")] = _fmt.marshal_ticket(ticket)
        self.caches[name] = cache

    def start(self) -> FakeKcm:
        """Listen on :attr:`path` and serve each connection in its own thread."""
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        listener.listen(8)
        self._listener = listener
        self._thread = threading.Thread(target=self._accept, args=(listener,), daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop listening, wait for the accept thread, and remove the socket. Idempotent."""
        listener, self._listener = self._listener, None
        if listener is not None:
            # On Linux close() alone does not wake another thread's accept().
            with suppress(OSError):
                listener.shutdown(socket.SHUT_RDWR)
            listener.close()
        if self._thread is not None:
            self._thread.join(5)
        if self.path.exists():
            os.unlink(self.path)

    def __enter__(self) -> FakeKcm:
        """Start serving; leaving the ``with`` block stops."""
        return self.start()

    def __exit__(self, *exc: object) -> None:
        """Stop serving, whatever ended the block."""
        self.stop()

    def _accept(self, listener: socket.socket) -> None:
        """Accept connections until the listener is closed under us."""
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        """Answer one connection's requests until the client hangs up."""
        with conn:
            while True:
                request = _recv_frame(conn)
                if request is None:
                    return
                status, results = self.answer(request)
                reply = struct.pack(">i", status) + results
                # heim-ipc's frame: the reply's length and a transport status, then the reply.
                conn.sendall(struct.pack(">II", len(reply), 0) + reply)

    def answer(self, request: bytes) -> _Answer:
        """The status and results for one request body (version, opcode, arguments)."""
        major, _minor, opcode = struct.unpack(">BBH", request[:4])
        name = _NAMES.get(opcode, str(opcode))
        if major != 2:
            return KRB5_CC_IO, b""
        if name in self.raw:
            return 0, self.raw[name]
        if name in self.fail:
            return self.fail[name], b""
        handler: Callable[[_Args], _Answer] | None = getattr(self, f"_op_{name.lower()}", None)
        if handler is None or (self.heimdal and opcode >= _MIT_EXTENSIONS):
            self.requests.append((name, ""))
            return KRB5_FCC_INTERNAL, b""
        with self._lock:
            try:
                return handler(_Args(request[4:]))
            except KeyError:
                return KRB5_FCC_NOFILE, b""

    def _named(self, args: _Args, op: str) -> _Cache:
        """The cache the request names, recording the op; ``KeyError`` if there is none."""
        name = args.name()
        self.requests.append((op, name))
        return self.caches[name]

    def _op_noop(self, args: _Args) -> _Answer:
        """``NOOP``: MIT's liveness probe."""
        self.requests.append(("NOOP", ""))
        return 0, b""

    def _op_gen_new(self, args: _Args) -> _Answer:
        """``GEN_NEW``: a fresh cache name under the default's (``kinit`` into a collection)."""
        self.requests.append(("GEN_NEW", ""))
        return 0, f"{self.default}:{next(self._counter)}".encode() + b"\0"

    def _op_initialize(self, args: _Args) -> _Answer:
        """``INITIALIZE``: an empty cache for a principal, replacing any of that name."""
        name = args.name()
        self.requests.append(("INITIALIZE", name))
        self.caches[name] = _Cache(principal=args.principal())
        return 0, b""

    def _op_destroy(self, args: _Args) -> _Answer:
        """``DESTROY``: ``kdestroy``."""
        name = args.name()
        self.requests.append(("DESTROY", name))
        del self.caches[name]
        return 0, b""

    def _op_store(self, args: _Args) -> _Answer:
        """``STORE``: one more marshalled credential."""
        cache = self._named(args, "STORE")
        cache.creds[_new_uuid()] = args.rest()
        return 0, b""

    def _op_retrieve(self, args: _Args) -> _Answer:
        """``RETRIEVE``: refused, as sssd refuses it; MIT then walks the cache."""
        self._named(args, "RETRIEVE")
        return KRB5_CC_NOSUPP, b""

    def _op_remove_cred(self, args: _Args) -> _Answer:
        """``REMOVE_CRED``: refused, as sssd refuses it."""
        self._named(args, "REMOVE_CRED")
        return KRB5_CC_NOSUPP, b""

    def _op_set_flags(self, args: _Args) -> _Answer:
        """``SET_FLAGS``: accepted and ignored."""
        self._named(args, "SET_FLAGS")
        return 0, b""

    def _op_get_principal(self, args: _Args) -> _Answer:
        """``GET_PRINCIPAL``: the cache's principal, marshalled."""
        return 0, self._named(args, "GET_PRINCIPAL").principal

    def _op_get_cred_uuid_list(self, args: _Args) -> _Answer:
        """``GET_CRED_UUID_LIST``: the credentials' UUIDs, concatenated."""
        return 0, b"".join(self._named(args, "GET_CRED_UUID_LIST").creds)

    def _op_get_cred_by_uuid(self, args: _Args) -> _Answer:
        """``GET_CRED_BY_UUID``: one credential, or ``KRB5_CC_END`` once it is gone."""
        cache = self._named(args, "GET_CRED_BY_UUID")
        cred = cache.creds.get(args.take(16))
        return (0, cred) if cred is not None else (KRB5_CC_END, b"")

    def _op_get_cred_list(self, args: _Args) -> _Answer:
        """``GET_CRED_LIST`` (MIT): every credential at once, each length-prefixed."""
        creds = list(self._named(args, "GET_CRED_LIST").creds.values())
        return 0, struct.pack(">I", len(creds)) + b"".join(
            struct.pack(">I", len(cred)) + cred for cred in creds
        )

    def _op_replace(self, args: _Args) -> _Answer:
        """``REPLACE`` (MIT): a whole cache - offset, principal, credentials - in one op."""
        name = args.name()
        self.requests.append(("REPLACE", name))
        offset = args.i32()
        cache = _Cache(principal=args.principal(), offset=offset)
        for _ in range(args.u32()):
            cache.creds[_new_uuid()] = args.take(args.u32())
        self.caches[name] = cache
        return 0, b""

    def _op_get_cache_uuid_list(self, args: _Args) -> _Answer:
        """``GET_CACHE_UUID_LIST``: every cache's UUID (``klist -l``)."""
        self.requests.append(("GET_CACHE_UUID_LIST", ""))
        return 0, b"".join(cache.uuid for cache in self.caches.values())

    def _op_get_cache_by_uuid(self, args: _Args) -> _Answer:
        """``GET_CACHE_BY_UUID``: a cache's name from its UUID."""
        self.requests.append(("GET_CACHE_BY_UUID", ""))
        wanted = args.take(16)
        for name, cache in self.caches.items():
            if cache.uuid == wanted:
                return 0, name.encode() + b"\0"
        return KRB5_FCC_NOFILE, b""

    def _op_get_default_cache(self, args: _Args) -> _Answer:
        """``GET_DEFAULT_CACHE``: the default cache's name."""
        self.requests.append(("GET_DEFAULT_CACHE", ""))
        return 0, self.default.encode() + b"\0"

    def _op_set_default_cache(self, args: _Args) -> _Answer:
        """``SET_DEFAULT_CACHE``: ``kswitch``."""
        self.default = args.name()
        self.requests.append(("SET_DEFAULT_CACHE", self.default))
        return 0, b""

    def _op_get_kdc_offset(self, args: _Args) -> _Answer:
        """``GET_KDC_OFFSET``: the KDC clock offset ``kinit`` recorded, signed seconds."""
        return 0, struct.pack(">i", self._named(args, "GET_KDC_OFFSET").offset)

    def _op_set_kdc_offset(self, args: _Args) -> _Answer:
        """``SET_KDC_OFFSET``: record the offset."""
        cache = self._named(args, "SET_KDC_OFFSET")
        cache.offset = args.i32()
        return 0, b""


def _recv_exactly(conn: socket.socket, count: int) -> bytes | None:
    """``count`` bytes from ``conn``, or ``None`` if it closes first."""
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _recv_frame(conn: socket.socket) -> bytes | None:
    """One length-prefixed request, or ``None`` at end of stream."""
    header = _recv_exactly(conn, 4)
    if header is None:
        return None
    return _recv_exactly(conn, struct.unpack(">I", header)[0])


# -- a python-gssapi stand-in -------------------------------------------------------

#: The fake mechanism's realm and the initiator every context reports.
FAKE_REALM = "XGFAL.TEST"
FAKE_USER = f"user@{FAKE_REALM}"

# Major statuses the fake raises (routine error << 16).
_DEFECTIVE_TOKEN = 9 << 16
_BAD_MIC = 6 << 16
# ``MUTUAL_FLAG``: an initiator asking for it waits for the acceptor's AP-REP.
_MUTUAL = 2


class _GeneralError(Exception):
    """python-gssapi's ``exceptions.GeneralError``: the package's own complaint."""


class _GSSError(Exception):
    """python-gssapi's ``exceptions.GSSError``: a major/minor status pair."""

    def __init__(self, maj_code: int, min_code: int, message: str = "") -> None:
        """The statuses, and the text ``gss_display_status`` would give the major one."""
        super().__init__(message or f"GSS error {maj_code:#x}/{min_code}")
        self.maj_code = maj_code
        self.min_code = min_code
        self.message = message

    def get_all_statuses(self, code: int, is_major: bool) -> list[str]:
        """``gss_display_status``: the major text given, ``minor text <n>`` for a minor code.

        Minor code 1 answers with python-gssapi's own "could not decode"
        sentence, which :mod:`xrdsec.krb5.gss` must drop.
        """
        if is_major:
            return [self.message] if self.message else []
        if code == 1:
            return ["gss_display_status call returned failure (major 327680, minor 22)"]
        return [f"minor text {code}"] if code else []


class _Flag(int):
    """One of python-gssapi's ``RequirementFlag`` values."""


class _WrapResult(types.SimpleNamespace):
    """python-gssapi's ``WrapResult``: ``message``, ``encrypted`` (and ``qop``)."""


class FakeGssapi(types.SimpleNamespace):
    """The fake ``gssapi`` module, and the knobs a test turns on it.

    ``fail`` maps a call's name (``Name``, ``Credentials``,
    ``SecurityContext``, ``step``, ``actual_flags``, ``wrap``, ``unwrap``,
    ``get_signature``, ``verify_signature``) to the exception it raises
    next, once; ``flags_override`` replaces the flags a context reports;
    ``no_conf`` makes ``wrap`` refuse confidentiality; ``last_credentials``
    records the keyword arguments of the last ``Credentials``.
    ``exceptions.GSSError(major, minor, text)`` and
    ``exceptions.GeneralError(text)`` build the failures to arm.
    """

    def __init__(self) -> None:
        """The module's constant namespaces; :func:`fake_gssapi_module` adds the classes."""
        super().__init__(
            exceptions=types.SimpleNamespace(GSSError=_GSSError, GeneralError=_GeneralError),
            NameType=types.SimpleNamespace(
                hostbased_service="hostbased", kerberos_principal="principal"
            ),
            MechType=types.SimpleNamespace(kerberos="krb5"),
        )
        self.fail: dict[str, BaseException] = {}
        self.flags_override: int | None = None
        self.no_conf = False
        self.last_credentials: dict[str, Any] = {}

    def maybe_fail(self, name: str) -> None:
        """Raise the failure armed for ``name``, if there is one."""
        if name in self.fail:
            raise self.fail.pop(name)


class _Bound:
    """A fake python-gssapi class, bound (as ``gss``) to one :class:`FakeGssapi`."""

    gss: ClassVar[FakeGssapi]


class _Name(_Bound):
    """``gssapi.Name``: a host-based ``service@host`` becomes ``service/host@XGFAL.TEST``."""

    def __init__(self, text: str, kind: str) -> None:
        """Import ``text`` as the library would canonicalise it."""
        self.gss.maybe_fail("Name")
        if kind == "hostbased":
            service, _, host = text.partition("@")
            text = f"{service}/{host or 'localhost'}@{FAKE_REALM}"
        self.text = text

    def __str__(self) -> str:
        """The principal's text, as ``str(gssapi.Name)`` gives it."""
        return self.text


class _Credentials(_Bound):
    """``gssapi.Credentials``: records its arguments on the module."""

    def __init__(self, **kwargs: Any) -> None:
        """Keep the keyword arguments, for the test to inspect."""
        self.gss.maybe_fail("Credentials")
        self.kwargs = kwargs
        self.gss.last_credentials = kwargs


class _SecurityContext(_Bound):
    """The toy mechanism: ``AP-REQ <target> <flags>``, ``AP-REP``, ``WC:``/``WI:`` wraps."""

    def __init__(self, **kwargs: Any) -> None:
        """An initiator (``usage="initiate"``) or acceptor context, not yet stepped."""
        self.gss.maybe_fail("SecurityContext")
        self.kwargs = kwargs
        self.usage = kwargs["usage"]
        self._complete = False
        self._last_err: BaseException | None = None
        self.flags = int(kwargs.get("flags") or 0)
        self.initiator_name: Any = self.gss.Name(FAKE_USER, "principal")
        self.target_name: Any = kwargs.get("name")

    @property
    def complete(self) -> bool:
        """Established yet; an acceptor's failure with an error token is raised here.

        python-gssapi's acceptor returns the error token from ``step`` and
        raises the failure from ``complete``, and so does this one.
        """
        if self._last_err is not None:
            raise self._last_err
        return self._complete

    @property
    def actual_flags(self) -> list[_Flag]:
        """The negotiated flags, one ``RequirementFlag`` each."""
        self.gss.maybe_fail("actual_flags")
        override = self.gss.flags_override
        flags = self.flags if override is None else override
        return [_Flag(1 << bit) for bit in range(8) if flags & (1 << bit)]

    def step(self, token: bytes | None) -> bytes | None:
        """One round of the toy handshake."""
        self.gss.maybe_fail("step")
        if self.usage == "initiate":
            return self._initiate(token)
        return self._accept(token)

    def _initiate(self, token: bytes | None) -> bytes | None:
        """First call: the AP-REQ; second (mutual only): check the AP-REP."""
        if token is None:
            self._complete = not self.flags & _MUTUAL
            return f"AP-REQ {self.target_name} {self.flags}".encode()
        if token != b"AP-REP":
            raise _GSSError(_DEFECTIVE_TOKEN, 0, "Invalid token was supplied")
        self._complete = True
        return None

    def _accept(self, token: bytes | None) -> bytes | None:
        """Accept an AP-REQ (answering AP-REP if mutual), or fail with a KRB-ERROR token."""
        if token is None or not token.startswith(b"AP-REQ "):
            self._last_err = _GSSError(_DEFECTIVE_TOKEN, 0, "Invalid token was supplied")
            return b"KRB-ERROR"
        _, target, flags = token.decode().split(" ")
        self.target_name = self.gss.Name(target, "principal")
        self.flags = int(flags)
        self._complete = True
        return b"AP-REP" if self.flags & _MUTUAL else None

    def wrap(self, data: bytes, encrypt: bool) -> _WrapResult:
        """``WC:`` (encrypted) or ``WI:`` (integrity only) and the data."""
        self.gss.maybe_fail("wrap")
        encrypted = encrypt and not self.gss.no_conf
        return _WrapResult(message=(b"WC:" if encrypted else b"WI:") + data, encrypted=encrypted)

    def unwrap(self, token: bytes) -> _WrapResult:
        """The data inside a ``WC:``/``WI:`` token; anything else fails its MIC."""
        self.gss.maybe_fail("unwrap")
        if token[:3] not in (b"WC:", b"WI:"):
            raise _GSSError(_BAD_MIC, 0, "A token had an invalid Message Integrity Check (MIC)")
        return _WrapResult(message=token[3:], encrypted=token[:3] == b"WC:", qop=0)

    def get_signature(self, data: bytes) -> bytes:
        """``MIC:`` and the data."""
        self.gss.maybe_fail("get_signature")
        return b"MIC:" + data

    def verify_signature(self, data: bytes, mic: bytes) -> int:
        """0, unless ``mic`` is not ``MIC:`` and the data (a bad MIC with no text)."""
        self.gss.maybe_fail("verify_signature")
        if mic != b"MIC:" + data:
            raise _GSSError(_BAD_MIC, 0, "")
        return 0


def fake_gssapi_module() -> FakeGssapi:
    """Enough of python-gssapi for :mod:`xrdsec.krb5.gss`: the toy mechanism above.

    Each call is a fresh module whose classes are bound to it alone, so the
    failures a test arms never leak into another. Install it with
    ``monkeypatch.setitem(sys.modules, "gssapi", fake_gssapi_module())`` and
    call :func:`xrdsec.krb5.gss.reset` around the test.
    """
    module = FakeGssapi()
    module.Name = type("Name", (_Name,), {"gss": module})
    module.Credentials = type("Credentials", (_Credentials,), {"gss": module})
    module.SecurityContext = type("SecurityContext", (_SecurityContext,), {"gss": module})
    return module
