"""``KCM:`` caches: a client for the KCM daemon's protocol over its Unix socket.

RHEL 9 and its rebuilds keep Kerberos tickets in ``sssd-kcm`` by default;
Heimdal ships its own ``kcm``. Both speak Heimdal's KCM protocol, and MIT's
``cc_kcm.c`` is the client this module follows:

* a request is major version 2, minor version 0, a 16-bit opcode, then the
  op's arguments - a cache name as a NUL-terminated string, and whatever
  else the op takes;
* a reply is a 32-bit status (a com_err code; 0 is success), then the op's
  results;
* on the Unix socket each travels in Heimdal's ``heim-ipc`` frame: a request
  behind its 32-bit length, a reply behind its length and a 32-bit transport
  status;
* integers are big-endian; principals and credentials are marshalled in the
  version 4 FILE ccache layout (:mod:`.ccache`); UUIDs are 16 bytes.

The socket is ``kcm_socket`` from ``[libdefaults]``, else Heimdal's
``/var/run/.heim_org.h5l.kcm-socket``. The daemon knows who is asking from
the socket's peer credentials, so there is nothing to authenticate here.

Reading is what MIT does: the default cache's name if the residual is empty
(``GET_DEFAULT_CACHE``), its principal (``GET_PRINCIPAL``), the KDC clock
offset (``GET_KDC_OFFSET``), and the credentials - all at once with MIT's
``GET_CRED_LIST`` extension, else one by one (``GET_CRED_UUID_LIST``,
``GET_CRED_BY_UUID``) from a daemon that refuses it, as Heimdal's does.
A service ticket fetched from the KDC is stored back with ``STORE``, as
MIT's ``krb5_get_credentials`` does, so that the next process - this one or
``klist`` - finds it.

Connections are short-lived: one per :meth:`KcmCache.read` or
:meth:`KcmCache.store`, closed before returning, so a daemon restart
between logins costs nothing and no socket outlives the call that opened
it. Nothing here is shared between threads.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from xrdcore.log import get_logger

from .ccache import _Reader, marshal_ticket, read_credentials, read_principal
from .model import Principal, Ticket

__all__ = ["DEFAULT_SOCKET", "KcmCache", "KcmError"]

_log = get_logger(__name__)

#: Heimdal's compiled-in socket, which sssd-kcm listens on too.
DEFAULT_SOCKET = "/var/run/.heim_org.h5l.kcm-socket"

#: (major, minor) at the front of every request; daemons refuse other majors.
KCM_PROTOCOL_VERSION = (2, 0)

#: Opcodes, numbered as in Heimdal's ``kcm_operation`` enum (MIT's
#: ``kcm.h`` copies them). Only the ones this client sends are named.
OP_STORE = 6
OP_GET_PRINCIPAL = 8
OP_GET_CRED_UUID_LIST = 9
OP_GET_CRED_BY_UUID = 10
OP_GET_DEFAULT_CACHE = 20
OP_GET_KDC_OFFSET = 22
OP_GET_CRED_LIST = 13001  # MIT's extension: every credential in one reply

#: A credential's handle in ``GET_CRED_UUID_LIST``: raw bytes, not text.
UUID_LEN = 16

#: MIT's limit on a reply, which no sane cache comes near.
MAX_REPLY = 10 * 1024 * 1024

# com_err codes a daemon answers with, from MIT's krb5.h.
KRB5_CC_NOTFOUND = -1765328243
KRB5_CC_END = -1765328242
KRB5_CC_IO = -1765328191
KRB5_FCC_NOFILE = -1765328189
KRB5_FCC_INTERNAL = -1765328188
KRB5_CC_NOSUPP = -1765328137

#: "No such cache", as sssd and Heimdal say it.
_ABSENT = (KRB5_FCC_NOFILE, KRB5_CC_NOTFOUND)

#: "I do not do that": Heimdal's KRB5_FCC_INTERNAL, sssd's KRB5_CC_NOSUPP for
#: an op it knows but lacks and KRB5_CC_IO for one it does not know. MIT's
#: ``unsupported_op_error`` treats the same three as a cue to fall back.
_UNSUPPORTED = (KRB5_FCC_INTERNAL, KRB5_CC_IO, KRB5_CC_NOSUPP)

#: A credential that vanished between listing and fetching.
_GONE = (KRB5_CC_END, KRB5_CC_NOTFOUND)

_NAMES = {
    KRB5_CC_NOTFOUND: "KRB5_CC_NOTFOUND",
    KRB5_CC_END: "KRB5_CC_END",
    KRB5_CC_IO: "KRB5_CC_IO",
    KRB5_FCC_NOFILE: "KRB5_FCC_NOFILE",
    KRB5_FCC_INTERNAL: "KRB5_FCC_INTERNAL",
    KRB5_CC_NOSUPP: "KRB5_CC_NOSUPP",
}


class KcmError(OSError):
    """The KCM daemon answered with an error status.

    An :class:`OSError` so that callers treating "cache unreachable" as one
    family (``except OSError``) need not know about KCM. ``code`` is the raw
    com_err value - the tuples above classify it - and ``op`` the request
    that drew it, for the message.
    """

    def __init__(self, code: int, op: int) -> None:
        """Record the status and opcode; the message names the code if known."""
        self.code = code
        self.op = op
        super().__init__(f"the KCM daemon refused op {op}: {_NAMES.get(code, code)}")


def _cstring(data: bytes) -> str:
    """A NUL-terminated name at the start of a reply."""
    end = data.find(b"\0")
    if end < 0:
        raise ValueError("malformed reply from the KCM daemon: an unterminated name")
    return data[:end].decode("utf-8", "replace")


class _Connection:
    """One connection to the daemon; requests on it are answered in order.

    Synchronous and unpipelined, as MIT's client is: each :meth:`call`
    waits for its reply before the next request is written, so replies need
    no correlation id. ``timeout`` bounds every send and receive, so a hung
    daemon fails a login instead of freezing it.
    """

    def __init__(self, path: str, timeout: float) -> None:
        """Connect to the socket at ``path``; the socket is closed if that fails."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect(path)
        except OSError:
            self.sock.close()
            raise

    def __enter__(self) -> _Connection:
        """The connection itself; leaving the block closes the socket."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the socket, whatever happened inside the block."""
        self.sock.close()

    def _recv(self, count: int) -> bytes:
        """Exactly ``count`` bytes; a stream socket may deliver them in pieces.

        EOF before the count is a ValueError: a daemon that hangs up
        mid-reply has not answered, and a truncated reply must not be
        parsed as a short one.
        """
        data = bytearray()
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise ValueError("the KCM daemon closed the connection mid-reply")
            data += chunk
        return bytes(data)

    def call(self, op: int, name: str | None = None, args: bytes = b"") -> bytes:
        """Send one request; the results of a successful reply, else :class:`KcmError`."""
        # Request: u8 major, u8 minor, u16 opcode, [cache name NUL], args.
        body = struct.pack(">BBH", *KCM_PROTOCOL_VERSION, op)
        if name is not None:
            body += name.encode("utf-8") + b"\0"
        # heim-ipc framing: u32 length in front of the request; in front of
        # the reply, u32 length then a signed u32 transport-level status.
        self.sock.sendall(struct.pack(">I", len(body + args)) + body + args)
        length, transport = struct.unpack(">Ii", self._recv(8))
        if transport:
            raise KcmError(transport, op)
        # Checked before reading so a corrupt length cannot make us buffer
        # gigabytes from a confused (or hostile) peer.
        if length > MAX_REPLY:
            raise ValueError(f"the KCM daemon's reply is too big ({length} bytes)")
        reply = self._recv(length)
        if len(reply) < 4:
            raise ValueError("malformed reply from the KCM daemon: no status")
        (status,) = struct.unpack(">i", reply[:4])
        if status:
            raise KcmError(status, op)
        return reply[4:]


def _counted(reply: bytes) -> list[bytes]:
    """``GET_CRED_LIST``'s results: a count, then that many length-prefixed credentials."""
    reader = _Reader(reply)
    return [reader.blob() for _ in range(reader.u32())]


@dataclass
class KcmCache:
    """A cache in a KCM daemon: ``KCM:`` for the default one, ``KCM:<name>`` for another.

    :attr:`name` is the full name, and becomes the resolved one - ``KCM:1000``
    rather than ``KCM:`` - once :meth:`read` has asked the daemon.

    Mutable on purpose (not frozen): resolving ``KCM:`` pins ``residual`` so
    that a :meth:`store` after a :meth:`read` writes to the cache that was
    read, even if ``kswitch`` changed the daemon's default in between.
    """

    residual: str
    socket_path: str = DEFAULT_SOCKET
    timeout: float = 30.0

    @property
    def name(self) -> str:
        """``KCM:`` and the residual - resolved, once :meth:`read` has run."""
        return f"KCM:{self.residual}"

    def _connect(self) -> _Connection:
        """A fresh connection; a missing socket says which path was tried.

        Only :class:`FileNotFoundError` is reworded: it is the "no KCM here"
        case callers turn into "no cache", while a refused or timed-out
        connection should surface as itself.
        """
        try:
            return _Connection(self.socket_path, self.timeout)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"no KCM daemon at {self.socket_path}") from exc

    def read(self) -> tuple[Principal, list[Ticket]]:
        """The cache's default principal and credentials, configuration entries left out.

        A daemon that is not there, or a cache it does not hold, raises
        :class:`FileNotFoundError` - what a missing FILE cache raises; any
        other failure is an :class:`OSError` or a :class:`ValueError`.
        """
        with self._connect() as conn:
            return self._read(conn)

    def _resolve(self, conn: _Connection) -> None:
        """Pin ``KCM:`` to the daemon's default cache, as MIT's ``kcm_resolve`` does."""
        if not self.residual:
            self.residual = _cstring(conn.call(OP_GET_DEFAULT_CACHE))

    def _read(self, conn: _Connection) -> tuple[Principal, list[Ticket]]:
        """:meth:`read` on an open connection: principal, offset, credentials.

        The principal is asked for first because it is how a KCM daemon says
        whether the cache exists at all.
        """
        self._resolve(conn)
        try:
            marshalled = conn.call(OP_GET_PRINCIPAL, self.residual)
        except KcmError as exc:
            if exc.code in _ABSENT:
                raise FileNotFoundError(f"credential cache {self.name} not found") from exc
            raise
        if not marshalled:  # Heimdal: a cache that exists but was never initialized
            raise FileNotFoundError(f"credential cache {self.name} not found")
        principal = read_principal(marshalled)
        offset = self._kdc_offset(conn)
        return principal, read_credentials(self._credentials(conn), offset, self.name)

    def _kdc_offset(self, conn: _Connection) -> float:
        """The KDC's clock minus ours, in seconds, as ``kinit`` recorded it; else 0."""
        try:
            reply = conn.call(OP_GET_KDC_OFFSET, self.residual)
        except KcmError:
            return 0.0  # MIT ignores a daemon that keeps no offset
        return float(struct.unpack(">i", reply[:4])[0]) if len(reply) >= 4 else 0.0

    def _credentials(self, conn: _Connection) -> list[bytes]:
        """Every marshalled credential: one ``GET_CRED_LIST``, else one per UUID.

        The fallback is MIT's: only the "unsupported op" statuses trigger it,
        so a real error from a daemon that does support the op is not masked
        by a second, slower attempt. A credential deleted between listing
        and fetching (``_GONE``) is skipped, as ``klist`` would skip it.
        """
        try:
            return _counted(conn.call(OP_GET_CRED_LIST, self.residual))
        except KcmError as exc:
            if exc.code not in _UNSUPPORTED:
                raise
        _log.debug("KCM daemon lacks GET_CRED_LIST; reading %s one credential at a time", self.name)
        uuids = conn.call(OP_GET_CRED_UUID_LIST, self.residual)
        if len(uuids) % UUID_LEN:
            raise ValueError("malformed reply from the KCM daemon: a torn UUID list")
        out: list[bytes] = []
        for at in range(0, len(uuids), UUID_LEN):
            try:
                out.append(conn.call(OP_GET_CRED_BY_UUID, self.residual, uuids[at : at + UUID_LEN]))
            except KcmError as exc:
                if exc.code not in _GONE:
                    raise
        return out

    def store(self, ticket: Ticket) -> bool:
        """Add ``ticket`` to the cache, as MIT does with a ticket from the KDC.

        Best effort: a daemon that refuses (a quota, a cache destroyed in the
        meantime) costs the next process a TGS exchange, not this login, so a
        failure is logged and reported as ``False``.
        """
        try:
            with self._connect() as conn:
                self._resolve(conn)
                conn.call(OP_STORE, self.residual, marshal_ticket(ticket))
        except (OSError, ValueError) as exc:
            _log.debug("could not store %s in %s: %s", ticket.server, self.name, exc)
            return False
        return True
