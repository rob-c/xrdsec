"""``KEYRING:`` caches: MIT's credential caches in Linux kernel keyrings.

MIT's ``cc_keyring.c`` keeps a cache collection as a keyring, and each cache
in it as a keyring of ``user`` (or ``big_key``) keys: the default principal
under ``__krb5_princ__``, the KDC clock offset under
``__krb5_time_offsets__``, and one key per credential, named after its
server principal. Each payload is marshalled as in a version 4 FILE cache
(:mod:`.ccache`). The collection's current cache is named by its
``krb_ccache:primary`` key: a 32-bit version (1), then a counted name.

The residual is ``anchor:collection[:cache]``, and the anchor says where
the collection hangs:

* ``persistent:<uid>`` - the user's persistent keyring (``KEYCTL_GET_PERSISTENT``),
  collection ``_krb``; RHEL 7 and 8 default to this;
* ``session:<name>``, ``user:<name>``, ``process:<name>``, ``thread:<name>`` -
  that special keyring, collection ``_krb_<name>``;
* a bare ``<name>`` - MIT's legacy form, in the session keyring, where a
  cache made by a pre-collection MIT is found by its bare name as well.

This module only reads. MIT creates the collection keyrings on first use,
and stores fetched service tickets back as keys; here, a keyring that is not
there is a cache that is not there, and a fetched ticket stays in this
process's memory, as it does for a FILE cache. The kernel is reached through
the ``keyctl`` system call, by ``ctypes``: :class:`Keyctl` wraps the five
operations a reader needs around a syscall function, which tests replace.

Why a raw syscall and not ``libkeyutils``: it is not installed on minimal
images, and the five operations used here are stable kernel ABI. The cost
is the per-architecture syscall number table below; an architecture
missing from it gets a clear error rather than a wrong call.

Byte order is mixed and that is deliberate: payloads MIT wrote (principal,
credentials, offsets, the primary key) are big-endian like a FILE cache,
while a keyring's own payload - the list of member serials the kernel
returns from ``KEYCTL_READ`` - is in host order.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import struct
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Union

from xrdcore.errors import CredentialError
from xrdcore.log import get_logger

from .ccache import read_credentials, read_principal
from .model import Principal, Ticket

__all__ = ["Keyctl", "KeyringCache", "parse_residual", "system_keyctl"]

_log = get_logger(__name__)

# keyctl(2) operations, from <linux/keyctl.h>.
KEYCTL_GET_KEYRING_ID = 0
KEYCTL_DESCRIBE = 6
KEYCTL_SEARCH = 10
KEYCTL_READ = 11
KEYCTL_GET_PERSISTENT = 22

# Special keyring IDs.
KEY_SPEC_THREAD_KEYRING = -1
KEY_SPEC_PROCESS_KEYRING = -2
KEY_SPEC_SESSION_KEYRING = -3
KEY_SPEC_USER_KEYRING = -4
KEY_SPEC_USER_SESSION_KEYRING = -5

#: ``__NR_keyctl`` per machine. The asm-generic number (219) serves arm64 and riscv64.
SYS_KEYCTL = {
    "x86_64": 250,
    "amd64": 250,
    "i386": 288,
    "i686": 288,
    "aarch64": 219,
    "arm64": 219,
    "riscv64": 219,
    "armv7l": 311,
    "armv6l": 311,
    "ppc64le": 271,
    "ppc64": 271,
    "s390x": 280,
}

# The errnos that mean "no such key" (their generic Linux values where this
# Python's errno module, off Linux, does not know them).
ENOKEY = getattr(errno, "ENOKEY", 126)
EKEYEXPIRED = getattr(errno, "EKEYEXPIRED", 127)
EKEYREVOKED = getattr(errno, "EKEYREVOKED", 128)
_MISSING = (ENOKEY, EKEYEXPIRED, EKEYREVOKED, errno.ENOENT)

# MIT's names, from cc_keyring.c. "legacy" is not spelled in a residual;
# :func:`parse_residual` assigns it to a residual with no anchor.
ANCHORS = ("persistent", "session", "user", "process", "thread", "legacy")
PERSISTENT_COLLECTION = "_krb"
COLLECTION_PREFIX = "_krb_"
PRIMARY_KEY = "krb_ccache:primary"
PRINCIPAL_KEY = "__krb5_princ__"
OFFSETS_KEY = "__krb5_time_offsets__"
COLLECTION_VERSION = 1
#: Key types a cache keyring's entries are stored as: ``big_key`` (backed by
#: shmem, for payloads past a page) is what MIT uses when the kernel has it.
_CRED_TYPES = ("user", "big_key")

#: What the syscall is given: key serials and lengths, names, and buffers to fill.
Arg = Union[int, bytes, None, "ctypes.Array[ctypes.c_char]"]
#: ``syscall(op, *args)``: the result, or :class:`OSError` with the errno.
Syscall = Callable[..., int]


def _missing(exc: OSError) -> bool:
    """Whether ``exc`` means "no such key" in any of the kernel's ways."""
    return exc.errno in _MISSING


class Keyctl:
    """The keyctl operations a reader needs, over ``syscall(op, *args)``.

    Every method raises :class:`OSError` with the kernel's errno, unchanged;
    deciding which errnos mean "absent" is :class:`KeyringCache`'s job. The
    syscall is injected so tests can stand a dictionary in for the kernel
    (``tests/test_krb5_keyring.py``) and exercise every branch off Linux.
    """

    def __init__(self, syscall: Syscall) -> None:
        """Wrap ``syscall``, which takes ``(op, *args)`` as keyctl(2) does."""
        self._call = syscall

    def keyring_id(self, special: int) -> int:
        """The serial of a special keyring, without creating it."""
        return self._call(KEYCTL_GET_KEYRING_ID, special, 0)

    def search(self, ring: int, kind: str, description: str) -> int:
        """A key of ``kind`` named ``description`` in ``ring`` or a keyring it holds."""
        return self._call(KEYCTL_SEARCH, ring, kind.encode(), description.encode("utf-8"), 0)

    def persistent(self, uid: int) -> int:
        """``uid``'s persistent keyring, linked into the process keyring as MIT links it."""
        return self._call(KEYCTL_GET_PERSISTENT, uid, KEY_SPEC_PROCESS_KEYRING)

    def _fetch(self, op: int, key: int) -> bytes:
        """The whole of what ``op`` returns for ``key``: sized first, then read."""
        # Both KEYCTL_READ and KEYCTL_DESCRIBE return the full size even when
        # the buffer is smaller, so a NULL buffer first asks "how big?".
        size = self._call(op, key, None, 0)
        while True:
            buffer = ctypes.create_string_buffer(max(size, 1))
            got = self._call(op, key, buffer, size)
            if got <= size:
                return buffer.raw[:got]
            size = got  # it grew between the calls

    def read(self, key: int) -> bytes:
        """A key's payload; for a keyring, its members' serials."""
        return self._fetch(KEYCTL_READ, key)

    def describe(self, key: int) -> tuple[str, str]:
        """A key's type and description."""
        text = self._fetch(KEYCTL_DESCRIBE, key).rstrip(b"\0").decode("utf-8", "replace")
        # At most four splits: the description itself (a principal) may hold ';'.
        parts = text.split(";", 4)  # type;uid;gid;perm;description
        return parts[0], parts[-1]

    def members(self, ring: int) -> list[int]:
        """The serials of the keys in keyring ``ring``.

        The kernel hands them over as an array of ``key_serial_t`` (int32) in
        host byte order, hence ``=`` and not ``>``; a trailing partial
        serial, which a racing unlink could leave, is dropped.
        """
        payload = self.read(ring)
        return list(struct.unpack(f"={len(payload) // 4}i", payload[: len(payload) // 4 * 4]))


def _libc_syscall(number: int) -> Syscall:
    """``syscall(2)`` for keyctl, through the C library.

    ``use_errno`` makes ctypes save errno right after the call, so
    :func:`ctypes.get_errno` reports the keyctl failure and not whatever a
    later libc call left behind.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.syscall
    function.restype = ctypes.c_long

    def call(op: int, *args: Arg) -> int:
        """``keyctl(op, *args)``: the non-negative result, or OSError with errno."""
        # Integers go as longs, which is what syscall(2) reads its arguments as.
        wide = [ctypes.c_long(arg) if isinstance(arg, int) else arg for arg in args]
        result = int(function(ctypes.c_long(number), ctypes.c_long(op), *wide))
        if result == -1:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return result

    return call


def system_keyctl() -> Keyctl:
    """This kernel's keyctl; a clear error where there are no kernel keyrings.

    Both errors end in the same one-line fix, because a ``KEYRING:`` name is
    usually inherited from a site ``krb5.conf`` the person did not write.
    """
    if not sys.platform.startswith("linux"):
        raise CredentialError(
            f"KEYRING: credential caches are Linux kernel keyrings, and this is {sys.platform}; "
            "use a file instead: KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u) kinit"
        )
    number = SYS_KEYCTL.get(platform.machine())
    if number is None:
        raise CredentialError(
            f"reading KEYRING: credential caches is not supported on {platform.machine()}; "
            "use a file instead: KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u) kinit"
        )
    return Keyctl(_libc_syscall(number))


def parse_residual(residual: str) -> tuple[str, str, str | None]:
    """``anchor:collection[:cache]`` as MIT's ``parse_residual`` splits it.

    With no colon at all the anchor is ``legacy``. An unknown anchor, or a
    persistent collection that is not a uid, is a :class:`CredentialError`.
    """
    anchor, sep, rest = residual.partition(":")
    if not sep:
        anchor, rest = "legacy", residual
    collection, sep, cache = rest.partition(":")
    if anchor not in ANCHORS:
        raise CredentialError(f"KEYRING:{residual} names an unknown keyring anchor {anchor!r}")
    if anchor == "persistent" and collection and not collection.isdigit():
        raise CredentialError(f"KEYRING:{residual}: {collection!r} is not a uid")
    return anchor, collection, (cache if sep else None)


def parse_primary(payload: bytes) -> str:
    """The name in a ``krb_ccache:primary`` key: version 1, a 32-bit length, the name."""
    if len(payload) < 8:
        raise ValueError("a keyring collection's primary key is truncated")
    version, length = struct.unpack(">II", payload[:8])
    if version != COLLECTION_VERSION:
        raise ValueError(f"unknown keyring collection version {version}")
    if length > len(payload) - 8:
        raise ValueError("a keyring collection's primary key is truncated")
    return payload[8 : 8 + length].decode("utf-8", "replace")


def _offset(payload: bytes) -> float:
    """``__krb5_time_offsets__``: signed seconds and microseconds, big-endian."""
    if len(payload) < 8:
        return 0.0
    seconds, micros = struct.unpack(">ii", payload[:8])
    return float(seconds + micros / 1_000_000)


@dataclass
class _Contents:
    """What a cache keyring holds, sorted by kind."""

    principal: bytes | None = None
    offset: float = 0.0
    creds: list[bytes] = field(default_factory=list)


@dataclass
class KeyringCache:
    """A cache in a kernel keyring, named ``KEYRING:<residual>``.

    The residual is parsed once, at construction, so a malformed name fails
    when the cache is opened - as :func:`.caches.open_ccache` promises -
    rather than at the first read. The keyrings themselves are looked up
    afresh on every :meth:`read`: serials change when ``kinit`` replaces a
    cache, and caching them would read a destroyed keyring.
    """

    residual: str
    keyctl: Keyctl

    def __post_init__(self) -> None:
        """Split the residual into anchor, collection and (optional) cache name."""
        self.anchor, self.collection, self.cache = parse_residual(self.residual)

    @property
    def name(self) -> str:
        """``KEYRING:`` and the residual, as the person (or krb5.conf) wrote it."""
        return f"KEYRING:{self.residual}"

    def read(self) -> tuple[Principal, list[Ticket]]:
        """The cache's default principal and credentials, configuration entries left out.

        A keyring or key that is not there raises :class:`FileNotFoundError`,
        what a missing FILE cache raises.
        """
        try:
            contents = self._contents(self._cache_id())
        except OSError as exc:
            # ENOENT already is a FileNotFoundError; re-raising it as itself
            # keeps the kernel's message rather than wrapping it in ours.
            if _missing(exc) and not isinstance(exc, FileNotFoundError):
                raise FileNotFoundError(f"credential cache {self.name} not found") from exc
            raise
        if contents.principal is None:  # a keyring MIT made but never initialized
            raise FileNotFoundError(f"credential cache {self.name} holds no principal")
        return read_principal(contents.principal), read_credentials(
            contents.creds, contents.offset, self.name
        )

    def store(self, ticket: Ticket) -> bool:
        """Not done: a fetched ticket stays in this process's memory."""
        return False

    # -- finding the cache keyring -----------------------------------------

    def _anchor_id(self) -> int:
        """The special keyring the collection hangs from (all anchors but persistent)."""
        fixed = {
            "user": KEY_SPEC_USER_KEYRING,
            "process": KEY_SPEC_PROCESS_KEYRING,
            "thread": KEY_SPEC_THREAD_KEYRING,
        }
        if self.anchor in fixed:
            return fixed[self.anchor]
        # MIT's session_write_anchor: the user-session keyring when the session is it.
        session = self.keyctl.keyring_id(KEY_SPEC_SESSION_KEYRING)
        user_session = self.keyctl.keyring_id(KEY_SPEC_USER_SESSION_KEYRING)
        return (
            KEY_SPEC_USER_SESSION_KEYRING if session == user_session else KEY_SPEC_SESSION_KEYRING
        )

    def _collection_id(self) -> int:
        """The serial of the collection keyring, found by search, never created.

        ``persistent`` without a uid means the caller's effective uid, as in
        MIT. Searching (rather than ``KEYCTL_GET_KEYRING_ID`` with create)
        is what keeps this module read-only.
        """
        if self.anchor == "persistent":
            uid = int(self.collection) if self.collection else os.geteuid()
            ring = self.keyctl.persistent(uid)
            return self.keyctl.search(ring, "keyring", PERSISTENT_COLLECTION)
        return self.keyctl.search(self._anchor_id(), "keyring", COLLECTION_PREFIX + self.collection)

    def _primary(self, collection: int) -> str:
        """The collection's current cache: its primary key, else MIT's first name for one."""
        try:
            key = self.keyctl.search(collection, "user", PRIMARY_KEY)
        except OSError as exc:
            if not _missing(exc):
                raise
            return self.collection or "tkt"
        return parse_primary(self.keyctl.read(key))

    def _cache_id(self) -> int:
        """The serial of the cache keyring the residual names.

        An explicit ``:cache`` part wins; otherwise the collection's primary.
        Only a ``legacy`` residual gets the second chance below, since only
        pre-collection MIT put a cache straight in the session keyring.
        """
        try:
            collection = self._collection_id()
            return self.keyctl.search(
                collection, "keyring", self.cache or self._primary(collection)
            )
        except OSError as exc:
            if self.anchor != "legacy" or not _missing(exc):
                raise
        # A legacy cache from an MIT before collections: named alone, in the session keyring.
        return self.keyctl.search(KEY_SPEC_SESSION_KEYRING, "keyring", self.collection)

    # -- reading it -----------------------------------------------------------

    def _contents(self, cache: int) -> _Contents:
        """Read every entry key in the cache keyring, sorted by what it is.

        A key that disappears between the listing and its read (``kdestroy``
        or a renewal racing us) is skipped, not fatal; keys of other types
        are not MIT's and are ignored.
        """
        out = _Contents()
        for key in self.keyctl.members(cache):
            try:
                kind, description = self.keyctl.describe(key)
                if kind in _CRED_TYPES:
                    self._sort(out, description, self.keyctl.read(key))
            except OSError as exc:
                if not _missing(exc):
                    raise
                _log.debug("key %d left %s while it was read", key, self.name)
        return out

    @staticmethod
    def _sort(out: _Contents, description: str, payload: bytes) -> None:
        """File one key's payload under principal, clock offset, or credential."""
        if description == PRINCIPAL_KEY:
            out.principal = payload
        elif description == OFFSETS_KEY:
            out.offset = _offset(payload)
        else:
            out.creds.append(payload)
