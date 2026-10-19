"""``KEYRING:`` credential caches: MIT's layout in Linux kernel keyrings.

Most of this runs anywhere: :class:`FakeKernel` below stands in for the
``keyctl`` system call - special keyrings, a recursive search, reads that
size then fill a ctypes buffer - and is filled in MIT's ``cc_keyring.c``
layout with caches MIT itself wrote (``tests/_krb5_mit.py``). What only a
Linux kernel can show is at the end, and skipped elsewhere: the real
syscall, and a cache laid out with ``keyutils``' own ``keyctl`` program. A
cache written by MIT's ``kinit`` and used to log in to a real ``xrootd`` is
xrdclient's interoperability suite's.
"""

from __future__ import annotations

import ctypes
import errno
import itertools
import os
import platform
import shutil
import struct
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from xrdcore.errors import CredentialError
from xrdsec.krb5 import caches, client, keyring
from xrdsec.krb5.caches import open_ccache
from xrdsec.krb5.ccache import marshal_principal, marshal_ticket, read_ccache
from xrdsec.krb5.keyring import (
    KEY_SPEC_PROCESS_KEYRING,
    KEY_SPEC_SESSION_KEYRING,
    KEY_SPEC_THREAD_KEYRING,
    KEY_SPEC_USER_KEYRING,
    KEY_SPEC_USER_SESSION_KEYRING,
    Keyctl,
    KeyringCache,
    parse_primary,
    parse_residual,
    system_keyctl,
)
from xrdsec.krb5.model import Principal, Ticket
from xrdsec.testing.krb5 import FakeKcm

from tests._krb5_mit import CAPTURED

REALM = "XRD.TEST"
JANE = Principal(("jane",), REALM, 1)
ENOKEY = keyring.ENOKEY
on_linux = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="platform: kernel keyrings exist only on Linux"
)


@dataclass
class _Key:
    kind: str
    description: str
    payload: bytes = b""
    members: list[int] = field(default_factory=list)


class FakeKernel:
    """The keyctl operations of ``keyctl(2)``, over keys held in a dict.

    It is called exactly as the real syscall wrapper is - ``(op, *args)``,
    buffers as ctypes arrays - and fails as it does, with ``OSError(errno)``.
    """

    def __init__(self, *, same_session: bool = False) -> None:
        self.keys: dict[int, _Key] = {}
        self._serials = itertools.count(1000)
        self.special: dict[int, int] = {}
        for spec in (
            KEY_SPEC_THREAD_KEYRING,
            KEY_SPEC_PROCESS_KEYRING,
            KEY_SPEC_USER_KEYRING,
            KEY_SPEC_USER_SESSION_KEYRING,
        ):
            self.special[spec] = self.ring("special")
        self.special[KEY_SPEC_SESSION_KEYRING] = (
            self.special[KEY_SPEC_USER_SESSION_KEYRING] if same_session else self.ring("session")
        )
        self.persistent: dict[int, int] = {}
        # (op, key) -> the errno for each coming call, in turn; None lets one through.
        self.errors: dict[tuple[int, int], list[int | None]] = {}
        self.grow: set[int] = set()  # keys whose payload grows after being sized
        self.calls: list[int] = []

    # -- building ----------------------------------------------------------

    def ring(self, description: str, parent: int | None = None) -> int:
        return self.add("keyring", description, parent=parent)

    def add(self, kind: str, description: str, payload: bytes = b"", parent=None) -> int:
        serial = next(self._serials)
        self.keys[serial] = _Key(kind, description, payload)
        if parent is not None:
            self.keys[self._resolve(parent)].members.append(serial)
        return serial

    def cache(self, parent: int, name: str, principal: bytes | None, creds=(), offset=None) -> int:
        """A cache keyring in MIT's layout, under ``parent``."""
        ring = self.ring(name, parent)
        if principal is not None:
            self.add("user", "__krb5_princ__", principal, ring)
        if offset is not None:
            self.add("user", "__krb5_time_offsets__", offset, ring)
        for number, cred in enumerate(creds):
            self.add("big_key" if number % 2 else "user", f"cred{number}", cred, ring)
        return ring

    def primary(self, collection: int, name: str, version: int = 1) -> None:
        payload = struct.pack(">II", version, len(name)) + name.encode()
        self.add("user", "krb_ccache:primary", payload, collection)

    # -- the syscall -----------------------------------------------------------

    def _resolve(self, key: int) -> int:
        return self.special.get(key, key)

    def _key(self, key: int) -> _Key:
        found = self.keys.get(self._resolve(key))
        if found is None:
            raise OSError(ENOKEY, "Required key not available")
        return found

    def _search(self, ring: int, kind: str, description: str) -> int | None:
        for member in self._key(ring).members:
            key = self.keys[member]
            if key.kind == kind and key.description == description:
                return member
            if key.kind == "keyring":
                found = self._search(member, kind, description)
                if found is not None:
                    return found
        return None

    def _fill(self, key: int, data: bytes, buffer, size: int) -> int:
        if key in self.grow and buffer is not None:
            self.grow.discard(key)
            return len(data) + 8  # it grew after the caller sized its buffer
        if buffer is not None and size >= len(data):
            ctypes.memmove(buffer, data, len(data))
        return len(data)

    def __call__(self, op: int, *args) -> int:
        self.calls.append(op)
        queued = self.errors.get((op, args[0])) or [None]
        code = queued.pop(0)
        if code is not None:
            raise OSError(code, os.strerror(code))
        handlers: dict[int, Callable[..., int]] = {
            keyring.KEYCTL_GET_KEYRING_ID: self._get_keyring_id,
            keyring.KEYCTL_GET_PERSISTENT: self._get_persistent,
            keyring.KEYCTL_SEARCH: self._search_op,
            keyring.KEYCTL_READ: self._read,
            keyring.KEYCTL_DESCRIBE: self._describe,
        }
        return handlers[op](*args)

    def _get_keyring_id(self, key: int, _create: int) -> int:
        return self._resolve(key)

    def _get_persistent(self, uid: int, _link_to: int) -> int:
        if uid not in self.persistent:
            self.persistent[uid] = self.ring(f"_persistent.{uid}")
        return self.persistent[uid]

    def _search_op(self, ring: int, kind: bytes, description: bytes, _link_to: int) -> int:
        found = self._search(ring, kind.decode(), description.decode())
        if found is None:
            raise OSError(ENOKEY, "Required key not available")
        return found

    def _read(self, key: int, buffer, size: int) -> int:
        entry = self._key(key)
        data = entry.payload
        if entry.kind == "keyring":
            data = struct.pack(f"={len(entry.members)}i", *entry.members)
        return self._fill(key, data, buffer, size)

    def _describe(self, key: int, buffer, size: int) -> int:
        entry = self._key(key)
        text = f"{entry.kind};1000;1000;3f010000;{entry.description}\0".encode()
        return self._fill(key, text, buffer, size)


def _captured(enctype: str) -> tuple[bytes, list[bytes], bytes]:
    """MIT's cache as keyring payloads: the principal, the credentials, and the file image."""
    image = bytes.fromhex(CAPTURED[enctype]["service_ccache"])
    holder = FakeKcm(Path("unused"))
    holder.load("x", image)
    return holder.caches["x"].principal, list(holder.caches["x"].creds.values()), image


def _ticket(server: tuple[str, ...], *, hours: float = 10) -> Ticket:
    now = int(time.time())
    return Ticket(
        client=JANE,
        server=Principal(server, REALM, 1),
        enctype=18,
        auth_time=now,
        start_time=now,
        end_time=int(now + hours * 3600),
        renew_till=0,
        flags=0x40E00000,
        der=b"\x61\x03\x30\x01\x00",
        key=bytes(range(32)),
    )


def _open(kernel: FakeKernel, residual: str) -> KeyringCache:
    cache = open_ccache(f"KEYRING:{residual}", keyctl=Keyctl(kernel))
    assert isinstance(cache, KeyringCache)
    return cache


# -- the residual, as MIT splits it -------------------------------------------


@pytest.mark.parametrize(
    "residual, expected",
    [
        ("persistent:1000", ("persistent", "1000", None)),
        ("persistent:", ("persistent", "", None)),
        ("persistent:1000:krb_ccache_AbC", ("persistent", "1000", "krb_ccache_AbC")),
        ("session:work", ("session", "work", None)),
        ("user:work:tkt2", ("user", "work", "tkt2")),
        ("process:p", ("process", "p", None)),
        ("thread:t", ("thread", "t", None)),
        ("legacyname", ("legacy", "legacyname", None)),
    ],
)
def test_the_residual_splits_as_mit_splits_it(residual, expected):
    assert parse_residual(residual) == expected


@pytest.mark.parametrize(
    "residual, message", [("galaxy:x", "unknown keyring anchor"), ("persistent:bob", "not a uid")]
)
def test_a_residual_mit_would_refuse_is_refused_on_opening(residual, message):
    with pytest.raises(CredentialError, match=message):
        open_ccache(f"KEYRING:{residual}", keyctl=Keyctl(FakeKernel()))


def test_the_primary_key_is_a_version_and_a_counted_name():
    assert parse_primary(struct.pack(">II", 1, 3) + b"tktXYZ") == "tkt"
    with pytest.raises(ValueError, match="version 2"):
        parse_primary(struct.pack(">II", 2, 3) + b"tkt")
    for torn in (b"\x00\x00\x00\x01", struct.pack(">II", 1, 9) + b"tkt"):
        with pytest.raises(ValueError, match="truncated"):
            parse_primary(torn)


# -- reading: what the FILE reader reads, from the keyring -----------------------


@pytest.mark.parametrize("enctype", sorted(CAPTURED))
def test_a_persistent_keyring_cache_reads_exactly_as_the_same_file_cache(tmp_path, enctype):
    principal, creds, image = _captured(enctype)
    kernel = FakeKernel()
    persistent = kernel(keyring.KEYCTL_GET_PERSISTENT, 1000, KEY_SPEC_PROCESS_KEYRING)
    collection = kernel.ring("_krb", persistent)
    kernel.primary(collection, "krb_ccache_q8Zp")
    kernel.cache(collection, "krb_ccache_q8Zp", principal, creds)
    kernel.ring("krb_ccache_other", collection)  # another cache in the collection
    path = tmp_path / "file"
    path.write_bytes(image)
    expected_principal, expected = read_ccache(str(path))
    got_principal, got = _open(kernel, "persistent:1000").read()
    assert got_principal == expected_principal and got == expected
    assert [t.key for t in got] == [t.key for t in expected]


def test_an_empty_uid_is_the_effective_uid(monkeypatch):
    kernel = FakeKernel()
    monkeypatch.setattr(os, "geteuid", lambda: 4242)
    persistent = kernel(keyring.KEYCTL_GET_PERSISTENT, 4242, KEY_SPEC_PROCESS_KEYRING)
    collection = kernel.ring("_krb", persistent)
    kernel.cache(collection, "tkt", marshal_principal(JANE), [marshal_ticket(_ticket(("x",)))])
    principal, (ticket,) = _open(kernel, "persistent:").read()
    assert principal.same_name(JANE) and ticket.server.components == ("x",)


@pytest.mark.parametrize("same_session", [False, True])
def test_a_session_collection_without_a_primary_uses_its_own_name(same_session):
    kernel = FakeKernel(same_session=same_session)
    anchor = KEY_SPEC_USER_SESSION_KEYRING if same_session else KEY_SPEC_SESSION_KEYRING
    collection = kernel.ring("_krb_work", anchor)
    kernel.cache(collection, "work", marshal_principal(JANE), [marshal_ticket(_ticket(("w",)))])
    assert _open(kernel, "session:work").read()[1][0].server.components == ("w",)


@pytest.mark.parametrize(
    "anchor, spec",
    [
        ("user", KEY_SPEC_USER_KEYRING),
        ("process", KEY_SPEC_PROCESS_KEYRING),
        ("thread", KEY_SPEC_THREAD_KEYRING),
    ],
)
def test_each_fixed_anchor_is_its_special_keyring(anchor, spec):
    kernel = FakeKernel()
    collection = kernel.ring("_krb_c", spec)
    kernel.cache(collection, "second", marshal_principal(JANE), [marshal_ticket(_ticket(("s",)))])
    kernel.cache(collection, "c", marshal_principal(JANE), [])
    assert _open(kernel, f"{anchor}:c:second").read()[1][0].server.components == ("s",)
    assert _open(kernel, f"{anchor}:c").read()[1] == []


def test_an_empty_collection_name_defaults_its_cache_to_tkt():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_", KEY_SPEC_USER_KEYRING)
    kernel.cache(collection, "tkt", marshal_principal(JANE))
    assert _open(kernel, "user:").read()[0].same_name(JANE)


def test_a_legacy_name_finds_a_collection_or_a_bare_pre_collection_cache():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_mine", KEY_SPEC_SESSION_KEYRING)
    kernel.cache(collection, "mine", marshal_principal(JANE), [marshal_ticket(_ticket(("c",)))])
    assert _open(kernel, "mine").read()[1][0].server.components == ("c",)
    # An MIT before 1.12 put the cache keyring itself in the session keyring.
    kernel.cache(KEY_SPEC_SESSION_KEYRING, "old", marshal_principal(JANE), [])
    assert _open(kernel, "old").read() == (JANE, [])


def test_the_kdc_offset_key_reaches_every_ticket():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_o", KEY_SPEC_USER_KEYRING)
    creds = [marshal_ticket(_ticket(("x",)))]
    kernel.cache(
        collection, "o", marshal_principal(JANE), creds, offset=struct.pack(">ii", -2, -500000)
    )
    assert _open(kernel, "user:o").read()[1][0].kdc_offset == -2.5
    short = kernel.cache(collection, "short", marshal_principal(JANE), creds, offset=b"\x00")
    assert short and _open(kernel, "user:o:short").read()[1][0].kdc_offset == 0.0


def test_config_entries_other_key_types_and_unreadable_payloads_are_left_out():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_m", KEY_SPEC_USER_KEYRING)
    config = replace(_ticket(("krb5_ccache_conf_data",)), server=Principal(("c",), "X-CACHECONF:"))
    creds = [marshal_ticket(config), b"\x00\x00", marshal_ticket(_ticket(("real",)))]
    ring = kernel.cache(collection, "m", marshal_principal(JANE), creds)
    kernel.ring("a-keyring-member", ring)
    kernel.add("logon", "not-ours", b"secret", ring)
    assert [t.server.components for t in _open(kernel, "user:m").read()[1]] == [("real",)]


def test_a_payload_that_grows_while_it_is_read_is_read_again():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_g", KEY_SPEC_USER_KEYRING)
    ring = kernel.cache(collection, "g", marshal_principal(JANE))
    kernel.grow.add(ring)
    assert _open(kernel, "user:g").read() == (JANE, [])
    assert kernel.keys[ring].members  # and the second read came back whole


# -- no cache is not an error; a broken one is ---------------------------------


@pytest.mark.parametrize("residual", ["user:absent", "persistent:1000", "session:none", "gone"])
def test_a_collection_or_cache_that_is_not_there_is_no_cache(residual):
    with pytest.raises(FileNotFoundError, match=f"KEYRING:{residual} not found"):
        _open(FakeKernel(), residual).read()


def test_a_cache_keyring_with_no_principal_is_no_cache():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_e", KEY_SPEC_USER_KEYRING)
    kernel.cache(collection, "e", None, [marshal_ticket(_ticket(("x",)))])
    with pytest.raises(FileNotFoundError, match="holds no principal"):
        _open(kernel, "user:e").read()


def test_a_key_that_is_revoked_mid_read_is_skipped_and_a_denied_one_is_an_error():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_r", KEY_SPEC_USER_KEYRING)
    creds = [marshal_ticket(_ticket(("a",))), marshal_ticket(_ticket(("b",)))]
    ring = kernel.cache(collection, "r", marshal_principal(JANE), creds)
    first_cred = kernel.keys[ring].members[1]
    kernel.errors[(keyring.KEYCTL_DESCRIBE, first_cred)] = [keyring.EKEYREVOKED]
    assert [t.server.components for t in _open(kernel, "user:r").read()[1]] == [("b",)]
    kernel.errors[(keyring.KEYCTL_READ, first_cred)] = [errno.EACCES]
    with pytest.raises(PermissionError):
        _open(kernel, "user:r").read()


def test_a_search_the_kernel_denies_is_an_error_not_an_absence():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_d", KEY_SPEC_USER_KEYRING)
    kernel.cache(collection, "d", marshal_principal(JANE))
    kernel.errors[(keyring.KEYCTL_SEARCH, collection)] = [errno.EACCES]
    with pytest.raises(PermissionError):
        _open(kernel, "user:d").read()
    # A legacy name: no collection (ENOKEY), then the bare-cache fallback is denied.
    kernel.errors[(keyring.KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING)] = [None, errno.EACCES]
    with pytest.raises(PermissionError):
        _open(kernel, "legacy").read()


def test_a_primary_key_of_an_unknown_version_is_an_error():
    kernel = FakeKernel()
    collection = kernel.ring("_krb_v", KEY_SPEC_USER_KEYRING)
    kernel.primary(collection, "tkt", version=2)
    with pytest.raises(ValueError, match="unknown keyring collection version 2"):
        _open(kernel, "user:v").read()


def test_a_keyring_cache_keeps_fetched_tickets_to_itself():
    assert _open(FakeKernel(), "user:x").store(_ticket(("x",))) is False


# -- where there is no kernel keyring ---------------------------------------------


def test_off_linux_a_keyring_cache_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(CredentialError, match=r"Linux kernel keyrings, and this is darwin"):
        open_ccache("KEYRING:persistent:1000")


def test_an_unknown_machine_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: "vax")
    with pytest.raises(CredentialError, match="not supported on vax"):
        system_keyctl()


def test_on_linux_the_syscall_comes_from_the_c_library(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    assert isinstance(system_keyctl(), Keyctl)  # built, not called: off Linux it must not be


# -- a login from a keyring cache ----------------------------------------


@pytest.fixture
def keyring_env(tmp_path, monkeypatch):
    kernel = FakeKernel()
    conf = tmp_path / "krb5.conf"
    conf.write_text(f"[libdefaults]\n default_realm = {REALM}\n")
    monkeypatch.setenv("KRB5_CONFIG", str(conf))
    monkeypatch.setenv("KRB5CCNAME", "KEYRING:persistent:1000")
    monkeypatch.setattr(caches, "system_keyctl", lambda: Keyctl(kernel))
    return kernel


def test_a_ticket_fetched_for_a_keyring_cache_stays_in_memory(keyring_env, monkeypatch):
    persistent = keyring_env(keyring.KEYCTL_GET_PERSISTENT, 1000, KEY_SPEC_PROCESS_KEYRING)
    collection = keyring_env.ring("_krb", persistent)
    ring = keyring_env.cache(
        collection, "1000", marshal_principal(JANE), [marshal_ticket(_ticket(("krbtgt", REALM)))]
    )
    asked = []

    def request_ticket(tgt, server, profile, **_):
        asked.append(server)
        return replace(tgt, server=server, key=bytes(32))

    monkeypatch.setattr(client, "request_ticket", request_ticket)
    service = f"xrootd/srv@{REALM}"
    found = client.service_credentials(service, "srv")
    assert found is not None and len(asked) == 1
    assert len(keyring_env.keys[ring].members) == 2  # principal and TGT: nothing written
    again = client.service_credentials(service, "srv")
    assert again is not None and len(asked) == 1  # from this process's memory
    assert [t.is_tgt for t in client.tickets()] == [True]


# -- on Linux: the real kernel ----------------------------------------------------------


def _real_keyctl() -> Keyctl:
    keyctl = system_keyctl()
    try:
        keyctl.keyring_id(KEY_SPEC_SESSION_KEYRING)
    except OSError as exc:  # a container's seccomp profile often forbids keyctl
        pytest.skip(f"keyctl is not permitted here: {exc}")
    return keyctl


@on_linux
def test_the_real_syscall_reads_the_session_keyring():
    keyctl = _real_keyctl()
    session = keyctl.keyring_id(KEY_SPEC_SESSION_KEYRING)
    assert session > 0
    kind, _description = keyctl.describe(session)
    assert kind == "keyring"
    assert isinstance(keyctl.members(session), list)


@on_linux
@pytest.mark.skipif(shutil.which("keyctl") is None, reason="keyutils' keyctl not installed")
def test_a_cache_laid_out_by_keyutils_is_read_through_the_real_syscall():
    keyctl = _real_keyctl()
    tag = f"xrdtest{os.getpid()}"

    def run(*argv: str, stdin: bytes | None = None) -> str:
        done = subprocess.run(["keyctl", *argv], input=stdin, capture_output=True, check=True)
        return done.stdout.decode().strip()

    probe = subprocess.run(
        ["keyctl", "newring", f"_krb_{tag}", "@s"],
        env={**os.environ, "LC_ALL": "C"},
        capture_output=True,
    )
    denied = any(
        message in probe.stderr
        for message in (
            b"Operation not permitted",
            b"Permission denied",
            b"Function not implemented",
        )
    )
    if probe.returncode and denied:
        pytest.skip("This container or kernel cannot create session keyrings")
    probe.check_returncode()
    collection = probe.stdout.decode().strip()
    try:
        cache = run("newring", tag, collection)
        run("padd", "user", "__krb5_princ__", cache, stdin=marshal_principal(JANE))
        ticket = _ticket(("krbtgt", REALM))
        run("padd", "user", f"krbtgt/{REALM}@{REALM}", cache, stdin=marshal_ticket(ticket))
        principal, (tgt,) = KeyringCache(f"session:{tag}", keyctl).read()
        assert principal.same_name(JANE) and tgt == ticket and tgt.key == ticket.key
    finally:
        run("unlink", collection, "@s")


# -- the syscall wrapper, without a kernel ----------------------------------------------


class _Syscall:
    """``syscall(2)`` that records its arguments and answers ``result``."""

    restype: object = None

    def __init__(self, result: int) -> None:
        self.result = result
        self.args: tuple[Any, ...] = ()

    def __call__(self, *args: Any) -> int:
        self.args = args
        return self.result


@pytest.mark.parametrize("result", [7, -1])
def test_keyctl_goes_through_syscall_with_long_arguments(monkeypatch, result):
    function = _Syscall(result)

    class Libc:
        syscall = function

    fake = SimpleNamespace(
        CDLL=lambda *args, **kwargs: Libc(), get_errno=lambda: 2, c_long=ctypes.c_long
    )
    monkeypatch.setattr(keyring, "ctypes", fake)
    call = keyring._libc_syscall(250)
    if result == -1:
        with pytest.raises(FileNotFoundError):
            call(3, 5, b"buf", None)
    else:
        assert call(3, 5, b"buf", None) == 7
    number, op, wide, buf, nothing = function.args
    assert (number.value, op.value, wide.value) == (250, 3, 5)
    assert (buf, nothing) == (b"buf", None)
    assert function.restype is ctypes.c_long
