"""``KCM:`` credential caches: the reader, against a KCM daemon on a Unix socket.

There is no ``sssd-kcm`` or Heimdal ``kcm`` on a developer's Mac, so the
daemon is :class:`xrdsec.testing.krb5.FakeKcm`: the KCM protocol, in a
thread, on a socket in a temporary directory. What keeps it honest is that
MIT's own client talks to it too - in xrdclient's interoperability suite,
MIT's ``kinit`` fills it, ``klist`` lists it and ``kvno`` adds to it - and
the caches it serves here are ones MIT wrote (``tests/_krb5_mit.py``). The
last section drives each of the daemon's ops directly, the ones MIT's
programs use included, so the fake itself is pinned too.
"""

from __future__ import annotations

import shutil
import socket
import struct
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from xrdcore.errors import CredentialError
from xrdsec.krb5 import client, kcm
from xrdsec.krb5.caches import FileCache, open_ccache
from xrdsec.krb5.ccache import (
    marshal_principal,
    marshal_ticket,
    read_ccache,
    read_credential,
    read_credentials,
)
from xrdsec.krb5.kcm import DEFAULT_SOCKET, KcmCache, KcmError
from xrdsec.krb5.model import Principal, Ticket
from xrdsec.krb5.profile import Profile
from xrdsec.testing import krb5 as fake
from xrdsec.testing.krb5 import FakeKcm

from tests._krb5_mit import CAPTURED

REALM = "XRD.TEST"


ENCTYPES = sorted(CAPTURED)


JANE = Principal(("jane",), REALM, 1)


@pytest.fixture
def short_dir():
    """A directory short enough for a Unix socket path (104 bytes on macOS)."""
    path = Path(tempfile.mkdtemp(prefix="kcm", dir="/tmp"))
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def daemon(short_dir):
    with FakeKcm(short_dir / "kcm.sock") as server:
        yield server


def test_the_fake_kcm_stops_its_accept_thread_on_every_platform(short_dir):
    server = FakeKcm(short_dir / "shutdown.sock").start()
    thread = server._thread
    server.stop()
    assert thread is not None and not thread.is_alive()
    server.stop()  # teardown is idempotent too


def _captured(enctype: str, name: str) -> bytes:
    return bytes.fromhex(CAPTURED[enctype][name])


def _file_view(tmp_path, image: bytes) -> tuple[Principal, list[Ticket]]:
    path = tmp_path / "file-cache"
    path.write_bytes(image)
    return read_ccache(str(path))


def _same(ours: list[Ticket], theirs: list[Ticket]) -> None:
    """Equal field by field, the session key and the clock offset included."""
    assert ours == theirs
    assert [(t.key, t.kdc_offset) for t in ours] == [(t.key, t.kdc_offset) for t in theirs]


def _ticket(server: tuple[str, ...], *, hours: float = 10, client: Principal = JANE) -> Ticket:
    now = int(time.time())
    return Ticket(
        client=client,
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


def _fill(daemon: FakeKcm, name: str, *tickets: Ticket, offset: int = 0) -> None:
    daemon.put(name, JANE, tickets, offset=offset)


@pytest.mark.parametrize("enctype", ENCTYPES)
@pytest.mark.parametrize("heimdal", [False, True], ids=["mit-extensions", "heimdal"])
def test_a_kcm_cache_reads_exactly_as_the_same_file_cache(tmp_path, daemon, enctype, heimdal):
    image = _captured(enctype, "service_ccache")  # MIT kinit + kvno: a TGT and a service ticket
    daemon.load("1000", image)
    daemon.heimdal = heimdal
    cache = KcmCache("", daemon.path.as_posix())
    principal, tickets = cache.read()
    expected_principal, expected = _file_view(tmp_path, image)
    assert principal == expected_principal
    _same(tickets, expected)
    assert [str(t.server) for t in tickets] == [
        f"krbtgt/{REALM}@{REALM}",
        f"xrootd/localhost@{REALM}",
    ]
    assert cache.name == "KCM:1000"  # resolved from the daemon's default
    ops = [op for op, _ in daemon.requests]
    walk = ["GET_CRED_LIST", "GET_CRED_UUID_LIST"] + ["GET_CRED_BY_UUID"] * 3
    assert ops == ["GET_DEFAULT_CACHE", "GET_PRINCIPAL", "GET_KDC_OFFSET"] + (
        walk if heimdal else ["GET_CRED_LIST"]
    )


def test_a_named_cache_is_read_without_asking_for_the_default(daemon):
    _fill(daemon, "1000:7", _ticket(("krbtgt", REALM)))
    cache = KcmCache("1000:7", str(daemon.path))
    principal, (tgt,) = cache.read()
    assert principal.same_name(JANE) and tgt.is_tgt and tgt.key == bytes(range(32))
    assert ("GET_DEFAULT_CACHE", "") not in daemon.requests


def test_the_kdc_offset_the_daemon_keeps_reaches_every_ticket(daemon):
    _fill(daemon, "1000", _ticket(("krbtgt", REALM)), offset=-300)
    (tgt,) = KcmCache("", str(daemon.path)).read()[1]
    assert tgt.kdc_offset == -300.0


@pytest.mark.parametrize(
    "setup",
    [
        lambda d: d.fail.__setitem__("GET_KDC_OFFSET", fake.KRB5_FCC_INTERNAL),
        lambda d: d.raw.__setitem__("GET_KDC_OFFSET", b"\x00\x01"),
    ],
    ids=["refused", "short"],
)
def test_a_daemon_that_keeps_no_offset_means_zero(daemon, setup):
    _fill(daemon, "1000", _ticket(("krbtgt", REALM)), offset=99)
    setup(daemon)
    assert KcmCache("", str(daemon.path)).read()[1][0].kdc_offset == 0.0


def test_configuration_entries_and_unreadable_credentials_are_left_out(daemon):
    config = _ticket(("krb5_ccache_conf_data", "fast_avail"))
    config = replace(config, server=Principal(config.server.components, "X-CACHECONF:", 1))
    _fill(daemon, "1000", config, _ticket(("krbtgt", REALM)))
    daemon.caches["1000"].creds[b"\xff" * 16] = b"\x00\x00\x00\x01truncated"
    (tgt,) = KcmCache("", str(daemon.path)).read()[1]
    assert tgt.is_tgt


def test_a_credential_that_vanishes_mid_walk_is_skipped(daemon):
    _fill(daemon, "1000", _ticket(("krbtgt", REALM)))
    daemon.heimdal = True
    real = daemon._op_get_cred_uuid_list

    def with_a_ghost(args):
        status, uuids = real(args)
        return status, uuids + b"\xee" * 16  # listed, but gone by the time it is fetched

    daemon._op_get_cred_uuid_list = with_a_ghost
    assert [t.is_tgt for t in KcmCache("", str(daemon.path)).read()[1]] == [True]


def test_no_daemon_is_no_cache(short_dir):
    with pytest.raises(FileNotFoundError, match="no KCM daemon at"):
        KcmCache("", str(short_dir / "absent.sock")).read()


def test_a_cache_the_daemon_does_not_hold_is_no_cache(daemon):
    with pytest.raises(FileNotFoundError, match="KCM:1000 not found"):
        KcmCache("", str(daemon.path)).read()
    daemon.fail["GET_PRINCIPAL"] = kcm.KRB5_CC_NOTFOUND
    with pytest.raises(FileNotFoundError):
        KcmCache("elsewhere", str(daemon.path)).read()


def test_an_uninitialized_cache_is_no_cache(daemon):
    daemon.put("1000", None)  # Heimdal: status 0 and no principal
    with pytest.raises(FileNotFoundError, match="not found"):
        KcmCache("", str(daemon.path)).read()


@pytest.mark.parametrize(
    "op, status",
    [("GET_PRINCIPAL", fake.KRB5_CC_IO), ("GET_CRED_LIST", fake.KRB5_FCC_NOFILE)],
)
def test_a_daemon_error_is_raised_with_its_name(daemon, op, status):
    _fill(daemon, "1000", _ticket(("krbtgt", REALM)))
    daemon.fail[op] = status
    with pytest.raises(KcmError, match="KRB5_") as info:
        KcmCache("", str(daemon.path)).read()
    assert info.value.code == status and isinstance(info.value, OSError)


def test_a_failed_fetch_in_the_uuid_walk_is_raised(daemon):
    _fill(daemon, "1000", _ticket(("krbtgt", REALM)))
    daemon.heimdal = True
    daemon.fail["GET_CRED_BY_UUID"] = fake.KRB5_CC_IO
    with pytest.raises(KcmError):
        KcmCache("", str(daemon.path)).read()


def test_an_unknown_status_is_named_by_number():
    assert "-5" in str(KcmError(-5, 8))


@pytest.mark.parametrize(
    "op, reply, message",
    [
        ("GET_DEFAULT_CACHE", b"1000", "unterminated name"),
        ("GET_CRED_UUID_LIST", b"\x00" * 17, "torn UUID list"),
    ],
)
def test_a_malformed_reply_is_a_value_error(daemon, op, reply, message):
    _fill(daemon, "1000", _ticket(("krbtgt", REALM)))
    daemon.heimdal = True
    daemon.raw[op] = reply
    with pytest.raises(ValueError, match=message):
        KcmCache("", str(daemon.path)).read()


def _scripted(path: Path, reply: bytes) -> threading.Thread:
    """A one-shot daemon that answers the first request with ``reply``, raw."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)

    def serve() -> None:
        conn, _ = listener.accept()
        with conn, listener:
            conn.recv(4096)  # the request, unread
            conn.sendall(reply)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


@pytest.mark.parametrize(
    "reply, error, message",
    [
        (struct.pack(">Ii", 0, -1765328191), KcmError, "KRB5_CC_IO"),  # heim-ipc transport error
        (struct.pack(">II", kcm.MAX_REPLY + 1, 0), ValueError, "too big"),
        (struct.pack(">II", 2, 0) + b"\x00\x00", ValueError, "no status"),
        (struct.pack(">II", 8, 0) + b"\x00\x00", ValueError, "closed the connection"),
    ],
    ids=["transport-status", "too-big", "no-status", "cut-short"],
)
def test_the_frame_is_checked(short_dir, reply, error, message):
    path = short_dir / "scripted.sock"
    thread = _scripted(path, reply)
    with pytest.raises(error, match=message):
        KcmCache("", str(path)).read()
    thread.join(5)


def test_a_daemon_that_is_not_listening_is_an_error_not_an_absence(short_dir):
    path = short_dir / "dead.sock"
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(str(path))
    dead.close()  # the socket file is there, nobody is behind it
    with pytest.raises(OSError) as info:
        KcmCache("", str(path)).read()
    assert not isinstance(info.value, FileNotFoundError)


@pytest.mark.parametrize("enctype", ENCTYPES)
def test_marshal_ticket_writes_the_bytes_mit_wrote(enctype):
    """MIT ``kvno``'s service ticket, re-marshalled by this client, is byte-identical."""
    image = _captured(enctype, "service_ccache")
    daemon = FakeKcm(Path("unused"))
    daemon.load("x", image)
    for original in daemon.caches["x"].creds.values():
        assert marshal_ticket(read_credential(original)) == original


def test_a_stored_ticket_is_in_the_cache_for_the_next_reader(daemon):
    _fill(daemon, "1000", _ticket(("krbtgt", REALM)))
    service = _ticket(("xrootd", "srv"))
    cache = KcmCache("", str(daemon.path))
    assert cache.store(service) is True  # resolves the default first
    assert cache.name == "KCM:1000"
    _tgt, stored = KcmCache("1000", str(daemon.path)).read()[1]
    _same([stored], [service])


def test_a_refused_store_is_not_fatal(daemon, short_dir):
    _fill(daemon, "1000", _ticket(("krbtgt", REALM)))
    daemon.fail["STORE"] = fake.KRB5_CC_NOSUPP
    assert KcmCache("1000", str(daemon.path)).store(_ticket(("xrootd", "srv"))) is False
    assert KcmCache("1000", str(short_dir / "gone.sock")).store(_ticket(("x",))) is False


def test_read_credentials_skips_what_it_cannot_parse():
    good = marshal_ticket(_ticket(("krbtgt", REALM)))
    assert len(read_credentials([b"", good, good[:-3]], 0.0, "KCM:x")) == 1


def test_the_socket_comes_from_krb5_conf_else_heimdals_default(tmp_path):
    configured = Profile.parse("[libdefaults]\n kcm_socket = /run/elsewhere.sock\n")
    cache = open_ccache("KCM:", configured)
    assert isinstance(cache, KcmCache) and cache.socket_path == "/run/elsewhere.sock"
    plain = open_ccache("KCM:1000", Profile.parse("[libdefaults]\n"))
    assert isinstance(plain, KcmCache) and plain.socket_path == DEFAULT_SOCKET
    assert plain.residual == "1000"


def test_file_and_dir_names_still_open_as_files(tmp_path):
    cache = open_ccache(f"FILE:{tmp_path}/cc", Profile.parse(""))
    assert isinstance(cache, FileCache) and cache.name == f"{tmp_path}/cc"
    assert cache.store(_ticket(("x",))) is False


@pytest.mark.parametrize("name", ["API:", "API:ABCD-1234"])
def test_a_macos_api_cache_is_refused_with_the_fix(name):
    with pytest.raises(CredentialError) as error:
        open_ccache(name, Profile.parse(""))
    message = str(error.value)
    assert name in message
    assert "Install python-gssapi (the 'krb5' extra)" in message
    assert "KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u) kinit" in message


SERVICE = f"xrootd/srv@{REALM}"


@pytest.fixture
def kcm_env(daemon, tmp_path, monkeypatch):
    conf = tmp_path / "krb5.conf"
    conf.write_text(f"[libdefaults]\n default_realm = {REALM}\n kcm_socket = {daemon.path}\n")
    monkeypatch.setenv("KRB5_CONFIG", str(conf))
    monkeypatch.setenv("KRB5CCNAME", "KCM:")
    return daemon


@pytest.fixture
def kdc(monkeypatch):
    asked: list[Principal] = []  # the services the KDC was asked for

    def request_ticket(tgt, server, profile, *, etypes, options=0, **_):
        asked.append(server)
        return replace(tgt, server=server, key=bytes(32), end_time=int(time.time()) + 600)

    monkeypatch.setattr(client, "request_ticket", request_ticket)
    return asked


def _login() -> client.ServiceCredentials | None:
    """A login to :data:`SERVICE` from the default cache - the daemon's, here."""
    return client.service_credentials(SERVICE, "srv")


def test_a_ticket_fetched_for_a_kcm_cache_is_stored_there_as_mit_does(kcm_env, kdc):
    _fill(kcm_env, "1000", _ticket(("krbtgt", REALM)))
    found = _login()
    assert found is not None and [str(p) for p in kdc] == [SERVICE]
    assert ("STORE", "1000") in kcm_env.requests
    # A new process - no memory of the fetch - finds it in the cache, and asks no KDC.
    client.clear_cache()
    again = _login()
    assert again is not None and len(kdc) == 1
    assert [str(t.server) for t in client.tickets()] == [f"krbtgt/{REALM}@{REALM}", str(kdc[0])]


def test_no_kcm_daemon_is_no_krb5_credential(tmp_path, short_dir, monkeypatch):
    conf = tmp_path / "krb5.conf"
    conf.write_text(f"[libdefaults]\n kcm_socket = {short_dir}/none.sock\n")
    monkeypatch.setenv("KRB5_CONFIG", str(conf))
    monkeypatch.setenv("KRB5CCNAME", "KCM:")
    assert _login() is None
    assert client.tickets() == []


def test_a_broken_kcm_daemon_is_named_in_the_error(kcm_env):
    _fill(kcm_env, "1000", _ticket(("krbtgt", REALM)))
    kcm_env.fail["GET_CRED_LIST"] = fake.KRB5_CC_IO
    kcm_env.fail["GET_CRED_UUID_LIST"] = fake.KRB5_CC_IO
    with pytest.raises(CredentialError, match="KCM:1000 is unreadable"):
        _login()


def test_expired_tickets_in_a_kcm_cache_say_so(kcm_env):
    _fill(kcm_env, "1000", _ticket(("krbtgt", REALM), hours=-1))
    with pytest.raises(CredentialError, match="in KCM:1000 expired"):
        _login()


# -- the fake daemon's own ops, as MIT's kinit, klist and kvno use them -----------------


def _request(op: str, *args: bytes) -> bytes:
    """A request body: version 2.0, the opcode, the arguments."""
    return struct.pack(">BBH", 2, 0, fake.KCM_OPS[op]) + b"".join(args)


def _name(text: str) -> bytes:
    return text.encode() + b"\0"


def test_kinit_creates_fills_and_switches_a_cache():
    daemon = FakeKcm(Path("unused"))
    principal = marshal_principal(JANE)
    assert daemon.answer(_request("NOOP")) == (0, b"")
    assert daemon.answer(_request("GEN_NEW")) == (0, b"1000:1\0")
    assert daemon.answer(_request("INITIALIZE", _name("1000:1"), principal)) == (0, b"")
    assert daemon.answer(_request("GET_PRINCIPAL", _name("1000:1"))) == (0, principal)
    tgt = marshal_ticket(_ticket(("krbtgt", REALM)))
    assert daemon.answer(_request("STORE", _name("1000:1"), tgt)) == (0, b"")
    assert daemon.answer(_request("SET_FLAGS", _name("1000:1"), b"\0\0\0\0")) == (0, b"")
    assert daemon.answer(_request("SET_KDC_OFFSET", _name("1000:1"), struct.pack(">i", -7)))[0] == 0
    assert daemon.answer(_request("GET_KDC_OFFSET", _name("1000:1"))) == (0, struct.pack(">i", -7))
    assert daemon.answer(_request("SET_DEFAULT_CACHE", _name("1000:1"))) == (0, b"")
    assert daemon.answer(_request("GET_DEFAULT_CACHE")) == (0, b"1000:1\0")
    status, listed = daemon.answer(_request("GET_CRED_LIST", _name("1000:1")))
    assert status == 0 and listed == struct.pack(">II", 1, len(tgt)) + tgt
    assert [op for op, _ in daemon.requests][:4] == [
        "NOOP",
        "GEN_NEW",
        "INITIALIZE",
        "GET_PRINCIPAL",
    ]


def test_replace_writes_a_whole_cache_in_one_op():
    daemon = FakeKcm(Path("unused"))
    creds = [marshal_ticket(_ticket(("krbtgt", REALM))), marshal_ticket(_ticket(("x", "y")))]
    body = struct.pack(">i", 30) + marshal_principal(JANE) + struct.pack(">I", len(creds))
    body += b"".join(struct.pack(">I", len(cred)) + cred for cred in creds)
    assert daemon.answer(_request("REPLACE", _name("1000"), body)) == (0, b"")
    assert daemon.caches["1000"].offset == 30
    assert sorted(daemon.caches["1000"].creds.values()) == sorted(creds)


def test_klist_walks_the_caches_and_their_credentials_by_uuid():
    daemon = FakeKcm(Path("unused"))
    daemon.put("1000", JANE, [_ticket(("krbtgt", REALM))])
    status, uuids = daemon.answer(_request("GET_CACHE_UUID_LIST"))
    assert status == 0 and len(uuids) == 16
    assert daemon.answer(_request("GET_CACHE_BY_UUID", uuids)) == (0, b"1000\0")
    assert daemon.answer(_request("GET_CACHE_BY_UUID", b"\0" * 16)) == (fake.KRB5_FCC_NOFILE, b"")
    status, creds = daemon.answer(_request("GET_CRED_UUID_LIST", _name("1000")))
    assert (status, creds) == (0, (0).to_bytes(16, "big"))
    status, cred = daemon.answer(_request("GET_CRED_BY_UUID", _name("1000"), creds))
    assert status == 0 and read_credential(cred).is_tgt
    missing = daemon.answer(_request("GET_CRED_BY_UUID", _name("1000"), b"\x01" * 16))
    assert missing == (fake.KRB5_CC_END, b"")


def test_kvno_and_kdestroy_are_answered_as_sssd_answers_them():
    daemon = FakeKcm(Path("unused"))
    daemon.put("1000", JANE)
    assert daemon.answer(_request("RETRIEVE", _name("1000"))) == (fake.KRB5_CC_NOSUPP, b"")
    assert daemon.answer(_request("REMOVE_CRED", _name("1000"))) == (fake.KRB5_CC_NOSUPP, b"")
    assert daemon.answer(_request("DESTROY", _name("1000"))) == (0, b"")
    assert daemon.answer(_request("GET_PRINCIPAL", _name("1000"))) == (fake.KRB5_FCC_NOFILE, b"")


def test_a_bad_version_an_unknown_op_and_heimdal_s_refusals():
    daemon = FakeKcm(Path("unused"), heimdal=True)
    assert daemon.answer(struct.pack(">BBH", 1, 0, 0)) == (fake.KRB5_CC_IO, b"")
    assert daemon.answer(struct.pack(">BBH", 2, 0, 999)) == (fake.KRB5_FCC_INTERNAL, b"")
    assert daemon.answer(_request("GET_NAME")) == (fake.KRB5_FCC_INTERNAL, b"")
    assert daemon.answer(_request("GET_CRED_LIST", _name("1000"))) == (fake.KRB5_FCC_INTERNAL, b"")
    assert ("999", "") in daemon.requests


def test_load_takes_only_a_version_4_image():
    daemon = FakeKcm(Path("unused"))
    with pytest.raises(ValueError, match="version 4"):
        daemon.load("x", struct.pack(">H", 0x0503) + b"\0" * 8)


def test_a_client_that_hangs_up_mid_frame_ends_its_connection(daemon):
    for partial in (b"", b"\x00\x00", struct.pack(">I", 8) + b"\x02\x00"):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(daemon.path))
            conn.sendall(partial)
    # The daemon still serves the next client.
    daemon.put("1000", JANE, [_ticket(("krbtgt", REALM))])
    assert KcmCache("1000", str(daemon.path)).read()[0].same_name(JANE)


def test_stopping_a_daemon_that_never_started_is_harmless(short_dir):
    FakeKcm(short_dir / "never.sock").stop()


def test_make_ticket_defaults_to_a_live_forwardable_ticket():
    ticket = fake.make_ticket(JANE, Principal(("krbtgt", REALM), REALM))
    assert ticket.forwardable and not ticket.expired and len(ticket.key) == 32
    assert fake.make_ticket(JANE, JANE, lifetime=-1).expired
