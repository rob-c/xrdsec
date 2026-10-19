"""The FILE credential cache, which cache is "the" cache, and the nouns: principals and tickets.

The caches here are written by :func:`write_ccache` below, straight from
the layout in MIT's ``ccache_file_format`` document - not by
:func:`xrdsec.krb5.ccache.marshal_ticket` - so the reader is checked against
an encoder of its own; ``test_krb5_mit.py`` reads caches MIT itself wrote.
"""

from __future__ import annotations

import os
import struct
import tempfile
import time
from collections.abc import Iterable, Sequence
from pathlib import Path

import pytest

from xrdcore.errors import CredentialError
from xrdsec.krb5 import ccache
from xrdsec.krb5.ccache import (
    CCACHE_VERSION_3,
    CCACHE_VERSION_4,
    ccache_name,
    read_ccache,
    resolve_ccache,
)
from xrdsec.krb5.model import Principal, Ticket
from xrdsec.krb5.profile import Profile

REALM = "EXAMPLE.ORG"


TICKET_DER = b"\x61\x03\x30\x01\x00"  # opaque to the client; any single TLV will do


KEY = bytes(range(32))


def _blob(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _principal(components: tuple[str, ...], realm: str = REALM, name_type: int = 1) -> bytes:
    return (
        struct.pack(">II", name_type, len(components))
        + _blob(realm.encode())
        + b"".join(_blob(part.encode()) for part in components)
    )


def _credential(
    client: tuple[str, ...],
    server: tuple[str, ...],
    *,
    end_time: float,
    enctype: int = 18,
    version: int = CCACHE_VERSION_4,
    der: bytes = TICKET_DER,
    addresses: Sequence[tuple[int, bytes]] = (),
    authdata: Sequence[tuple[int, bytes]] = (),
    flags: int = 0x40E00000,
    realm: str = REALM,
    key: bytes = KEY,
) -> bytes:
    out = _principal(client) + _principal(server, realm)
    out += struct.pack(">H", enctype)
    if version == CCACHE_VERSION_3:
        out += struct.pack(">H", enctype)  # version 3 wrote it twice
    out += _blob(key)  # the session key
    out += struct.pack(">IIII", int(end_time) - 3600, int(end_time) - 3600, int(end_time), 0)
    out += b"\x00"  # is_skey
    out += struct.pack(">I", flags)
    out += struct.pack(">I", len(addresses))
    out += b"".join(struct.pack(">H", kind) + _blob(value) for kind, value in addresses)
    out += struct.pack(">I", len(authdata))
    out += b"".join(struct.pack(">H", kind) + _blob(value) for kind, value in authdata)
    out += _blob(der) + _blob(b"")
    return out


def write_ccache(
    path: Path,
    entries: Iterable[tuple[tuple[str, ...], tuple[str, ...], float]],
    *,
    version: int = CCACHE_VERSION_4,
    default: tuple[str, ...] = ("jane",),
    flags: int = 0x40E00000,
) -> str:
    """A FILE credential cache, in the format MIT and Heimdal write."""
    out = struct.pack(">H", version)
    if version == CCACHE_VERSION_4:
        out += struct.pack(">H", 0)  # no header tags
    out += _principal(default)
    for client, server, end_time in entries:
        out += _credential(client, server, end_time=end_time, version=version, flags=flags)
    path.write_bytes(out)
    return str(path)


@pytest.fixture
def cache(tmp_path):
    ahead = time.time() + 36000
    return write_ccache(
        tmp_path / "krb5cc_1000",
        [
            (("jane",), ("krbtgt", REALM), ahead),
            (("jane",), ("xrootd", "srv.example.org"), ahead),
        ],
    )


def test_a_version_4_cache_reads_back(cache):
    default, found = read_ccache(cache)
    assert str(default) == f"jane@{REALM}"
    assert [str(ticket.server) for ticket in found] == [
        f"krbtgt/{REALM}@{REALM}",
        f"xrootd/srv.example.org@{REALM}",
    ]
    assert all(str(ticket.client) == f"jane@{REALM}" for ticket in found)


def test_the_session_key_is_kept_and_never_printed(cache):
    ticket = read_ccache(cache)[1][0]
    assert ticket.key == KEY
    assert KEY.hex() not in repr(ticket) and "key" not in repr(ticket)


def test_a_version_3_cache_reads_back(tmp_path):
    """Version 3 repeats the enctype; getting that wrong desynchronises everything."""
    path = write_ccache(
        tmp_path / "v3",
        [(("jane",), ("krbtgt", REALM), time.time() + 60)],
        version=CCACHE_VERSION_3,
    )
    _default, found = read_ccache(path)
    assert len(found) == 1
    assert found[0].enctype == 18 and found[0].key == KEY


def test_the_ticket_fields_survive_the_round_trip(cache):
    ticket = read_ccache(cache)[1][0]
    assert ticket.enctype == 18
    assert ticket.flags == 0x40E00000 and ticket.forwardable
    assert ticket.der == TICKET_DER
    assert ticket.auth_time == ticket.start_time == ticket.end_time - 3600
    assert ticket.renew_till == 0


def test_the_ticket_granting_ticket_is_identified(cache):
    granting, service = read_ccache(cache)[1]
    assert granting.is_tgt
    assert not service.is_tgt


def test_mits_configuration_entries_are_not_tickets(tmp_path):
    """kinit stores fast_avail, pa_type and the like as pseudo-tickets in X-CACHECONF:."""
    body = struct.pack(">HH", CCACHE_VERSION_4, 0) + _principal(("jane",))
    body += _credential(
        ("jane",), ("krb5_ccache_conf_data", "fast_avail"), end_time=3600, realm="X-CACHECONF:"
    )
    body += _credential(("jane",), ("krbtgt", REALM), end_time=time.time() + 60)
    path = tmp_path / "conf"
    path.write_bytes(body)
    assert [str(t.server) for t in read_ccache(str(path))[1]] == [f"krbtgt/{REALM}@{REALM}"]


def test_expiry_is_reported_from_the_cache(tmp_path):
    path = write_ccache(
        tmp_path / "mixed",
        [
            (("jane",), ("krbtgt", REALM), time.time() - 60),
            (("jane",), ("xrootd", "srv"), time.time() + 600),
        ],
    )
    stale, live = read_ccache(path)[1]
    assert stale.expired and stale.remaining() < 0
    assert not live.expired
    assert live.remaining() == pytest.approx(600, abs=5)


def test_an_unknown_version_is_named(tmp_path):
    path = tmp_path / "future"
    path.write_bytes(struct.pack(">H", 0x0505) + b"\x00" * 32)
    with pytest.raises(ValueError, match="0x0505"):
        read_ccache(str(path))


def test_a_truncated_entry_costs_the_tail_not_the_answer(tmp_path):
    """A cache being rewritten under us must not lose the tickets already read."""
    path = write_ccache(tmp_path / "cut", [(("jane",), ("krbtgt", REALM), time.time() + 60)])
    with open(path, "rb") as handle:
        data = handle.read()
    cut = tmp_path / "cut2"
    cut.write_bytes(data + _principal(("jane",))[:10])
    default, found = read_ccache(str(cut))
    assert str(default) == f"jane@{REALM}"
    assert len(found) == 1


def test_the_cursor_refuses_to_read_past_the_end():
    reader = ccache._Reader(b"\x00\x01")
    assert reader.u16() == 1
    assert reader.exhausted
    with pytest.raises(ValueError, match="truncated"):
        reader.take(1)
    with pytest.raises(ValueError, match="truncated"):
        ccache._Reader(b"").take(-1)


def test_a_ticket_carrying_addresses_and_authorization_data_still_reads_back(tmp_path):
    """Both lists are skipped, not parsed - but skipping them must be exact."""
    ahead = time.time() + 3600
    path = tmp_path / "krb5cc_addr"
    body = struct.pack(">HH", CCACHE_VERSION_4, 0) + _principal(("jane",))
    body += _credential(
        ("jane",),
        ("krbtgt", REALM),
        end_time=ahead,
        addresses=((2, b"\x7f\x00\x00\x01"), (2, b"\x0a\x00\x00\x01")),
        authdata=((1, b"restrictions"),),
    )
    path.write_bytes(body)
    _, found = read_ccache(str(path))
    assert [str(t.server) for t in found] == [f"krbtgt/{REALM}@{REALM}"]
    assert found[0].is_tgt


def test_the_kdc_clock_offset_in_a_version_4_header_is_kept(tmp_path):
    """Tag 1 (DeltaTime) is seconds and microseconds, signed; other tags are skipped."""
    header = struct.pack(">HH4s", 2, 4, b"????") + struct.pack(">HHii", 1, 8, -300, 250_000)
    body = struct.pack(">HH", CCACHE_VERSION_4, len(header)) + header + _principal(("jane",))
    body += _credential(("jane",), ("krbtgt", REALM), end_time=time.time() + 60)
    path = tmp_path / "skewed"
    path.write_bytes(body)
    assert read_ccache(str(path))[1][0].kdc_offset == -299.75
    odd = struct.pack(">HHi", 1, 4, 7)  # not the 8 bytes DeltaTime has: ignored
    body = struct.pack(">HH", CCACHE_VERSION_4, len(odd)) + odd + _principal(("jane",))
    path.write_bytes(body + _credential(("jane",), ("krbtgt", REALM), end_time=time.time() + 60))
    assert read_ccache(str(path))[1][0].kdc_offset == 0.0


def test_the_cache_path_follows_the_kerberos_convention(monkeypatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    assert resolve_ccache() == f"/tmp/krb5cc_{os.geteuid()}"
    monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/mine")
    assert resolve_ccache() == "/tmp/mine"
    monkeypatch.setenv("KRB5CCNAME", "/tmp/bare")
    assert resolve_ccache() == "/tmp/bare"
    monkeypatch.setenv("KRB5CCNAME", "/tmp/odd:name")
    assert resolve_ccache() == "/tmp/odd:name"


@pytest.mark.parametrize("name", ["KCM:", "KEYRING:persistent:1000", "API:", "MEMORY:x", "WEIRD:x"])
def test_a_cache_that_is_not_a_file_is_an_error_that_says_what_to_do(monkeypatch, name):
    monkeypatch.setenv("KRB5CCNAME", name)
    with pytest.raises(CredentialError, match=r"KRB5CCNAME=FILE:/tmp/krb5cc_\$\(id -u\) kinit"):
        resolve_ccache()


def test_a_dir_collection_resolves_to_its_primary_cache(tmp_path):
    collection = tmp_path / "cc"
    collection.mkdir()
    assert resolve_ccache(f"DIR:{collection}") == str(collection / "tkt")  # none yet: MIT's default
    (collection / "primary").write_text("tktABC\n")
    assert resolve_ccache(f"DIR:{collection}") == str(collection / "tktABC")
    assert resolve_ccache(f"DIR::{collection}/tktXYZ") == f"{collection}/tktXYZ"


def test_the_default_name_comes_from_krb5_conf_when_the_environment_is_silent(monkeypatch):
    monkeypatch.delenv("KRB5CCNAME", raising=False)
    monkeypatch.setenv("USER", "jane")
    profile = Profile.parse(
        "[libdefaults]\n"
        " default_ccache_name = FILE:%{TEMP}/cc_%{uid}_%{euid}_%{USERID}_%{username}%{null}\n"
    )
    uid, euid = os.getuid(), os.geteuid()
    expected = f"FILE:{tempfile.gettempdir()}/cc_{uid}_{euid}_{euid}_jane"
    assert ccache_name(profile) == expected
    kcm = Profile.parse("[libdefaults]\n default_ccache_name = KCM:\n")
    with pytest.raises(CredentialError, match="lives outside the filesystem"):
        resolve_ccache(profile=kcm)


def test_a_principal_prints_the_way_kinit_does():
    assert str(Principal(("xrootd", "srv.example.org"), REALM)) == f"xrootd/srv.example.org@{REALM}"
    assert str(Principal(("jane",), REALM)) == f"jane@{REALM}"
    assert str(Principal(("jane",), "")) == "jane"
    assert not Principal((), "")


def test_ticket_repr_says_who_and_how_long():
    ticket = Ticket(
        client=Principal(("jane",), REALM),
        server=Principal(("xrootd", "srv"), REALM),
        enctype=18,
        auth_time=0,
        start_time=0,
        end_time=int(time.time()) + 300,
        renew_till=0,
        flags=0,
    )
    assert repr(ticket).startswith("Ticket(server='xrootd/srv@EXAMPLE.ORG', expires_in=")
    assert "299" in repr(ticket) or "300" in repr(ticket)


def test_a_ticket_with_no_end_time_never_expires():
    ticket = Ticket(Principal(("j",), ""), Principal(("s",), ""), 18, 0, 0, 0, 0, 0)
    assert not ticket.expired


# -- the shared entry codec (FILE, KCM and KEYRING all use it) ---------------------


def _ticket() -> Ticket:
    return Ticket(
        Principal(("alice",), "EXAMPLE", 1),
        Principal(("xrootd", "host"), "EXAMPLE", 2),
        18,
        100,
        101,
        200,
        300,
        0x40000000,
        b"opaque-ticket",
        bytes(range(32)),
    )


@pytest.mark.parametrize("version", [ccache.CCACHE_VERSION_3, ccache.CCACHE_VERSION_4])
def test_local_cache_reader_round_trips_both_versions(version):
    ticket = _ticket()
    blob = ccache.marshal_ticket(ticket)
    if version == ccache.CCACHE_VERSION_3:
        offset = len(ccache.marshal_principal(ticket.client))
        offset += len(ccache.marshal_principal(ticket.server)) + 2
        blob = blob[:offset] + struct.pack(">H", ticket.enctype) + blob[offset:]
    reader = ccache._Reader(blob)
    restored = ccache._read_entry(reader, version, 12.5)
    assert restored == ticket
    assert restored.kdc_offset == 12.5
    assert restored.key == ticket.key
    assert reader.exhausted


@pytest.mark.parametrize("fraction", range(32))
def test_truncated_local_cache_keeps_value_error(fraction):
    blob = ccache.marshal_ticket(_ticket())
    with pytest.raises(ValueError, match="truncated"):
        ccache.read_credential(blob[: len(blob) * fraction // 32])


def test_partial_cache_tail_keeps_complete_credentials(tmp_path):
    ticket = _ticket()
    path = tmp_path / "cache"
    path.write_bytes(
        struct.pack(">HH", ccache.CCACHE_VERSION_4, 0)
        + ccache.marshal_principal(ticket.client)
        + ccache.marshal_ticket(ticket)
        + b"\0"
    )
    client, entries = ccache.read_ccache(str(path))
    assert client == ticket.client
    assert entries == [ticket]
