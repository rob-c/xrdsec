"""The FILE credential cache that ``kinit`` writes, read with its keys.

Versions 3 and 4 of the format are what MIT and Heimdal write: a default
principal, then one entry per credential - client, server, the session key,
times, flags, addresses, authorization data and the ticket itself. The key
is kept, in memory only, because without it a ticket is useless: it is what
the authenticator in an AP-REQ is encrypted under.

The same marshalled principal and credential are what a KCM daemon
exchanges over its socket (:mod:`.kcm`) and what MIT stores in a kernel
keyring (:mod:`.keyring`), so the entry reader - and :func:`marshal_ticket`,
its inverse - live here and serve all three.

Which cache is "the" cache follows MIT: ``$KRB5CCNAME``, else
``default_ccache_name`` from ``krb5.conf``, else ``/tmp/krb5cc_<uid>``.
:func:`resolve_ccache` answers "which file?" for ``FILE:`` and ``DIR:``
names, and refuses the rest, which are not files; :func:`.caches.open_ccache`
opens any name a login can use, ``KCM:`` and ``KEYRING:`` included.

The file layout (MIT's ``ccache_file_format`` document; every integer is
big-endian in versions 3 and 4, unlike the host-order versions 1 and 2,
which nothing has written for decades and which are refused)::

    u16 version                      0x0503 or 0x0504
    v4 only: u16 header_len, then header_len bytes of (u16 tag, u16 len, value)
    principal default                see _read_principal
    credential*                      until end of file, see _read_entry

A string or a binary value ("counted octet string") is a u32 length then
the bytes. Times are u32 seconds since the epoch, in the KDC's clock.

Ownership: the cache file is ``kinit``'s. It is opened read-only, read in
one ``read()`` and closed, and nothing here ever writes it - see
:meth:`.caches.FileCache.store` for why.
"""

from __future__ import annotations

import os
import struct
import tempfile

from xrdcore.errors import CredentialError
from xrdcore.log import get_logger

from .model import Principal, Ticket
from .profile import Profile

__all__ = [
    "CCACHE_VERSION_3",
    "CCACHE_VERSION_4",
    "ccache_name",
    "is_config_entry",
    "marshal_principal",
    "marshal_ticket",
    "read_ccache",
    "read_credential",
    "read_credentials",
    "read_principal",
    "resolve_ccache",
]

_log = get_logger(__name__)

#: The first two bytes of a cache file: format 5 (krb5), versions 4 and 3.
#: Version 4 adds the header (and its clock offset); entries are identical
#: apart from version 3 writing the key's enctype twice.
CCACHE_VERSION_4 = 0x0504
CCACHE_VERSION_3 = 0x0503

#: MIT keeps cache metadata as pseudo-credentials in this realm; they are not tickets.
_CONFIG_REALM = "X-CACHECONF:"

#: The version 4 header tag that carries the KDC's clock offset.
_TAG_DELTATIME = 1

#: Cache types that exist but are not files, so :func:`resolve_ccache` can
#: tell "not a file" apart from "never heard of it" in its message.
_UNREACHABLE = ("KCM", "KEYRING", "API", "MEMORY", "MSLSA")


class _Reader:
    """A big-endian cursor that refuses to read past the end.

    Every short read is a :class:`ValueError` naming the offset, which the
    readers above catch to give up on one entry (or the tail of a file)
    rather than the whole cache. Lengths in the file are not trusted: a
    corrupt u32 length simply fails :meth:`take` instead of allocating.
    """

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        """Start at offset 0 of ``data``, which the reader never copies."""
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        """The next ``count`` bytes; ValueError if fewer are left."""
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError(f"credential cache truncated at offset {self.pos}")
        out = self.data[self.pos : self.pos + count]
        self.pos += count
        return out

    def u16(self) -> int:
        """A big-endian unsigned 16-bit integer."""
        return int(struct.unpack(">H", self.take(2))[0])

    def u32(self) -> int:
        """A big-endian unsigned 32-bit integer."""
        return int(struct.unpack(">I", self.take(4))[0])

    def blob(self) -> bytes:
        """A counted octet string: u32 length, then that many bytes."""
        return self.take(self.u32())

    @property
    def exhausted(self) -> bool:
        """Whether the cursor has reached the end: the loop condition for entries."""
        return self.pos >= len(self.data)


def _read_principal(reader: _Reader) -> Principal:
    """One principal, in the layout versions 3 and 4 share.

    ``u32 name_type, u32 count, string realm, string component * count``.
    Version 1 counted the realm among the components; that layout is
    refused with its version. Undecodable names are replaced, not fatal:
    they only ever reach messages and comparisons.
    """
    name_type = reader.u32()
    count = reader.u32()
    realm = reader.blob().decode("utf-8", "replace")
    components = tuple(reader.blob().decode("utf-8", "replace") for _ in range(count))
    return Principal(components, realm, name_type)


def _skip_list(reader: _Reader) -> None:
    """Addresses and authorization data: a count of (u16 type, blob) pairs, unused here."""
    for _ in range(reader.u32()):
        reader.u16()
        reader.blob()


def _kdc_offset(header: bytes) -> float:
    """A version 4 header's DeltaTime tag: the KDC's clock minus ours, else 0.

    The header is a run of ``(u16 tag, u16 length, value)``; tag 1 holds the
    offset as signed seconds and microseconds, which ``kinit`` records when
    ``kdc_timesync`` is on - MIT's default.
    """
    tags = _Reader(header)
    while not tags.exhausted:
        tag, value = tags.u16(), tags.take(tags.u16())
        if tag == _TAG_DELTATIME and len(value) == 8:
            seconds, micros = struct.unpack(">ii", value)
            return float(seconds + micros / 1_000_000)
    return 0.0


def _read_entry(reader: _Reader, version: int, kdc_offset: float) -> Ticket:
    """One credential, the cursor left on the byte after it.

    ``principal client, principal server, keyblock, u32 authtime,
    u32 starttime, u32 endtime, u32 renew_till, u8 is_skey, u32 ticket_flags,
    addresses, authdata, string ticket, string second_ticket``, where a
    keyblock is ``u16 enctype [u16 enctype again in v3], string key``.
    ``kdc_offset`` comes from the file header and is stamped onto every
    ticket, since it is a property of the cache, not of one entry.
    """
    client = _read_principal(reader)
    server = _read_principal(reader)
    enctype = reader.u16()
    if version == CCACHE_VERSION_3:
        reader.u16()  # version 3 wrote the enctype twice
    key = reader.blob()
    auth_time, start_time, end_time, renew_till = (reader.u32() for _ in range(4))
    reader.take(1)  # is_skey: user-to-user, never used here
    flags = reader.u32()
    _skip_list(reader)  # addresses
    _skip_list(reader)  # authorization data
    der = reader.blob()
    reader.blob()  # second ticket, used only for user-to-user
    return Ticket(
        client=client,
        server=server,
        enctype=enctype,
        auth_time=auth_time,
        start_time=start_time,
        end_time=end_time,
        renew_till=renew_till,
        flags=flags,
        der=der,
        key=key,
        kdc_offset=kdc_offset,
    )


def is_config_entry(ticket: Ticket) -> bool:
    """Whether an entry is one of MIT's configuration pseudo-credentials."""
    return ticket.server.realm == _CONFIG_REALM


def read_principal(data: bytes) -> Principal:
    """A marshalled principal, alone: what a KCM daemon or a keyring key holds."""
    return _read_principal(_Reader(data))


def read_credential(data: bytes, kdc_offset: float = 0.0) -> Ticket:
    """One marshalled (version 4) credential, alone."""
    return _read_entry(_Reader(data), CCACHE_VERSION_4, kdc_offset)


def read_credentials(blobs: list[bytes], kdc_offset: float, where: str) -> list[Ticket]:
    """Credentials marshalled one per blob, as a KCM daemon or a keyring hands them over.

    One that will not parse is skipped rather than fatal - the FILE reader
    likewise gives up only what it cannot read - and configuration entries
    are left out.
    """
    out: list[Ticket] = []
    for blob in blobs:
        try:
            ticket = read_credential(blob, kdc_offset)
        except (ValueError, struct.error) as exc:
            _log.debug("skipping an unreadable credential in %s: %s", where, exc)
            continue
        if not is_config_entry(ticket):
            out.append(ticket)
    return out


def _blob(data: bytes) -> bytes:
    """A counted octet string: the inverse of :meth:`_Reader.blob`."""
    return struct.pack(">I", len(data)) + data


def marshal_principal(principal: Principal) -> bytes:
    """A principal in the layout versions 3 and 4 share: the inverse of :func:`read_principal`."""
    head = struct.pack(">II", principal.name_type, len(principal.components))
    parts = (principal.realm, *principal.components)
    return head + b"".join(_blob(part.encode("utf-8")) for part in parts)


def marshal_ticket(ticket: Ticket) -> bytes:
    """A credential as a version 4 entry, as MIT's ``k5_marshal_cred`` writes it.

    What a :class:`Ticket` does not keep is written as MIT writes it for a
    ticket the TGS exchange returned: no addresses, no authorization data,
    not user-to-user, no second ticket.
    """
    times = (ticket.auth_time, ticket.start_time, ticket.end_time, ticket.renew_till)
    return b"".join(
        (
            marshal_principal(ticket.client),
            marshal_principal(ticket.server),
            struct.pack(">H", ticket.enctype),
            _blob(ticket.key),
            # four times, is_skey = 0 (not user-to-user), then the flags.
            struct.pack(">IIIIBI", *times, 0, ticket.flags),
            struct.pack(">II", 0, 0),  # addresses, authorization data
            _blob(ticket.der),
            _blob(b""),  # second ticket
        )
    )


def read_ccache(path: str) -> tuple[Principal, list[Ticket]]:
    """Parse a FILE credential cache into its default principal and tickets.

    Entries that will not parse end the scan rather than raising, because a
    cache being rewritten under us should cost the tail, not the whole
    answer. MIT's configuration pseudo-entries are left out.
    """
    with open(path, "rb") as handle:
        reader = _Reader(handle.read())
    version = reader.u16()
    if version not in (CCACHE_VERSION_3, CCACHE_VERSION_4):
        raise ValueError(f"unsupported credential cache version 0x{version:04x} in {path}")
    kdc_offset = _kdc_offset(reader.take(reader.u16())) if version == CCACHE_VERSION_4 else 0.0
    default = _read_principal(reader)

    out: list[Ticket] = []
    while not reader.exhausted:
        try:
            ticket = _read_entry(reader, version, kdc_offset)
        except (ValueError, struct.error) as exc:
            _log.debug("credential cache %s ends early: %s", path, exc)
            break
        if not is_config_entry(ticket):
            out.append(ticket)
    return default, out


def _expand(name: str) -> str:
    """MIT's ``%{...}`` tokens in ``default_ccache_name``, the ones seen in the wild.

    Distributions ship ``KEYRING:persistent:%{uid}`` and
    ``KCM:`` defaults; ``%{USERID}`` is MIT's Windows-compatible spelling of
    the effective uid. Unknown tokens are left as they are, so the name
    that fails to open is the one a person can see in ``krb5.conf``.
    """
    tokens = {
        "%{uid}": str(os.getuid()),
        "%{euid}": str(os.geteuid()),
        "%{USERID}": str(os.geteuid()),
        "%{TEMP}": tempfile.gettempdir(),
        "%{username}": os.environ.get("USER", ""),
        "%{null}": "",
    }
    for token, value in tokens.items():
        name = name.replace(token, value)
    return name


def ccache_name(profile: Profile | None = None) -> str:
    """The default cache's full name, ``TYPE:residual``, as MIT would choose it.

    ``$KRB5CCNAME`` wins, then ``default_ccache_name`` from ``krb5.conf``,
    then MIT's compiled-in default. The effective uid is used, as MIT does,
    so a setuid helper reads the cache of whom it runs as. ``profile`` is
    loaded only when the environment does not answer, which keeps the
    common case free of a ``krb5.conf`` parse.
    """
    name = os.environ.get("KRB5CCNAME", "")
    if not name:
        configured = (profile or Profile.load()).libdefault("default_ccache_name")
        name = _expand(configured) if configured else f"FILE:/tmp/krb5cc_{os.geteuid()}"
    return name


def _dir_primary(directory: str) -> str:
    """A ``DIR:`` collection's current cache: the file named in ``primary``.

    ``kswitch`` rewrites ``primary`` to change the default; the name in it is
    relative to the directory. A collection with no ``primary`` yet is read
    as MIT does, via its first cache name ``tkt``.
    """
    try:
        with open(os.path.join(directory, "primary"), encoding="utf-8") as handle:
            primary = handle.read().strip()
    except OSError:
        primary = "tkt"  # what MIT creates when there is no primary yet
    return os.path.join(directory, primary)


def resolve_ccache(name: str | None = None, profile: Profile | None = None) -> str:
    """The file a cache name refers to.

    Raises :class:`~xrdcore.errors.CredentialError` for a cache type that
    is not a file - ``KCM:`` and ``KEYRING:`` included: a login reads those
    through :func:`.caches.open_ccache`, but they have no path to give.
    """
    name = name if name is not None else ccache_name(profile)
    kind, sep, rest = name.partition(":")
    # A colon inside a path (``/tmp/odd:name``) is not a type prefix: MIT
    # treats a "type" containing a slash as part of a FILE path too.
    if not sep or "/" in kind:
        return name  # a bare path
    if kind == "FILE":
        return rest
    if kind == "DIR":
        # ``DIR::/path/tktXYZ`` names one cache in a collection directly.
        return rest[1:] if rest.startswith(":") else _dir_primary(rest)
    reason = (
        "lives outside the filesystem"
        if kind in _UNREACHABLE
        else "is not a type this client knows"
    )
    raise CredentialError(
        f"Kerberos credential cache {name!r} {reason}, so it has no file to name. "
        f"Get a ticket into a file with: KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u) kinit"
    )
