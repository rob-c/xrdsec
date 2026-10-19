"""Principals and credentials: the nouns every other Kerberos module shares.

Both are frozen value objects with no I/O, so caches, the ASN.1 layer and
the exchanges can pass them around freely. What must not break: a
:class:`Ticket` never shows its session key in ``repr`` or equality, and
:meth:`Principal.same_name` - not ``==`` - is how names are compared,
because caches and KDCs disagree about name types.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

__all__ = [
    "NT_PRINCIPAL",
    "NT_SRV_INST",
    "TKT_FLG_FORWARDABLE",
    "TKT_FLG_FORWARDED",
    "Principal",
    "Ticket",
    "parse_principal",
]

#: Name types (RFC 4120 section 6.2). ``krb5_parse_name`` yields the first;
#: service principals the KDC returns often carry the second, which is why
#: name types are ignored when principals are compared.
NT_PRINCIPAL = 1
NT_SRV_INST = 2

#: Ticket flags, as the 32-bit integer MIT stores them (bit 0 is the MSB):
#: RFC 4120 section 5.3 flag 1 is ``forwardable``, flag 2 ``forwarded``.
TKT_FLG_FORWARDABLE = 0x40000000
TKT_FLG_FORWARDED = 0x20000000


@dataclass(frozen=True, slots=True)
class Principal:
    """A Kerberos principal: components and a realm.

    ``name_type`` defaults to 0 (``NT-UNKNOWN``), which is what a principal
    built by hand rather than parsed or read from the wire carries.
    """

    components: tuple[str, ...]
    realm: str
    name_type: int = 0

    def __str__(self) -> str:
        """``a/b@REALM`` for messages; unquoted, so not for re-parsing."""
        return "/".join(self.components) + (f"@{self.realm}" if self.realm else "")

    def __bool__(self) -> bool:
        """False for the empty principal, which a never-initialised cache holds."""
        return bool(self.components)

    def same_name(self, other: Principal) -> bool:
        """Equal as Kerberos compares principals: the name type does not count."""
        return self.components == other.components and self.realm == other.realm


def parse_principal(text: str, default_realm: str = "") -> Principal:
    """``"xrootd/host@REALM"`` as a :class:`Principal`, the way ``krb5_parse_name`` reads it.

    A backslash quotes the next character, so ``a\\/b`` is one component.
    With no ``@``, the realm is ``default_realm``. After the ``@``, ``/`` and
    ``@`` are ordinary characters, as MIT reads them. Nothing here fails:
    a strange name yields a principal no KDC knows, and the KDC's error
    says so in terms a person recognises.
    """
    components: list[str] = []
    current: list[str] = []
    realm: str | None = None
    chars = iter(text)
    for char in chars:
        if char == "\\":
            current.append(next(chars, ""))
        elif char == "/" and realm is None:
            components.append("".join(current))
            current = []
        elif char == "@" and realm is None:
            components.append("".join(current))
            current, realm = [], ""
        else:
            current.append(char)
    if realm is None:
        components.append("".join(current))
        return Principal(tuple(components), default_realm, NT_PRINCIPAL)
    return Principal(tuple(components), "".join(current), NT_PRINCIPAL)


@dataclass(frozen=True, slots=True)
class Ticket:
    """One credential: a ticket, its session key, and what the KDC said about it.

    ``der`` is the ticket exactly as the KDC issued it - opaque to the
    client, encrypted for the service. ``key`` is the session key the KDC
    shared with the client for it; it never leaves memory, is never logged,
    and is left out of ``repr``. ``enctype`` is the session key's.
    ``kdc_offset`` is how many seconds the KDC's clock is ahead of this
    host's, as ``kinit`` measured it and wrote it into the cache; MIT adds it
    to the local time in every authenticator (``kdc_timesync``), and so does
    this client, so that a host whose clock is off still logs in.
    """

    client: Principal
    server: Principal
    enctype: int
    auth_time: int
    start_time: int
    end_time: int
    renew_till: int
    flags: int
    der: bytes = b""
    key: bytes = field(default=b"", repr=False, compare=False)
    kdc_offset: float = field(default=0.0, compare=False)

    @property
    def expired(self) -> bool:
        """Past its end time by this host's clock; an end time of 0 never expires."""
        return self.end_time != 0 and self.end_time <= time.time()

    def remaining(self) -> float:
        """Seconds of validity left; negative once expired."""
        return self.end_time - time.time()

    @property
    def is_tgt(self) -> bool:
        """True for a ticket-granting ticket, ``krbtgt/REALM@REALM``."""
        return bool(self.server.components) and self.server.components[0] == "krbtgt"

    @property
    def forwardable(self) -> bool:
        """Whether the KDC will issue a forwarded copy: ``kinit -f`` asked for it."""
        return bool(self.flags & TKT_FLG_FORWARDABLE)

    def __repr__(self) -> str:
        """Server and time left: enough to debug with, nothing secret."""
        return f"Ticket(server={str(self.server)!r}, expires_in={self.remaining():.0f}s)"
