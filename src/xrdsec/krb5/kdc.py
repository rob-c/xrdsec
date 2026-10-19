"""Talking to a KDC: one request, one reply, over UDP or TCP.

RFC 4120 section 7.2: over UDP a message is one datagram; over TCP it is
preceded by its length as four big-endian bytes. The client tries UDP first,
as MIT does, and moves to TCP when the KDC answers ``KRB_ERR_RESPONSE_TOO_BIG``
or when the request is larger than ``udp_preference_limit``; a ``kdc``
entry written ``tcp/host`` is only ever asked over TCP. KDCs are tried in
the order ``krb5.conf`` lists them, and the first to answer wins.

A reply is returned as bytes. Whether it is a KRB-ERROR is for the caller
to decide, except for "too big", which is this module's business.

Deliberately absent: DNS SRV discovery (``_kerberos._udp.REALM``), the
``kkdcp`` HTTPS proxy, and ``master_kdc`` retries. Grid sites list their
KDCs in ``krb5.conf``, and an error naming the missing ``kdc =`` line is
more useful than a DNS lookup that silently picks something else. Only the
TGS exchange comes through here - the AS exchange is ``kinit``'s - so
nothing sent over this wire is a password-derived secret.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

from xrdcore.errors import CredentialError
from xrdcore.log import get_logger
from xrdcore.sockets import recv_exact

from ..der import DERError
from .asn1 import APP_KRB_ERROR, decode_krb_error
from .profile import Profile

__all__ = ["KdcAddress", "exchange", "parse_kdc"]

_log = get_logger(__name__)

#: The registered Kerberos port, for both UDP and TCP.
KDC_PORT = 88

#: MIT's default: requests longer than this go over TCP to begin with.
UDP_PREFERENCE_LIMIT = 1465

#: The KRB-ERROR code that means "ask me again over TCP" (RFC 4120 section 7.2.1).
KRB_ERR_RESPONSE_TOO_BIG = 52

#: Seconds to wait for one KDC before trying the next.
TIMEOUT = 5.0

#: No KDC reply this client wants is anywhere near this long.
MAX_REPLY = 1 << 20


@dataclass(frozen=True, slots=True)
class KdcAddress:
    """One ``kdc =`` entry: where, and over what.

    ``transport`` is what the entry pinned: ``tcp/`` means never UDP,
    ``udp/`` means never fall back to TCP, and no prefix lets
    :func:`_ask` choose by request size and the "too big" error.
    """

    host: str
    port: int
    transport: str  # "udp", "tcp", or "" for either

    def __str__(self) -> str:
        """The entry as ``krb5.conf`` would spell it, for failure messages."""
        prefix = f"{self.transport}/" if self.transport else ""
        return f"{prefix}{self.host}:{self.port}"


def parse_kdc(entry: str) -> KdcAddress | None:
    """``host``, ``host:port``, ``[v6]:port``, with an optional ``tcp/`` or ``udp/``.

    ``kkdcp`` HTTPS proxies are not supported; they come back as ``None``,
    as does anything else unparseable, so :func:`exchange` skips the entry
    and tries the rest rather than failing on one typo.
    """
    transport = entry[:3].lower() if entry[3:4] == "/" else ""
    if transport not in ("", "tcp", "udp") or "://" in entry:
        return None
    host, port = _host_port(entry[4:] if transport else entry)
    if not host or (port and not port.isdigit()):
        return None
    return KdcAddress(host, int(port) if port else KDC_PORT, transport)


def _host_port(text: str) -> tuple[str, str]:
    """Split ``host:port``; a bracketed or bare IPv6 address keeps its colons."""
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, rest[1:] if rest.startswith(":") else ""
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, port
    return text, ""


def _udp(address: KdcAddress, request: bytes, timeout: float) -> bytes:
    """One datagram out, one back, to the first address ``host`` resolves to.

    No retransmission: MIT resends on a timer, but a lost datagram here
    just moves on to the next KDC after ``timeout``, which keeps the code
    simple at the cost of a slower failover. A reply larger than 64 KiB
    cannot arrive over UDP at all, which is what "too big" is for.
    """
    # Only the first resolved address is tried, since a failure here falls
    # through to the next KDC entry; getaddrinfo raises rather than return none.
    family, kind, proto, _name, sockaddr = socket.getaddrinfo(
        address.host, address.port, type=socket.SOCK_DGRAM
    )[0]
    with socket.socket(family, kind, proto) as sock:
        sock.settimeout(timeout)
        # Connecting a datagram socket means only the KDC's own replies arrive.
        sock.connect(sockaddr)
        sock.send(request)
        return sock.recv(65535)


def _tcp(address: KdcAddress, request: bytes, timeout: float) -> bytes:
    """One request over TCP: each direction framed by a 4-byte big-endian length.

    The high bit of that length is reserved by RFC 4120 section 7.2.2 for
    extensions nobody deployed; :data:`MAX_REPLY` refuses it along with any
    other implausible size before anything is buffered. A KDC that hangs up
    part-way is :class:`xrdcore.sockets.ShortRead`, an :class:`OSError`, so
    :func:`exchange` moves on to the next KDC as it does after a timeout.
    """
    with socket.create_connection((address.host, address.port), timeout=timeout) as sock:
        sock.sendall(len(request).to_bytes(4, "big") + request)
        size = int.from_bytes(recv_exact(sock, 4), "big")
        if size > MAX_REPLY:
            raise OSError(f"the KDC announced a {size}-byte reply")
        return recv_exact(sock, size)


def _too_big(reply: bytes) -> bool:
    """Whether ``reply`` is the KRB-ERROR asking for a retry over TCP.

    Any other reply - a TGS-REP, another error, garbage - is the caller's
    to interpret, so a decode failure here is "no", not an exception.
    """
    if not reply.startswith(bytes([APP_KRB_ERROR])):
        return False
    try:
        return decode_krb_error(reply).code == KRB_ERR_RESPONSE_TOO_BIG
    except DERError:
        return False  # malformed; let the caller say so


def _ask(address: KdcAddress, request: bytes, udp_limit: int, timeout: float) -> bytes:
    """One KDC, by the transport its entry and the request size call for."""
    if address.transport == "tcp" or (address.transport == "" and len(request) > udp_limit):
        return _tcp(address, request, timeout)
    reply = _udp(address, request, timeout)
    if _too_big(reply) and address.transport != "udp":
        _log.debug("KDC %s: reply too big for UDP, retrying over TCP", address)
        return _tcp(address, request, timeout)
    return reply


def exchange(profile: Profile, realm: str, request: bytes, *, timeout: float = TIMEOUT) -> bytes:
    """Send ``request`` to a KDC for ``realm`` and return its reply.

    KDCs are tried in ``krb5.conf`` order and the first reply wins - even a
    KRB-ERROR, which is an answer, not a failure to answer. Only when every
    KDC fails to reply is a :class:`~xrdcore.errors.CredentialError`
    raised, listing each one's failure so a person can tell a firewall from
    a typo. ``udp_preference_limit`` from ``[libdefaults]`` is honoured as
    MIT honours it; a non-numeric value falls back to MIT's default.
    """
    entries = profile.kdcs(realm)
    addresses = [found for found in map(parse_kdc, entries) if found is not None]
    if not addresses:
        raise CredentialError(
            f"krb5.conf lists no usable KDC for realm {realm!r}; this client does not look "
            f"KDCs up in DNS, so add [realms] {realm} = {{ kdc = <host> }} "
            "(the file is $KRB5_CONFIG, else /etc/krb5.conf)"
        )
    limit_text = profile.libdefault("udp_preference_limit")
    limit = int(limit_text) if limit_text.isdigit() else UDP_PREFERENCE_LIMIT
    failures: list[str] = []
    for address in addresses:
        try:
            return _ask(address, request, limit, timeout)
        except OSError as exc:  # timeouts included: both are OSError subclasses
            failures.append(f"{address}: {exc or type(exc).__name__}")
    raise CredentialError(f"no KDC for realm {realm} answered ({'; '.join(failures)})")
