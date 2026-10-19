"""Service tickets from a credential cache: the portable Kerberos client's front door.

A protocol that authenticates with Kerberos needs a ticket for its server's
principal and that ticket's session key - XRootD's ``krb5`` plugin, for one,
wants a raw AP-REQ built from them (:func:`.tgs.build_ap_req`), and a
KRB-CRED with a forwarded TGT when it runs ``-exptkn``
(:func:`.tgs.build_krb_cred`). :func:`service_credentials` finds both the way
MIT's library would:

1. open the cache ``kinit`` wrote (:func:`.caches.open_ccache`: ``FILE:``,
   ``DIR:``, ``KCM:`` or ``KEYRING:``) and keep the tickets still live;
2. give the server principal a realm - the one it names, else
   ``[domain_realm]``'s for its host, else the client's own;
3. use a service ticket the cache already holds, else one this process
   fetched before, else ask the realm's KDC for one with the TGT
   (:func:`.tgs.request_ticket`) - the step ``kinit`` leaves to the first
   program that needs the service;
4. when asked, fetch a fresh *forwarded* TGT as ``krb5_fwd_tgt_creds`` does.

A fetched ticket is kept in this process's memory (:func:`clear_cache` drops
them) and offered to the cache, which a KCM cache takes, as MIT's library
gives it one; a file or a keyring is never written. :func:`tickets` and
:func:`inspect_cache` are the read-only, ``klist``-style views.

Every failure a person can act on is a :class:`~xrdcore.errors.CredentialError`
whose sentence ends in the command that fixes it (``kinit``, ``kinit -f``).
No cache at all is not an error: :func:`service_credentials` returns
``None``, so a client trying mechanisms in turn moves on quietly. What a
client then does with the tickets - its framing, its error types, whether
it tries the system library (:mod:`.gss`) first - is the client's.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from xrdcore.errors import CredentialError
from xrdcore.log import get_logger

from .caches import CredentialCache, FileCache, open_ccache
from .ccache import ccache_name
from .model import Principal, Ticket, parse_principal
from .profile import Profile, enctype_list
from .tgs import KDC_OPT_FORWARDABLE, KDC_OPT_FORWARDED, request_ticket

__all__ = [
    "DEFAULT_ENCTYPES",
    "CacheInfo",
    "ServiceCredentials",
    "clear_cache",
    "inspect_cache",
    "request_enctypes",
    "service_credentials",
    "target_principal",
    "tickets",
]

_log = get_logger(__name__)

#: MIT's default ``default_tgs_enctypes`` order, restricted to what :mod:`.rfc3961` does.
DEFAULT_ENCTYPES = (18, 17, 20, 19)

#: Service tickets fetched from the KDC, by (cache, client, service). A
#: process that opens many connections to one server asks the KDC once.
_FETCHED: dict[tuple[str, str, str], Ticket] = {}
_FETCHED_LOCK = threading.Lock()

#: A remembered ticket is reused only with more than this many seconds left,
#: so a login never starts with one that lapses mid-handshake.
_REUSE_MARGIN = 60


@dataclass(frozen=True, slots=True)
class ServiceCredentials:
    """What a login to one service needs: whom it is for, the ticket, a TGT to forward.

    ``ticket`` carries the session key the AP-REQ's authenticator is sealed
    under; ``forward`` is the forwarded TGT a ``-exptkn`` server asks for,
    ``None`` unless :func:`service_credentials` was asked to fetch one.
    """

    target: Principal
    ticket: Ticket
    forward: Ticket | None = None


@dataclass(frozen=True, slots=True)
class CacheInfo:
    """``klist``'s headline for a cache: its name, its principal, its latest expiry.

    ``expires_at`` is the latest end time of any ticket in the cache (epoch
    seconds) - the TGT's, normally - and 0 for a cache that holds none, so
    a cache with only expired tickets reads as expired. No key is included.
    """

    name: str
    principal: str
    expires_at: int


def clear_cache() -> None:
    """Forget the service tickets this process fetched from a KDC.

    For tests, and for a program that knows its tickets were revoked; the
    next login asks the KDC again.
    """
    with _FETCHED_LOCK:
        _FETCHED.clear()


def tickets(path: str | None = None) -> list[Ticket]:
    """Every unexpired ticket in the credential cache. Empty if there is none.

    ``path`` is a FILE cache; by default it is whichever cache MIT would use,
    ``KCM:`` and ``KEYRING:`` included. An unreadable or unsupported cache is
    logged and reads as empty: this is a listing, not a login.
    """
    try:
        cache = FileCache(path) if path else open_ccache()
        _default, found = cache.read()
    except (OSError, ValueError, CredentialError) as exc:
        _log.debug("no usable credential cache: %s", exc)
        return []
    return [ticket for ticket in found if not ticket.expired]


def inspect_cache(name: str | None = None) -> CacheInfo:
    """Describe a cache without exporting its keys or contacting a KDC.

    ``name`` is a full cache name (``FILE:/tmp/krb5cc_1000``, ``KCM:``,
    ``KEYRING:persistent:1000``); ``None`` is the default MIT would use.
    :class:`FileNotFoundError` means there is no such cache; a cache of a
    type this reader cannot reach, or one that does not parse, is a
    :class:`~xrdcore.errors.CredentialError` naming it.
    """
    full = name if name is not None else ccache_name()
    cache = open_ccache(full)
    try:
        principal, found = cache.read()
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise _unreadable(cache.name, exc) from exc
    expires = max((ticket.end_time for ticket in found), default=0)
    return CacheInfo(full, str(principal), expires)


def _unreadable(name: str, exc: Exception) -> CredentialError:
    """The error for a cache that exists but cannot be read; returned for the caller to raise."""
    return CredentialError(f"the Kerberos credential cache {name} is unreadable: {exc}")


def target_principal(name: str, host: str, profile: Profile, default_realm: str = "") -> Principal:
    """``name`` as a principal with a realm, as MIT would complete it.

    The realm ``name`` carries wins; else ``[domain_realm]``'s for the host
    in ``name``'s second component (or ``host`` when it has none); else
    ``default_realm`` - the client's own, for a login - which may be empty.
    """
    target = parse_principal(name)
    if target.realm:
        return target
    instance = target.components[1] if len(target.components) > 1 else host
    realm = profile.realm_for_host(instance) or default_realm
    return Principal(target.components, realm, target.name_type)


def request_enctypes(profile: Profile) -> list[int]:
    """The enctypes to ask the KDC for, as MIT's library would choose them.

    ``default_tgs_enctypes`` from ``krb5.conf``, else ``permitted_enctypes``,
    each filtered to what the portable code implements; a setting that names
    nothing usable falls through rather than sending an empty list, which a
    KDC answers with ``KDC_ERR_ETYPE_NOSUPP``.
    """
    for tag in ("default_tgs_enctypes", "permitted_enctypes"):
        configured = profile.libdefault(tag)
        if configured:
            found = enctype_list(configured)
            if found:
                return found
    return list(DEFAULT_ENCTYPES)


def service_credentials(
    service: str, host: str, *, forward: bool = False, profile: Profile | None = None
) -> ServiceCredentials | None:
    """A ticket for ``service`` from the default cache, and a forwarded TGT if asked.

    ``service`` is a principal, with or without a realm (``xrootd/host``);
    ``host`` stands in for its instance when it has none. ``None`` when there
    is no cache, or the cache holds no tickets at all - nothing to log in
    with, which is not an error. A cache whose tickets have all expired, a
    TGT that cannot be used, or a KDC that refuses is a
    :class:`~xrdcore.errors.CredentialError` saying what to run.
    """
    profile = profile or Profile.load()
    cache = open_ccache(profile=profile)
    try:
        client, found = cache.read()
    except FileNotFoundError as exc:
        _log.debug("no credential cache: %s", exc)
        return None
    except (OSError, ValueError) as exc:
        raise _unreadable(cache.name, exc) from exc
    live = [ticket for ticket in found if not ticket.expired]
    if not live:
        if found:
            raise _expired(cache.name, found)
        return None
    target = target_principal(service, host, profile, client.realm)
    ticket = _service_ticket(cache, client, live, target, profile)
    forwarded = _forwarded_tgt(cache.name, client, live, profile) if forward else None
    return ServiceCredentials(target, ticket, forwarded)


def _expired(path: str, found: list[Ticket]) -> CredentialError:
    """The error for a cache whose tickets have all expired.

    Returned, not raised, so the ``raise`` is at the caller. It quotes the
    *latest* expiry - how long ago the user's most recent ``kinit`` ran out -
    and the principal, so a stale cache under the wrong name is visible.
    """
    latest = max(found, key=lambda ticket: ticket.end_time)
    minutes = int(-latest.remaining() // 60)
    return CredentialError(
        f"the Kerberos tickets for {latest.client} in {path} expired {minutes} minutes ago; "
        "run kinit"
    )


def _tgt(path: str, client: Principal, live: list[Ticket]) -> Ticket:
    """The live TGT for the client's own realm, ``krbtgt/REALM@REALM``.

    Only the home realm's: the portable code does not follow cross-realm
    referrals, so a TGT for another realm would only lead to a KDC error.
    A ticket without a session key is no use for a TGS exchange and is passed
    over. Raises :class:`~xrdcore.errors.CredentialError` naming ``kinit``.
    """
    home = Principal(("krbtgt", client.realm), client.realm)
    for ticket in live:
        if ticket.server.same_name(home) and ticket.key:
            return ticket
    raise CredentialError(
        f"no live ticket-granting ticket for {client.realm} in {path} to get a service "
        "ticket with; run kinit"
    )


def _service_ticket(
    cache: CredentialCache,
    client: Principal,
    live: list[Ticket],
    target: Principal,
    profile: Profile,
) -> Ticket:
    """A ticket for ``target``: from the cache, from memory, or from the KDC.

    One from the KDC is kept in memory, and offered to the cache - which a
    KCM cache takes, as MIT's library stores it there.

    The lock guards the dictionary, not the KDC round trip: two threads that
    miss together both fetch, which costs a request but never blocks one
    login on another.
    """
    for ticket in live:
        if ticket.server.same_name(target) and ticket.key:
            return ticket
    slot = (cache.name, str(client), str(target))
    with _FETCHED_LOCK:
        held = _FETCHED.get(slot)
    if held is not None and held.remaining() > _REUSE_MARGIN:
        return held
    tgt = _tgt(cache.name, client, live)
    ticket = request_ticket(tgt, target, profile, etypes=request_enctypes(profile))
    with _FETCHED_LOCK:
        _FETCHED[slot] = ticket
    cache.store(ticket)
    return ticket


def _forwarded_tgt(path: str, client: Principal, live: list[Ticket], profile: Profile) -> Ticket:
    """A new TGT marked forwarded, for a server that asked for one.

    The cached TGT is not sent as it is: the KDC is asked for a fresh
    ``krbtgt`` ticket with ``FORWARDED`` set (and ``FORWARDABLE``, so the
    server can pass it on in turn), which is what ``krb5_fwd_tgt_creds``
    does and what marks the ticket as one a third party now holds. The
    KDC grants that only for a TGT that is itself forwardable, hence the
    check and the ``kinit -f`` advice.
    """
    tgt = _tgt(path, client, live)
    if not tgt.forwardable:
        raise CredentialError(
            "the server wants a forwarded ticket-granting ticket, but "
            f"the one in {path} is not forwardable; run kinit -f"
        )
    return request_ticket(
        tgt,
        tgt.server,
        profile,
        etypes=request_enctypes(profile),
        options=KDC_OPT_FORWARDED | KDC_OPT_FORWARDABLE,
    )
