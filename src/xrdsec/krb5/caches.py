"""Opening a credential cache by name, whatever holds it.

``FILE:`` and ``DIR:`` caches are files (:mod:`.ccache`); ``KCM:`` caches
live in a daemon reached over a Unix socket (:mod:`.kcm`); ``KEYRING:``
caches live in the Linux kernel (:mod:`.keyring`). Each opens as a
:class:`CredentialCache`: a name to put in messages, :meth:`~CredentialCache.read`
for the default principal and the tickets, and
:meth:`~CredentialCache.store` for a ticket fetched from the KDC - which only
a KCM cache takes, as MIT's library does; for the others it stays in this
process's memory.

macOS's own ``API:`` caches are held by Heimdal's credential service behind
XPC, and ``MEMORY:`` and ``MSLSA:`` caches by another process or Windows.
Only the system library reaches those - through python-gssapi, in
:mod:`.gss` - so opening one here explains how to get a FILE cache instead.
Which of the two a client tries first is the client's policy, not this
module's: xrdclient's ``$XRD_KRB5_BACKEND``, for one.
"""

from __future__ import annotations

from typing import Protocol

from xrdcore.errors import CredentialError

from .ccache import ccache_name, read_ccache, resolve_ccache
from .kcm import DEFAULT_SOCKET, KcmCache
from .keyring import Keyctl, KeyringCache, system_keyctl
from .model import Principal, Ticket
from .profile import Profile

__all__ = ["CredentialCache", "FileCache", "open_ccache"]

#: The one-line fix every "this cache type cannot be read" message ends with:
#: a FILE cache is the one format every backend, and every grid tool, reads.
_TO_A_FILE = "KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u) kinit"


class CredentialCache(Protocol):
    """A cache a login reads its tickets from.

    Structural, so the three portable caches need no common base class. Implementations
    open whatever they read from per call and hold nothing between calls,
    which is what lets ``kinit`` renew the cache under a long-running
    process.
    """

    @property
    def name(self) -> str:
        """How messages name this cache: a path, or ``KCM:``/``KEYRING:`` and its residual."""
        ...

    def read(self) -> tuple[Principal, list[Ticket]]:
        """The default principal and every ticket; :class:`FileNotFoundError` for no cache."""
        ...

    def store(self, ticket: Ticket) -> bool:
        """Keep a ticket fetched from the KDC in the cache; ``False`` if it was not."""
        ...


class FileCache:
    """A FILE cache; :attr:`name` is its path, as messages have always named it."""

    __slots__ = ("path",)

    def __init__(self, path: str) -> None:
        """Name the file; nothing is opened until :meth:`read`."""
        self.path = path

    @property
    def name(self) -> str:
        """The resolved path (a ``DIR:`` collection's primary already followed)."""
        return self.path

    def read(self) -> tuple[Principal, list[Ticket]]:
        """Parse the file afresh, so a ``kinit`` since the last read is seen."""
        return read_ccache(self.path)

    def store(self, ticket: Ticket) -> bool:
        """Not done: rewriting a file ``kinit`` owns would race with it."""
        return False


def _refuse_api(name: str) -> CredentialError:
    """The error for a macOS ``API:`` cache, with both ways out.

    Returned rather than raised so the caller's ``raise`` shows in the
    traceback where the decision was made.
    """
    return CredentialError(
        f"Kerberos credential cache {name!r} is a macOS API: cache, held by the system's "
        "Heimdal credential service, which the portable cache reader cannot reach. "
        "Install python-gssapi (the 'krb5' extra) so the system library is used, "
        f"or get a ticket into a file with: {_TO_A_FILE}"
    )


def open_ccache(
    name: str | None = None, profile: Profile | None = None, *, keyctl: Keyctl | None = None
) -> CredentialCache:
    """The cache ``name`` names - by default the one MIT would use.

    ``keyctl`` replaces the kernel for a ``KEYRING:`` cache, for tests.
    Raises :class:`~xrdcore.errors.CredentialError` for a cache type that
    cannot be read here, naming the fix.

    The type prefix is dispatched on as ``krb5_cc_resolve`` does it. No
    prefix means FILE, and so does an unknown one: :func:`.resolve_ccache`
    then reports the unreadable type with the fix, which keeps every "cannot
    read this cache" message in one place. ``DIR:`` is resolved to its
    primary FILE there too.
    """
    name = name if name is not None else ccache_name(profile)
    kind, sep, rest = name.partition(":")
    if sep and kind == "KCM":
        return _open_kcm(rest, profile)
    if sep and kind == "KEYRING":
        return KeyringCache(rest, keyctl or system_keyctl())
    if sep and kind == "API":
        raise _refuse_api(name)
    return FileCache(resolve_ccache(name, profile))


def _open_kcm(residual: str, profile: Profile | None) -> KcmCache:
    """``kcm_socket`` from ``[libdefaults]``, else Heimdal's default path."""
    configured = (profile or Profile.load()).libdefault("kcm_socket")
    return KcmCache(residual, configured or DEFAULT_SOCKET)
