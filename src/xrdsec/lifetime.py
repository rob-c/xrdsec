"""The credential in use now, how long it has left, and when it has been replaced.

:mod:`xrdsec.credentials` answers *where* a credential is; this module
answers the questions a long-running program asks about it afterwards, over
and over: is there one now, when does it run out, is it about to, and is it
a *new* one since I last looked? A workload manager watching thousands of
jobs, a submission tool refusing a proxy that cannot outlive the job, and a
daemon that must re-delegate after ``voms-proxy-init`` all ask exactly
these, and before this module each answered them with its own arithmetic.

========================  ===================================================
:class:`Credential`       one credential: kind, file, expiry, identity
:class:`CredentialProvider`  anything whose ``current()`` says what it is now
:class:`ProxyFile`        the X.509 proxy at a path, or wherever the search finds one
:class:`BearerToken`      the WLCG bearer token: given, from a file, or discovered
:func:`chain_expiry`      when a certificate chain stops being usable
:func:`assess`            expired, too short, low, or fine - one ordering for every tool
:class:`CredentialWatch`  one provider seen by several consumers: warn once, notice renewals
========================  ===================================================

**Re-read, never cached.** A provider reads its source each time it is
asked, because the whole point is to notice a proxy re-made by
``xrdarc proxy`` or ``voms-proxy-init`` under the same path. Something that
cannot be read *now* (a proxy half-written, a token file mid-rotation) is
``None`` - "nothing usable at the moment" - never an exception: a watcher
that raised would stop watching on the one transient that matters.

**Expiry is the chain's, not the leaf's.** A proxy cannot outlive anything
above it, so :func:`chain_expiry` is the earliest ``notAfter`` in the chain,
the moment a server checking the whole chain would start refusing it.

**Cost.** Importing this module costs :mod:`xrdsec.credentials` and
:mod:`xrdsec.tokens` (neither imports ``ssl`` or ``cryptography``); the
X.509 stack is imported only when :class:`ProxyFile` first reads a file.
"""

from __future__ import annotations

import enum
import os
import threading
import time
from collections.abc import Hashable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from xrdcore.errors import XrdError

from . import credentials as _credentials
from . import tokens as _tokens

if TYPE_CHECKING:
    from .x509 import ProxyCredential

__all__ = [
    "BearerToken",
    "Credential",
    "CredentialProvider",
    "CredentialWatch",
    "Lifetime",
    "ProxyFile",
    "Sighting",
    "assess",
    "chain_expiry",
]


class _Dated(Protocol):
    """Anything with a ``notAfter``: a certificate view of :mod:`xrdsec.x509` or a test's."""

    @property
    def not_after(self) -> float:
        """The end of validity, as seconds since the epoch."""
        ...


def chain_expiry(chain: Iterable[_Dated]) -> float:
    """When ``chain`` stops being usable: the earliest ``notAfter`` among its links.

    A proxy cannot outlive its issuer, so the leaf's own date is not the
    answer - a server that checks the chain refuses it as soon as anything
    above it has expired. Raises :class:`ValueError` for an empty chain,
    which has no expiry to speak of.
    """
    return min(link.not_after for link in chain)


@dataclass(frozen=True, slots=True)
class Credential:
    """One credential as a watcher sees it: its kind, where it is, whose, and when it expires.

    ``kind`` is ``"proxy"`` or ``"token"``; ``path`` the file it was read
    from (``None`` for a token given as a string); ``expires_at`` seconds
    since the epoch, or ``None`` when nothing says (an opaque token);
    ``identity`` the user behind it - a proxy's end-entity DN, a token's
    ``sub`` - for messages. A token's value never appears in ``repr``: it is
    a password, and credentials end up in logs.
    """

    kind: str
    path: str | None = None
    expires_at: float | None = None
    identity: str | None = None
    token: str | None = field(default=None, repr=False)

    @classmethod
    def of_proxy(cls, proxy: ProxyCredential, *, path: str | None = None) -> Credential:
        """The :class:`Credential` for a loaded proxy: its chain's expiry and its user's DN.

        ``path`` defaults to the file the proxy was loaded from, if any.
        """
        return cls("proxy", path or proxy.path or None, chain_expiry(proxy.chain), proxy.identity)

    def remaining(self, now: float | None = None) -> float | None:
        """Seconds left (negative once expired), or ``None`` when the expiry is unknown."""
        if self.expires_at is None:
            return None
        return self.expires_at - (time.time() if now is None else now)

    @property
    def generation(self) -> tuple[str | None, float | None]:
        """What tells one issue of this credential from the next.

        A proxy re-made at the same path has a new expiry; a token swapped
        into another file has a new path. Two sightings with the same
        generation are the same credential, so nothing needs renewing.
        """
        return (self.path, self.expires_at)


class CredentialProvider(Protocol):
    """Something that can say what the current credential is."""

    def current(self) -> Credential | None:
        """The credential to use now, or ``None`` when there is none (or none readable)."""
        ...


class ProxyFile:
    """The X.509 proxy at ``path``, or wherever :func:`~xrdsec.credentials.find_proxy` finds one.

    ``environ`` is the environment the search reads (default
    :data:`os.environ` at call time), as everywhere in xrdsec. The file is
    read with :func:`~xrdsec.proxies.load_credential`, so a proxy that fails
    its private-file checks counts as no proxy - it could not be used either.
    """

    def __init__(
        self, path: str | None = None, *, environ: Mapping[str, str] | None = None
    ) -> None:
        """Watch ``path``, or the searched-for location when it is ``None``."""
        self.path = path
        self.environ = environ

    def current(self) -> Credential | None:
        """The proxy as it is on disk now; ``None`` if there is no readable one."""
        # Imported here: the X.509 stack is the expensive part of xrdsec, and a
        # program that only watches tokens should not pay for it.
        from .proxies import load_credential

        path = self.path or _credentials.find_proxy(self.environ)
        if path is None or not os.path.isfile(path):
            return None
        try:
            return Credential.of_proxy(load_credential(path), path=path)
        except (OSError, ValueError, XrdError):
            # Half-written, foreign-owned, not a proxy at all: none usable now.
            return None


class BearerToken:
    """The WLCG bearer token: ``token`` itself, from ``token_file``, or by WLCG discovery.

    Discovery is :func:`~xrdsec.credentials.find_bearer_token`, the
    specification's order. A token file that cannot be read for an ordinary
    reason means "no token now"; one refused on security grounds is still
    refused (as no token), never silently replaced by the next location.
    """

    def __init__(
        self,
        token: str | None = None,
        *,
        token_file: str | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        """Watch ``token`` (fixed), ``token_file``, or the discovered token."""
        self._token = token
        self.token_file = token_file
        self.environ = environ

    def current(self) -> Credential | None:
        """The token found now, with its (unverified) expiry and subject."""
        try:
            token = _credentials.find_bearer_token(
                self.environ, explicit=self._token, token_file=self.token_file
            )
        except OSError:
            return None
        if not token:
            return None
        # Unverified, for display and expiry warnings only: the server is the
        # one that validates a token, and an opaque one simply has no claims.
        subject = _tokens.token_claims(token).get("sub")
        return Credential(
            "token",
            self.token_file,
            _tokens.token_expiry(token),
            str(subject) if subject is not None else None,
            token=token,
        )


class Lifetime(enum.Enum):
    """How a credential's remaining life compares with what the caller needs."""

    #: Enough left, or no known expiry.
    OK = "ok"
    #: Usable, but under the warning threshold: say so before jobs fail at stage-out.
    LOW = "low"
    #: Not expired, but under the hard minimum the caller asked for.
    SHORT = "short"
    #: Nothing left: every server will refuse it.
    EXPIRED = "expired"


def assess(left: float | None, *, minimum: float = 0.0, warn_below: float = 0.0) -> Lifetime:
    """Classify ``left`` seconds of life: expired, short of ``minimum``, low, or fine.

    The order is the contract: an expired credential is :attr:`~Lifetime.EXPIRED`
    whatever the thresholds (zero seconds left counts as expired - a request
    signed now would arrive dead), then ``minimum`` (a refusal, like
    ``arcsub --min-lifetime``), then ``warn_below`` (a warning). ``None``
    means the expiry is unknown, which nothing can refuse.
    """
    if left is None:
        return Lifetime.OK
    if left <= 0:
        return Lifetime.EXPIRED
    if left < minimum:
        return Lifetime.SHORT
    if left < warn_below:
        return Lifetime.LOW
    return Lifetime.OK


@dataclass(frozen=True, slots=True)
class Sighting:
    """What one :meth:`CredentialWatch.check` saw, and what the caller should do about it."""

    credential: Credential
    #: Seconds left when checked (see :meth:`Credential.remaining`).
    left: float | None
    lifetime: Lifetime
    #: The lifetime is not :attr:`~Lifetime.OK` and this expiry has not been
    #: warned about yet: warn now, once, rather than at every poll.
    warn: bool
    #: This consumer saw a different credential last time: what it holds
    #: (a delegation, a running job's proxy) can be renewed with this one.
    renewed: bool


class CredentialWatch:
    """One provider watched by several consumers: one warning per expiry, renewals per consumer.

    A program that polls a credential has two things to get right, and both
    are state: warning about an expiring credential *once* (not once per poll,
    not once per backend), and noticing that a *new* credential has appeared
    since a given consumer last looked - each consumer separately, because
    each holds its own copy to renew. The first sighting is never a renewal:
    there was nothing before it to replace. Thread-safe; the provider is read
    outside the lock.
    """

    def __init__(self, provider: CredentialProvider) -> None:
        """Watch ``provider``; nothing is read until the first :meth:`check`."""
        self.provider = provider
        self._lock = threading.Lock()
        self._warned: float | None = None
        self._seen: dict[Hashable, tuple[str | None, float | None]] = {}

    def check(
        self,
        consumer: Hashable = None,
        *,
        minimum: float = 0.0,
        warn_below: float = 0.0,
        now: float | None = None,
    ) -> Sighting | None:
        """Read the provider once and say what ``consumer`` should do; ``None`` without one.

        ``minimum`` and ``warn_below`` are :func:`assess`'s. ``consumer``
        names who is asking (a backend, a CE); its renewal flag compares with
        its own last sighting only.
        """
        credential = self.provider.current()
        if credential is None:
            return None
        left = credential.remaining(now)
        lifetime = assess(left, minimum=minimum, warn_below=warn_below)
        generation = credential.generation
        with self._lock:
            warn = lifetime is not Lifetime.OK and self._warned != credential.expires_at
            if warn:
                self._warned = credential.expires_at
            previous = self._seen.get(consumer)
            self._seen[consumer] = generation
        renewed = previous is not None and previous != generation
        return Sighting(credential, left, lifetime, warn, renewed)
