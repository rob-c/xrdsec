"""What a proxy-making command does, from user certificate to proxy file and back.

``voms-proxy-init``/``voms-proxy-info`` (xrdclient's ``xrd-proxy``) and
``arcproxy`` (xrdarc's ``xrdarc proxy``) do the same work under different
spellings: find the user certificate and key, read the key (asking for its
pass phrase only if it is encrypted), ask each VO's VOMS server for an
attribute certificate, issue a proxy carrying them, write it where every
grid tool looks, and later read it back and describe it. This module is that
work, once; each command keeps only its options and its output format.

The steps, in the order a command calls them:

1. :func:`find_user_pair` - which certificate and key sign, under the
   :class:`Conventions` of the tool being stood in for
   (:data:`VOMS_PROXY_INIT`, :data:`ARCPROXY`); then
   :func:`xrdsec.proxies.load_credential` reads them, with the command's own
   pass-phrase callback.
2. :func:`voms_requests` - ``VO[:FQAN]`` options as :class:`VOMSRequest`\\ s.
3. :func:`make_proxy` - refuse an expired signer (:func:`require_alive`),
   fetch the ACs (:func:`fetch_acs`, reporting through a :class:`Progress`),
   then issue the proxy in memory (:func:`xrdsec.proxies.create_proxy`).
   The ACs come first so that a VOMS refusal leaves no half-made proxy and
   never replaces a working one.
4. :func:`proxy_target` and :func:`xrdsec.proxies.write_proxy` - where it
   goes, and whether a symbolic link there may be followed.
5. :func:`read_proxy_info` - the file read back under the private-file rules
   and described (:class:`~xrdsec.proxies.ProxyInfo`).

What a maintainer must not break: the symbolic-link rule of
:func:`proxy_target` (a link at the predictable ``/tmp/x509up_u<uid>`` is
somebody else's trap, so it is followed only when the user named the path),
the ACs-before-proxy order, and that nothing here prints, prompts or exits -
those are the commands' business, which is what lets two tools with
different output share it.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import os
import time
import warnings
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import NamedTuple, Protocol

from xrdcore.errors import CredentialError, rebuild

from . import credentials, discovery
from .lifetime import chain_expiry
from .proxies import DEFAULT_LIFETIME, ProfileName, ProxyInfo, create_proxy, describe_proxy
from .voms_client import (
    DEFAULT_TIMEOUT,
    VOMSServer,
    VOMSWarning,
    fetch_ac,
    find_vomses,
    servers_for,
)
from .x509 import ProxyCredential, load_certificates

__all__ = [
    "ARCPROXY",
    "VOMS_PROXY_INIT",
    "Conventions",
    "ExpiredCredentialError",
    "NoCredentialError",
    "Progress",
    "ProxyRequest",
    "Target",
    "VOMSRequest",
    "fetch_acs",
    "find_user_pair",
    "make_proxy",
    "proxy_target",
    "read_proxy_info",
    "require_alive",
    "voms_requests",
]

#: How a proxy file is named in a refusal, as everywhere in xrdsec.
_PROXY_KIND = "X.509 proxy"

#: :attr:`ProxyRequest.lifetime`'s default, in seconds: twelve hours, as
#: ``voms-proxy-init`` and ``arcproxy`` both make them.
_DEFAULT_SECONDS = DEFAULT_LIFETIME.total_seconds()


class NoCredentialError(CredentialError, FileNotFoundError):
    """There is nothing where a credential was looked for: no user certificate, no proxy.

    A :class:`~xrdcore.errors.CredentialError` (the user cannot authenticate
    like this) and a :class:`FileNotFoundError` (``errno`` is ``ENOENT``), so
    a command that maps ``OSError``\\ s to exit codes or errno values and one
    that maps credential errors both get it right. :attr:`path` is the file
    that is not there, ``""`` when a search found nothing.
    """

    def __init__(self, message: str, path: str = "") -> None:
        """``message`` is the whole sentence; ``path`` is kept apart for programs."""
        # The one-argument form keeps ``str(exc)`` the sentence alone (OSError
        # given an errno prefixes ``[Errno 2]``); the errno is set after.
        super().__init__(message)
        self.errno = errno.ENOENT
        self.path = path

    def __reduce__(self) -> tuple[Callable[..., BaseException], tuple[object, ...]]:
        """Pickle with :attr:`path` intact (the errno is restored by ``__init__``)."""
        return rebuild, (type(self), (self.args[0],), {"path": self.path})


class ExpiredCredentialError(CredentialError):
    """The credential that would sign a proxy has expired.

    Kept apart from the other refusals because it is the one a user fixes by
    making a new proxy (or renewing a certificate), and tools say so with
    their own words and codes (``arcproxy``'s ``EKEYEXPIRED``).
    """


@dataclass(frozen=True, slots=True)
class Conventions:
    """Where the tool a command stands in for looks, and how it reads its options.

    The two tools disagree in small ways their users rely on, so each is a
    named value rather than a set of flags at every call.
    """

    #: The upstream tool, for messages.
    name: str
    #: Where the user certificate and key are searched for when the command
    #: line does not name both. Only the pair steps: a proxy never signs a
    #: proxy these tools make.
    search: discovery.Search
    #: Whether a certificate named without a key holds the key too
    #: (``arcproxy --cert file.pem``), or the key is searched for as if
    #: nothing had been named (``voms-proxy-init -cert``).
    lone_cert_holds_key: bool
    #: Whether several ``VO:FQAN`` options for one VO make one request (one
    #: AC per VO, as ``voms-proxy-init`` sends them) or one each, in order
    #: (``arcproxy -S``).
    merge_voms: bool


#: ``voms-proxy-init``: ``$X509_USER_CERT`` and ``$X509_USER_KEY`` as named,
#: else ``~/.globus/usercert.pem`` and ``userkey.pem``.
VOMS_PROXY_INIT = Conventions(
    name="voms-proxy-init",
    search=discovery.Search(
        name="voms-proxy-init",
        steps=("user-pair", "globus-pair"),
        missing_named_proxy="present",
        pair_check="none",
        home_pair_check="isfile",
    ),
    lone_cert_holds_key=False,
    merge_voms=True,
)
#: ``arcproxy``: ARC's own search (:data:`xrdsec.discovery.ARC`) with the
#: proxy steps taken out, and a configured pair that is not there passed
#: over for ``~/.arc`` and ``~/.globus`` rather than chosen and then failing.
ARCPROXY = Conventions(
    name="arcproxy",
    search=dataclasses.replace(
        discovery.ARC,
        name="arcproxy",
        steps=("user-pair", "arc-pair", "globus-pair"),
        pair_check="isfile",
    ),
    lone_cert_holds_key=True,
    merge_voms=False,
)


def find_user_pair(
    conventions: Conventions,
    *,
    cert: str | None = None,
    key: str | None = None,
    configured: tuple[str | None, str | None] = (None, None),
    environ: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """The user certificate and key to sign with: ``(certificate, key)``.

    ``cert`` and ``key`` are what the command line named; whatever it left
    out is searched for under ``conventions`` (see :class:`Conventions` for
    a certificate named alone). ``configured`` is the tool's own
    certificate and key settings (ARC's ``certificatepath``/``keypath``),
    which take the place of ``$X509_USER_CERT`` and ``$X509_USER_KEY`` in
    the search. Nothing is read: :func:`xrdsec.proxies.load_credential`
    does that, under the private-file checks. Raises
    :class:`NoCredentialError` when nothing is named or found.
    """
    if cert and (key or conventions.lone_cert_holds_key):
        return cert, key or cert
    found = discovery.discover_x509(
        conventions.search, cert=configured[0], key=configured[1], environ=environ
    )
    if found is None:
        raise NoCredentialError(_nothing_found(conventions.search))
    return cert or found.cert, key or found.key


def _nothing_found(search: discovery.Search) -> str:
    """The message for an empty search, naming every place that was searched."""
    homes = [f"~/.{step.split('-')[0]}" for step in search.steps if step != "user-pair"]
    return (
        "no user certificate found: name the certificate and key, set X509_USER_CERT and "
        f"X509_USER_KEY, or install usercert.pem and userkey.pem in {' or '.join(homes)}"
    )


# ---------------------------------------------------------------------------
# VOMS attribute certificates
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VOMSRequest:
    """One request to a VO's VOMS servers: the VO, and the FQANs wanted (none: the defaults)."""

    vo: str
    fqans: tuple[str, ...] = ()


def voms_requests(options: Sequence[str], conventions: Conventions) -> tuple[VOMSRequest, ...]:
    """``VO[:FQAN]`` options as requests, grouped as ``conventions`` says.

    ``atlas`` asks for the VO's default groups; ``atlas:/atlas/Role=pilot``
    for that group and role. Merged (``voms-proxy-init``), the FQANs of one
    VO join one request, in the order the VO was first named; unmerged
    (``arcproxy``), each option is its own request and its own AC. The FQAN
    syntax is checked by :func:`xrdsec.voms_client.fetch_ac`. Raises
    :class:`ValueError` for an option with no VO name - a usage error.
    """
    parsed = [_voms_option(option) for option in options]
    if not conventions.merge_voms:
        return tuple(VOMSRequest(vo, fqans) for vo, fqans in parsed)
    grouped: dict[str, tuple[str, ...]] = {}  # insertion order: the order first named
    for vo, fqans in parsed:
        grouped[vo] = grouped.get(vo, ()) + fqans
    return tuple(VOMSRequest(vo, fqans) for vo, fqans in grouped.items())


def _voms_option(option: str) -> tuple[str, tuple[str, ...]]:
    """One ``VO[:FQAN]`` option split: the VO, and the FQAN if one was given."""
    vo, _, fqan = option.partition(":")
    if not vo:
        raise ValueError(f"a VOMS request needs a VO name: {option!r}")
    return vo, (fqan,) if fqan else ()


@dataclass(frozen=True, slots=True)
class ProxyRequest:
    """Everything a user asked a proxy-making command for, as one value.

    The options of ``voms-proxy-init`` and ``arcproxy`` reduced to what
    :func:`make_proxy` needs; a command fills it from its own spellings.
    """

    #: Seconds the proxy is to last (never past the signer's chain).
    lifetime: float = _DEFAULT_SECONDS
    #: The proxy key's size, and the proxy's limitation, path length and
    #: profile (:data:`xrdsec.proxies.PROFILES`).
    bits: int = 2048
    limited: bool = False
    path_length: int | None = None
    profile: ProfileName = "rfc3820"
    #: The ACs to ask for, and how long they are to last: by default as
    #: long as the proxy - an AC that outlives its proxy is useless, one that
    #: expires first drops the VO's attributes mid-job.
    voms: tuple[VOMSRequest, ...] = ()
    voms_lifetime: float | None = None
    #: ``vomses`` files or directories; empty means the standard places
    #: (:func:`xrdsec.voms_client.find_vomses`).
    vomses: tuple[str, ...] = ()
    #: How the VOMS servers are reached (:func:`xrdsec.voms_client.fetch_ac`).
    timeout: float = DEFAULT_TIMEOUT
    ca_path: str | None = None
    system_ca: bool = False
    x509_strict: bool = True


class Progress(Protocol):
    """What a command tells its user while a proxy is made: three hooks, called in order.

    The library never prints: ``voms-proxy-init`` says ``Contacting host
    [DN] "vo"...`` before each request and ``Remote VOMS server contacted
    successfully.`` after, ``arcproxy`` only ``Contacting VOMS server for
    vo``, and one prints warnings where the other logs them. A protocol
    rather than a base class, so a command can define its hooks without
    importing this module (and the crypto stack) before its options are
    parsed. Without one, nothing is said and each warning is issued again as
    a :class:`~xrdsec.voms_client.VOMSWarning`, so nothing is lost.
    """

    def contacting(self, request: VOMSRequest, servers: Sequence[VOMSServer]) -> None:
        """About to ask ``servers`` (in order, the first that answers wins) for ``request``."""
        ...

    def contacted(self, request: VOMSRequest) -> None:
        """``request`` was answered with an AC."""
        ...

    def warned(self, message: str) -> None:
        """A warning while asking: an AC this machine cannot verify, a lifetime cut short."""
        ...


class _Silent:
    """The :class:`Progress` used when a caller gives none: warnings stay Python warnings."""

    def contacting(self, request: VOMSRequest, servers: Sequence[VOMSServer]) -> None:
        """Nothing to say before a request."""

    def contacted(self, request: VOMSRequest) -> None:
        """Nothing to say after one."""

    def warned(self, message: str) -> None:
        """Issue the warning again, outside the collection that caught it."""
        warnings.warn(message, VOMSWarning, stacklevel=2)


def fetch_acs(
    signer: ProxyCredential, request: ProxyRequest, progress: Progress | None = None
) -> list[bytes]:
    """One DER attribute certificate per entry of ``request.voms``, in order, asked with ``signer``.

    Each VO's servers are found in the ``vomses`` configuration
    (:func:`~xrdsec.voms_client.servers_for`) and asked in order
    (:func:`~xrdsec.voms_client.fetch_ac`). The warnings each request raises
    reach ``progress.warned`` once it is done - even when it, or a later
    VO, fails the command, since the warning may be why. Raises the
    :class:`~xrdsec.voms_client.VOMSError` kinds (configuration, refusal,
    no server answering) and :class:`ValueError` for a malformed FQAN.
    """
    if not request.voms:
        return []
    hooks: Progress = _Silent() if progress is None else progress
    configured = find_vomses(request.vomses or None)
    lifetime = request.voms_lifetime or request.lifetime
    acs: list[bytes] = []
    for wanted in request.voms:
        servers = servers_for(wanted.vo, configured)
        hooks.contacting(wanted, servers)
        with _warnings_to(hooks):
            ac = fetch_ac(
                servers,
                signer,
                fqans=wanted.fqans,
                lifetime=lifetime,
                timeout=request.timeout,
                ca_path=request.ca_path,
                system_ca=request.system_ca,
                x509_strict=request.x509_strict,
            )
        hooks.contacted(wanted)
        acs.append(ac)
    return acs


@contextlib.contextmanager
def _warnings_to(progress: Progress) -> Iterator[None]:
    """Collect the warnings raised inside, then hand each to ``progress.warned``.

    Handed over after the filters are restored, so a hook that warns again
    (the default) is not caught by its own collection. :mod:`warnings`'
    state is process-wide: a command makes one proxy at a time.
    """
    caught: list[warnings.WarningMessage] = []
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            yield
    finally:
        for warning in caught:
            progress.warned(str(warning.message))


# ---------------------------------------------------------------------------
# The proxy
# ---------------------------------------------------------------------------


def require_alive(signer: ProxyCredential, *, now: float | None = None) -> None:
    """Refuse an expired ``signer`` up front: :class:`ExpiredCredentialError`.

    :func:`xrdsec.proxies.create_proxy` refuses it too, but as one
    ``ValueError`` among many, and only after the VOMS servers were asked
    with a credential they will not accept. The expiry is the chain's
    (:func:`xrdsec.lifetime.chain_expiry`): a credential dies with the first
    certificate above it that does.
    """
    moment = time.time() if now is None else now
    if chain_expiry(signer.chain) <= moment:
        raise ExpiredCredentialError(
            f"the credential {signer.chain[0].subject} has expired; it cannot issue a proxy"
        )


def make_proxy(
    signer: ProxyCredential,
    request: ProxyRequest,
    progress: Progress | None = None,
    *,
    now: float | None = None,
) -> ProxyCredential:
    """The proxy ``request`` describes, signed by ``signer``, in memory.

    :func:`require_alive`, then :func:`fetch_acs`, then
    :func:`xrdsec.proxies.create_proxy` with the ACs - in that order (see
    the module docstring). ``now`` pins the clock, for tests. Raises what
    those raise: :class:`ExpiredCredentialError`, the VOMS errors, and
    :class:`~xrdsec.proxies.ProxyError`/:class:`ValueError` for a proxy that
    cannot be issued (a key size refused, a signer that may not delegate).
    """
    require_alive(signer, now=now)
    acs = fetch_acs(signer, request, progress)
    return create_proxy(
        signer,
        lifetime=request.lifetime,
        bits=request.bits,
        limited=request.limited,
        voms_acs=acs,
        profile=request.profile,
        path_length=request.path_length,
        now=now,
    )


class Target(NamedTuple):
    """Where a proxy file is, and whether a symbolic link there may be followed."""

    path: str
    follow_symlinks: bool


def proxy_target(
    named: str | os.PathLike[str] | None = None, environ: Mapping[str, str] | None = None
) -> Target:
    """The proxy file a command writes, reads or removes.

    ``named`` (``-out``, ``-file``, ``--proxy``), else ``$X509_USER_PROXY``,
    else ``/tmp/x509up_u<uid>`` (:func:`xrdsec.credentials.default_proxy_path`).
    A path somebody named may be a symbolic link to wherever they keep
    proxies; the predictable default may not, because anyone can create a
    link there before the user's first ``voms-proxy-init``.
    """
    if named:
        return Target(os.fspath(named), True)
    env = os.environ if environ is None else environ
    path = credentials.default_proxy_path(env)
    return Target(path, bool(env.get("X509_USER_PROXY", "").strip()))


def read_proxy_info(
    path: str | os.PathLike[str], *, follow_symlinks: bool = True, now: float | None = None
) -> ProxyInfo:
    """Read the proxy file at ``path`` and describe it: ``voms-proxy-info``, ``arcproxy -I``.

    Read under :func:`xrdsec.credentials.read_private_file`'s rules (the
    file holds a private key: one that others can read is refused, with
    the ``chmod`` that fixes it), not following a symbolic link unless
    ``follow_symlinks`` (see :func:`proxy_target`). ``now`` is the moment
    :attr:`~xrdsec.proxies.ProxyInfo.time_left` is counted from; a command
    that prints the ACs' time left too passes the same reading to
    :meth:`~xrdsec.voms.VOMSEntry.remaining`, so the lines agree. Raises
    :class:`NoCredentialError` when nothing is there, and
    :class:`~xrdcore.errors.CredentialError` for a file with no certificate.
    """
    name = os.fspath(path)
    try:
        data = credentials.read_private_file(
            name, kind=_PROXY_KIND, predictable=not follow_symlinks
        )
    except FileNotFoundError:
        raise NoCredentialError(f"there is no proxy at {name}", name) from None
    chain = load_certificates(data)
    if not chain:
        raise CredentialError(f"there is no certificate in {name}")
    return describe_proxy(chain, path=name, now=now)
