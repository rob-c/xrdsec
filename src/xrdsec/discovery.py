"""Which X.509 credential and which trust anchors to use: each tool's search, as data.

Every grid tool looks in the same handful of places - a proxy someone named,
the default proxy file, a user certificate and key - but each in its own
order and with its own idea of what a missing file means. Those differences
are visible to users (one tool logs in, the next says "no credential"), so
they are kept exactly, as :class:`Search` values:

* :data:`XRDCLIENT` - XRootD's client: a named proxy, then a user
  certificate and key when both are set, then ``/tmp/x509up_u<uid>`` if it
  is there. A named proxy is presented even when it is missing, so the
  failure names it.
* :data:`GFAL2` - gfal2 (and davix) looking for a credential to present:
  a named proxy that is missing stops the search with a warning, because a
  proxy from anywhere else would be a different identity than the
  environment named; then the default proxy, ``$X509_USER_CERT`` and
  ``$X509_USER_KEY`` (both must exist), then ``~/.globus``.
* :data:`GFAL2_SEED` - what ``gfal2_context_new`` writes into the options:
  the same places, trusting the variables without looking at the files.
* :data:`ARC` - ARC's ``UserConfig::InitializeCredentials``: a named proxy
  that is missing is an error; the default proxy, also under ``$TMPDIR``;
  then a certificate and key (not checked), then ``~/.arc`` and ``~/.globus``.

The answers are plain values - :class:`X509Location` paths and where they
came from - and nothing is read or loaded here: that is
:mod:`xrdsec.tls`'s and :mod:`xrdsec.x509`'s job. The single-tool lookups it
is built from - one variable, one conventional place - are
:mod:`xrdsec.credentials`. A tool's own settings
(``Config.proxy``, ARC's ``proxypath``) are passed in; the environment is
``environ``, the process's by default.

Trust anchors follow the same pattern (:func:`discover_ca_dir`): the
configured directory or ``$X509_CERT_DIR``, ARC's per-user directories, then
the grid-wide ``grid-security/certificates``; ``None`` means the system store.
The grid-wide directories are the one input the environment does not
carry, so they are a parameter too (``grid_security=``, or
:data:`xrdsec.credentials.GRID_SECURITY_DIRS` for a whole test suite).
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from xrdcore.errors import CredentialError
from xrdcore.log import get_logger

from . import credentials

__all__ = [
    "ARC",
    "GFAL2",
    "GFAL2_SEED",
    "SEARCHES",
    "XRDCLIENT",
    "Search",
    "Step",
    "X509Location",
    "discover_ca_dir",
    "discover_x509",
]

_log = get_logger(__name__)

#: One place to look, by name:
#:
#: * ``named-proxy`` - the tool's own proxy setting, else ``$X509_USER_PROXY``;
#: * ``default-proxy`` - ``/tmp/x509up_u<uid>``;
#: * ``tmpdir-proxy`` - ``$TMPDIR/x509up_u<uid>``;
#: * ``user-pair`` - the tool's certificate and key settings, else
#:   ``$X509_USER_CERT`` and ``$X509_USER_KEY``, both set;
#: * ``globus-pair`` / ``arc-pair`` - ``usercert.pem`` and ``userkey.pem``
#:   in ``~/.globus`` / ``~/.arc``.
Step = Literal[
    "named-proxy", "default-proxy", "tmpdir-proxy", "user-pair", "globus-pair", "arc-pair"
]


@dataclass(frozen=True, slots=True)
class Search:
    """One tool's credential search: where it looks, in order, and how strictly."""

    #: A label, for messages.
    name: str
    #: The places, in order; the first that yields a credential wins.
    steps: tuple[Step, ...]
    #: What a named proxy that does not exist means: ``"present"`` it anyway
    #: (loading it then fails, naming it), ``"stop"`` - no credential, with a
    #: warning - or ``"raise"`` a :class:`~xrdcore.errors.CredentialError`.
    missing_named_proxy: Literal["present", "stop", "raise"]
    #: How a certificate/key pair from ``user-pair`` is checked: not at all,
    #: as existing files, or as files this process can read.
    pair_check: Literal["none", "isfile", "readable"]
    #: How ``globus-pair``/``arc-pair`` files are checked.
    home_pair_check: Literal["isfile", "readable"]
    #: Per-user CA directories, under the home directory, before the
    #: grid-wide one (ARC's ``~/.arc/certificates``).
    user_ca_dirs: tuple[str, ...] = ()


XRDCLIENT = Search(
    name="xrdclient",
    steps=("named-proxy", "user-pair", "default-proxy"),
    missing_named_proxy="present",
    pair_check="none",
    home_pair_check="isfile",
)
GFAL2 = Search(
    name="gfal2",
    steps=("named-proxy", "default-proxy", "user-pair", "globus-pair"),
    missing_named_proxy="stop",
    pair_check="isfile",
    home_pair_check="isfile",
)
GFAL2_SEED = Search(
    name="gfal2-seed",
    steps=("named-proxy", "default-proxy", "user-pair", "globus-pair"),
    missing_named_proxy="present",
    pair_check="none",
    home_pair_check="readable",
)
ARC = Search(
    name="arc",
    steps=(
        "named-proxy",
        "default-proxy",
        "tmpdir-proxy",
        "user-pair",
        "arc-pair",
        "globus-pair",
    ),
    missing_named_proxy="raise",
    pair_check="none",
    home_pair_check="isfile",
    user_ca_dirs=(".arc/certificates", ".globus/certificates"),
)

#: The searches by name.
SEARCHES = {search.name: search for search in (XRDCLIENT, GFAL2, GFAL2_SEED, ARC)}


@dataclass(frozen=True, slots=True)
class X509Location:
    """Where an X.509 credential is: a certificate file and the file holding its key.

    The same path twice for a proxy, which carries its key. ``source`` says
    which step found it, in gfal2's words (``"X509_USER_PROXY"``,
    ``"default proxy location"``, ...). ``named`` is whether somebody chose
    it - a setting or a variable - rather than it being found at a default
    location: a named credential that will not load is an error, a found one
    is a guess that may be passed over.
    """

    cert: str
    key: str
    source: str
    named: bool

    @property
    def is_proxy(self) -> bool:
        """A single file holding the chain and its key."""
        return self.cert == self.key


def _uid_suffix(uid: int | None = None) -> str:
    """What names a user's default credential files: ``uid``, else the effective uid.

    ``x509up_u<uid>``, as :func:`xrdsec.credentials.default_proxy_path` names
    it. Where there is no uid (Windows) and none was given, the login name
    stands in, as ARC's own tools use it there.
    """
    if uid is not None:
        return str(uid)
    if hasattr(os, "geteuid"):
        return str(os.geteuid())
    import getpass

    return getpass.getuser()


def _standard_proxy_path(uid: int | None = None) -> str:
    """``/tmp/x509up_u<uid>``: where ``voms-proxy-init``, gfal2 and XRootD look.

    :data:`xrdsec.credentials.TMP_DIR` on POSIX, because that is the name
    every grid tool agrees on; Windows has no ``/tmp``, so its temporary
    directory stands in there.
    """
    name = f"x509up_u{_uid_suffix(uid)}"
    if sys.platform == "win32":
        import tempfile

        return os.path.join(tempfile.gettempdir(), name)
    return os.path.join(credentials.TMP_DIR, name)


def _trimmed(env: Mapping[str, str], name: str) -> str | None:
    """``$name`` with surrounding blanks dropped; blank counts as unset."""
    return env.get(name, "").strip() or None


def _home(env: Mapping[str, str]) -> str:
    """The home directory: ``$HOME``, ``%USERPROFILE%``, else the password database's."""
    return env.get("HOME") or env.get("USERPROFILE") or os.path.expanduser("~")


def _passes(path: str, check: str) -> bool:
    """Whether ``path`` passes a pair check."""
    if check == "none":
        return True
    if check == "readable":
        return os.access(path, os.R_OK)
    return os.path.isfile(path)


#: Missing named proxies already warned about, so a busy process warns once each.
_WARNED: set[str] = set()
_WARNED_LOCK = threading.Lock()


def _warn_missing(path: str) -> None:
    """Say once per path that the named proxy is missing and nothing stands in."""
    with _WARNED_LOCK:
        if path in _WARNED:
            return
        _WARNED.add(path)
    _log.warning(
        "X509_USER_PROXY names %s, which does not exist; no X.509 credential "
        "will be presented (a proxy from anywhere else would be a different identity)",
        path,
    )


class _Stop(Exception):
    """The search ends with no credential (a missing named proxy, under ``stop``)."""


@dataclass(frozen=True, slots=True)
class _Inputs:
    """Everything one :func:`discover_x509` call reads, so each step takes one argument.

    ``proxy``/``cert``/``key`` are the tool's own settings (``None``: not
    configured); ``uid`` names the default proxy files (``None``: this
    process's).
    """

    search: Search
    env: Mapping[str, str]
    proxy: str | None
    cert: str | None
    key: str | None
    uid: int | None


def _named_proxy(given: _Inputs) -> X509Location | None:
    """``proxy`` or ``$X509_USER_PROXY``, judged as the search judges a missing one."""
    named = (given.proxy or "").strip() or _trimmed(given.env, "X509_USER_PROXY")
    if not named:
        return None
    if not os.path.isfile(named):
        if given.search.missing_named_proxy == "raise":
            raise CredentialError(
                f"The proxy {named} does not exist. Create one (voms-proxy-init, arcproxy) "
                "or unset X509_USER_PROXY."
            )
        if given.search.missing_named_proxy == "stop":
            _warn_missing(named)
            raise _Stop
    return X509Location(named, named, "X509_USER_PROXY", True)


def _proxy_at(path: str, source: str) -> X509Location | None:
    """The proxy at a default location, if a file is there."""
    return X509Location(path, path, source, False) if os.path.isfile(path) else None


def _user_pair(given: _Inputs) -> X509Location | None:
    """The configured or environment certificate and key, when both are set and pass."""
    cert = given.cert or _trimmed(given.env, "X509_USER_CERT")
    key = given.key or _trimmed(given.env, "X509_USER_KEY")
    if not (cert and key):
        return None
    check = given.search.pair_check
    if not (_passes(cert, check) and _passes(key, check)):
        return None
    return X509Location(cert, key, "X509_USER_CERT and X509_USER_KEY", True)


def _home_pair(given: _Inputs, directory: str) -> X509Location | None:
    """``usercert.pem``/``userkey.pem`` under ``~/<directory>``, when both pass."""
    base = os.path.join(_home(given.env), directory)
    cert, key = os.path.join(base, "usercert.pem"), os.path.join(base, "userkey.pem")
    check = given.search.home_pair_check
    if _passes(cert, check) and _passes(key, check):
        return X509Location(cert, key, "default certificate location", False)
    return None


def _step(step: Step, given: _Inputs) -> X509Location | None:
    """What one step finds."""
    if step == "named-proxy":
        return _named_proxy(given)
    if step == "default-proxy":
        return _proxy_at(_standard_proxy_path(given.uid), "default proxy location")
    if step == "tmpdir-proxy":
        tmpdir = _trimmed(given.env, "TMPDIR")
        if not tmpdir:
            return None
        name = f"x509up_u{_uid_suffix(given.uid)}"
        return _proxy_at(os.path.join(tmpdir, name), "TMPDIR proxy location")
    if step == "user-pair":
        return _user_pair(given)
    return _home_pair(given, ".globus" if step == "globus-pair" else ".arc")


def discover_x509(
    search: Search = XRDCLIENT,
    *,
    proxy: str | None = None,
    cert: str | None = None,
    key: str | None = None,
    environ: Mapping[str, str] | None = None,
    uid: int | None = None,
) -> X509Location | None:
    """The X.509 credential ``search`` would present, or ``None`` if there is none.

    ``proxy``, ``cert`` and ``key`` are the tool's own settings, which take
    the place of ``$X509_USER_PROXY``, ``$X509_USER_CERT`` and
    ``$X509_USER_KEY``. ``uid`` names the default proxy files
    (``x509up_u<uid>`` in ``/tmp`` and ``$TMPDIR``), as it does for
    :func:`xrdsec.credentials.find_proxy`: a tool acting for another account
    (a service resolving a user's proxy, a test) asks for that account's
    file without changing its effective uid. The default is this process's.
    Like everywhere in :mod:`xrdsec.credentials`, ``uid`` only names files;
    whether a file is *yours* is checked when it is read. Raises
    :class:`~xrdcore.errors.CredentialError` only for a missing named proxy
    under a search that says so (:data:`ARC`).
    """
    env = os.environ if environ is None else environ
    given = _Inputs(search, env, proxy, cert, key, uid)
    try:
        for step in search.steps:
            found = _step(step, given)
            if found is not None:
                return found
    except _Stop:
        return None
    return None


def discover_ca_dir(
    search: Search = XRDCLIENT,
    *,
    configured: str | None = None,
    environ: Mapping[str, str] | None = None,
    grid_security: Sequence[str] | None = None,
) -> str | None:
    """The trust-anchor directory: configured, ``$X509_CERT_DIR``, per-user, grid-wide.

    ``configured`` (or ``$X509_CERT_DIR``) is returned as given, even if it
    does not exist: the user named it, and a TLS failure naming it is the
    right outcome. Otherwise the search's per-user directories and then
    ``<grid_security>/certificates`` are taken if they exist. ``None`` means
    "the system store".

    ``grid_security`` lists the ``grid-security`` directories to look in,
    in order; the default is :data:`xrdsec.credentials.GRID_SECURITY_DIRS`,
    else the platform's (``/etc/grid-security``, plus Homebrew's on a Mac).
    It exists because the grid-wide step is the one input a caller cannot
    otherwise steer: an installation under another prefix names its own,
    and a hermetic test passes ``()`` (or sets the attribute) instead of
    depending on the machine having no ``/etc/grid-security/certificates``.
    """
    env = os.environ if environ is None else environ
    named = (configured or "").strip() or _trimmed(env, "X509_CERT_DIR")
    if named:
        return named
    home = _home(env)
    for relative in search.user_ca_dirs:
        candidate = os.path.join(home, relative)
        if os.path.isdir(candidate):
            return candidate
    if grid_security is None:
        candidates = credentials._candidates("certificates")
    else:
        candidates = tuple(os.path.join(directory, "certificates") for directory in grid_security)
    return next((path for path in candidates if os.path.isdir(path)), None)
