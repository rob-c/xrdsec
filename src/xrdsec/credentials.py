"""Where a grid client's credentials and trust anchors are, and how to read one safely.

Every tool that talks to grid storage or a grid service asks the same
questions before its first request - which proxy, which certificate and key,
which bearer token, which CA directory - and the answers are conventions
shared by XrdCl, gfal2/davix, ARC, ``voms-proxy-init`` and the WLCG token
tools. This module is the one implementation of those conventions for every
client on the stack - xrdclient, xgfalclient, xrdarc, users' own scripts -
so each gets the same answer the transfer code gets:

==============================  ==========================================
:func:`default_proxy_path`      ``$X509_USER_PROXY``, else ``/tmp/x509up_u<uid>``
:func:`find_proxy`              the proxy to present, or ``None``
:func:`find_user_credential`    ``$X509_USER_CERT``/``KEY``, else ``~/.globus``
:func:`find_bearer_token`       WLCG Bearer Token Discovery, in full
:func:`bearer_token_files`      the files that search may read, in order
:func:`grid_ca_path`            ``$X509_CERT_DIR``, else ``grid-security/certificates``
:func:`grid_voms_dir`           ``$X509_VOMS_DIR``, else ``grid-security/vomsdir``
:func:`read_private_file`       a credential file, once shown to be yours alone
:func:`write_private_file`      a credential file written ``0600``, atomically
==============================  ==========================================

**Inputs are arguments, not ambient state.** Each lookup takes ``environ``
(default :data:`os.environ`, read at call time) and, where a file name has
the uid in it, ``uid`` (default :func:`os.geteuid`). A tool that resolves
credentials from a configuration file of its own, or a test, passes a
mapping instead of patching the process environment. A variable that is set
but blank (or only whitespace) counts as unset everywhere here: an empty
``X509_CERT_DIR=`` in a login profile means "not configured", never "the
current directory". ``uid`` only ever names files; whether a file is
*yours* is always checked against the effective uid of this process.

**Named versus guessed.** A location the user *named* - an environment
variable, an argument - is the answer even when nothing is there yet:
:func:`find_proxy` returns ``$X509_USER_PROXY`` whether or not it exists,
because silently presenting a different identity from the one the
environment named is worse than failing. Whether a missing named file is an
error (XrdCl, ARC) or just "no proxy" (davix, for token-only access) is the
caller's call. A location that is only *predictable* - ``/tmp/x509up_u<uid>``,
``/tmp/bt_u<uid>`` - is used only if a regular file is there that passes
:func:`read_private_file`'s checks, and one that is there but fails them
raises :class:`~xrdcore.errors.InsecureCredentialError` rather than being
skipped: falling through to the next location would log in with whatever
somebody else left at the first.

**One difference between the tools** is kept as a keyword rather than a
fork: what a token file that cannot be read *for an ordinary reason* means.
XRootD's client lets the :class:`OSError` through; gfal2 (davix) treats it as
"no token here" - :func:`find_bearer_token`'s ``skip_unreadable=True``. A
refusal on security grounds is raised either way.

**Cost and neighbours.** Importing this module costs :mod:`os`, :mod:`stat`,
:mod:`xrdcore.errors` and :mod:`xrdcore.log`; it is on the import path of
every transfer (through a client's configuration defaults), so it must never
import the crypto, TLS or client stacks (the writer's :mod:`tempfile` is
stdlib). A client's own configuration-shaped adapters (a proxy path from its
settings, a token search fed from a URL and a ``Config``) call the private
``_discover``/``_token_files``, which take every input - ``TMP_DIR`` included
- as an argument. Each tool's whole X.509 search order is
:mod:`xrdsec.discovery`; the WLCG token search with a URL token in front is
:mod:`xrdsec.tokens`; TLS client contexts built from these answers are
:mod:`xrdsec.tls`.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import sys
import tempfile
from collections.abc import Iterable, Iterator, Mapping

from xrdcore.errors import CredentialError, InsecureCredentialError
from xrdcore.log import get_logger

__all__ = [
    "DEFAULT_CA_PATH",
    "GRID_SECURITY_DIRS",
    "MAX_CREDENTIAL_SIZE",
    "TMP_DIR",
    "bearer_token_files",
    "default_ca_path",
    "default_proxy_path",
    "find_bearer_token",
    "find_proxy",
    "find_user_credential",
    "grid_ca_path",
    "grid_voms_dir",
    "read_private_file",
    "write_private_file",
]

#: The conventional CA directory: hashed certificates, signing policies, CRLs.
DEFAULT_CA_PATH = "/etc/grid-security/certificates"

#: Far more than any proxy chain, token or keytab; a larger "credential" is
#: a mistake (or ``/dev/zero`` behind a link) and is not read into memory.
MAX_CREDENTIAL_SIZE = 1 << 20

#: Where the default proxy and the last-resort token file live. The WLCG
#: specification and every grid tool say ``/tmp`` literally, not ``$TMPDIR``
#: (which on macOS is a per-user directory no other tool would look in).
#: A module attribute so a test can point the token search somewhere
#: hermetic; a client's own adapter may pass a ``TMP_DIR`` of its own to
#: ``_discover``.
TMP_DIR = "/tmp"

#: The ``grid-security`` directories the grid-wide trust anchors, LSC files
#: and ``vomses`` are looked for in, most likely first; ``None`` (the
#: default) is the platform's conventional ones - ``/etc/grid-security``, and
#: on a Mac Homebrew's prefixes too. A module attribute for the same reason
#: as :data:`TMP_DIR`: a test suite cannot remove ``/etc/grid-security``
#: from the machine it runs on, so without this a test of "no CA directory
#: anywhere" passes or fails by host. Setting it to directories the suite
#: owns (or ``()``) makes :func:`grid_ca_path`, :func:`grid_voms_dir`,
#: :func:`xrdsec.discovery.discover_ca_dir` and the ``vomses`` search
#: answer the same everywhere. Read per call, never cached.
GRID_SECURITY_DIRS: tuple[str, ...] | None = None

#: Group and other permission bits: a credential file has none of them.
_SHARED = stat.S_IRWXG | stat.S_IRWXO
_WRITABLE = stat.S_IWGRP | stat.S_IWOTH

#: How a token file is named in a refusal.
_TOKEN_KIND = "bearer token file"

_log = get_logger(__name__)


def _environ(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    """``environ``, or the process environment as it is now."""
    return os.environ if environ is None else environ


def _uid(uid: int | None) -> int:
    """``uid``, or the effective uid - what ``id -u`` prints, as the specs say."""
    return os.geteuid() if uid is None else uid


def _setting(env: Mapping[str, str], name: str) -> str | None:
    """``$name`` with surrounding whitespace removed; blank counts as unset."""
    return env.get(name, "").strip() or None


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------


def _candidates(kind: str) -> tuple[str, ...]:
    """The conventional homes of ``grid-security/<kind>``, most likely first.

    :data:`GRID_SECURITY_DIRS` when it is set. Otherwise Linux has the one;
    on a Mac, Homebrew's prefix is searched too, Apple Silicon's before
    Intel's. ``sys.platform`` and the attribute are read per call, which is
    what lets a test ask for the other platform's answer, or for none.
    """
    if GRID_SECURITY_DIRS is not None:
        return tuple(os.path.join(directory, kind) for directory in GRID_SECURITY_DIRS)
    suffix = f"grid-security/{kind}"
    if sys.platform == "darwin":
        return (f"/etc/{suffix}", f"/opt/homebrew/etc/{suffix}", f"/usr/local/etc/{suffix}")
    return (f"/etc/{suffix}",)


def _grid_directory(env: Mapping[str, str], variable: str, kind: str) -> str | None:
    """``$<variable>``, else the first ``grid-security/<kind>`` that exists, else ``None``.

    ``None`` is the honest answer for a machine with no such directory at
    all; a configured value is returned without checking it exists, so a
    typo is reported where it is used rather than papered over.
    """
    return _setting(env, variable) or next(
        (path for path in _candidates(kind) if os.path.isdir(path)), None
    )


def grid_ca_path(environ: Mapping[str, str] | None = None) -> str | None:
    """The CA directory: ``$X509_CERT_DIR``, else ``grid-security/certificates``.

    ``None`` when neither is there - and a blank ``$X509_CERT_DIR`` is
    neither: handing ``""`` to OpenSSL as a ``capath`` would trust nothing
    and fail every handshake with a message about the server. With ``None``,
    a client's configuration and :func:`xrdsec.tls.client_context` use
    the operating system's store instead, which is right for an endpoint
    with a public certificate.
    """
    return _grid_directory(_environ(environ), "X509_CERT_DIR", "certificates")


def grid_voms_dir(environ: Mapping[str, str] | None = None) -> str | None:
    """The VOMS LSC directory: ``$X509_VOMS_DIR``, else ``grid-security/vomsdir``."""
    return _grid_directory(_environ(environ), "X509_VOMS_DIR", "vomsdir")


def default_ca_path(environ: Mapping[str, str] | None = None) -> str:
    """:func:`grid_ca_path`, falling back to :data:`DEFAULT_CA_PATH`.

    For trust checks that need *a* directory to name in an error message
    even when none exists: "cannot read /etc/grid-security/..." tells a
    user what to install, where "no CA directory" does not.
    """
    return grid_ca_path(environ) or DEFAULT_CA_PATH


# ---------------------------------------------------------------------------
# X.509: proxy, certificate and key
# ---------------------------------------------------------------------------


def default_proxy_path(environ: Mapping[str, str] | None = None, uid: int | None = None) -> str:
    """Where the proxy is, or a new one goes: ``$X509_USER_PROXY``, else ``/tmp/x509up_u<uid>``.

    The path is answered whether or not a file is there - this is the name
    ``voms-proxy-init`` writes to and XrdCl's GSI reads from. To ask whether
    there is a proxy to present, use :func:`find_proxy`.
    """
    return _setting(_environ(environ), "X509_USER_PROXY") or os.path.join(
        TMP_DIR, f"x509up_u{_uid(uid)}"
    )


def find_proxy(
    environ: Mapping[str, str] | None = None,
    uid: int | None = None,
    *,
    extra: Iterable[str | os.PathLike[str]] = (),
) -> str | None:
    """The proxy to present: ``$X509_USER_PROXY``, else the first default that is there.

    A named ``$X509_USER_PROXY`` is returned as it is, present or not (see
    the module docstring: it is never replaced by a guess). Otherwise the
    default ``/tmp/x509up_u<uid>`` and then each of ``extra`` - other
    predictable homes a tool knows of, such as ARC's ``$TMPDIR/x509up_u<uid>``
    - is tried in order; the first one there is the answer, and ``None``
    means none is.

    A default location that holds something other than a private regular
    file of this user's - a symbolic link, somebody else's file, one others
    may read - raises :class:`~xrdcore.errors.InsecureCredentialError`.
    That check is made on the name, so it is advice for an early, clear
    error; the file is checked again on the open descriptor when it is read
    (:func:`read_private_file` with ``predictable=True``), which is the
    check that counts.
    """
    named = _setting(_environ(environ), "X509_USER_PROXY")
    if named:
        return named
    defaults = (os.path.join(TMP_DIR, f"x509up_u{_uid(uid)}"), *(os.fspath(p) for p in extra))
    return next((path for path in defaults if _private_file_at(path, "X.509 proxy")), None)


def _private_file_at(path: str, kind: str) -> bool:
    """Whether a private regular file of ours is at the predictable ``path``.

    ``False`` when nothing is there; raises for something that should not be.
    ``lstat``, so a symbolic link is seen as one and refused, as
    :func:`read_private_file` refuses one at a predictable name.
    """
    try:
        info = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    if stat.S_ISLNK(info.st_mode):
        raise _link_refused(path, kind)
    _check(path, info, kind)
    return True


def find_user_credential(
    environ: Mapping[str, str] | None = None,
    *,
    dirs: Iterable[str | os.PathLike[str]] = ("~/.globus",),
) -> tuple[str, str] | None:
    """A user certificate and its key, kept apart: ``(certificate, key)`` or ``None``.

    ``$X509_USER_CERT`` and ``$X509_USER_KEY`` when both are set (returned
    as named, present or not - one without the other is ignored, as gfal2
    ignores it); else the first of ``dirs`` holding both ``usercert.pem``
    and ``userkey.pem``. ``~`` in ``dirs`` is ``environ["HOME"]`` when that
    is set, so a caller's own environment decides whose home it is. A tool
    with more conventional homes passes them, ARC's first:
    ``dirs=("~/.arc", "~/.globus")``.

    Nothing is read here. The key is checked - ours, ``0600`` or tighter -
    when it is used: :func:`xrdsec.tls.client_context` reads it through
    :func:`read_private_file` and never writes it anywhere.
    """
    env = _environ(environ)
    cert, key = _setting(env, "X509_USER_CERT"), _setting(env, "X509_USER_KEY")
    if cert and key:
        return cert, key
    for directory in dirs:
        base = _expand_home(os.fspath(directory), env)
        pair = os.path.join(base, "usercert.pem"), os.path.join(base, "userkey.pem")
        if os.path.isfile(pair[0]) and os.path.isfile(pair[1]):
            return pair
    return None


def _expand_home(path: str, env: Mapping[str, str]) -> str:
    """``path`` with a leading ``~`` replaced by ``env``'s ``HOME`` (or this user's home).

    Only ``~`` and ``~/...``: ``~other`` is another user's home, which only
    the password database knows, so it is left to :func:`os.path.expanduser`.
    """
    if path != "~" and not path.startswith("~/"):
        return os.path.expanduser(path)
    home = _setting(env, "HOME") or os.path.expanduser("~")
    return home + path[1:]


# ---------------------------------------------------------------------------
# Bearer tokens
# ---------------------------------------------------------------------------


def find_bearer_token(
    environ: Mapping[str, str] | None = None,
    uid: int | None = None,
    *,
    explicit: str | None = None,
    token_file: str | None = None,
    skip_unreadable: bool = False,
) -> str | None:
    """The bearer token to present, by WLCG Bearer Token Discovery, or ``None``.

    The order is the specification's - what ``XrdSecztn``, ``htgettoken``,
    ``oidc-agent`` and the SciTokens libraries follow - after the two things
    a caller can pass:

    1. ``explicit``, a token the caller already has (a ``--token`` option);
    2. ``token_file``, a file the caller was told to read (``--token-file``):
       it outranks the environment, because it was named for this call;
    3. ``$BEARER_TOKEN``;
    4. the file ``$BEARER_TOKEN_FILE`` names;
    5. ``$XDG_RUNTIME_DIR/bt_u<uid>``;
    6. ``/tmp/bt_u<uid>``.

    A step that yields nothing - unset, a missing file, a file with only
    whitespace in it - passes to the next, as the reference implementations
    do. A file that is there but not private to this user raises
    :class:`~xrdcore.errors.InsecureCredentialError` instead (see the
    module docstring); so does a symbolic link at steps 5 and 6, while the
    files at steps 2 and 4 were named and may be links. Any other
    :class:`OSError` reading a file - a permission denied, a directory where
    the file should be - propagates: it is a problem to report, not an
    absent token, unless ``skip_unreadable=True`` (gfal2's reading), which
    passes such a file over as "no token here". The token comes back
    stripped of surrounding whitespace.
    """
    return _discover(_environ(environ), _uid(uid), explicit, token_file, TMP_DIR, skip_unreadable)


def bearer_token_files(
    environ: Mapping[str, str] | None = None,
    uid: int | None = None,
    *,
    token_file: str | None = None,
) -> list[tuple[str, bool]]:
    """Every file :func:`find_bearer_token` may read, in order, each with whether it is predictable.

    For messages ("no token in ..."), for ``doctor``-style reports, and for
    a tool that watches the files for renewal. A predictable file -
    ``bt_u<uid>`` in ``$XDG_RUNTIME_DIR`` or ``/tmp`` - is opened without
    following a symbolic link; one the user named is followed.
    """
    return _token_files(_environ(environ), _uid(uid), token_file, TMP_DIR)


def _token_files(
    env: Mapping[str, str], uid: int, token_file: str | None, tmp_dir: str
) -> list[tuple[str, bool]]:
    """:func:`bearer_token_files` with every input explicit, ``tmp_dir`` included.

    ``tmp_dir`` is a parameter so that a client's own adapter can pass its
    own ``TMP_DIR`` - an attribute its test suite points at an empty
    directory to stay hermetic - through the one implementation.
    """
    files: list[tuple[str, bool]] = []
    if token_file:
        files.append((token_file, False))
    from_env = _setting(env, "BEARER_TOKEN_FILE")
    if from_env:
        files.append((from_env, False))
    name = f"bt_u{uid}"
    runtime = _setting(env, "XDG_RUNTIME_DIR")
    if runtime:
        files.append((os.path.join(runtime, name), True))
    files.append((os.path.join(tmp_dir, name), True))
    return files


def _discover(
    env: Mapping[str, str],
    uid: int,
    explicit: str | None,
    token_file: str | None,
    tmp_dir: str,
    skip_unreadable: bool = False,
) -> str | None:
    """:func:`find_bearer_token` with every input explicit; see :func:`_token_files`."""
    for found in _token_candidates(env, uid, explicit, token_file, tmp_dir, skip_unreadable):
        token = (found or "").strip()
        if token:
            return token
    return None


def _token_candidates(
    env: Mapping[str, str],
    uid: int,
    explicit: str | None,
    token_file: str | None,
    tmp_dir: str,
    skip_unreadable: bool = False,
) -> Iterator[str | None]:
    """What each discovery step finds, in order.

    A generator so that a file is only opened once every step before it has
    come up empty: a token in ``$BEARER_TOKEN`` must not be shadowed - or
    blocked, by an :class:`InsecureCredentialError` - by a stale file at a
    later step.
    """
    yield explicit
    files = _token_files(env, uid, token_file, tmp_dir)
    if token_file:
        yield _read_token(*files.pop(0), skip_unreadable)  # step 2 outranks the environment
    yield env.get("BEARER_TOKEN")
    for path, predictable in files:
        yield _read_token(path, predictable, skip_unreadable)


def _read_token(path: str, predictable: bool, skip_unreadable: bool = False) -> str | None:
    """The text of the token file at ``path``, or ``None`` when there is no file there.

    Undecodable bytes become U+FFFD rather than an exception: the server
    will refuse such a token with a message that names it, which is more
    use than a :class:`UnicodeDecodeError` here.
    """
    try:
        data = read_private_file(path, kind=_TOKEN_KIND, predictable=predictable)
    except FileNotFoundError:
        return None
    except CredentialError:
        raise  # a refusal on security grounds is never "no token here"
    except OSError:
        if skip_unreadable:
            return None
        raise
    # The path, never the contents: which file won is what a user debugging
    # "logged in as the wrong identity" needs to see.
    _log.debug("found a bearer token file at %s", path)
    return data.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Reading a credential file
# ---------------------------------------------------------------------------


def read_private_file(
    path: str | os.PathLike[str],
    *,
    kind: str,
    predictable: bool = False,
    limit: int = MAX_CREDENTIAL_SIZE,
) -> bytes:
    """The contents of the credential file at ``path``, once it is shown to be yours alone.

    The rules are the grid's own (``voms-proxy-init`` writes ``0600``,
    ``XrdSecsss`` and ``XrdSecgsi`` refuse anything wider): a regular file,
    owned by the effective uid - root included, who must not pick up a
    proxy somebody else planted at ``/tmp/x509up_u0`` - with no group or
    other permission bits. They are checked on the *open* descriptor
    (``fstat``), never on the name before opening, so the file inspected is
    the file read. A FIFO or device at the name is opened non-blocking and
    refused, so a planted pipe cannot hang a login.

    ``kind`` names the credential in messages ("X.509 proxy", "bearer token
    file", "SSS keytab"). ``predictable=True`` is for a name anyone could
    guess, in a directory anyone can write (``/tmp/x509up_u<uid>``,
    ``bt_u<uid>``): a symbolic link there is refused (``O_NOFOLLOW``), where
    at a name the user chose it is followed and the file at its end checked.
    ``limit`` bounds what is read; a larger file raises
    :class:`~xrdcore.errors.CredentialError` rather than filling memory.

    Raises :class:`FileNotFoundError` (and the other :class:`OSError`\\ s) as
    :func:`open` would, so a caller can still tell "there is nothing there"
    from "there is something there I will not use" - the latter is
    :class:`~xrdcore.errors.InsecureCredentialError` (a
    :class:`PermissionError` and a :class:`~xrdcore.errors.CredentialError`),
    whose message names the file and the fix.
    """
    name = os.fspath(path)
    fd = _open(name, kind, predictable)
    try:
        # Checked before a file object is made of it: ``open`` itself
        # refuses a directory, with a less useful message than this one.
        _check(name, os.fstat(fd), kind)
        with open(fd, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise CredentialError(f"the {kind} {name} is larger than {limit} bytes")
    return data


def _open(path: str, kind: str, predictable: bool) -> int:
    """A read-only descriptor for ``path``, refusing a link at a predictable name.

    ``O_NOCTTY`` so a planted terminal device cannot become our controlling
    terminal, ``O_NONBLOCK`` so a FIFO opens at once (to be refused by
    :func:`_check`), ``O_CLOEXEC`` so no child process inherits a secret.
    """
    flags = os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC
    if predictable:
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path, flags)
    except OSError as exc:
        # ELOOP is what Linux and macOS say for O_NOFOLLOW on a link; the
        # BSDs say EMLINK. Either way: a link where a link should not be.
        if predictable and exc.errno in (errno.ELOOP, errno.EMLINK):
            raise _link_refused(path, kind) from None
        raise


def _link_refused(path: str, kind: str) -> InsecureCredentialError:
    """The refusal for a symbolic link at a predictable credential location."""
    return InsecureCredentialError(
        f"the {kind} {path} is a symbolic link, which is not followed at a "
        "predictable location like this one; remove it and put the file "
        "itself there, or name the real file explicitly",
        path,
    )


def _check(path: str, info: os.stat_result, kind: str) -> None:
    """Refuse ``info`` unless it is a regular file, ours, and nobody else's to touch."""
    if not stat.S_ISREG(info.st_mode):
        raise InsecureCredentialError(f"the {kind} {path} is not a regular file", path)
    me = os.geteuid()
    if info.st_uid != me:
        raise InsecureCredentialError(
            f"the {kind} {path} belongs to uid {info.st_uid}, not to you (uid {me}), "
            "so it is not used; create your own copy, or chown it if it really is yours",
            path,
        )
    mode = stat.S_IMODE(info.st_mode)
    if mode & _SHARED:
        what = "writable" if mode & _WRITABLE else "readable"
        raise InsecureCredentialError(
            f"the {kind} {path} is {what} by group or others (mode {mode:04o}); "
            f"run: chmod 600 {path}",
            path,
        )


# ---------------------------------------------------------------------------
# Writing a credential file
# ---------------------------------------------------------------------------


def write_private_file(
    path: str | os.PathLike[str], data: bytes, *, kind: str, predictable: bool = False
) -> str:
    """Write ``data`` to ``path`` atomically, readable and writable by its owner only.

    The writer's half of :func:`read_private_file`'s rules, as
    ``voms-proxy-init`` keeps them:

    * the bytes go to a new file made with :func:`tempfile.mkstemp` beside
      ``path`` - ``O_CREAT|O_EXCL|O_NOFOLLOW``, mode ``0600``, an
      unpredictable name - so no other user can have planted it, and it is
      never readable by anyone else, not even for an instant;
    * it is flushed to disk and then renamed over ``path``. A rename
      replaces whatever name was there without following it, so a reader
      sees the old credential or the new one, never half of one, and a
      symbolic link planted at ``path`` is replaced rather than written
      through. In a sticky directory like ``/tmp`` another user's file (or
      link) at ``path`` cannot be replaced at all; that is reported as
      :class:`~xrdcore.errors.InsecureCredentialError`, naming the file.

    ``predictable=True`` is for a name anyone could guess
    (``/tmp/x509up_u<uid>``), as for :func:`read_private_file`: a symbolic
    link there is refused outright. Otherwise - a path the user named - a
    link is followed and its target replaced, so a credential kept elsewhere
    and linked into place stays where it is kept. ``kind`` names the
    credential in messages. Returns the path actually written.
    """
    name = os.fspath(path)
    if predictable and os.path.islink(name):
        raise InsecureCredentialError(
            f"the {kind} {name} is a symbolic link, which is not written through at a "
            "predictable location like this one; remove it, or name the real file explicitly",
            name,
        )
    target = os.path.abspath(name) if predictable else os.path.realpath(name)
    descriptor, temporary = tempfile.mkstemp(prefix=".xrd-credential.", dir=os.path.dirname(target))
    try:
        with open(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        if isinstance(exc, PermissionError):
            _refuse_foreign(target, kind, exc)
        raise
    return target


def _refuse_foreign(path: str, kind: str, exc: PermissionError) -> None:
    """Turn "cannot replace another user's file" into a refusal that names it.

    A sticky directory forbids renaming over somebody else's entry, which
    is exactly the planted-file case; any other permission problem (an
    unwritable directory) is left as the :class:`PermissionError` it is.
    """
    try:
        owner = os.lstat(path).st_uid
    except OSError:
        return
    if owner != os.geteuid():
        raise InsecureCredentialError(
            f"the {kind} {path} belongs to uid {owner}, not to you (uid {os.geteuid()}), "
            "and cannot be replaced; remove it or write the credential somewhere else",
            path,
        ) from exc
