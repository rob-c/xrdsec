"""TLS client contexts with the grid's trust, revocation and credential rules.

For a client's own ``davs://``/``roots://`` connections, and for any tool
that opens HTTPS connections of its own - an ARC CE client, an FTS or Rucio
REST call, a storage element's tape API, a VOMS server - and wants exactly
the same TLS:

* the grid CA directory (:func:`xrdsec.credentials.grid_ca_path`) with the
  operating system's store optionally alongside it, or the system store
  alone when there is no grid directory;
* CRL checking against the CA directory's ``<hash>.r0`` files, leaf or chain;
* a proxy, or a certificate and a separate - possibly encrypted - key, the
  key read through the private-file checks and never written anywhere, or a
  credential that exists only in memory;
* one shared context per setup, rebuilt when a proxy is renewed, a CRL is
  fetched or the trust store changes, and reused otherwise.

Typical use, with the credentials found the way every grid tool finds them::

    from xrdsec import credentials, tls

    proxy = credentials.find_proxy()
    context = tls.client_context(cert=proxy, ca_path=credentials.grid_ca_path())

The context presents nothing unless ``cert`` (or ``present_default=True``)
asks it to: a client that authenticates with a bearer token, or not at all,
must not hand a server the proxy it happens to find in ``/tmp``. A client
that presents the default proxy unasked, as gfal2 and XrdCl do, says so with
``present_default=True``; its configuration-shaped wrapper (xrdclient's
``tls_context``) is built on :func:`client_context`, so every caller shares
one builder and one cache.

What must not break: a cached context is shared between threads and
connections, so nothing may mutate one after it is returned. Importing this
module imports :mod:`ssl`, so cheap entry points (a CLI's ``--help``) should
import it only when a connection is about to be made.
"""

from __future__ import annotations

import hashlib
import os
import ssl
import threading
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from xrdcore.log import get_logger

from . import credentials, usercred

_log = get_logger(__name__)

__all__ = [
    "CRL_ENV",
    "SYSTEM_CA_ENV",
    "KeyPassword",
    "clear_cache",
    "client_context",
    "crl_mode",
]


def crl_mode(value: str) -> str:
    """A CRL setting as a client's configuration holds it: ``""``, ``"leaf"`` or ``"chain"``.

    The vocabulary ``$XRD_CHECKCRL`` has always had: unset or a "no" is off,
    ``chain`` is the whole chain, and anything else - ``1``, ``yes``,
    ``leaf`` - the server's own certificate.
    """
    word = value.strip().lower()
    if word in ("", "0", "no", "off", "false"):
        return ""
    return "chain" if word == "chain" else "leaf"


#: ``1`` adds the operating system's trust store to a grid CA directory for
#: every scheme; ``0`` never does. Unset leaves it to the caller. Read by a
#: client's configuration (xrdclient's ``Config.tls_system_ca``), never here:
#: :func:`client_context` does what its ``system_ca`` argument says.
SYSTEM_CA_ENV = "XRD_TLSSYSTEMCA"

#: ``1`` (or ``leaf``) checks the server certificate against the CRLs in the
#: CA directory; ``chain`` checks every certificate in its chain. Off unless
#: set. Read by a client's configuration (xrdclient's ``Config.check_crl``);
#: :func:`crl_mode` is the vocabulary, and ``check_crl=`` takes any word of it.
CRL_ENV = "XRD_CHECKCRL"

#: How many distinct TLS setups are remembered. A process uses one or two -
#: grid trust, grid plus system trust - and a renewed proxy replaces its
#: predecessor's entry soon enough; the bound only stops a long-lived process
#: that cycles through many proxies from keeping every one of them.
_CACHE_SIZE = 8

#: ``key -> context``, least recently used first. See :func:`client_context`.
_cache: OrderedDict[tuple[object, ...], ssl.SSLContext] = OrderedDict()
_cache_lock = threading.Lock()

#: What :func:`client_context` accepts as a pass phrase: the text, its
#: bytes, or something to call for it only when the key is encrypted.
KeyPassword = str | bytes | Callable[[], str | bytes]


@dataclass(frozen=True, slots=True)
class _Recipe:
    """Everything a context is built from, other than the files' contents.

    ``key`` is ``None`` when ``cert`` is a proxy - chain and key in one file,
    loaded by name as XrdCl and davix load one - and the path of a separate
    key otherwise, which is read through the private-file checks and piped
    to OpenSSL (:func:`xrdsec.usercred.load_pair`). ``present_default``
    only matters with no ``cert``. Hashable, because with the files'
    ``stat`` it is the cache key.
    """

    cert: str | None
    key: str | None
    ca_file: str | None
    ca_path: str | None
    verify: bool
    system: bool
    crl: ssl.VerifyFlags
    present_default: bool
    #: SHA-256 of an in-memory credential's PEM (``credential_pem``), so equal
    #: credentials share a context without the key itself being the cache key.
    memory: str | None = None
    #: Whether Python's RFC 5280 strict checks stay on (see ``x509_strict``).
    strict: bool = True
    #: Whether ``ssl`` checks the server's name (see ``check_hostname``).
    hostname: bool = True
    #: The ALPN protocols offered, in preference order; ``()`` offers none.
    alpn: tuple[str, ...] = ()


def client_context(
    *,
    cert: str | os.PathLike[str] | None = None,
    key: str | os.PathLike[str] | None = None,
    ca_path: str | os.PathLike[str] | None = None,
    ca_file: str | os.PathLike[str] | None = None,
    verify: bool = True,
    system_ca: bool = False,
    check_crl: str | bool | None = None,
    key_password: KeyPassword | None = None,
    present_default: bool = False,
    credential_pem: bytes | None = None,
    x509_strict: bool = True,
    check_hostname: bool = True,
    alpn: Sequence[str] = (),
) -> ssl.SSLContext:
    """A client TLS context for a grid endpoint, shared and rebuilt as its files change.

    The one context builder on the stack: every ``roots://``, ``https://``,
    ``davs://`` and S3 connection a client makes, and every tool that makes
    its own HTTPS connections - an ARC or FTS client, a REST call to a
    storage element, a VOMS server - gets the same trust, revocation and
    caching rules from it.

    **Who this client is.** Nothing, unless asked: a token-only or anonymous
    client must not present a certificate it was never told about.
    ``cert`` alone is a proxy (chain and key in one PEM file). ``cert`` and
    ``key`` are a certificate and its separate key; the key is read through
    :func:`xrdsec.credentials.read_private_file` - ours, ``0600``, else
    :class:`~xrdcore.errors.InsecureCredentialError` - and handed to
    OpenSSL through a pipe, so no copy of it is ever written. Naming the
    proxy as its own ``key`` gets the proxy those checks too. An encrypted
    key is unlocked with ``key_password`` (text, bytes, or a callable asked
    only when needed); without one it is a
    :class:`~xrdcore.errors.CredentialError`. ``present_default=True``,
    with no ``cert``, offers ``$X509_USER_PROXY`` or ``/tmp/x509up_u<uid>``
    when one is there, as gfal2 and XrdCl do - a guess, so one that will
    not load is passed over with a warning. ``credential_pem`` instead of
    ``cert`` presents a credential that exists only in memory - chain and
    unencrypted key in one PEM, ``ProxyCredential.to_pem()`` - piped to
    OpenSSL (:func:`xrdsec.usercred.load_memory`) and never written.

    **Trust.** ``ca_file`` and the hashed directory ``ca_path`` (a grid's
    ``/etc/grid-security/certificates``: see
    :func:`xrdsec.credentials.grid_ca_path`); with neither, the operating
    system's store. ``system_ca=True`` adds the system store to a grid
    directory, for an endpoint outside the grid's PKI. A blank path counts
    as none - ``""`` as a ``capath`` would trust nothing. ``verify=False``
    turns server verification off entirely; nothing does that implicitly.

    **Revocation.** ``check_crl`` - ``True``/``"leaf"`` for the server's
    certificate, ``"chain"`` for every certificate on its path, anything
    ``$XRD_CHECKCRL`` accepts (see :data:`CRL_ENV`, :func:`crl_mode`) -
    checks the ``<hash>.r0`` CRLs in ``ca_path``. Off by default and without
    a ``ca_path`` or verification, because a CA whose CRL is missing then
    fails every handshake. There is deliberately no "check a CRL only when
    there is one" mode, which ARC gets from an OpenSSL verify callback that
    forgives ``X509_V_ERR_UNABLE_TO_GET_CRL``: :mod:`ssl` exposes no such
    callback, and the context exists before the server's chain is known, so
    any rule over the directory's contents would either still fail closed
    for a CA without a CRL or check less than ARC does.

    **Strictness.** ``x509_strict=False`` turns off the RFC 5280 strict
    checks (``VERIFY_X509_STRICT``) Python 3.13 enables by default, which
    some grid CAs predate - gfal2 (davix) and ARC never apply them. It is
    part of the cache key, like every other argument.

    **Names and protocols.** ``check_hostname=False`` leaves the server's
    certificate verified against the trust anchors but its name unchecked
    by ``ssl``: for GSI (GridFTP, SRM, LFC's Csec, dCache's dcap tunnels),
    whose own ``host/<fqdn>`` check is made against the certificate's DN
    after the handshake, as Globus does - never as a way of skipping the
    check. ``alpn`` offers those protocols in that order (RFC 7301). Both
    are part of the cache key, so a GSI context is never handed to a caller
    that relies on the hostname check.

    **Sharing and reload.** Building a context reads a trust store and a
    chain, which cost more than the handshake, so one context is built per
    distinct setup and shared between threads and connections. The cache
    key is every argument except ``key_password`` plus each file's and the
    CA directory's ``stat``: a renewed proxy, a ``fetch-crl`` run or a
    changed ``SSL_CERT_FILE`` gets a fresh context on the next call while
    the previous one serves the connections made with it. A shared context
    must not be modified - wrap sockets with it, nothing else - and
    :func:`clear_cache` forgets them all.
    """
    _check_identity(cert, key, credential_pem)
    path, cafile = _given(ca_path), _given(ca_file)
    recipe = _Recipe(
        cert=_given(cert),
        key=_given(key),
        ca_file=cafile,
        ca_path=path,
        verify=verify,
        # create_default_context falls back to the system store by itself
        # when it has no CAs; asking for it "as well" only means something
        # alongside a CA file or directory.
        system=system_ca and bool(cafile or path),
        crl=_crl_flags(check_crl) if verify and path else ssl.VerifyFlags(0),
        present_default=present_default and credential_pem is None,
        memory=_digest(credential_pem),
        strict=x509_strict,
        hostname=check_hostname,
        alpn=tuple(alpn),
    )
    password = usercred.password_supplier(key_password, recipe.key or "")
    return _cached(recipe, password, credential_pem)


def _check_identity(
    cert: str | os.PathLike[str] | None,
    key: str | os.PathLike[str] | None,
    credential_pem: bytes | None,
) -> None:
    """Refuse a client identity :func:`client_context` cannot present unambiguously."""
    if key is not None and cert is None:
        raise ValueError("a private key was given without the certificate it belongs to")
    if credential_pem is not None and cert is not None:
        raise ValueError("present either a credential file (cert=) or one in memory, not both")


def _digest(pem: bytes | None) -> str | None:
    """What an in-memory credential is cached under: its SHA-256, never the key itself."""
    return None if pem is None else hashlib.sha256(pem).hexdigest()


def clear_cache() -> None:
    """Forget every context :func:`client_context` has built.

    Never needed for correctness - a changed file or setting is a new key -
    but it lets a test, or an application that rotated its trust store
    in place without touching the directory, start from nothing.
    """
    with _cache_lock:
        _cache.clear()


def _given(path: str | os.PathLike[str] | None) -> str | None:
    """``path`` as a string, or ``None`` for none at all or a blank one."""
    if path is None:
        return None
    text = os.fspath(path)
    return text if text.strip() else None


def _cached(
    recipe: _Recipe, password: Callable[[], bytes] | None, pem: bytes | None = None
) -> ssl.SSLContext:
    """The context for ``recipe``: the cached one if its files are unchanged, else a new one.

    Built outside the lock - a build reads files and may ask a person for
    a pass phrase - so two threads may race to build the same context; the
    second simply replaces the first in the cache, and both are valid.
    A build that raises leaves nothing behind.
    """
    key = _cache_key(recipe)
    with _cache_lock:
        cached = _cache.get(key)
        if cached is not None:
            _cache.move_to_end(key)
            return cached
    ctx = _build(recipe, password, pem)
    with _cache_lock:
        _cache[key] = ctx
        while len(_cache) > _CACHE_SIZE:
            _cache.popitem(last=False)
    return ctx


def _build(
    recipe: _Recipe, password: Callable[[], bytes] | None, pem: bytes | None = None
) -> ssl.SSLContext:
    """The context :func:`client_context` describes, built from scratch."""
    ctx = ssl.create_default_context(cafile=recipe.ca_file, capath=recipe.ca_path)
    if recipe.system:
        # create_default_context only falls back to the system store when it
        # was given no CAs of its own; here it is wanted alongside them.
        ctx.load_default_certs()
    ctx.verify_flags |= recipe.crl
    if not recipe.strict:
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    # Before ``verify_mode``: ``ssl`` refuses CERT_NONE while names are checked.
    ctx.check_hostname = recipe.hostname
    if recipe.alpn:
        ctx.set_alpn_protocols(list(recipe.alpn))
    if not recipe.verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if pem is not None:
        usercred.load_memory(ctx, pem)
        return ctx
    if recipe.cert is None:
        if recipe.present_default:
            _present_default_proxy(ctx)
        return ctx
    if recipe.key is not None:
        usercred.load_pair(ctx, recipe.cert, recipe.key, password)
        return ctx
    # An RFC 3820 proxy is a cert chain plus its key in one PEM file.
    try:
        ctx.load_cert_chain(recipe.cert)
    except OSError as exc:
        # ssl's own message names neither the file nor the setting that
        # chose it, and a stale X509_USER_PROXY is how most people get here.
        raise _unusable_proxy(exc, recipe.cert) from exc
    return ctx


def _crl_flags(setting: str | bool | None) -> ssl.VerifyFlags:
    """The verification flags a CRL setting asks for (see :func:`client_context`)."""
    if setting is None or isinstance(setting, bool):
        mode = "leaf" if setting else ""
    else:
        mode = crl_mode(setting)
    if not mode:
        return ssl.VerifyFlags(0)
    return ssl.VERIFY_CRL_CHECK_CHAIN if mode == "chain" else ssl.VERIFY_CRL_CHECK_LEAF


def _stat(path: str | None) -> tuple[int, int, int] | None:
    """What identifies one version of a file or directory, or ``None``."""
    if not path:
        return None
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (info.st_ino, info.st_size, info.st_mtime_ns)


def _cache_key(recipe: _Recipe) -> tuple[object, ...]:
    """Everything :func:`_build` reads, so equal keys build equal contexts.

    The default proxy is only consulted when it is to be presented and no
    certificate was named, so its path is only part of the key then - read
    from :func:`~xrdsec.credentials.default_proxy_path` per call, as the build
    reads it.
    ``SSL_CERT_FILE``/``SSL_CERT_DIR`` steer the system store that
    ``create_default_context`` and ``load_default_certs`` read.
    """
    default = (
        credentials.default_proxy_path() if recipe.present_default and not recipe.cert else None
    )
    return (
        recipe,
        _stat(recipe.cert),
        _stat(recipe.key),
        _stat(recipe.ca_file),
        _stat(recipe.ca_path),
        default,
        _stat(default),
        os.environ.get("SSL_CERT_FILE"),
        os.environ.get("SSL_CERT_DIR"),
    )


def _unusable_proxy(exc: OSError, path: str) -> OSError:
    """``exc`` again, saying which file - as one message, not an ``args`` tuple."""
    # ``(errno, message)``, because an ``SSLError`` given one argument prints
    # it as a tuple: ``('cannot use the X.509 proxy ...',)``.
    reason = exc.strerror or str(exc)
    return type(exc)(exc.errno or 0, f"cannot use the X.509 proxy {path}: {reason}")


def _present_default_proxy(ctx: ssl.SSLContext) -> None:
    """Offer ``$X509_USER_PROXY`` or ``/tmp/x509up_u<uid>``, as gfal2 and XrdCl do.

    ``roots://`` GSI has always found it there; without this, ``https://`` to a
    grid storage element went out with no certificate and every request that
    needed one came back ``403``. A discovered file is a guess, so one that
    will not load is passed over with a warning rather than failing a request
    that may not need a certificate at all. A proxy somebody *named* - a
    client's proxy setting, ``client_context(cert=)`` - is never replaced by
    this one. The path is looked up per call
    (:func:`xrdsec.credentials.default_proxy_path`), which is what lets a
    test suite keep a developer's real proxy out.
    """
    path = credentials.default_proxy_path()
    if not os.path.isfile(path):
        return
    try:
        ctx.load_cert_chain(path)
    except OSError as exc:
        _log.warning("not presenting the X.509 proxy %s: %s", path, exc)
