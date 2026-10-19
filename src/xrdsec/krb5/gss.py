"""Kerberos 5 through the platform's GSS-API library: contexts driven by tokens.

Protocols that speak Kerberos as GSS-API (dCache's ``kdcap``, LFC's Csec,
ssh's ``gssapi-with-mic``) all do the same thing: ferry opaque tokens
between ``gss_init_sec_context`` and the server until the context is
established, then ``gss_wrap``/``gss_unwrap`` their messages or sign them.
That is the whole API here::

    ctx = gss.ClientContext("host", "door.example.org")
    token = ctx.step()
    while True:
        if token:
            send(token)
        if ctx.complete:
            break
        token = ctx.step(receive())
    line = ctx.unwrap(receive())

The tokens come from the platform's library through python-gssapi (the
``xrdsec[krb5]`` extra), which is the only thing that can use every cache
type the machine is configured for (KCM via sssd on EL9, ``FILE:``,
``KEYRING:``, macOS's ``API:`` and ``MEMORY:``) with the site's own rules
(DNS KDC discovery, cross-realm referrals, every enctype it allows). The
pure-Python client in :mod:`.client` reads ``FILE:``, ``DIR:``, ``KCM:`` and
``KEYRING:`` caches without any of that installed; a client chooses
between the two.

XRootD's ``krb5`` plugin is the odd one out: it wants a *raw* AP-REQ, not
a GSS token. :func:`initiator_ap_req` asks the library for a one-token
context and removes the RFC 2743 envelope (:func:`unwrap_ap_req`), so a
platform-only cache can still log in to it.

Credentials are the library's defaults - ``KRB5CCNAME`` or the configured
default cache for an initiator, ``KRB5_KTNAME`` or ``/etc/krb5.keytab``
for an acceptor - and ``ccache=``/``keytab=`` pick others per context.
Every failure is a :class:`KerberosError` (an
:class:`~xrdcore.errors.AuthenticationError`) whose ``code`` is an
``errno``: ``EACCES`` for a refused or impossible authentication,
``ETIMEDOUT`` when no KDC answered, ``EPROTO`` for a corrupt or replayed
token, ``EPROTONOSUPPORT`` when python-gssapi is not installed.

A context may be used from several threads: each call holds the context's
own lock, and the binding is shared (GSS libraries are thread-safe across
distinct contexts). Importing this module does not import ``gssapi``; the
first context (or :func:`available`) does, so a program that never uses
Kerberos never loads the native library.
"""

from __future__ import annotations

import errno
import threading
from types import TracebackType
from typing import Self, TypedDict, Unpack

from ..der import oid_string, parse
from ._gssapi import HOSTBASED, PRINCIPAL, GssapiBackend, GssapiMechanism, Target
from ._status import KerberosError

__all__ = [
    "CONF_FLAG",
    "DELEG_FLAG",
    "HOSTBASED",
    "INSTALL_HINT",
    "INTEG_FLAG",
    "KRB5_MECHANISM",
    "MUTUAL_FLAG",
    "PRINCIPAL",
    "REPLAY_FLAG",
    "SEQUENCE_FLAG",
    "AcceptorContext",
    "ClientContext",
    "Context",
    "GssapiBackend",
    "InitiatorOptions",
    "KerberosError",
    "Target",
    "available",
    "backend",
    "initiator_ap_req",
    "load_backend",
    "reset",
    "unwrap_ap_req",
]

#: Appended to "not available" errors: how to get the binding.
INSTALL_HINT = (
    "install python-gssapi (python -m pip install 'xrdsec[krb5]'); Linux source "
    "installs also need Kerberos development headers and a C compiler"
)

#: The Kerberos 5 GSS-API mechanism (RFC 1964), as an initiator token names it.
KRB5_MECHANISM = "1.2.840.113554.1.2.2"

# ``gss_init_sec_context`` request flags (RFC 2744).
DELEG_FLAG = 1
MUTUAL_FLAG = 2
REPLAY_FLAG = 4
SEQUENCE_FLAG = 8
CONF_FLAG = 16
INTEG_FLAG = 32

#: The names :func:`load_backend` accepts; both mean python-gssapi today.
_NAMES = ("auto", "gssapi")

#: Loaded backends by the name they were asked for (``auto`` included).
_BACKENDS: dict[str, GssapiBackend] = {}
#: Guards ``_BACKENDS`` so two first contexts import the binding once.
_LOCK = threading.Lock()


def _load_gssapi() -> GssapiBackend:
    """Import python-gssapi and wrap it; ``ImportError``/``OSError`` if unusable.

    ``OSError`` too because the binding's import loads the system GSS
    library, which can be missing even when the wheel is installed.
    """
    import gssapi

    return GssapiBackend(gssapi)


def _select(choice: str, hint: str) -> GssapiBackend:
    """The backend for a name, or a ``KerberosError`` saying why there is none."""
    if choice not in _NAMES:
        raise KerberosError(f"unknown Kerberos backend {choice!r} (expected gssapi)", errno.EINVAL)
    try:
        return _load_gssapi()
    except (ImportError, OSError) as exc:
        raise KerberosError(
            f"Kerberos 5 (GSS-API) is not available: {exc}; {hint}", errno.EPROTONOSUPPORT
        ) from exc


def load_backend(name: str | None = None, *, hint: str = INSTALL_HINT) -> GssapiBackend:
    """The binding to use: ``name`` (``auto`` or ``gssapi``), python-gssapi either way.

    The result is cached per name; a failure is not, so the next call
    searches again, and :func:`reset` forgets successes too (for tests, and
    for programs that install a library while running). ``hint`` ends the
    "not available" message: a client names its own extra there.
    """
    choice = name or "auto"
    with _LOCK:
        found = _BACKENDS.get(choice)
        if found is None:
            found = _BACKENDS[choice] = _select(choice, hint)
        return found


def reset() -> None:
    """Forget the backends found so far.

    Existing contexts keep the backend they were made with; only the next
    :func:`load_backend` searches again.
    """
    with _LOCK:
        _BACKENDS.clear()


def available(name: str | None = None, *, hint: str = INSTALL_HINT) -> str | None:
    """``None`` if Kerberos through GSS-API can be used, else a sentence saying why not.

    A protocol asks this before offering Kerberos to a server, so an
    unconfigured host falls through to the next mechanism instead of
    failing mid-handshake.
    """
    try:
        load_backend(name, hint=hint)
    except KerberosError as exc:
        return exc.message
    return None


def backend(name: str | None = None) -> str | None:
    """``gssapi``; ``None`` if the binding is unavailable."""
    try:
        return load_backend(name).name
    except KerberosError:
        return None


class Context:
    """What the two sides share: locking, message protection, names.

    The mechanism is owned by the context: :meth:`close` (also called by
    ``with`` and on collection) releases it, after which every call fails
    with ``EBADF``. Message protection before establishment is ``EPROTO``,
    so a protocol bug cannot leak data through a half-made context.
    """

    def __init__(self, mechanism: GssapiMechanism, backend_name: str) -> None:
        """Take ownership of ``mechanism``; ``backend_name`` is reported as :attr:`backend`."""
        self._mech: GssapiMechanism | None = mechanism
        self._lock = threading.Lock()
        self._names: tuple[str, str, int] | None = None
        self.backend = backend_name
        self.complete = False

    def __enter__(self) -> Self:
        """The context itself; leaving the ``with`` block closes it."""
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the context, whatever ended the block; exceptions propagate."""
        self.close()

    def __del__(self) -> None:
        """Release the library context if the owner never closed it."""
        self.close()

    def _established(self) -> GssapiMechanism:
        """The mechanism, provided the context is open and established; else ``KerberosError``."""
        if self._mech is None:
            raise KerberosError("the Kerberos context has been closed", errno.EBADF)
        if not self.complete:
            raise KerberosError("the Kerberos context is not yet established", errno.EPROTO)
        return self._mech

    def _step(self, token: bytes) -> bytes:
        """One establishment round; on completion record the names and run :meth:`_check`.

        ``complete`` is set only after ``_check`` passes, so a context that
        fails a side's demands (no mutual authentication) never reads as
        established, even though the library considers it so.
        """
        with self._lock:
            if self._mech is None:
                raise KerberosError("the Kerberos context has been closed", errno.EBADF)
            if self.complete:
                raise KerberosError("the Kerberos context is already established", errno.EPROTO)
            out = self._mech.step(token)
            if self._mech.complete:
                self._names = self._mech.inquire()
                self._check()
                self.complete = True
            return out

    def _check(self) -> None:
        """A side's own demands of the negotiated context; none by default."""

    def wrap(self, data: bytes, confidential: bool = True) -> bytes:
        """``gss_wrap``: a token carrying ``data``, encrypted unless told otherwise.

        GSS-API may silently downgrade to integrity-only protection when
        confidentiality was not negotiated; that is refused (``EPROTO``)
        rather than sending plaintext the caller asked to encrypt.
        """
        with self._lock:
            token, encrypted = self._established().wrap(data, confidential)
        if confidential and not encrypted:
            raise KerberosError("gss_wrap could not provide confidentiality", errno.EPROTO)
        return token

    def unwrap(self, token: bytes, *, require_confidential: bool = False) -> bytes:
        """``gss_unwrap``: the data ``token`` carries, integrity checked.

        ``require_confidential`` refuses a token that was only signed, for
        protocols where every message must be encrypted: otherwise a peer
        (or a man in the middle that cannot forge MICs but can choose not to
        encrypt) could make us accept plaintext.
        """
        with self._lock:
            data, encrypted = self._established().unwrap(token)
        if require_confidential and not encrypted:
            raise KerberosError("the peer sent an unencrypted token", errno.EPROTO)
        return data

    def get_mic(self, data: bytes) -> bytes:
        """``gss_get_mic``: a signature over ``data``."""
        with self._lock:
            return self._established().get_mic(data)

    def verify_mic(self, data: bytes, mic: bytes) -> None:
        """``gss_verify_mic``: raise ``EPROTO`` unless ``mic`` signs ``data``."""
        with self._lock:
            self._established().verify_mic(data, mic)

    @property
    def initiator_name(self) -> str | None:
        """The client principal (``user@REALM``), once established."""
        return None if self._names is None else self._names[0]

    @property
    def target_name(self) -> str | None:
        """The service principal (``host/door@REALM``), once established."""
        return None if self._names is None else self._names[1]

    @property
    def flags(self) -> int:
        """The negotiated ``*_FLAG`` bits; ``0`` until established."""
        return 0 if self._names is None else self._names[2]

    def close(self) -> None:
        """Delete the context and release what it holds. Idempotent."""
        lock = getattr(self, "_lock", None)
        if lock is None:  # __init__ failed before there was anything to close
            return
        with lock:
            mechanism, self._mech = self._mech, None
            if mechanism is not None:
                mechanism.close()


class InitiatorOptions(TypedDict, total=False):
    """:class:`ClientContext`'s keyword options, for a client that wraps it.

    The RFC 2744 request flags one by one, the target as a whole principal,
    and a credential cache other than the default; see
    :class:`ClientContext` for what each means.
    """

    principal: str | None
    mutual: bool
    delegate: bool
    replay: bool
    sequence: bool
    integrity: bool
    confidentiality: bool
    ccache: str | None


class ClientContext(Context):
    """The initiator: authenticates to ``service@host`` with the user's ticket.

    ``principal`` names the target as a full Kerberos principal instead
    (``xrootd/host@REALM``). ``mutual`` (the default) makes the server prove
    itself, and an established context without it is refused. ``delegate``
    forwards the TGT. ``ccache`` picks a credential cache other than the
    default (``KRB5CCNAME`` already does that for the whole process).
    ``replay``, ``sequence``, ``integrity`` and ``confidentiality`` are the
    remaining RFC 2744 request flags, all on by default as ``kinit``-style
    clients expect. ``backend`` names the binding (:func:`load_backend`).
    """

    def __init__(
        self,
        service: str,
        host: str,
        *,
        backend: str | None = None,
        **options: Unpack[InitiatorOptions],
    ) -> None:
        """Import the target name and prepare the context; no token is made yet.

        A missing ticket is a ``KerberosError`` with a ``kinit`` hint, raised
        here or by the first :meth:`step`, depending on when the library
        looks.
        """
        principal = options.get("principal")
        if principal:
            target = Target(principal, PRINCIPAL)
        else:
            target = Target(f"{service}@{host}" if host else service, HOSTBASED)
        flags = _request_flags(options)
        found = load_backend(backend)
        super().__init__(found.initiator(target, flags, options.get("ccache")), found.name)
        self.target = target
        self.requested = flags

    def step(self, token: bytes = b"") -> bytes:
        """Consume the server's ``token`` (empty to start); return what to send."""
        return self._step(token)

    def _check(self) -> None:
        """Refuse an established context without the mutual authentication we asked for.

        Without this, a server that skipped AP-REP would be trusted on the
        strength of our own ticket alone, which proves nothing about it.
        """
        if self.requested & MUTUAL_FLAG and not self.flags & MUTUAL_FLAG:
            raise KerberosError(
                f"{self.target.name} did not authenticate itself (no mutual authentication)",
                errno.EACCES,
            )


def _request_flags(options: InitiatorOptions) -> int:
    """The ``gss_init_sec_context`` flag word for ``options``; each defaults as documented."""
    return (
        (DELEG_FLAG if options.get("delegate", False) else 0)
        | (MUTUAL_FLAG if options.get("mutual", True) else 0)
        | (REPLAY_FLAG if options.get("replay", True) else 0)
        | (SEQUENCE_FLAG if options.get("sequence", True) else 0)
        | (CONF_FLAG if options.get("confidentiality", True) else 0)
        | (INTEG_FLAG if options.get("integrity", True) else 0)
    )


class AcceptorContext(Context):
    """The acceptor: verifies a client's AP-REQ with a key from a keytab.

    With no ``service`` any key in the keytab will do, which is how a test
    server with a one-principal keytab wants it; ``keytab`` overrides
    ``KRB5_KTNAME``. On Heimdal without ``gss_acquire_cred_from`` that
    override is process-wide.
    """

    def __init__(
        self,
        service: str | None = None,
        host: str | None = None,
        *,
        principal: str | None = None,
        keytab: str | None = None,
        backend: str | None = None,
    ) -> None:
        """Acquire acceptor credentials (``principal``, else ``service@host``, else any key)."""
        name: Target | None = None
        if principal:
            name = Target(principal, PRINCIPAL)
        elif service:
            name = Target(f"{service}@{host}" if host else service, HOSTBASED)
        found = load_backend(backend)
        super().__init__(found.acceptor(name, keytab), found.name)

    def step(self, token: bytes) -> bytes:
        """Consume the client's ``token``; return the reply (AP-REP) to send, if any."""
        if not token:
            raise KerberosError("an acceptor needs the client's token", errno.EINVAL)
        return self._step(token)


def initiator_ap_req(principal: str, *, backend: str | None = None) -> bytes:
    """The raw AP-REQ the system library builds for ``principal``, from its default cache.

    No request flags, so the library makes a single token and needs no
    reply - what XRootD's ``krb5`` plugin (``krb5_rd_req`` on a raw AP-REQ)
    expects - and the GSS envelope is removed (:func:`unwrap_ap_req`). The
    library may fetch a service ticket from the KDC, and may store it in the
    user's cache, as every Kerberos program does.
    """
    with ClientContext(
        "",
        "",
        principal=principal,
        mutual=False,
        replay=False,
        sequence=False,
        integrity=False,
        confidentiality=False,
        backend=backend,
    ) as context:
        return unwrap_ap_req(context.step())


def unwrap_ap_req(token: bytes) -> bytes:
    """The AP-REQ inside an initiator token: the RFC 2743 header and RFC 4121 TOK_ID removed.

    The envelope is ``[APPLICATION 0]`` holding the Kerberos mechanism OID,
    then the two-byte token id ``01 00`` (KRB_AP_REQ), then the AP-REQ
    (``[APPLICATION 14]``) itself, filling the rest exactly. Anything else
    is ``EPROTO``: a library that answered with some other mechanism, or a
    malformed token, must not be sent on as if it were a ticket.
    """
    try:
        wrapper, end = parse(token)
        mechanism, pos = parse(wrapper.value)
        payload = wrapper.value[pos:]
        request, request_end = parse(payload[2:])
        valid = (
            wrapper.tag == 0x60
            and end == len(token)
            and oid_string(mechanism) == KRB5_MECHANISM
            and payload[:2] == b"\x01\x00"
            and request.tag == 0x6E
            and request_end == len(payload) - 2
        )
    except ValueError:
        valid = False
    if not valid:
        raise KerberosError(
            "the system Kerberos library returned a malformed AP-REQ token", errno.EPROTO
        )
    return payload[2:]
