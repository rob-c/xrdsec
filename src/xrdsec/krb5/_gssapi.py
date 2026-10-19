"""GSS-API through the optional python-gssapi package (the ``krb5`` extra).

The maintained binding owns native handles and ABI differences (MIT vs
Heimdal, macOS's GSS.framework). Passing its module in keeps error and
handshake tests independent of an installed KDC:
:func:`xrdsec.testing.krb5.fake_gssapi_module` supplies a module with the
same shape. Nothing here imports ``gssapi``; :func:`.gss.load_backend` does,
and hands the module to :class:`GssapiBackend`.

Every binding exception is translated here, through :func:`._status.describe`,
so callers above see only :class:`~._status.KerberosError` with an ``errno``.
:class:`.gss.ClientContext` and :class:`.gss.AcceptorContext` own the
locking and the policy (mutual authentication, confidentiality); a
:class:`GssapiMechanism` is one bare library context.
"""

from __future__ import annotations

import errno
from dataclasses import dataclass
from typing import Any

from ._status import KerberosError, describe

__all__ = ["HOSTBASED", "PRINCIPAL", "GssapiBackend", "GssapiMechanism", "Target"]

#: ``GSS_C_NT_HOSTBASED_SERVICE`` - ``service@host``, the realm from the host.
HOSTBASED = "hostbased"
#: ``GSS_KRB5_NT_PRINCIPAL_NAME`` - a full ``primary/instance@REALM``.
PRINCIPAL = "principal"


@dataclass(frozen=True, slots=True)
class Target:
    """A name to import: the text and which GSS name type it is.

    ``kind`` is :data:`HOSTBASED` (``service@host``; the library
    canonicalises the host and maps it to a realm, per krb5.conf) or
    :data:`PRINCIPAL` (used verbatim, for servers whose principal does not
    follow the host name).
    """

    name: str
    kind: str = HOSTBASED


#: What python-gssapi says when ``gss_display_status`` could not decode a code.
_UNDECODED = "gss_display_status call returned failure"


class GssapiBackend:
    """Contexts built with ``gssapi.SecurityContext``.

    ``errors`` is the exception set every call translates: the library's
    ``GSSError``, the package's own ``GeneralError``, and
    ``NotImplementedError`` for a missing GSS extension.

    Loaded once per process (:func:`.gss.load_backend`) and shared by every
    context, so it holds no per-context state.
    """

    #: The binding's name, reported as a context's ``backend``.
    name = "gssapi"

    def __init__(self, module: Any) -> None:
        """Bind to ``module`` - the imported ``gssapi`` package, or a test fake."""
        self.gssapi = module
        self.errors: tuple[type[BaseException], ...] = (
            module.exceptions.GSSError,
            module.exceptions.GeneralError,
            NotImplementedError,
        )

    def fail(self, what: str, exc: BaseException, *, protection: bool = False) -> KerberosError:
        """``exc`` from the package, as a ``KerberosError``.

        ``what`` names the operation for the message ("preparing Kerberos
        authentication failed: ..."); ``protection`` marks wrap/unwrap/MIC
        calls, whose failures mean a corrupt stream (see
        :func:`._status.errno_for`).
        """
        major = int(getattr(exc, "maj_code", 0) or 0)
        minor = int(getattr(exc, "min_code", 0) or 0)
        if isinstance(exc, NotImplementedError):
            # The library lacks an extension (credential stores, most often).
            return KerberosError(f"{what} failed: {exc}", errno.EOPNOTSUPP)
        if not major:
            # ``GeneralError``: the package's own complaint, not the library's.
            return KerberosError(f"{what} failed: {exc}", errno.EACCES)
        # ``GSSError.get_all_statuses`` is ``gss_display_status``; MIT keeps
        # the detailed minor text per thread, so this runs straight after the
        # failure, and a message saying the lookup itself failed is dropped.
        statuses: Any = getattr(exc, "get_all_statuses", lambda code, is_major: [])
        texts = [str(text) for text in statuses(major, True)]
        details = [str(text) for text in statuses(minor, False) if _UNDECODED not in str(text)]
        return describe(what, major, minor, (texts, details), protection=protection)

    def _name(self, target: Target) -> Any:
        """``gss_import_name`` for ``target`` with the matching name type."""
        kinds = self.gssapi.NameType
        kind = kinds.hostbased_service if target.kind == HOSTBASED else kinds.kerberos_principal
        return self.gssapi.Name(target.name, kind)

    def initiator(self, target: Target, flags: int, ccache: str | None) -> GssapiMechanism:
        """A client context for ``target`` requesting ``flags``, from ``ccache`` or the default.

        Credential problems the library can see now (an unusable explicit
        ``ccache``) are raised here as ``KerberosError``; others surface from
        the first :meth:`GssapiMechanism.step`. A non-default ``ccache``
        needs ``gss_acquire_cred_from`` (the credential-store extension);
        without it the binding raises
        ``NotImplementedError``, reported as ``EOPNOTSUPP``. With the
        default cache no credentials object is made at all, so the library
        resolves ``KRB5CCNAME`` itself at first use.
        """
        g = self.gssapi
        try:
            creds = None
            if ccache:
                creds = g.Credentials(
                    usage="initiate", mechs=[g.MechType.kerberos], store={"ccache": ccache}
                )
            context = g.SecurityContext(
                name=self._name(target),
                mech=g.MechType.kerberos,
                flags=flags,
                usage="initiate",
                creds=creds,
            )
        except self.errors as exc:
            raise self.fail("preparing Kerberos authentication", exc) from exc
        return GssapiMechanism(self, context)

    def acceptor(self, name: Target | None, keytab: str | None) -> GssapiMechanism:
        """A server context accepting as ``name`` (any keytab key if ``None``).

        A ``keytab`` other than the default uses the credential-store
        extension too, as an explicit ``ccache`` does for an initiator.
        """
        g = self.gssapi
        try:
            creds = None
            if name is not None or keytab:
                creds = g.Credentials(
                    name=self._name(name) if name is not None else None,
                    usage="accept",
                    mechs=[g.MechType.kerberos],
                    store={"keytab": keytab} if keytab else None,
                )
            context = g.SecurityContext(creds=creds, usage="accept")
        except self.errors as exc:
            raise self.fail("preparing a Kerberos acceptor", exc) from exc
        return GssapiMechanism(self, context)


class GssapiMechanism:
    """A ``gssapi.SecurityContext``, with its exceptions translated.

    The binding's ``SecurityContext`` is not thread-safe; the owning
    :class:`.gss.ClientContext` or :class:`.gss.AcceptorContext` serialises
    calls.
    """

    def __init__(self, backend: GssapiBackend, context: Any) -> None:
        """Own ``context`` (a ``gssapi.SecurityContext``) until :meth:`close`."""
        self.backend = backend
        self.context: Any = context
        #: True once the library says the context is established.
        self.complete = False

    def step(self, token: bytes) -> bytes:
        """Feed the peer's token (empty to start); return the one to send.

        A failure keeps any error token the library produced on the
        exception, for the protocol to forward.
        """
        out = None
        try:
            out = self.context.step(token or None)
            # An acceptor that fails with an error token to send returns the
            # token from ``step`` and raises the failure from ``complete``.
            complete = bool(self.context.complete)
        except self.backend.errors as exc:
            error = self.backend.fail("Kerberos authentication", exc)
            error.token = bytes(out or b"")
            raise error from exc
        self.complete = complete
        return bytes(out or b"")

    def wrap(self, data: bytes, confidential: bool) -> tuple[bytes, bool]:
        """``gss_wrap``: the token, and whether it was actually encrypted."""
        try:
            result = self.context.wrap(data, confidential)
        except self.backend.errors as exc:
            raise self.backend.fail("gss_wrap", exc, protection=True) from exc
        return bytes(result.message), bool(result.encrypted)

    def unwrap(self, token: bytes) -> tuple[bytes, bool]:
        """``gss_unwrap``: the data, and whether it had been encrypted."""
        try:
            result = self.context.unwrap(token)
        except self.backend.errors as exc:
            raise self.backend.fail("gss_unwrap", exc, protection=True) from exc
        return bytes(result.message), bool(result.encrypted)

    def get_mic(self, data: bytes) -> bytes:
        """``gss_get_mic``: a detached signature (the binding's ``get_signature``)."""
        try:
            return bytes(self.context.get_signature(data))
        except self.backend.errors as exc:
            raise self.backend.fail("gss_get_mic", exc, protection=True) from exc

    def verify_mic(self, data: bytes, mic: bytes) -> None:
        """``gss_verify_mic``: ``EPROTO`` unless ``mic`` signs ``data`` (``verify_signature``)."""
        try:
            self.context.verify_signature(data, mic)
        except self.backend.errors as exc:
            raise self.backend.fail("gss_verify_mic", exc, protection=True) from exc

    def inquire(self) -> tuple[str, str, int]:
        """The initiator's name, the target's name, and the negotiated flags as bits."""
        context = self.context
        try:
            flags = 0
            for flag in context.actual_flags:
                flags |= int(flag)
            return str(context.initiator_name), str(context.target_name), flags
        except self.backend.errors as exc:
            raise self.backend.fail("gss_inquire_context", exc) from exc

    def close(self) -> None:
        """Drop the binding's context; it calls ``gss_delete_sec_context`` when collected.

        Called once, by the owning context's ``close``.
        """
        self.context = None
