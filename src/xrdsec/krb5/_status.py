"""GSS-API status codes, and what they mean to a caller that speaks ``errno``.

A GSS-API call reports a *major* status (the RFC 2744 routine and calling
errors, identical in every implementation) and a *minor* status (the
mechanism's own code: for krb5, a com_err value from the ``krb5`` or
``k5g`` table, or a plain ``errno``). Every backend ends up here so that a
missing ticket, an unreachable KDC or a tampered token read the same way and
carry the same ``errno`` whichever library (MIT, Heimdal, macOS) produced
them. The one binding is python-gssapi (:mod:`._gssapi`), but the knowledge
is about GSS-API and Kerberos, not about that binding. The ``errno`` values
are the ones gfal2's plugins report for the same failures (``EACCES`` for a
refused login, ``ETIMEDOUT`` for a silent KDC), which is what xgfalclient's
``GError`` carries; any client that classifies failures by ``errno`` can
use them as they are.

The numbers are fixed by the standards: RFC 2744 §3.9.1 for the major status
layout, and the com_err tables (``krb5_err.et``, ``gssapi_err_krb5.et``) for
the minor codes recognised below. Tests pin each mapping.
"""

from __future__ import annotations

import errno
from collections.abc import Callable, Sequence

from xrdcore.errors import AuthenticationError

__all__ = [
    "COMPLETE",
    "CONTINUE_NEEDED",
    "KerberosError",
    "describe",
    "errno_for",
    "hint_for",
    "is_error",
    "routine_text",
    "signed",
]

#: ``GSS_S_COMPLETE``: the call succeeded.
COMPLETE = 0
#: ``GSS_S_CONTINUE_NEEDED``: a supplementary bit, not an error - send the
#: output token and call again with the peer's answer.
CONTINUE_NEEDED = 1

# A major status is three fields: calling errors (bits 24-31), routine
# errors (16-23) and supplementary information (0-15), RFC 2744 §3.9.1.
CALLING_MASK = 0xFF000000
ROUTINE_MASK = 0x00FF0000
SUPPLEMENTARY_MASK = 0x0000FFFF

# Routine errors, as the number in bits 16-23 of the major status.
BAD_MECH = 1
BAD_NAME = 2
BAD_NAMETYPE = 3
BAD_BINDINGS = 4
BAD_STATUS = 5
BAD_MIC = 6
NO_CRED = 7
NO_CONTEXT = 8
DEFECTIVE_TOKEN = 9
DEFECTIVE_CREDENTIAL = 10
CREDENTIALS_EXPIRED = 11
CONTEXT_EXPIRED = 12
FAILURE = 13
BAD_QOP = 14
UNAUTHORIZED = 15
UNAVAILABLE = 16
DUPLICATE_ELEMENT = 17
NAME_NOT_MN = 18

#: RFC 2744's words for each routine error, for when the library cannot
#: say it itself (``gss_display_status`` failing, or a fake library).
_ROUTINE_TEXT = {
    BAD_MECH: "An unsupported mechanism was requested",
    BAD_NAME: "An invalid name was supplied",
    BAD_NAMETYPE: "A supplied name was of an unsupported type",
    BAD_BINDINGS: "Incorrect channel bindings were supplied",
    BAD_STATUS: "An invalid status code was supplied",
    BAD_MIC: "A token had an invalid Message Integrity Check (MIC)",
    NO_CRED: "No credentials were supplied, or the credentials were unavailable",
    NO_CONTEXT: "No context has been established",
    DEFECTIVE_TOKEN: "Invalid token was supplied",
    DEFECTIVE_CREDENTIAL: "Invalid credential was supplied",
    CREDENTIALS_EXPIRED: "The referenced credential has expired",
    CONTEXT_EXPIRED: "The referenced context has expired",
    FAILURE: "Unspecified GSS failure",
    BAD_QOP: "The quality-of-protection requested could not be provided",
    UNAUTHORIZED: "The operation is forbidden by local security policy",
    UNAVAILABLE: "The operation or option is not available or unsupported",
    DUPLICATE_ELEMENT: "The requested credential element already exists",
    NAME_NOT_MN: "The provided name was not a mechanism name",
}

#: The ``errno`` for each routine error during context establishment. A
#: failure to authenticate is ``EACCES`` whatever the detail, as gfal2's
#: plugins report it; name and argument problems are the caller's
#: ``EINVAL``; a missing mechanism is ``EPROTONOSUPPORT``.
_ROUTINE_ERRNO = {
    BAD_MECH: errno.EPROTONOSUPPORT,
    BAD_NAME: errno.EINVAL,
    BAD_NAMETYPE: errno.EINVAL,
    BAD_STATUS: errno.EINVAL,
    NO_CONTEXT: errno.EPROTO,
    DEFECTIVE_TOKEN: errno.EPROTO,
    BAD_QOP: errno.EINVAL,
    UNAVAILABLE: errno.EOPNOTSUPP,
    DUPLICATE_ELEMENT: errno.EEXIST,
    NAME_NOT_MN: errno.EINVAL,
}

# Minor statuses worth recognising: com_err codes from MIT's ``krb5`` table
# (Heimdal uses the same numbers) and MIT's ``k5g`` GSS table. A com_err
# code is the table's base plus the error's index; the krb5 table's base is
# negative once read as a signed 32-bit value, which is why :func:`signed`
# exists.
_KRB5_BASE = -1765328384
KDC_ERR_S_PRINCIPAL_UNKNOWN = _KRB5_BASE + 7
AP_ERR_TKT_EXPIRED = _KRB5_BASE + 32
AP_ERR_SKEW = _KRB5_BASE + 37
CC_NOTFOUND = _KRB5_BASE + 141
KDC_UNREACH = _KRB5_BASE + 156
FCC_NOFILE = _KRB5_BASE + 195
KG_TGT_MISSING = 39756034
KG_EMPTY_CCACHE = 39756044

#: Minor codes that all mean "you have no usable ticket", whatever the
#: library calls it: expired, no cache, empty cache, no TGT.
_NO_TICKET = frozenset(
    {AP_ERR_TKT_EXPIRED, CC_NOTFOUND, FCC_NOFILE, KG_TGT_MISSING, KG_EMPTY_CCACHE}
)
#: Routine errors that mean the same when the minor code says nothing more.
_NO_TICKET_ROUTINES = frozenset({NO_CRED, DEFECTIVE_CREDENTIAL, CREDENTIALS_EXPIRED})


class KerberosError(AuthenticationError):
    """A GSS-API failure, classified: ``code`` is an ``errno``, the raw statuses are kept.

    ``message`` is the whole sentence (what was being done, then the
    library's words, then a hint); ``code`` is the ``errno`` it stands for
    (:func:`errno_for`), so a client can map it to its own error type
    without parsing text. ``major`` and ``minor`` are the GSS statuses, 0
    when the failure was not the library's. ``token`` is whatever the
    library produced alongside the failure - an acceptor's ``KRB-ERROR``
    reply, which a protocol may forward so the initiator learns why it was
    refused.

    ``args`` is ``(message, code)``: the shape xgfalclient's ``GError``
    has, so that client can derive its own ``KerberosError`` from this one
    and ``GError`` together and keep both contracts.
    """

    def __init__(
        self, message: str, code: int, major: int = 0, minor: int = 0, token: bytes = b""
    ) -> None:
        """``message`` and its ``errno``; the statuses are 0 when not from GSS."""
        super().__init__(message, code)
        self.message = message
        self.code = code
        self.major = major
        self.minor = minor
        self.token = token

    def __str__(self) -> str:
        """The sentence alone, not the ``(message, code)`` tuple ``Exception`` would print."""
        return self.message

    def __reduce__(self) -> tuple[Callable[..., BaseException], tuple[object, ...]]:
        """Pickle with every field, so an error from a worker process keeps its statuses."""
        return (type(self), (self.message, self.code, self.major, self.minor, self.token))


def signed(minor: int) -> int:
    """A minor status as the signed 32-bit com_err value it was built as.

    Bindings hand minor codes over as unsigned ``OM_uint32``; the com_err
    constants above are written signed, as the C headers define them.
    """
    minor &= 0xFFFFFFFF
    return minor - (1 << 32) if minor & 0x80000000 else minor


def is_error(major: int) -> bool:
    """``GSS_ERROR()``: a calling or routine error (supplementary bits aside)."""
    return bool(major & (CALLING_MASK | ROUTINE_MASK))


def routine_text(major: int) -> str:
    """RFC 2744's description of ``major``'s routine error.

    A calling error takes precedence (the call was malformed, so the routine
    field means nothing); a status with only supplementary bits is a token
    the library refused as a replay or out of order.
    """
    if major & CALLING_MASK:
        return "A required argument was invalid or missing"
    routine = (major & ROUTINE_MASK) >> 16
    if routine:
        return _ROUTINE_TEXT.get(routine, f"GSS major status 0x{major:08x}")
    return "The token was a duplicate, out of sequence or too old"


def errno_for(major: int, minor: int, *, protection: bool = False) -> int:
    """The ``errno`` a failed call stands for.

    Network failures in the minor code win over everything (the user's fix
    is the network, not their ticket); then calling errors (our bug:
    ``EINVAL``); then the routine table, defaulting to ``EACCES`` - the
    "authentication failed" errno gfal2's plugins use.

    ``protection`` marks message protection (wrap, unwrap, MIC), where a bad
    signature or a replayed token is a corrupt stream (``EPROTO``) rather
    than an authentication refusal.
    """
    code = signed(minor)
    if code in (KDC_UNREACH, errno.ETIMEDOUT):
        return errno.ETIMEDOUT
    if code == errno.ECONNREFUSED:
        return errno.ECONNREFUSED
    if major & CALLING_MASK:
        return errno.EINVAL
    routine = (major & ROUTINE_MASK) >> 16
    if routine == 0 or (protection and routine == BAD_MIC):
        # Only supplementary bits (a replayed or reordered token), or a
        # message whose signature does not verify: the stream is corrupt.
        return errno.EPROTO
    return _ROUTINE_ERRNO.get(routine, errno.EACCES)


def hint_for(major: int, minor: int) -> str:
    """What the user can do about it, when there is something obvious.

    Returned with a leading space and parentheses so it can be appended to
    the library's message unconditionally; empty when there is no advice.
    The four cases are the ones users actually meet at grid sites: no
    ticket, a mistyped host, clock skew and an unreachable KDC.
    """
    code = signed(minor)
    routine = (major & ROUTINE_MASK) >> 16
    if code in _NO_TICKET or routine in _NO_TICKET_ROUTINES:
        return " (no valid Kerberos ticket: run kinit, or point KRB5CCNAME at a credential cache)"
    if code == KDC_ERR_S_PRINCIPAL_UNKNOWN:
        return " (the KDC does not know the service principal: check the host name)"
    if code == AP_ERR_SKEW:
        return " (the clocks of this host and the server differ too much)"
    if code == KDC_UNREACH:
        return " (no KDC answered: check the network and krb5.conf)"
    return ""


def describe(
    what: str,
    major: int,
    minor: int,
    texts: tuple[Sequence[str], Sequence[str]],
    *,
    protection: bool = False,
) -> KerberosError:
    """The ``KerberosError`` for a failed call, from the library's own words.

    ``texts`` is what ``gss_display_status`` said for the major and the
    minor status, in that order; either may be empty (the library could not
    word it), and then a generic text stands in.

    Failures are worded the same way whatever the library: what was being
    done, then the library's messages. MIT's ``GSS_S_FAILURE`` text ("Unspecified GSS
    failure. Minor code may provide more information") is dropped when the
    minor code does provide it, and a supplementary-only status (a replayed
    token) leaves out the minor text, which MIT gives as "Success".
    """
    major_texts, minor_texts = texts
    routine = (major & ROUTINE_MASK) >> 16
    parts = list(major_texts) or [routine_text(major)]
    if minor and is_error(major):
        detail = list(minor_texts) or [f"minor code {signed(minor)}"]
        parts = detail if routine == FAILURE and minor_texts else parts + detail
    message = f"{what} failed: {': '.join(parts)}{hint_for(major, minor)}"
    return KerberosError(message, errno_for(major, minor, protection=protection), major, minor)
