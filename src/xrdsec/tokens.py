"""The bearer token to present, with a URL's own token in front: one search for every tool.

``root://`` (the ``ztn`` mechanism), ``davs://``, HTTP third-party copy, gfal2
and an ARC CE all ask the same question, and when each tool answered it on
its own they answered it differently: one shell could log in as one identity
over ``root://`` and another over ``davs://``. The search itself is
:func:`xrdsec.credentials.find_bearer_token` - the WLCG Bearer Token
Discovery specification, what ``XrdSecztn``, ``htgettoken``, ``oidc-agent``
and the SciTokens libraries all follow. This module is the adapter a
protocol calls, with what is written at the call site in front of it:

1. a token in the URL itself (``?authz=`` or ``?access_token=``, HTTP only:
   on ``root://`` such a CGI is the server's to interpret, not a login) -
   ``query=``;
2. a token the caller configured - ``token=``;
3. a token file the caller named explicitly - ``token_file=`` - when it is
   something other than ``$BEARER_TOKEN_FILE``, which is merely a client's
   usual default for that setting and is read at step 5 where the
   specification puts it (:func:`explicit_token_file`);
4. ``$BEARER_TOKEN``;
5. the file ``$BEARER_TOKEN_FILE`` names;
6. ``$XDG_RUNTIME_DIR/bt_u<euid>``;
7. ``/tmp/bt_u<euid>``.

Steps 2 to 7 are :func:`~xrdsec.credentials.find_bearer_token` with
``explicit`` and ``token_file``; its rules apply unchanged - a file that is
there but not private to this user raises
:class:`~xrdcore.errors.InsecureCredentialError`, and ``skip_unreadable=True``
is gfal2's reading of a file that cannot be read for an ordinary reason.

:func:`token_claims`, :func:`token_expiry` and :func:`check_token` read a
JWT's claims *unverified*, for one purpose only: to say "your token has
expired" before a server answers with a bare ``401``. The decoding is strict
(canonical base64url, JSON objects, no detached payload); the one difference
between the tools is a keyword - the XRootD client tolerates whole-quantum
``=`` padding (``padding=True``), gfal2's reading does not.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from collections.abc import Mapping

from xrdcore.errors import TokenExpiredError

from . import credentials

__all__ = [
    "TOKEN_FIELDS",
    "check_token",
    "discover_token",
    "explicit_token_file",
    "token_claims",
    "token_expiry",
    "token_files",
    "url_token",
]

#: Query fields that carry a bearer token in an HTTP URL. They are presented
#: in the ``Authorization`` header and never sent in a request target.
TOKEN_FIELDS = ("authz", "access_token")


def _environ(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    """``environ``, or the process environment."""
    return os.environ if environ is None else environ


def url_token(query: Mapping[str, str]) -> str | None:
    """The bearer token a URL's decoded ``query`` carries, if any."""
    for name in TOKEN_FIELDS:
        value = query.get(name)
        if value:
            return value.removeprefix("Bearer ").strip()
    return None


def explicit_token_file(
    token_file: str | None, environ: Mapping[str, str] | None = None
) -> str | None:
    """``token_file``, if somebody chose it rather than inheriting it.

    A client's token-file setting usually defaults to ``$BEARER_TOKEN_FILE``;
    left at that, it is the specification's step 5, which comes *after*
    ``$BEARER_TOKEN``. Set to anything else - in code, in a settings file,
    with ``--token-file`` - it was written for this call and outranks the
    ambient environment.
    """
    if token_file and token_file != _environ(environ).get("BEARER_TOKEN_FILE"):
        return token_file
    return None


def token_files(
    token_file: str | None = None,
    environ: Mapping[str, str] | None = None,
    uid: int | None = None,
) -> list[tuple[str, bool]]:
    """Every file :func:`discover_token` may read, in order, each with whether it is predictable.

    :func:`xrdsec.credentials.bearer_token_files` for ``token_file`` when it
    was named explicitly (:func:`explicit_token_file`).
    """
    env = _environ(environ)
    return credentials.bearer_token_files(env, uid, token_file=explicit_token_file(token_file, env))


def discover_token(
    *,
    token: str | None = None,
    token_file: str | None = None,
    query: Mapping[str, str] | None = None,
    environ: Mapping[str, str] | None = None,
    uid: int | None = None,
    skip_unreadable: bool = False,
) -> str | None:
    """The bearer token to present, or ``None`` if there is not one to be had.

    ``query`` is the decoded query of an HTTP URL, where a token may ride;
    ``token`` and ``token_file`` are what the caller configured; ``environ``
    and ``uid`` replace the process's (for tests and for tools that resolve
    a configuration first). Raises
    :class:`~xrdcore.errors.InsecureCredentialError` for a token file that is
    there but not private to this user.
    """
    found = url_token(query) if query is not None else None
    if found:
        return found
    env = _environ(environ)
    return credentials.find_bearer_token(
        env,
        uid,
        explicit=token,
        token_file=explicit_token_file(token_file, env),
        skip_unreadable=skip_unreadable,
    )


#: The base64url alphabet (RFC 4648 s. 5), which a JWS segment is written in.
_SEGMENT = re.compile(r"[A-Za-z0-9_-]*")


def _segment(text: str, padding: bool) -> bytes:
    """One base64url segment of a compact JWS, decoded strictly.

    RFC 7515 s. 2 leaves the padding off, so by default an ``=`` is refused
    like any other character outside the alphabet. ``padding=True`` - the
    XRootD client's reading, because some issuers keep it - tolerates one or
    two trailing ``=``, but only where they make a whole quantum. Either way
    an impossible length, or a spelling that does not re-encode to itself
    (non-zero bits left over in the last character), is refused, so two
    different strings never decode to the same claims. Each refusal is a
    :exc:`ValueError`.
    """
    stripped = text.rstrip("=") if padding else text
    extra = len(text) - len(stripped)
    if extra > 2 or (extra and len(text) % 4) or len(stripped) % 4 == 1:
        raise ValueError("invalid base64url padding")
    if not _SEGMENT.fullmatch(stripped):
        raise ValueError("not base64url")
    # Cannot raise: every character is in the alphabet and the length is one
    # base64 can end on, so the padding put back makes it whole.
    decoded = base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != stripped:
        raise ValueError("non-canonical base64url segment")
    return decoded


def _segment_object(text: str, padding: bool) -> dict[str, object]:
    """One JWT segment as the JSON object it must encode, else :exc:`ValueError`.

    Non-UTF-8 bytes and invalid JSON are ``ValueError`` already; nesting too
    deep for :mod:`json` (``[[[[...``) is a :exc:`RecursionError`, turned into
    one here so that a hostile token reads as "no claims" rather than
    escaping as an exception nobody expects from a diagnostic.
    """
    try:
        value = json.loads(_segment(text, padding))
    except RecursionError as exc:
        raise ValueError("JSON nested too deeply") from exc
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


def token_claims(token: str, *, padding: bool = False) -> dict[str, object]:
    """Unverified JWT claims for diagnostics only; never an authorization decision.

    Only the shape is checked: three dot-separated segments whose first two
    are base64url JSON objects (RFC 7519 s. 7.2). The signature is never
    decoded or examined, so nothing here may be used to decide access; it
    exists so an expired token can be named before a server refuses it.
    Anything else - a macaroon or other opaque credential, a malformed
    segment, RFC 7797's detached payload (``"b64": false``, whose compact
    form carries no claims) - has none, and ``{}`` says so. ``padding`` is
    :func:`_segment`'s: whether whole-quantum ``=`` padding is tolerated.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        header = _segment_object(parts[0], padding)
        claims = _segment_object(parts[1], padding)
    except ValueError:
        return {}
    if header.get("b64", True) is False:
        return {}
    return claims


def token_expiry(token: str, *, padding: bool = False) -> float | None:
    """The ``exp`` claim as a UNIX timestamp, if the token carries one as whole seconds.

    Read unverified (:func:`token_claims`). Only a non-negative integer -
    as a JSON number or a string of digits - counts: RFC 7519's NumericDate
    is seconds, and a fractional or negative value is more likely a broken
    issuer than a deadline worth enforcing, so it is left for the server to
    judge. The XRootD ``ztn`` login checks this against the lifetime a
    server asks for.
    """
    exp = token_claims(token, padding=padding).get("exp")
    if isinstance(exp, (int, float, str)) and str(exp).isdigit():
        return float(exp)
    return None


def check_token(token: str, *, now: float | None = None) -> None:
    """Fail early for an expired JWT; opaque tokens and macaroons remain usable.

    Raises :class:`~xrdcore.errors.TokenExpiredError` with a sentence saying
    what to do, instead of the server's bare 401. The ``exp`` claim is read
    unverified (see :func:`token_claims`): the check can only ever refuse a
    token, never grant anything, so an attacker gains nothing by forging it.
    A token without a usable ``exp`` is left for the server to judge.
    """
    expiry = token_claims(token).get("exp")
    if not isinstance(expiry, (int, float, str)):
        return
    try:
        expired = float(expiry) <= (time.time() if now is None else now)
    except (ValueError, TypeError):
        return
    if expired:
        raise TokenExpiredError("Your bearer token has expired. Get a new token and try again.")
