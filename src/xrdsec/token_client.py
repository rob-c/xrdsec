"""Get a WLCG bearer token, and check one: the half :mod:`xrdsec.tokens` does not do.

:mod:`xrdsec.tokens` finds the token to present, as the WLCG Bearer Token
Discovery specification lays it out. This asks an *issuer* for a new one, in
the shapes the WLCG Common JWT Profile describes, with nothing but the
standard library and ``cryptography``:

* an issuer is found from its own OpenID Provider configuration
  (:func:`discover` on an IAM's base URL) or from a resource server that
  advertises its issuers at ``/.well-known/wlcg-token`` - which is how a
  storage element tells a client where to go;
* **device flow** (:func:`device_authorization`, :func:`device_poll`): the one
  a person can use with no certificate at all, a browser and a code;
* **X.509 as the client** (:func:`acquire`): the client-credentials grant where
  mutual TLS with the user certificate *is* the client authentication, so no
  secret is asked for and no browser is needed;
* **narrowing** an existing token to one storage element or path, with the
  RFC 8693 token exchange (:func:`exchange`), which is the only way to get a
  smaller ``scope`` than the one you hold;
* what comes back is a JWT whose signature is checked against the issuer's
  published keys and whose ``iss``, ``aud``, ``exp``, ``nbf`` are read
  (:func:`verify`);
* it is written where the discovery specification says a client looks
  (:func:`write_token`), which is the same search
  :func:`xrdsec.tokens.discover_token` reads back.

Every request is made through :func:`xrdsec.tls.client_context`, so the CA
directory a transfer trusts is the one a token request trusts, and a proxy's
key is handed to OpenSSL in memory rather than written out.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import time
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from xrdcore.errors import XrdError

from . import credentials

__all__ = [
    "ACCESS_TOKEN",
    "AUDIENCE",
    "DEFAULT_SCOPE",
    "DEVICE_GRANT",
    "DIRACX_BEGIN",
    "DIRACX_END",
    "EXCHANGE",
    "Issuer",
    "Token",
    "TokenError",
    "acquire",
    "device_authorization",
    "device_poll",
    "discover",
    "embedded",
    "exchange",
    "read_token",
    "token_file_path",
    "verify",
    "write_token",
]

#: The JWT access token type both OAuth and RFC 8693 spell out.
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"

#: RFC 8693's grant: exchange a token for one with a smaller scope.
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

#: RFC 8628's grant: the polling half of the device flow.
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

#: The audience every WLCG storage service accepts, whatever its own name.
AUDIENCE = "https://wlcg.cern.ch/jwt/v1/any"

#: What to ask for when nobody says: read and write, and the VO's groups.
DEFAULT_SCOPE = "storage.read:/ storage.modify:/ wlcg.groups"

#: Where a resource server publishes the issuers it trusts (WLCG profile).
WLCG_TOKEN_DOCUMENT = "/.well-known/wlcg-token"

#: Where an issuer publishes its endpoints (OpenID Connect Discovery).
OIDC_DOCUMENT = "/.well-known/openid-configuration"

#: How long any request may take before it is given up on.
TIMEOUT = 30.0

#: How DIRAC keeps a token in a proxy file: a block of base64 JSON between these.
#:
#: ``dirac-login`` (DIRAC 9's ``DIRAC.Core.Security.DiracX``) obtains a token by
#: *proxy exchange* - the server's ``Framework/ProxyManager`` answers
#: ``exchangeProxyForToken()`` for the identity the TLS handshake proved, and the
#: same file then carries both credentials. No client registration and no device
#: flow: the proxy is the credential. Reading that block needs nothing of DIRAC.
DIRACX_BEGIN = "-----BEGIN DIRACX-----"
DIRACX_END = "-----END DIRACX-----"

#: Clock skew allowed when a token's ``exp``/``nbf`` are read, in seconds.
LEEWAY = 60

#: How many hours a token is assumed good for when the issuer does not say.
ASSUMED_LIFETIME = 3600.0


class TokenError(XrdError):
    """A token could not be obtained or could not be believed."""

    def __init__(self, message: str, *, code: str = "token") -> None:
        """Carry ``message`` for people, and ``code`` for callers that report by class."""
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class Issuer:
    """Where a token comes from: an IAM's ``iss``, and the endpoints it publishes."""

    #: The issuer identifier: the ``iss`` a token must carry, usually a URL.
    url: str
    #: Where to POST a token request.
    token_endpoint: str
    #: Where its signing keys are published, as a JWKS.
    jwks_uri: str
    #: Where the device flow begins, when the issuer publishes one.
    device_endpoint: str = ""
    #: Where a client can register itself (RFC 7591), when the issuer allows it.
    registration_endpoint: str = ""

    @property
    def name(self) -> str:
        """The issuer as a person would recognise it: its host and the last path part."""
        parts = urllib.parse.urlsplit(self.url)
        tail = parts.path.rstrip("/").rsplit("/", 1)[-1]
        return f"{parts.netloc}{'/' + tail if tail else ''}"


@dataclass(frozen=True, slots=True)
class Token:
    """A token as the issuer answered: the JWT, and what it says it is good for."""

    #: The JWT itself.
    access_token: str
    #: What the issuer said its lifetime is, in seconds (``expires_in``), if it said.
    expires_in: float = 0.0
    #: The scope the issuer granted, which may be narrower than the one asked for.
    scope: str = ""
    #: The token type, normally ``Bearer``.
    token_type: str = "Bearer"
    #: When the request was answered, for a token that counts from now.
    issued_at: float = field(default_factory=time.time)

    @property
    def claims(self) -> dict[str, Any]:
        """The JWT's claims, decoded but *not* verified; see :func:`verify`."""
        from .tokens import token_claims

        return token_claims(self.access_token)

    @property
    def expiry(self) -> float:
        """When it stops being valid: the JWT's ``exp``, else ``expires_in`` from now."""
        try:
            stated = float(self.claims.get("exp", 0.0))
        except (TypeError, ValueError):
            stated = 0.0
        return stated or self.issued_at + (self.expires_in or ASSUMED_LIFETIME)

    def time_left(self, now: float | None = None) -> float:
        """Seconds until it expires, never negative."""
        return max(0.0, self.expiry - (time.time() if now is None else now))


# ---------------------------------------------------------------------------
# Talking to an issuer
# ---------------------------------------------------------------------------


def _context(credential: Any, ca_path: str | None) -> ssl.SSLContext:
    """A client TLS context for a token endpoint: the **system store and the grid's**.

    A token issuer is a public web service - the per-experiment IAMs at CERN
    carry Sectigo certificates, the WLCG and EGI IAMs HARICA (GEANT TLS), the
    CILogon tenants Amazon - so its chain is anchored in the operating
    system's store, not in the IGTF bundle that signs grid hosts. Trusting only
    :func:`xrdsec.credentials.grid_ca_path` therefore fails with "certificate
    verify failed: unable to get local issuer certificate" - on a machine whose
    grid bundle is absent, stale or simply does not carry those roots.

    ``system_ca=True`` adds the system store *to* whatever grid directory is
    found, which is what that flag is for; the grid directory is still used, so
    an IGTF-signed issuer (some sites run one) verifies too. VOMS servers keep
    the grid-only trust they have always had: they are part of the grid PKI.

    No public CA keys are vendored here. All nine providers probed on
    11 November 2026 verified from the system store *and* from the IGTF bundle
    (Sectigo, HARICA and Amazon roots are IGTF members), so shipping keys in
    this package would add a renewal burden - and a supply-chain one - for no
    reach.
    """
    from .tls import client_context

    return client_context(
        credential_pem=credential.to_pem() if credential is not None else None,
        ca_path=ca_path or credentials.grid_ca_path(),
        system_ca=True,
        check_hostname=True,
    )


def _http(
    url: str,
    context: ssl.SSLContext,
    *,
    form: Mapping[str, str] | None = None,
    json_body: bytes | None = None,
    timeout: float = TIMEOUT,
) -> dict[str, Any]:
    """One HTTPS request: ``form`` makes it a POST, and its JSON answer comes back.

    An OAuth refusal - a non-200 answer with ``error``/``error_description`` -
    becomes a :class:`TokenError` quoting the issuer, because the issuer's own
    words ("invalid_client", "authorization_pending") are what a person needs.
    """
    import http.client

    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise TokenError(f"{url} is not https: a token must not travel in clear")
    body = None
    headers = {"Accept": "application/json", "User-Agent": _agent()}
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        body = json_body
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPSConnection(
        parts.hostname or "", parts.port or 443, context=context, timeout=timeout
    )
    try:
        posting = form is not None or json_body is not None
        connection.request("POST" if posting else "GET", _target(parts), body=body, headers=headers)
        response = connection.getresponse()
        return _json(response.status, response.read(), url)
    except (OSError, http.client.HTTPException) as exc:
        raise TokenError(_transport(url, exc)) from exc
    finally:
        connection.close()


def _target(parts: urllib.parse.SplitResult) -> str:
    """The request target: path and query, never a fragment."""
    return f"{parts.path or '/'}{'?' + parts.query if parts.query else ''}"


def _agent() -> str:
    """The ``User-Agent`` every request carries."""
    from ._version import __version__

    return f"xrdsec/{__version__}"


def _transport(url: str, exc: BaseException) -> str:
    """Why a request did not complete, naming the TLS verdict when there is one."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"cannot talk to {url}: its certificate is not trusted ({exc.verify_message})"
    return f"cannot talk to {url}: {exc or type(exc).__name__}"


def _json(status: int, body: bytes, url: str) -> dict[str, Any]:
    """``body`` as a JSON object, or :class:`TokenError` saying what came back instead."""
    try:
        answer = json.loads(body or b"{}")
    except ValueError as exc:
        raise TokenError(f"{url} answered with something that is not JSON: {exc}") from exc
    if not isinstance(answer, dict):
        raise TokenError(f"{url} answered with JSON, but not an object")
    # 2xx is success: a token endpoint answers 200, and RFC 7591 registration
    # answers 201 with the client it just created.
    if not 200 <= status < 300:
        raise TokenError(_refusal(status, answer, body, url))
    return answer


def _refusal(status: int, answer: Mapping[str, Any], body: bytes, url: str) -> str:
    """What the issuer said when it said no: OAuth's ``error`` and ``error_description``."""
    if answer.get("error"):
        detail = answer.get("error_description") or ""
        said = f": {answer['error']}{f' - {detail}' if detail else ''}"
        return f"{url} refused the request ({status}){said}"
    text = body[:200].decode("utf-8", "replace").strip()
    return f"{url} refused the request ({status}){f': {text}' if text else ''}"


# ---------------------------------------------------------------------------
# Finding the issuer
# ---------------------------------------------------------------------------


def discover(
    where: str,
    *,
    credential: Any = None,
    ca_path: str | None = None,
    timeout: float = TIMEOUT,
) -> list[Issuer]:
    """Every issuer ``where`` leads to: an IAM itself, or a resource that names its issuers.

    ``where`` is either an issuer's base URL - in which case its OpenID
    Provider configuration is read - or a resource server's URL, where the
    WLCG profile puts ``/.well-known/wlcg-token``: a JSON object whose
    ``issuers`` are then read the same way. A storage element answers the
    second; a person usually knows the first.
    """
    context = _context(credential, ca_path)
    base = where.rstrip("/")
    document = _document(base + OIDC_DOCUMENT, context, timeout)
    if document.get("token_endpoint"):
        return [_issuer_of(document, base)]
    names = _document(base + WLCG_TOKEN_DOCUMENT, context, timeout).get("issuers")
    if not isinstance(names, list) or not names:
        raise TokenError(f"{base} publishes neither an OpenID configuration nor a wlcg-token one")
    return [
        _issuer_of(_document(str(name).rstrip("/") + OIDC_DOCUMENT, context, timeout), str(name))
        for name in names
    ]


def _document(url: str, context: ssl.SSLContext, timeout: float) -> dict[str, Any]:
    """One discovery document; a 404 is an empty one, as "not published here" reads."""
    try:
        return _http(url, context, timeout=timeout)
    except TokenError as refused:
        if "refused the request (404)" in str(refused):
            return {}
        raise


def _issuer_of(document: Mapping[str, Any], fallback: str) -> Issuer:
    """The :class:`Issuer` a discovery document describes."""
    endpoint = str(document.get("token_endpoint") or "")
    if not endpoint:
        raise TokenError(f"{fallback} publishes no token endpoint")
    return Issuer(
        url=str(document.get("issuer") or fallback),
        token_endpoint=endpoint,
        jwks_uri=str(document.get("jwks_uri") or ""),
        device_endpoint=str(document.get("device_authorization_endpoint") or ""),
        registration_endpoint=str(document.get("registration_endpoint") or ""),
    )


# ---------------------------------------------------------------------------
# Asking for a token
# ---------------------------------------------------------------------------


def acquire(
    issuer: Issuer,
    credential: Any,
    *,
    audience: str = AUDIENCE,
    scope: str = DEFAULT_SCOPE,
    client_id: str = "",
    ca_path: str | None = None,
    timeout: float = TIMEOUT,
) -> Token:
    """A token from ``issuer`` for ``credential``: client credentials, X.509 as the client.

    The WLCG profile's way for a certificate holder: mutual TLS with the
    certificate is the client authentication, so no secret is asked for and no
    browser is needed, and the issuer derives the identity - and the VO
    groups, which become ``wlcg.groups`` - from that certificate. Present the
    *user* certificate from the PKCS#12 bundle, not a proxy: an IAM's gateway
    commonly refuses a proxy certificate at the TLS layer.
    """
    form = {"grant_type": "client_credentials"}
    if client_id:
        form["client_id"] = client_id
    if scope:
        form["scope"] = scope
    if audience:
        form["audience"] = audience
    return _token(
        _http(issuer.token_endpoint, _context(credential, ca_path), form=form, timeout=timeout)
    )


def exchange(
    issuer: Issuer,
    subject_token: str,
    *,
    audience: str = AUDIENCE,
    scope: str = DEFAULT_SCOPE,
    credential: Any = None,
    client_id: str = "",
    ca_path: str | None = None,
    timeout: float = TIMEOUT,
) -> Token:
    """A narrower token for ``subject_token``: RFC 8693, at the same issuer.

    Asking for a smaller ``scope`` - one storage element, one path - is why
    this exists: a token that can write everywhere should not be left lying
    about when one that cannot is enough. ``credential``, when given, is the
    client authentication as in :func:`acquire`; an issuer may allow an
    exchange with the subject token alone.
    """
    form = {
        "grant_type": EXCHANGE,
        "subject_token": subject_token,
        "subject_token_type": ACCESS_TOKEN,
        "requested_token_type": ACCESS_TOKEN,
    }
    if client_id:
        form["client_id"] = client_id
    if scope:
        form["scope"] = scope
    if audience:
        form["audience"] = audience
    return _token(
        _http(issuer.token_endpoint, _context(credential, ca_path), form=form, timeout=timeout)
    )


def device_authorization(
    issuer: Issuer,
    client_id: str,
    *,
    scope: str = DEFAULT_SCOPE,
    ca_path: str | None = None,
    timeout: float = TIMEOUT,
) -> dict[str, Any]:
    """Start a device flow: the code to show a person, and where to show it.

    The answer carries ``user_code``, ``verification_uri`` (and usually
    ``verification_uri_complete``), ``device_code``, ``interval`` and
    ``expires_in`` - RFC 8628's device authorization response.
    """
    if not issuer.device_endpoint:
        raise TokenError(
            f"{issuer.name} publishes no device authorization endpoint", code="no_device"
        )
    if not client_id:
        raise TokenError(
            "the device flow needs a client id: register a public client with the issuer",
            code="no_client",
        )
    # RFC 8628 asks for these in a form body; DiracX (LHCb's own issuer) reads them
    # from the *query string* and answers 422 without them. Sending both costs
    # nothing and works at either kind of issuer.
    asked = {"client_id": client_id, "scope": scope}
    separator = "&" if urllib.parse.urlsplit(issuer.device_endpoint).query else "?"
    return _http(
        issuer.device_endpoint + separator + urllib.parse.urlencode(asked),
        _context(None, ca_path),
        form=asked,
        timeout=timeout,
    )


#: The grant a command-line client uses: a code, and something to refresh with.
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

#: What a registered public client asks for: an identity, a refresh token, and the
#: claim that carries group membership.
PUBLIC_SCOPES = "openid profile offline_access"


def register(
    issuer: Issuer,
    *,
    name: str = "xrd-auth",
    scope: str = PUBLIC_SCOPES,
    grants: Sequence[str] = (DEVICE_GRANT, "refresh_token"),
    contacts: Sequence[str] = (),
    ca_path: str | None = None,
    timeout: float = 20.0,
    context: ssl.SSLContext | None = None,
) -> dict[str, Any]:
    """Register a public client at ``issuer`` and return what it answered (RFC 7591).

    Most IAMs in WLCG allow this without asking anyone: the client is public, it
    holds no secret, and a person still has to approve every device code. LHCb's
    IAM does not - it wants an admin-issued initial access token - and the issuer's
    own words are what comes back in that case.
    """
    if not issuer.registration_endpoint:
        raise TokenError(
            f"{issuer.name} publishes no registration endpoint: register a client by hand",
            code="no_registration",
        )
    asked: dict[str, Any] = {
        "client_name": name,
        "grant_types": list(grants),
        "redirect_uris": ["http://localhost"],
        "scope": scope,
        # A command line cannot keep a secret, so the client is public by design.
        "token_endpoint_auth_method": "none",
        "contacts": [contact for contact in contacts if contact],
    }
    body = json.dumps(asked).encode()
    registered = _http(
        issuer.registration_endpoint,
        _context(None, ca_path) if context is None else context,
        json_body=body,
        timeout=timeout,
    )
    if not registered.get("client_id"):
        raise TokenError(
            f"{issuer.name} answered a registration request without a client id",
            code="no_client",
        )
    return registered


def device_poll(
    issuer: Issuer,
    client_id: str,
    device_code: str,
    *,
    ca_path: str | None = None,
    timeout: float = TIMEOUT,
) -> Token | None:
    """One poll of the device flow: the token once the person has approved, else ``None``.

    RFC 8628's two pending answers - ``authorization_pending`` and
    ``slow_down`` - are ``None`` (the caller waits and asks again), so a loop
    reads as it looks. Every other refusal is raised.
    """
    form = {"grant_type": DEVICE_GRANT, "device_code": device_code, "client_id": client_id}
    try:
        return _token(
            _http(issuer.token_endpoint, _context(None, ca_path), form=form, timeout=timeout)
        )
    except TokenError as refused:
        pending = "authorization_pending", "slow_down"
        if any(f": {one}" in str(refused) for one in pending):
            return None
        raise


def _token(answer: Mapping[str, Any]) -> Token:
    """The :class:`Token` an issuer's answer carries, or why there is not one."""
    token = str(answer.get("access_token") or "")
    if not token:
        raise TokenError("the issuer answered without an access token")
    return Token(
        access_token=token,
        expires_in=_float(answer.get("expires_in")),
        scope=str(answer.get("scope") or ""),
        token_type=str(answer.get("token_type") or "Bearer"),
    )


def _float(value: Any) -> float:
    """``value`` as seconds, ``0`` when it is not a number."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# Where a token goes
# ---------------------------------------------------------------------------


def _environ(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    """``environ``, or the process environment."""
    return os.environ if environ is None else environ


def token_file_path(environ: Mapping[str, str] | None = None, uid: int | None = None) -> str:
    """Where this module writes a token: the first place the discovery specification reads.

    ``$BEARER_TOKEN_FILE`` when a session has chosen a file, else
    ``$XDG_RUNTIME_DIR/bt_u<euid>``, else ``/tmp/bt_u<euid>`` - the same order
    :func:`xrdsec.tokens.discover_token` looks in, so what is written here is
    what a client will find.
    """
    files = credentials.bearer_token_files(_environ(environ), uid)
    if not files:
        raise TokenError(
            "there is nowhere to write a token: no $BEARER_TOKEN_FILE, $XDG_RUNTIME_DIR or /tmp",
            code="no_token_file",
        )
    return files[0][0]


def write_token(
    access_token: str,
    path: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    uid: int | None = None,
) -> str:
    """Write ``access_token`` where a client will look, readable only by its owner.

    A symbolic link is not written through - the ``bt_u<uid>`` name in ``/tmp``
    is predictable, so a hostile one must be refused rather than followed - and
    the mode is set again after the write, for a file that already existed.
    """
    target = path or token_file_path(environ, uid)
    data = access_token.strip().encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        handle = os.open(target, flags, 0o600)
    except OSError as exc:
        raise TokenError(f"cannot write {target}: {exc}", code="no_token_file") from exc
    try:
        os.write(handle, data)
    finally:
        os.close(handle)
    os.chmod(target, 0o600)
    return target


def embedded(text: str) -> dict[str, Any] | None:
    """The token DIRAC embedded in a proxy file, as the JSON it wrapped, or ``None``.

    DIRAC's own writer puts base64 of ``TokenResponse`` between
    :data:`DIRACX_BEGIN` and :data:`DIRACX_END` in the proxy PEM, so one file
    carries both credentials. A file without that block - the ordinary case for
    an ``xrd-proxy init`` proxy - answers ``None``.
    """
    start = text.find(DIRACX_BEGIN)
    end = text.find(DIRACX_END, start + len(DIRACX_BEGIN))
    if start < 0 or end < 0:
        return None
    payload = "".join(text[start + len(DIRACX_BEGIN) : end].split())
    try:
        found = json.loads(base64.b64decode(payload))
    except (ValueError, TypeError) as exc:
        raise TokenError(
            f"the DIRACX block in this file is not base64 JSON: {exc}", code="not_a_jwt"
        ) from exc
    if not isinstance(found, dict) or not found.get("access_token"):
        raise TokenError("the DIRACX block carries no access token", code="not_a_jwt")
    return found


def from_pem(text: str) -> Token:
    """The :class:`Token` a DIRAC proxy file carries, or :class:`TokenError` if it carries none."""
    block = embedded(text)
    if block is None:
        raise TokenError("this file carries no DIRACX token block", code="no_token")
    return Token(
        access_token=str(block["access_token"]),
        expires_in=_float(block.get("expires_in")),
        token_type=str(block.get("token_type") or "Bearer"),
    )


def read_token(environ: Mapping[str, str] | None = None, uid: int | None = None) -> tuple[str, str]:
    """The token a client would present, and where it came from.

    Raises :class:`~xrdcore.errors.TokenExpiredError`-free: an expired token is
    still returned, and :func:`xrdsec.tokens.check_token` is what refuses it -
    a report that cannot describe an expired token is no use for fixing it.
    """
    from .tokens import discover_token, token_source

    env = _environ(environ)
    token = discover_token(environ=env, uid=uid)
    if token is None:
        raise TokenError("there is no bearer token to read", code="no_token")
    return token, token_source(token, environ=env, uid=uid)


# ---------------------------------------------------------------------------
# Believing a token
# ---------------------------------------------------------------------------


def verify(
    access_token: str,
    *,
    issuer: Issuer | None = None,
    jwks: Mapping[str, Any] | None = None,
    audience: str | None = None,
    ca_path: str | None = None,
    now: float | None = None,
    leeway: float = LEEWAY,
    timeout: float = TIMEOUT,
) -> dict[str, Any]:
    """The claims of ``access_token`` once its signature and times have been checked.

    ``jwks`` is the issuer's key set, or ``issuer`` is asked for its
    ``jwks_uri``. The ``alg`` comes from the token's own header and must be one
    this knows (``RS256/384/512``, ``ES256/384/512``); the ``kid`` chooses the
    key. Then ``exp`` and ``nbf`` are read with ``leeway`` seconds of clock
    skew, ``iss`` must match the issuer when one was named, and ``aud`` must
    contain ``audience`` when one was asked for.

    What is *not* checked: that the issuer is trusted for this audience - that
    is the resource server's policy - and anything about the VO beyond reading
    ``wlcg.groups``.
    """
    header, claims, signed, signature = _pieces(access_token)
    keys = jwks if jwks is not None else _fetch_jwks(issuer, ca_path, timeout)
    _check_signature(header, _key_for(keys, header), signed, signature)
    _check_times(claims, now, leeway)
    _check_issuer(claims, issuer)
    _check_audience(claims, audience)
    return claims


def _pieces(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """A JWT split into header, claims, the bytes that were signed, and the signature."""
    segments = token.strip().split(".")
    if len(segments) != 3:
        raise TokenError("this is not a JWT: it does not have three segments", code="not_a_jwt")
    header = _object(_decode(segments[0]), "header")
    claims = _object(_decode(segments[1]), "claims")
    if not header.get("alg"):
        raise TokenError("the JWT header names no algorithm", code="no_algorithm")
    return header, claims, f"{segments[0]}.{segments[1]}".encode(), _decode(segments[2])


def _decode(segment: str) -> bytes:
    """One base64url segment, padded as the alphabet wants it."""
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, TypeError) as exc:
        raise TokenError(f"this is not base64url: {exc}", code="not_a_jwt") from exc


def _object(raw: bytes, what: str) -> dict[str, Any]:
    """``raw`` as a JSON object, or :class:`TokenError` naming which part was not."""
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise TokenError(f"the JWT {what} is not JSON: {exc}", code="not_a_jwt") from exc
    if not isinstance(value, dict):
        raise TokenError(f"the JWT {what} is not a JSON object", code="not_a_jwt")
    return value


def _fetch_jwks(issuer: Issuer | None, ca_path: str | None, timeout: float) -> Mapping[str, Any]:
    """The issuer's published keys, as the discovery document named them."""
    if issuer is None or not issuer.jwks_uri:
        raise TokenError(
            "no key set to check the signature with: name the issuer, or pass its JWKS",
            code="no_keys",
        )
    return _http(issuer.jwks_uri, _context(None, ca_path), timeout=timeout)


def _key_for(jwks: Mapping[str, Any], header: Mapping[str, Any]) -> Mapping[str, Any]:
    """The key ``header``'s ``kid`` names, or the only key there is."""
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise TokenError("the key set is empty", code="no_keys")
    kid = header.get("kid")
    matching = [
        key for key in keys if isinstance(key, dict) and (kid is None or key.get("kid") == kid)
    ]
    if len(matching) != 1:
        named = f"kid {kid}" if kid else "no kid, and more than one key"
        raise TokenError(f"no single key in the set matches ({named})", code="no_keys")
    return matching[0]


def _check_signature(
    header: Mapping[str, Any], jwk: Mapping[str, Any], signed: bytes, signature: bytes
) -> None:
    """Verify ``signature`` over ``signed`` with ``jwk``, by the algorithm named."""
    algorithm = str(header.get("alg"))
    try:
        _verifier(algorithm, jwk)(signed, signature)
    except TokenError:
        raise
    except Exception as exc:  # a bad signature of any kind is one answer
        raise TokenError(
            f"the signature does not check out with {algorithm}: {exc}", code="bad_signature"
        ) from exc


def _verifier(algorithm: str, jwk: Mapping[str, Any]) -> Any:
    """A callable that raises unless ``signature`` is genuine, for one algorithm."""
    if algorithm.startswith("RS"):
        return _rsa_verifier(algorithm[2:], jwk)
    if algorithm.startswith("ES"):
        return _ec_verifier(algorithm[2:], jwk)
    raise TokenError(f"{algorithm} is not a JWS algorithm this verifies", code="bad_algorithm")


#: The digest each JWS algorithm's number names, by the digits in its name.
_DIGESTS = {"256": "SHA256", "384": "SHA384", "512": "SHA512"}

#: The curve each ``ES`` algorithm uses, by the digits in its name.
_CURVES = {"256": "SECP256R1", "384": "SECP384R1", "512": "SECP521R1"}


def _digest(size: str) -> Any:
    """The hash class an algorithm's digits name, or :class:`TokenError`."""
    from cryptography.hazmat.primitives import hashes

    name = _DIGESTS.get(size)
    if name is None:
        raise TokenError(f"there is no digest for {size!r}", code="bad_algorithm")
    return getattr(hashes, name)


def _rsa_verifier(size: str, jwk: Mapping[str, Any]) -> Any:
    """``RS256``/``RS384``/``RS512``: PKCS#1 v1.5 over the digest named."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    digest = _digest(size)
    key = rsa.RSAPublicNumbers(_number(jwk, "e"), _number(jwk, "n")).public_key()

    def checked(signed: bytes, signature: bytes) -> None:
        key.verify(signature, signed, padding.PKCS1v15(), digest())

    return checked


def _ec_verifier(size: str, jwk: Mapping[str, Any]) -> Any:
    """``ES256``/``ES384``/``ES512``: ECDSA over a signature in JWS's raw ``r||s`` form."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    curve = getattr(ec, _CURVES.get(size, ""), None)
    if curve is None:
        raise TokenError(f"there is no curve for {size!r}", code="bad_algorithm")
    digest = _digest(size)
    numbers = ec.EllipticCurvePublicNumbers(_number(jwk, "x"), _number(jwk, "y"), curve())
    key = numbers.public_key()

    def checked(signed: bytes, signature: bytes) -> None:
        half = len(signature) // 2
        first = int.from_bytes(signature[:half], "big")
        second = int.from_bytes(signature[half:], "big")
        key.verify(encode_dss_signature(first, second), signed, ec.ECDSA(digest()))

    return checked


def _number(jwk: Mapping[str, Any], name: str) -> int:
    """A JWK's base64url-encoded number, as an integer."""
    value = jwk.get(name)
    if not isinstance(value, str) or not value:
        raise TokenError(f"the key has no {name!r}", code="no_keys")
    return int.from_bytes(_decode(value), "big")


def _check_times(claims: Mapping[str, Any], now: float | None, leeway: float) -> None:
    """``exp`` must be in the future and ``nbf``, if there is one, in the past."""
    moment = time.time() if now is None else now
    expiry = _when(claims, "exp")
    if expiry is None:
        raise TokenError("the token has no exp claim: it never expires", code="no_expiry")
    if moment > expiry + leeway:
        raise TokenError(f"the token expired {_human(moment - expiry)} ago", code="expired")
    start = _when(claims, "nbf")
    if start is not None and moment + leeway < start:
        raise TokenError(
            f"the token is not valid yet: nbf is {_human(start - moment)} away", code="not_yet"
        )


def _when(claims: Mapping[str, Any], name: str) -> float | None:
    """A NumericDate claim as a float, or ``None`` when it is absent."""
    value = claims.get(name)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise TokenError(f"the {name} claim is not a number: {value!r}") from exc


def _human(seconds: float) -> str:
    """A duration as a person reads it: ``3h 12m``, ``12m``, ``45s``."""
    whole = int(abs(seconds))
    if whole < 60:
        return f"{whole}s"
    if whole < 3600:
        return f"{whole // 60}m"
    return f"{whole // 3600}h {whole % 3600 // 60}m"


def _check_issuer(claims: Mapping[str, Any], issuer: Issuer | None) -> None:
    """``iss`` must be the issuer asked about, when one was."""
    if issuer is None:
        return
    claimed = str(claims.get("iss") or "")
    if claimed != issuer.url:
        raise TokenError(
            f"the token says it came from {claimed!r}, not {issuer.url!r}", code="wrong_issuer"
        )


def _check_audience(claims: Mapping[str, Any], audience: str | None) -> None:
    """``aud`` must include ``audience``, when one was asked for."""
    if audience is None:
        return
    claimed = claims.get("aud")
    audiences = [claimed] if isinstance(claimed, str) else list(claimed or [])
    if audience not in audiences:
        shown = ", ".join(str(one) for one in audiences) or "nothing"
        raise TokenError(f"the token is for {shown}, not {audience}", code="wrong_audience")
