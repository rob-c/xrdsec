"""The WLCG profile's two halves this module owns: ask an issuer, then believe the answer.

The issuer here is a route table on :class:`~xrdsec.testing.https.FakeHTTPSServer`,
so every claim about the protocol is checked against bytes on the wire: the
form of a client-credentials request with the certificate as the client
authentication, RFC 8628's device flow, RFC 8693 for a narrower token, and a
JWT whose signature is checked against a key set that is fetched, not assumed.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import ssl
import stat
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from xrdsec import credentials, token_client
from xrdsec.proxies import load_credential
from xrdsec.testing.https import FakeHTTPSServer, Request, Response
from xrdsec.testing.pki import PKI

KID = "k1"


def _b64(raw: bytes) -> str:
    """base64url without padding, as JWS and JWK spell it."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwk(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, kid: str = KID) -> dict[str, str]:
    """The public half of ``key`` as a JWK the verifier understands."""
    if isinstance(key, rsa.RSAPrivateKey):
        rsa_numbers = key.public_key().public_numbers()
        width = (rsa_numbers.n.bit_length() + 7) // 8
        return {
            "kty": "RSA",
            "kid": kid,
            "n": _b64(rsa_numbers.n.to_bytes(width, "big")),
            "e": _b64(rsa_numbers.e.to_bytes((rsa_numbers.e.bit_length() + 7) // 8, "big")),
        }
    ec_numbers = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "kid": kid,
        "x": _b64(ec_numbers.x.to_bytes(32, "big")),
        "y": _b64(ec_numbers.y.to_bytes(32, "big")),
    }


def _signature(key: Any, body: str) -> str:
    """The signature ``key`` makes over ``body``, in JWS's own spelling."""
    if isinstance(key, rsa.RSAPrivateKey):
        return _b64(key.sign(body.encode(), padding.PKCS1v15(), hashes.SHA256()))
    first, second = decode_dss_signature(key.sign(body.encode(), ec.ECDSA(hashes.SHA256())))
    return _b64(first.to_bytes(32, "big") + second.to_bytes(32, "big"))


def _jwt(key: Any, claims: dict[str, Any], *, kid: str = KID, algorithm: str = "") -> str:
    """A token signed the way an issuer would sign it."""
    algorithm = algorithm or ("RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256")
    header = {"alg": algorithm, "typ": "JWT", "kid": kid}
    body = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
    return f"{body}.{_signature(key, body)}"


def _claims(**overrides: Any) -> dict[str, Any]:
    """A WLCG-profile token's claims; ``iss`` is filled in by the fixture that knows it."""
    now = time.time()
    claims: dict[str, Any] = {
        "iss": "",
        "sub": "rcurrie",
        "aud": [token_client.AUDIENCE],
        "scope": "storage.read:/eos/user/r/rcurrie storage.modify:/eos/user/r/rcurrie",
        "wlcg.ver": "1.0",
        "wlcg.groups": ["/lhcb", "/lhcb/Role=NULL/Capability=NULL"],
        "iat": int(now),
        "nbf": int(now) - 10,
        "exp": int(now) + 3600,
    }
    claims.update(overrides)
    return claims


class Issuer:
    """A fake issuer: the discovery documents, a token endpoint, a device endpoint, keys."""

    #: The CA directory these servers are signed by; the fixture fills it in.
    ca_path: str = ""

    def __init__(self, server: FakeHTTPSServer, key: Any) -> None:
        self.server = server
        self.key = key
        self.claims = _claims()
        self.oidc = True
        self.wlcg = True
        self.device = True
        self.reply: tuple[int, bytes] | None = None
        self.device_reply: dict[str, Any] | None = None
        self.keys_body: bytes | None = None
        self.doc_body: bytes | None = None
        self.forms: list[dict[str, str]] = []
        self.paths: list[str] = []
        self.identities: list[str] = []
        self.routes()

    @property
    def url(self) -> str:
        """Where a client starts looking: the fake server's base."""
        return self.server.url

    @property
    def identity(self) -> str:
        """The issuer identifier a token carries, distinct from where a client starts.

        A real deployment is like this: a storage element at one host names its
        issuer at another, and the token's ``iss`` is the latter.
        """
        return f"{self.server.url}/iam"

    def _issuer(self) -> token_client.Issuer:
        """The discovered issuer, for the calls a test makes directly."""
        (found,) = token_client.discover(self.url, ca_path=self._ca())
        return found

    def _ca(self) -> str:
        """The CA directory these servers are signed by (the fixture's)."""
        return str(self.ca_path)

    def routes(self) -> None:
        """Answer the GETs and POSTs a token client makes."""

        def document() -> bytes:
            """The OpenID configuration, built per request so a test can change it."""
            fields = {
                "issuer": self.identity,
                "token_endpoint": f"{self.url}/token",
                "jwks_uri": f"{self.url}/jwks",
            }
            if self.device:
                fields["device_authorization_endpoint"] = f"{self.url}/devicecode"
            return json.dumps(fields).encode()

        def oidc(request: Request) -> Response:
            return (
                Response(200, self.doc_body if self.doc_body is not None else document())
                if self.oidc
                else Response(404)
            )

        def wlcg(request: Request) -> Response:
            if not self.wlcg:
                return Response(404)
            return Response(200, json.dumps({"issuers": [self.identity]}).encode())

        self.server.route(
            "GET",
            r"/iam/\.well-known/openid-configuration",
            lambda request: Response(
                200, self.doc_body if self.doc_body is not None else document()
            ),
        )
        self.server.route("GET", r"/\.well-known/openid-configuration", oidc)
        self.server.route("GET", r"/\.well-known/wlcg-token", wlcg)
        self.server.route("GET", r"/jwks", lambda request: Response(200, self.keys()))
        self.server.route("POST", r"/token", self.token)
        self.server.route("POST", r"/devicecode", self.devicecode)

    def keys(self) -> bytes:
        """The JWKS document, with the key the tokens are signed under."""
        if self.keys_body is not None:
            return self.keys_body
        return json.dumps({"keys": [_jwk(self.key)]}).encode()

    def _record(self, request: Request) -> None:
        """Note the form, the path and the identity a request arrived with."""
        self.forms.append({k: v[0] for k, v in urllib_parse(request.body)})
        self.paths.append(request.path)
        self.identities.append(request.peer.identity if request.peer else "")

    def token(self, request: Request) -> Response:
        """The token endpoint."""
        self._record(request)
        if self.reply is not None:
            return Response(*self.reply)
        body = {
            "access_token": _jwt(self.key, {**self.claims, "iss": self.identity}),
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": self.claims["scope"],
        }
        return Response(200, json.dumps(body).encode())

    def devicecode(self, request: Request) -> Response:
        """The device authorization endpoint."""
        self._record(request)
        answer = self.device_reply or {
            "device_code": "dev-1",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://example.org/device",
            "verification_uri_complete": "https://example.org/device?c=ABCD-EFGH",
            "interval": 1,
            "expires_in": 600,
        }
        return Response(200, json.dumps(answer).encode())


def urllib_parse(body: bytes) -> list[tuple[str, list[str]]]:
    """A form body as ``(key, values)`` pairs, without importing more than needed."""
    import urllib.parse

    return list(urllib.parse.parse_qs(body.decode()).items())


def _optional_client_context(pki: PKI) -> ssl.SSLContext:
    """The host certificate, asking for a client certificate but not insisting on one.

    A real issuer is like this: its discovery documents are public and its
    token endpoint is authenticated, so one listener sees both.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pki.host_cert_path), str(pki.host_key_path))
    context.load_verify_locations(cafile=str(pki.ca_file))
    context.verify_mode = ssl.CERT_OPTIONAL
    context.verify_flags |= ssl.VERIFY_ALLOW_PROXY_CERTS
    return context


@pytest.fixture
def issuer(pki: PKI) -> Any:
    """A fake issuer that speaks to a client trusting the test CA."""
    with FakeHTTPSServer(tls=_optional_client_context(pki)) as server:
        made = Issuer(server, rsa.generate_private_key(public_exponent=65537, key_size=2048))
        made.ca_path = str(pki.ca_dir)
        yield made


# ---------------------------------------------------------------------------
# Finding the issuer
# ---------------------------------------------------------------------------


def test_an_issuer_is_read_from_its_own_document(issuer: Issuer) -> None:
    found = issuer._issuer()
    assert found.url == issuer.identity
    assert found.token_endpoint == f"{issuer.url}/token"
    assert found.jwks_uri == f"{issuer.url}/jwks"
    assert found.device_endpoint == f"{issuer.url}/devicecode"
    assert found.name.endswith("/iam")


def test_a_resource_server_names_the_issuers_it_trusts(issuer: Issuer) -> None:
    """The storage element's half of the profile: only ``/.well-known/wlcg-token`` answers."""
    issuer.oidc = False
    (found,) = token_client.discover(issuer.url, ca_path=issuer._ca())
    assert found.url == issuer.identity


def test_a_place_that_publishes_neither_is_refused(issuer: Issuer) -> None:
    issuer.oidc, issuer.wlcg = False, False
    with pytest.raises(token_client.TokenError, match="neither"):
        token_client.discover(issuer.url, ca_path=issuer._ca())


def test_a_document_without_a_token_endpoint_is_refused() -> None:
    """A discovery document that lost its endpoint is the failure this reports first."""
    with pytest.raises(token_client.TokenError, match="publishes no token endpoint"):
        token_client._issuer_of({"issuer": "https://x"}, "https://x")


def test_a_document_that_is_not_json_is_named() -> None:
    with pytest.raises(token_client.TokenError, match="not JSON"):
        token_client._json(200, b"?", "https://x/.well-known/openid-configuration")


# ---------------------------------------------------------------------------
# Asking for a token
# ---------------------------------------------------------------------------


def test_the_certificate_is_the_client_authentication(issuer: Issuer, pki: PKI) -> None:
    """X.509 client credentials: no secret, and the issuer sees the certificate's identity."""
    credential = load_credential(pki.user_cert_path, pki.user_key_path)
    token = token_client.acquire(
        issuer._issuer(),
        credential,
        scope="storage.read:/eos/user/r/rcurrie",
        client_id="my-client",
        ca_path=issuer._ca(),
    )
    form = issuer.forms[-1]
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == "my-client"
    assert form["audience"] == token_client.AUDIENCE
    assert form["scope"] == "storage.read:/eos/user/r/rcurrie"
    assert issuer.identities[-1] == str(credential.subject)
    assert token.claims["sub"] == "rcurrie" and token.time_left() > 3000


def test_a_narrower_token_is_an_exchange(issuer: Issuer) -> None:
    """RFC 8693: how a broad token becomes one that can only read one path."""
    token_client.exchange(
        issuer._issuer(),
        "the-token-i-hold",
        scope="storage.read:/eos/user/r/rcurrie",
        client_id="my-client",
        ca_path=issuer._ca(),
    )
    form = issuer.forms[-1]
    assert form["client_id"] == "my-client"
    assert form["grant_type"] == token_client.EXCHANGE
    assert form["subject_token"] == "the-token-i-hold"
    assert form["subject_token_type"] == token_client.ACCESS_TOKEN
    assert form["requested_token_type"] == token_client.ACCESS_TOKEN
    assert form["audience"] == token_client.AUDIENCE


def test_the_device_flow_hands_a_person_a_code(issuer: Issuer) -> None:
    started = token_client.device_authorization(
        issuer._issuer(), "my-client", scope="storage.read:/", ca_path=issuer._ca()
    )
    assert started["user_code"] == "ABCD-EFGH"
    assert issuer.forms[-1] == {"client_id": "my-client", "scope": "storage.read:/"}
    assert issuer.paths[-1] == "/devicecode"


def test_a_device_flow_that_is_not_published_says_so(issuer: Issuer) -> None:
    issuer.device = False
    (found,) = token_client.discover(issuer.url, ca_path=issuer._ca())
    with pytest.raises(token_client.TokenError, match="no device authorization endpoint"):
        token_client.device_authorization(found, "c", ca_path=issuer._ca())


def test_a_device_flow_without_a_client_id_says_so(issuer: Issuer) -> None:
    with pytest.raises(token_client.TokenError, match="needs a client id"):
        token_client.device_authorization(issuer._issuer(), "", ca_path=issuer._ca())


@pytest.mark.parametrize(
    ("error", "pending"),
    [(None, True), ("authorization_pending", True), ("slow_down", True)],
    ids=["approved", "pending", "slow-down"],
)
def test_a_poll_returns_a_token_or_says_to_wait(
    issuer: Issuer, error: str | None, pending: bool
) -> None:
    """RFC 8628's two pending answers are ``None``; every other refusal is raised."""
    if error is not None:
        issuer.reply = (400, json.dumps({"error": error, "error_description": "not yet"}).encode())
    polled = token_client.device_poll(issuer._issuer(), "my-client", "dev-1", ca_path=issuer._ca())
    if pending:
        assert (polled is None) is (error is not None)
        if error is None:
            assert polled is not None and polled.time_left() > 3000
    else:
        assert polled is None


def test_a_denied_device_flow_is_refused(issuer: Issuer) -> None:
    issuer.reply = (400, json.dumps({"error": "access_denied"}).encode())
    with pytest.raises(token_client.TokenError, match="access_denied"):
        token_client.device_poll(issuer._issuer(), "my-client", "dev-1", ca_path=issuer._ca())


# ---------------------------------------------------------------------------
# Refusals and transport
# ---------------------------------------------------------------------------


def test_an_issuer_that_says_no_is_quoted(issuer: Issuer) -> None:
    issuer.reply = (
        401,
        json.dumps({"error": "invalid_client", "error_description": "no such client"}).encode(),
    )
    with pytest.raises(token_client.TokenError, match="invalid_client - no such client"):
        token_client.exchange(issuer._issuer(), "t", ca_path=issuer._ca())


@pytest.mark.parametrize(
    ("status", "body"),
    [(500, b"<html>oops</html>"), (400, b'{"something": "else"}')],
    ids=["not-json", "json-without-error"],
)
def test_a_refusal_says_what_came_back(issuer: Issuer, status: int, body: bytes) -> None:
    issuer.reply = (status, body)
    with pytest.raises(
        token_client.TokenError, match=rf"refused the request \({status}\)|not JSON"
    ):
        token_client.exchange(issuer._issuer(), "t", ca_path=issuer._ca())


def test_an_answer_that_is_not_an_object_is_refused(issuer: Issuer) -> None:
    issuer.reply = (200, b"[1, 2]")
    with pytest.raises(token_client.TokenError, match="not an object"):
        token_client.exchange(issuer._issuer(), "t", ca_path=issuer._ca())


def test_an_answer_without_a_token_is_refused(issuer: Issuer) -> None:
    issuer.reply = (200, b'{"scope": "x"}')
    with pytest.raises(token_client.TokenError, match="without an access token"):
        token_client.exchange(issuer._issuer(), "t", ca_path=issuer._ca())


def test_a_token_request_over_plain_http_is_refused() -> None:
    issuer = token_client.Issuer("http://x/", "http://x/token", "")
    with pytest.raises(token_client.TokenError, match="not https"):
        token_client.exchange(issuer, "t")


def test_a_connection_that_cannot_be_made_says_which_url() -> None:
    issuer = token_client.Issuer("https://127.0.0.1:9/", "https://127.0.0.1:9/token", "")
    with pytest.raises(token_client.TokenError, match="cannot talk to"):
        token_client.exchange(issuer, "t", timeout=2)


def test_an_untrusted_issuer_certificate_is_named_as_such(issuer: Issuer) -> None:
    """The CA directory a transfer trusts is the one a token request trusts."""
    found = token_client.Issuer(issuer.identity, f"{issuer.url}/token", "")
    with pytest.raises(token_client.TokenError, match="certificate is not trusted"):
        token_client.exchange(found, "t", ca_path=None)  # the system store, not the test CA


# ---------------------------------------------------------------------------
# Believing a token
# ---------------------------------------------------------------------------


def test_a_genuine_token_verifies(issuer: Issuer) -> None:
    claims = token_client.verify(
        _jwt(issuer.key, _claims(iss=issuer.identity)),
        issuer=issuer._issuer(),
        audience=token_client.AUDIENCE,
        ca_path=issuer._ca(),
    )
    assert claims["wlcg.ver"] == "1.0" and "/lhcb" in claims["wlcg.groups"]


def test_a_token_signed_with_an_elliptic_curve_key_verifies(issuer: Issuer) -> None:
    """``ES256`` is the other half of the profile, and its signature is raw ``r||s``."""
    key = ec.generate_private_key(ec.SECP256R1())
    issuer.keys_body = json.dumps({"keys": [_jwk(key)]}).encode()
    claims = token_client.verify(
        _jwt(key, _claims(iss=issuer.identity)), issuer=issuer._issuer(), ca_path=issuer._ca()
    )
    assert claims["sub"] == "rcurrie"


@pytest.mark.parametrize(
    ("claims", "audience", "code"),
    [
        (_claims(aud=["https://other.example.org"]), token_client.AUDIENCE, "wrong_audience"),
        (_claims(iss="https://not.example.org"), None, "wrong_issuer"),
        (_claims(exp=int(time.time()) - 3600), None, "expired"),
        (_claims(nbf=int(time.time()) + 3600), None, "not_yet"),
        ({"iss": "", "aud": [token_client.AUDIENCE]}, None, "no_expiry"),
    ],
    ids=["audience", "issuer", "expired", "nbf", "no-exp"],
)
def test_a_token_that_is_not_what_was_asked_for_is_refused(
    issuer: Issuer, claims: dict[str, Any], audience: str | None, code: str
) -> None:
    claims = {**claims, "iss": claims.get("iss") or issuer.identity}
    with pytest.raises(token_client.TokenError) as refused:
        token_client.verify(
            _jwt(issuer.key, claims),
            issuer=issuer._issuer(),
            audience=audience,
            ca_path=issuer._ca(),
        )
    assert refused.value.code == code


def test_a_signature_from_another_key_is_refused(issuer: Issuer) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(token_client.TokenError, match="signature does not check out"):
        token_client.verify(_jwt(other, _claims()), issuer=issuer._issuer(), ca_path=issuer._ca())


def test_a_key_the_set_does_not_have_is_refused(issuer: Issuer) -> None:
    with pytest.raises(token_client.TokenError, match="no single key"):
        token_client.verify(
            _jwt(issuer.key, _claims(), kid="elsewhere"),
            issuer=issuer._issuer(),
            ca_path=issuer._ca(),
        )


def test_a_token_with_a_claim_that_is_not_a_number_is_refused(issuer: Issuer) -> None:
    with pytest.raises(token_client.TokenError, match="exp claim is not a number"):
        token_client.verify(
            _jwt(issuer.key, _claims(exp="soon")), issuer=issuer._issuer(), ca_path=issuer._ca()
        )


def test_something_that_is_not_a_jwt_is_refused(issuer: Issuer) -> None:
    with pytest.raises(token_client.TokenError, match="three segments"):
        token_client.verify("not-a-token", issuer=issuer._issuer(), ca_path=issuer._ca())


def test_a_header_or_claims_that_are_not_objects_are_refused() -> None:
    header = _b64(b"[1]")
    with pytest.raises(token_client.TokenError, match="header is not a JSON object"):
        token_client.verify(f"{header}.{_b64(b'{}')}.{_b64(b's')}", jwks={"keys": []})
    body = _b64(b"{")
    with pytest.raises(token_client.TokenError, match="claims is not JSON"):
        token_client.verify(f"{_b64(b'{}')}.{body}.{_b64(b's')}", jwks={"keys": []})


def test_a_header_without_an_algorithm_is_refused() -> None:
    with pytest.raises(token_client.TokenError, match="names no algorithm"):
        token_client.verify(f"{_b64(b'{}')}.{_b64(b'{}')}.{_b64(b's')}", jwks={"keys": []})


def test_an_empty_or_ambiguous_key_set_is_refused() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _jwt(key, _claims())
    with pytest.raises(token_client.TokenError, match="key set is empty"):
        token_client.verify(token, jwks={"keys": []})
    with pytest.raises(token_client.TokenError, match="no single key"):
        token_client.verify(token, jwks={"keys": [{"kid": "a"}, {"kid": "b"}]})


@pytest.mark.parametrize(
    "algorithm", ["RS999", "XX256", "ES999"], ids=["bad-digest", "bad-family", "bad-curve"]
)
def test_an_algorithm_this_cannot_verify_says_so(algorithm: str) -> None:
    header = _b64(json.dumps({"alg": algorithm}).encode())
    token = f"{header}.{_b64(b'{}')}.{_b64(b's')}"
    keys = {
        "keys": [
            {
                "kid": None,
                "n": _b64(b"\x01"),
                "e": _b64(b"\x01"),
                "x": _b64(b"\x01"),
                "y": _b64(b"\x01"),
            }
        ]
    }
    with pytest.raises(token_client.TokenError, match=r"not a JWS algorithm|no digest|no curve"):
        token_client.verify(token, jwks=keys)


def test_a_key_without_numbers_is_refused(issuer: Issuer) -> None:
    with pytest.raises(token_client.TokenError, match="has no 'n'"):
        token_client.verify(_jwt(issuer.key, _claims()), jwks={"keys": [{"kid": KID, "e": "AQAB"}]})


def test_a_token_with_no_key_set_to_check_against_is_refused() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(token_client.TokenError, match="no key set"):
        token_client.verify(_jwt(key, _claims()))
    without = token_client.Issuer("https://x/", "https://x/token", "")
    with pytest.raises(token_client.TokenError, match="no key set"):
        token_client.verify(_jwt(key, _claims()), issuer=without)


# ---------------------------------------------------------------------------
# The token object, and where it goes
# ---------------------------------------------------------------------------


def test_a_token_knows_its_own_times(issuer: Issuer) -> None:
    token = token_client.Token(access_token=_jwt(issuer.key, _claims()))
    assert token.time_left() > 3000 and token.expiry > time.time()
    assert token.claims["sub"] == "rcurrie"


@pytest.mark.parametrize(
    ("claims", "expires_in"),
    [({"sub": "x"}, 600), ({"exp": "soon"}, 0)],
    ids=["no-exp", "unreadable-exp"],
)
def test_a_token_without_a_readable_exp_falls_back_to_expires_in(
    issuer: Issuer, claims: dict[str, Any], expires_in: float
) -> None:
    token = token_client.Token(access_token=_jwt(issuer.key, claims), expires_in=expires_in)
    assert token.expiry > time.time() + 300


def test_an_issuer_names_itself_the_way_a_person_recognises_it() -> None:
    assert token_client.Issuer("https://a/iam/x", "t", "j").name == "a/x"
    assert token_client.Issuer("https://a", "t", "j").name == "a"


def test_a_token_is_written_where_the_discovery_specification_reads(tmp_path: pathlib.Path) -> None:
    runtime = tmp_path / "run"
    runtime.mkdir()
    environ = {"XDG_RUNTIME_DIR": str(runtime), "HOME": str(tmp_path)}
    path = token_client.write_token("the-token\n", environ=environ, uid=os.geteuid())
    assert path == str(runtime / f"bt_u{os.geteuid()}")
    assert pathlib.Path(path).read_bytes() == b"the-token\n"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_a_token_file_named_in_the_environment_wins(tmp_path: pathlib.Path) -> None:
    chosen = tmp_path / "mine.token"
    environ = {"BEARER_TOKEN_FILE": str(chosen), "HOME": str(tmp_path)}
    assert token_client.token_file_path(environ=environ) == str(chosen)


def test_writing_through_a_symlink_is_refused(tmp_path: pathlib.Path) -> None:
    """The ``/tmp`` name is predictable: a link there must not be written through."""
    target = tmp_path / "elsewhere"
    target.write_text("")
    link = tmp_path / "bt"
    link.symlink_to(target)
    with pytest.raises(token_client.TokenError, match="cannot write"):
        token_client.write_token("t", str(link), environ={}, uid=os.geteuid())


def test_nowhere_to_write_a_token_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "bearer_token_files", lambda *a, **k: [])
    with pytest.raises(token_client.TokenError, match="nowhere to write"):
        token_client.token_file_path({}, 501)


def test_the_token_a_client_would_present_is_read_back(tmp_path: pathlib.Path) -> None:
    chosen = tmp_path / "chosen"
    chosen.write_text("the-token")
    chosen.chmod(0o600)
    token, source = token_client.read_token(environ={"BEARER_TOKEN_FILE": str(chosen)}, uid=501)
    assert token == "the-token" and source == "$BEARER_TOKEN_FILE"
    with pytest.raises(token_client.TokenError, match="no bearer token"):
        token_client.read_token(environ={}, uid=501)


def test_a_duration_reads_as_a_person_says_it() -> None:
    assert token_client._human(45) == "45s"
    assert token_client._human(90) == "1m"
    assert token_client._human(7200) == "2h 0m"


def test_a_lifetime_that_is_not_a_number_counts_as_none() -> None:
    assert token_client._float("soon") == 0.0
    assert token_client._float(12) == 12.0


# ---------------------------------------------------------------------------
# The knobs nobody turns: defaults left out, and the small refusals
# ---------------------------------------------------------------------------


def test_a_request_leaves_out_what_was_not_asked_for(issuer: Issuer, pki: PKI) -> None:
    """Empty values are omitted, not sent as empty form fields an issuer would read literally."""
    credential = load_credential(pki.user_cert_path, pki.user_key_path)
    token_client.acquire(
        issuer._issuer(), credential, audience="", scope="", client_id="", ca_path=issuer._ca()
    )
    assert issuer.forms[-1] == {"grant_type": "client_credentials"}
    token_client.exchange(
        issuer._issuer(), "t", audience="", scope="", client_id="", ca_path=issuer._ca()
    )
    assert issuer.forms[-1] == {
        "grant_type": token_client.EXCHANGE,
        "subject_token": "t",
        "subject_token_type": token_client.ACCESS_TOKEN,
        "requested_token_type": token_client.ACCESS_TOKEN,
    }


def test_a_discovery_document_that_fails_other_than_by_not_existing_raises() -> None:
    """A 404 means "not published here"; a broken answer is reported, not swallowed."""
    context = ssl.create_default_context()
    with pytest.raises(token_client.TokenError, match="cannot talk to"):
        token_client._document("https://127.0.0.1:9/x", context, 2)


def test_a_segment_that_cannot_be_decoded_at_all_is_refused() -> None:
    with pytest.raises(token_client.TokenError, match="not base64url"):
        token_client._decode(None)  # type: ignore[arg-type]  # a caller that is not a string


def test_an_issuer_that_was_not_named_is_not_checked_for(issuer: Issuer) -> None:
    """A token verified without an issuer is checked for signature and times only."""
    claims = token_client.verify(
        _jwt(issuer.key, _claims(iss="https://anywhere.example.org")),
        issuer=None,
        jwks={"keys": [_jwk(issuer.key)]},
    )
    assert claims["iss"] == "https://anywhere.example.org"


# ---------------------------------------------------------------------------
# What a token endpoint is trusted with
# ---------------------------------------------------------------------------


def test_a_token_endpoint_is_trusted_with_the_system_store_as_well(monkeypatch: Any) -> None:
    """An IAM carries a public web certificate: the grid bundle alone cannot vouch for it.

    Trusting only the grid CA directory failed with "unable to get local issuer
    certificate" on a machine whose bundle was absent - while every provider
    verifies from the operating system's store.
    """
    from xrdsec import tls

    seen: dict[str, Any] = {}

    def captured(**kwargs: Any) -> Any:
        seen.update(kwargs)
        return ssl.create_default_context()

    monkeypatch.setattr(tls, "client_context", captured)
    token_client._context(None, "/some/where")
    assert seen["system_ca"] is True
    assert seen["ca_path"] == "/some/where"
    assert seen["credential_pem"] is None


def test_the_grid_directory_is_still_used_when_none_was_named(monkeypatch: Any) -> None:
    from xrdsec import tls

    seen: dict[str, Any] = {}
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: "/grid/certs")
    monkeypatch.setattr(
        tls, "client_context", lambda **kwargs: seen.update(kwargs) or ssl.create_default_context()
    )
    token_client._context(None, None)
    assert seen["ca_path"] == "/grid/certs"
    assert seen["system_ca"] is True


# ---------------------------------------------------------------------------
# The token DIRAC keeps inside a proxy file
# ---------------------------------------------------------------------------


def _diracx_pem(token: dict[str, Any]) -> str:
    """A proxy-shaped file with DIRAC's own token block in it."""
    payload = base64.b64encode(json.dumps(token).encode()).decode()
    return (
        "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
        f"{token_client.DIRACX_BEGIN}\n{payload}\n{token_client.DIRACX_END}\n"
    )


def test_a_dirac_proxy_carries_its_token_in_a_block_of_its_own() -> None:
    """`dirac-login` exchanges the proxy for a token and writes both into one file.

    That is DIRAC's way in without a device flow or a registered client: the
    proxy authenticates the RPC, the server mints the token, and the file ends up
    carrying both. Reading the block needs nothing of DIRAC.
    """
    token = {
        "access_token": "header.payload.signature",
        "expires_in": 3600,
        "token_type": "Bearer",
        "refresh_token": "refresh",
    }
    found = token_client.embedded(_diracx_pem(token))
    assert found is not None and found["refresh_token"] == "refresh"
    assert token_client.from_pem(_diracx_pem(token)).expires_in == 3600


def test_an_ordinary_proxy_carries_no_token() -> None:
    with pytest.raises(token_client.TokenError, match="no DIRACX token block"):
        token_client.from_pem("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    assert token_client.embedded("nothing here") is None


def test_a_dirac_block_that_is_not_base64_json_is_refused() -> None:
    broken = f"{token_client.DIRACX_BEGIN}\n!!!\n{token_client.DIRACX_END}\n"
    with pytest.raises(token_client.TokenError, match="not base64 JSON"):
        token_client.embedded(broken)
    nothing = base64.b64encode(b"{}").decode()
    empty = f"{token_client.DIRACX_BEGIN}\n{nothing}\n{token_client.DIRACX_END}\n"
    with pytest.raises(token_client.TokenError, match="carries no access token"):
        token_client.embedded(empty)
