"""WLCG bearer token discovery, and the unverified expiry check."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from xrdcore.errors import InsecureCredentialError, TokenExpiredError
from xrdsec import credentials, tokens


@pytest.fixture
def tmp(monkeypatch, tmp_path):
    """Point the last-resort ``/tmp/bt_u<uid>`` at a directory of the test's own."""
    directory = tmp_path / "tmp"
    directory.mkdir()
    monkeypatch.setattr(credentials, "TMP_DIR", str(directory))
    return directory


def secret(path: Path, text: str = "tok", mode: int = 0o600) -> Path:
    path.write_text(text)
    os.chmod(path, mode)
    return path


def name() -> str:
    return f"bt_u{os.geteuid()}"


def test_nothing_anywhere_is_none(tmp):
    assert tokens.discover_token() is None


def test_the_specification_order(tmp, tmp_path, monkeypatch):
    runtime = tmp_path / "run"
    runtime.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    secret(tmp / name(), "from-tmp")
    assert tokens.discover_token() == "from-tmp"
    secret(runtime / name(), "from-runtime\n")
    assert tokens.discover_token() == "from-runtime"
    env_file = secret(tmp_path / "env-file", "from-env-file")
    monkeypatch.setenv("BEARER_TOKEN_FILE", str(env_file))
    assert tokens.discover_token() == "from-env-file"
    monkeypatch.setenv("BEARER_TOKEN", " from-env ")
    assert tokens.discover_token() == "from-env"
    # The default token_file setting is $BEARER_TOKEN_FILE: still step 5.
    assert tokens.discover_token(token_file=str(env_file)) == "from-env"
    explicit = secret(tmp_path / "explicit", "from-explicit")
    assert tokens.discover_token(token_file=str(explicit)) == "from-explicit"
    assert tokens.discover_token(token="configured", token_file=str(explicit)) == "configured"
    query = {"authz": "Bearer from-url"}
    assert tokens.discover_token(token="configured", query=query) == "from-url"


def test_blank_steps_pass_to_the_next(tmp, tmp_path, monkeypatch):
    monkeypatch.setenv("BEARER_TOKEN", "   ")
    monkeypatch.setenv("BEARER_TOKEN_FILE", str(secret(tmp_path / "blank", "\n")))
    secret(tmp / name(), "last")
    assert tokens.discover_token(token="", query={"access_token": ""}) == "last"


def test_environ_replaces_the_process_environment(tmp):
    assert tokens.discover_token(environ={"BEARER_TOKEN": "given"}) == "given"
    assert tokens.token_files(environ={}) == [(os.path.join(str(tmp), name()), True)]


def test_url_token():
    assert tokens.url_token({"access_token": "abc"}) == "abc"
    assert tokens.url_token({"other": "x"}) is None


def test_explicit_token_file():
    env = {"BEARER_TOKEN_FILE": "/a"}
    assert tokens.explicit_token_file("/a", env) is None
    assert tokens.explicit_token_file("/b", env) == "/b"
    assert tokens.explicit_token_file(None, env) is None


def test_a_shared_token_file_is_refused_not_skipped(tmp):
    secret(tmp / name(), mode=0o644)
    with pytest.raises(InsecureCredentialError, match="chmod 600"):
        tokens.discover_token()


def test_a_symlink_at_a_predictable_name_is_refused(tmp, tmp_path):
    real = secret(tmp_path / "real")
    (tmp / name()).symlink_to(real)
    with pytest.raises(InsecureCredentialError, match="symbolic link"):
        tokens.discover_token()


def test_a_named_file_may_be_a_symlink(tmp, tmp_path, monkeypatch):
    real = secret(tmp_path / "real", "linked")
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setenv("BEARER_TOKEN_FILE", str(link))
    assert tokens.discover_token() == "linked"


def test_an_unreadable_file_raises_or_is_skipped(tmp, tmp_path, monkeypatch):
    directory = tmp_path / "dir"
    directory.mkdir()
    monkeypatch.setenv("BEARER_TOKEN_FILE", str(directory / "missing" / "x"))
    assert tokens.discover_token() is None  # missing: next step
    monkeypatch.setattr(
        credentials, "read_private_file", lambda *a, **k: (_ for _ in ()).throw(OSError(5, "EIO"))
    )
    with pytest.raises(OSError, match="EIO"):
        tokens.discover_token()
    assert tokens.discover_token(skip_unreadable=True) is None


def _jwt(claims: object) -> str:
    def part(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


def test_token_claims_are_read_strictly():
    assert tokens.token_claims(_jwt({"exp": 5})) == {"exp": 5}
    assert tokens.token_claims("not.a.jwt!") == {}
    assert tokens.token_claims("macaroon") == {}
    padded = _jwt({"exp": 5}).split(".")
    padded[1] += "="
    assert tokens.token_claims(".".join(padded)) == {}
    array = base64.urlsafe_b64encode(b"[1]").rstrip(b"=").decode()
    assert tokens.token_claims(f"{array}.{array}.x") == {}


def _segment(value: object) -> str:
    """``value`` as JSON (or raw bytes as given), base64url, padding off."""
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


#: ``{"alg":"none"}``, 19 characters: one short of a whole quantum, so it can take an ``=``.
_HEADER = "eyJhbGciOiJub25lIn0"


def test_the_signature_segment_is_never_decoded():
    """Expiry inspection must not depend on it."""
    assert tokens.token_claims(f"{_HEADER}.{_segment({'exp': 1})}.!!not base64!!") == {"exp": 1}


def test_whole_quantum_padding_is_the_xrootd_clients_reading():
    """Some issuers keep the ``=``: with ``padding=True`` it is fine where it ends a quantum."""
    one, two = _segment({"exp": 12}), _segment({"exp": 1})
    assert (len(one) % 4, len(two) % 4) == (3, 2)
    assert tokens.token_claims(f"{_HEADER}.{one}=.sig", padding=True) == {"exp": 12}
    assert tokens.token_claims(f"{_HEADER}.{two}==.sig", padding=True) == {"exp": 1}
    assert tokens.token_claims(f"{_HEADER}=.{two}.sig", padding=True) == {"exp": 1}
    assert tokens.token_claims(f"{_HEADER}.{one}=.sig") == {}  # gfal2's reading refuses it


@pytest.mark.parametrize(
    "payload",
    [
        _segment({"exp": 1}) + "===",  # more padding than base64 ever needs
        _segment({"exp": 123}) + "=",  # padding where none was needed
        _segment({"exp": 12}) + "==",  # more padding than this one needed
        "+" + _segment({"exp": 1})[1:],  # the other base64 alphabet
        _segment({"exp": 1})[:4] + "=" + _segment({"exp": 1})[4:],  # padding inside
        _segment({"exp": 1}) + "!",  # not base64 of any kind
        "A" * 5,  # a length no base64 encoding has
        _segment({"a": 1})[:-1] + "1",  # spare bits set: non-canonical
        _segment(b"\x80not text"),  # not UTF-8
        _segment(b"{not json"),
        _segment(b"[" * 100_000),  # unterminated nesting
        _segment([1, 2]),  # JSON, but not an object
        "",  # nothing at all
    ],
    ids=lambda payload: f"{len(payload)}-chars",
)
@pytest.mark.parametrize("padding", [False, True])
def test_a_malformed_payload_has_no_claims(payload, padding):
    """Strict either way: two different strings never decode to the same claims."""
    assert tokens.token_claims(f"{_HEADER}.{payload}.sig", padding=padding) == {}


@pytest.mark.parametrize("header", [_segment([]), _segment(b"nope"), "!", ""])
def test_a_malformed_header_has_no_claims(header):
    assert tokens.token_claims(f"{header}.{_segment({'exp': 1})}.sig") == {}


def test_a_detached_payload_has_no_claims():
    """RFC 7797 ``"b64": false``: the claims are not in the token."""
    header = _segment({"alg": "none", "b64": False})
    assert tokens.token_claims(f"{header}.{_segment({'exp': 1})}.sig") == {}


def test_exactly_three_segments_make_a_jwt():
    payload = _segment({"exp": 1})
    assert tokens.token_claims(f"{_HEADER}.{payload}.sig.extra") == {}
    assert tokens.token_claims(f"{_HEADER}.{payload}") == {}


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"exp": 4102444800}, 4102444800.0),
        ({"exp": "4102444800"}, 4102444800.0),
        ({}, None),
        ({"exp": 1.5}, None),  # NumericDate is whole seconds here
        ({"exp": -1}, None),
        ({"exp": True}, None),
        ({"exp": None}, None),
    ],
)
def test_token_expiry_reads_whole_seconds_only(claims, expected):
    assert tokens.token_expiry(_jwt(claims)) == expected
    assert tokens.token_expiry("opaque") is None


def test_check_token():
    tokens.check_token(_jwt({"exp": 2000}), now=1000)
    tokens.check_token(_jwt({"exp": "soon"}))
    tokens.check_token(_jwt({"exp": None}))
    tokens.check_token("opaque")
    with pytest.raises(TokenExpiredError, match="expired"):
        tokens.check_token(_jwt({"exp": "500"}), now=1000)
    with pytest.raises(TokenExpiredError):
        tokens.check_token(_jwt({"exp": 1}))


def test_a_url_token_comes_first_and_loses_its_scheme(tmp, monkeypatch):
    monkeypatch.setenv("BEARER_TOKEN", "env")
    assert tokens.discover_token(query={"authz": "Bearer url"}, token="configured") == "url"
    assert tokens.discover_token(query={"other": "x"}, token="configured") == "configured"


def test_the_files_listed_follow_the_explicit_rule(tmp, monkeypatch):
    monkeypatch.setenv("BEARER_TOKEN_FILE", "/from/env")
    inherited = tokens.token_files("/from/env", uid=5)
    assert inherited[0] == ("/from/env", False) and len(inherited) == 3
    assert tokens.token_files("/named", uid=5)[:2] == [("/named", False), ("/from/env", False)]


def test_json_nesting_too_deep_for_the_parser_is_no_claims(monkeypatch):
    """Python 3.11-3.13's ``json`` recurses and gives up with ``RecursionError``.

    3.14's parser is iterative, so the deep payload above parses there; the
    seam stands in for the older interpreters, where it does not.
    """

    def too_deep(_text):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(json, "loads", too_deep)
    assert tokens.token_claims(f"{_HEADER}.{_segment({'exp': 1})}.sig") == {}
