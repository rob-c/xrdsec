"""``xrdsec.credentials``: grid credential discovery as a public, environment-explicit API.

Ported from xrdclient's ``tests/test_credentials.py``; its tests of
xrdclient's own Config-shaped adapters became tests of the keywords xrdsec
adds instead (gfal2's ``skip_unreadable``).

Every lookup takes the environment (and, where a file name carries it, the
uid) as an argument, so these tests pass a mapping and an unused uid instead
of patching the process - which is the point of the API: a tool with a
configuration file of its own, or a test, asks without side effects. The
one exception is the last-resort ``/tmp/bt_u<uid>`` step, whose directory is
the module's :data:`~xrdsec.credentials.TMP_DIR`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from xrdcore.errors import CredentialError, InsecureCredentialError
from xrdsec import credentials

#: A uid nobody on a test machine has, so ``/tmp/x509up_u<uid>`` and
#: ``/tmp/bt_u<uid>`` are never a real user's files.
NOBODY = 2_147_483_000 + os.getpid() % 600


def _private(path: Path, data: bytes | str = b"secret", mode: int = 0o600) -> str:
    """Write ``data`` at ``path`` with ``mode``; return the path as text."""
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)
    return str(path)


@pytest.fixture
def hermetic_tmp(tmp_path, monkeypatch):
    """An empty stand-in for ``/tmp``, the one location that is not an argument."""
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp))
    return tmp


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------


def test_the_ca_directory_comes_from_the_environment_given(tmp_path):
    assert credentials.grid_ca_path({"X509_CERT_DIR": str(tmp_path)}) == str(tmp_path)
    assert credentials.grid_voms_dir({"X509_VOMS_DIR": " /v "}) == "/v"


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_a_blank_ca_directory_is_unset_not_the_current_directory(blank, monkeypatch):
    """The xrdarc bug: ``X509_CERT_DIR=`` handed ``""`` to OpenSSL as a CA path."""
    monkeypatch.setattr(os.path, "isdir", lambda _path: False)
    assert credentials.grid_ca_path({"X509_CERT_DIR": blank}) is None
    assert credentials.default_ca_path({"X509_CERT_DIR": blank}) == credentials.DEFAULT_CA_PATH


def test_the_process_environment_is_the_default(tmp_path, monkeypatch):
    monkeypatch.setenv("X509_CERT_DIR", str(tmp_path))
    assert credentials.grid_ca_path() == str(tmp_path)


def test_grid_security_dirs_steer_every_grid_wide_lookup(tmp_path, monkeypatch):
    """The attribute replaces the platform's ``grid-security`` homes, so a suite is hermetic."""
    grid = tmp_path / "grid-security"
    (grid / "certificates").mkdir(parents=True)
    (grid / "vomsdir").mkdir()
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", (str(tmp_path / "none"), str(grid)))
    assert credentials.grid_ca_path({}) == str(grid / "certificates")
    assert credentials.grid_voms_dir({}) == str(grid / "vomsdir")
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", ())
    assert credentials.grid_ca_path({}) is None
    assert credentials.default_ca_path({}) == credentials.DEFAULT_CA_PATH
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", None)
    assert credentials._candidates("vomsdir")[0] == "/etc/grid-security/vomsdir"


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------


def test_the_default_proxy_path_names_the_uid_given(monkeypatch):
    monkeypatch.setattr(credentials, "TMP_DIR", "/tmp")
    assert credentials.default_proxy_path({}, uid=1234) == "/tmp/x509up_u1234"
    assert credentials.default_proxy_path({"X509_USER_PROXY": " /p "}, uid=1) == "/p"
    assert credentials.default_proxy_path({"X509_USER_PROXY": "  "}, uid=7) == "/tmp/x509up_u7"


def test_a_named_proxy_is_the_answer_even_when_missing(tmp_path):
    """Never swapped for a guess; whether missing is an error is the caller's call."""
    named = str(tmp_path / "absent")
    found = credentials.find_proxy({"X509_USER_PROXY": named}, uid=NOBODY, extra=[tmp_path])
    assert found == named


def test_with_nothing_named_the_first_default_that_is_there_wins(tmp_path):
    assert credentials.find_proxy({}, uid=NOBODY) is None
    first, second = tmp_path / "a", tmp_path / "b"
    _private(second)
    assert credentials.find_proxy({}, uid=NOBODY, extra=[first, second]) == str(second)
    _private(first)
    assert credentials.find_proxy({}, uid=NOBODY, extra=[first, second]) == str(first)


def test_a_missing_directory_on_the_way_is_nothing_there(tmp_path):
    _private(tmp_path / "file")
    assert credentials.find_proxy({}, uid=NOBODY, extra=[tmp_path / "file" / "x"]) is None


@pytest.mark.parametrize(
    ("arrange", "match"),
    [
        (lambda p, t: _private(p, mode=0o644), "chmod 600"),
        (lambda p, t: p.symlink_to(_private(t)), "symbolic link"),
        (lambda p, t: p.mkdir(), "not a regular file"),
    ],
    ids=["readable", "link", "directory"],
)
def test_something_unsafe_at_a_default_location_is_refused(tmp_path, arrange, match):
    """Not skipped: the next location would log in as whoever planted this one."""
    planted = tmp_path / "x509up"
    arrange(planted, tmp_path / "target")
    _private(tmp_path / "fine")
    with pytest.raises(InsecureCredentialError, match=match):
        credentials.find_proxy({}, uid=NOBODY, extra=[planted, tmp_path / "fine"])


def test_the_process_environment_names_the_proxy_by_default(monkeypatch):
    monkeypatch.setenv("X509_USER_PROXY", "/from/env")
    assert credentials.default_proxy_path() == "/from/env"
    assert credentials.find_proxy() == "/from/env"


# ---------------------------------------------------------------------------
# User certificate and key
# ---------------------------------------------------------------------------


def test_the_named_pair_wins(tmp_path):
    env = {"X509_USER_CERT": "/c.pem", "X509_USER_KEY": " /k.pem "}
    assert credentials.find_user_credential(env) == ("/c.pem", "/k.pem")


def test_half_a_pair_is_ignored_and_the_home_directory_searched(tmp_path):
    globus = tmp_path / ".globus"
    globus.mkdir()
    env = {"HOME": str(tmp_path), "X509_USER_CERT": "/c.pem"}
    assert credentials.find_user_credential(env) is None
    _private(globus / "usercert.pem")
    assert credentials.find_user_credential(env) is None  # no key yet
    _private(globus / "userkey.pem")
    assert credentials.find_user_credential(env) == (
        str(globus / "usercert.pem"),
        str(globus / "userkey.pem"),
    )


def test_other_directories_are_searched_in_the_order_given(tmp_path):
    for name in ("arc", "globus"):
        (tmp_path / name).mkdir()
        _private(tmp_path / name / "usercert.pem")
        _private(tmp_path / name / "userkey.pem")
    env = {"HOME": str(tmp_path)}
    found = credentials.find_user_credential(env, dirs=("~/arc", tmp_path / "globus"))
    assert found is not None
    cert, _key = found
    assert cert == str(tmp_path / "arc" / "usercert.pem")


def test_without_home_in_the_environment_given_the_users_home_is_used(tmp_path, monkeypatch):
    """``~`` is then this process's home - here a directory of the test's own."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _private(tmp_path / "usercert.pem")
    _private(tmp_path / "userkey.pem")
    # ``~user`` is that user's home, which only the password database knows.
    assert credentials.find_user_credential({}, dirs=("~nonesuch-user-xrd",)) is None
    assert credentials.find_user_credential({}, dirs=("~",)) == (
        str(tmp_path / "usercert.pem"),
        str(tmp_path / "userkey.pem"),
    )


# ---------------------------------------------------------------------------
# Bearer token
# ---------------------------------------------------------------------------


def test_each_step_of_the_wlcg_order_outranks_the_next(tmp_path, hermetic_tmp):
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    env = {
        "BEARER_TOKEN": "env",
        "BEARER_TOKEN_FILE": _private(tmp_path / "env-file", "env_file"),
        "XDG_RUNTIME_DIR": str(xdg),
    }
    _private(xdg / f"bt_u{NOBODY}", "xdg")
    _private(hermetic_tmp / f"bt_u{NOBODY}", "tmp\n")
    named = _private(tmp_path / "named", " named\n")

    def find(**kwargs: Any) -> str | None:
        return credentials.find_bearer_token(env, NOBODY, **kwargs)

    assert find(explicit="explicit", token_file=named) == "explicit"
    assert find(token_file=named) == "named"
    assert find() == "env"
    del env["BEARER_TOKEN"]
    assert find() == "env_file"
    del env["BEARER_TOKEN_FILE"]
    assert find() == "xdg"
    del env["XDG_RUNTIME_DIR"]
    assert find() == "tmp"
    assert credentials.find_bearer_token({}, NOBODY + 1) is None


def test_blank_values_and_missing_files_pass_to_the_next_step(tmp_path, hermetic_tmp):
    env = {"BEARER_TOKEN": "  ", "BEARER_TOKEN_FILE": str(tmp_path / "absent")}
    _private(hermetic_tmp / f"bt_u{NOBODY}", "last")
    empty = _private(tmp_path / "empty", "\n")
    assert credentials.find_bearer_token(env, NOBODY, explicit=" ", token_file=empty) == "last"


def test_an_insecure_token_file_raises_instead_of_falling_through(tmp_path, hermetic_tmp):
    """The xrdarc bug: this surfaced as an uncaught gfal2 ``GError``."""
    _private(hermetic_tmp / f"bt_u{NOBODY}", "fallback")
    leaked = _private(tmp_path / "leaked", "tok", mode=0o644)
    with pytest.raises(InsecureCredentialError, match="chmod 600"):
        credentials.find_bearer_token({"BEARER_TOKEN_FILE": leaked}, NOBODY)
    # A step that already answered means the file is never opened.
    env = {"BEARER_TOKEN": "env", "BEARER_TOKEN_FILE": leaked}
    assert credentials.find_bearer_token(env, NOBODY) == "env"


def test_the_environment_given_is_the_only_one_read(tmp_path, hermetic_tmp, monkeypatch):
    """The xrdarc bug: a gfal2 config file overrode ``$BEARER_TOKEN``; nothing here can."""
    monkeypatch.setenv("BEARER_TOKEN", "ambient")
    assert credentials.find_bearer_token({"BEARER_TOKEN": "given"}, NOBODY) == "given"
    assert credentials.find_bearer_token({}, NOBODY) is None


def test_a_link_is_followed_where_named_and_refused_where_predictable(tmp_path, hermetic_tmp):
    real = _private(tmp_path / "real", "linked")
    (tmp_path / "named").symlink_to(real)
    assert credentials.find_bearer_token({}, NOBODY, token_file=str(tmp_path / "named")) == (
        "linked"
    )
    (hermetic_tmp / f"bt_u{NOBODY}").symlink_to(real)
    with pytest.raises(InsecureCredentialError, match="symbolic link"):
        credentials.find_bearer_token({}, NOBODY)


def test_the_files_searched_are_listed_in_order(tmp_path):
    env = {"BEARER_TOKEN_FILE": "/env", "XDG_RUNTIME_DIR": "/run/user/9"}
    assert credentials.bearer_token_files(env, 9, token_file="/named") == [
        ("/named", False),
        ("/env", False),
        ("/run/user/9/bt_u9", True),
        (os.path.join(credentials.TMP_DIR, "bt_u9"), True),
    ]


def test_an_adapter_may_pass_a_tmp_dir_of_its_own(tmp_path):
    """What a client's configuration-shaped search (xrdclient's ``_tokens``) calls."""
    tmp = tmp_path / "tokens-tmp"
    tmp.mkdir()
    _private(tmp / f"bt_u{NOBODY}", "from-tmp")
    assert credentials._discover({}, NOBODY, None, None, str(tmp)) == "from-tmp"
    assert credentials._token_files({}, NOBODY, None, str(tmp))[-1] == (
        str(tmp / f"bt_u{NOBODY}"),
        True,
    )


def test_an_unreadable_token_file_raises_or_is_skipped(tmp_path, hermetic_tmp):
    """XRootD lets the error through; gfal2 (``skip_unreadable``) reads it as no token."""
    unreadable = tmp_path / "dir-not-file"
    unreadable.mkdir()
    (unreadable / "x").write_text("")
    _private(hermetic_tmp / f"bt_u{NOBODY}", "last")
    env = {"BEARER_TOKEN_FILE": str(unreadable / "x" / "y")}
    with pytest.raises(NotADirectoryError):
        credentials.find_bearer_token(env, NOBODY)
    assert credentials.find_bearer_token(env, NOBODY, skip_unreadable=True) == "last"


def test_a_refusal_is_raised_even_when_skipping_the_unreadable(tmp_path, hermetic_tmp):
    leaked = _private(tmp_path / "leaked", "tok", mode=0o644)
    with pytest.raises(InsecureCredentialError, match="chmod 600"):
        credentials.find_bearer_token({"BEARER_TOKEN_FILE": leaked}, NOBODY, skip_unreadable=True)


# ---------------------------------------------------------------------------
# Reading a credential file
# ---------------------------------------------------------------------------


def test_a_private_file_is_read(tmp_path):
    path = _private(tmp_path / "proxy", b"chain")
    assert credentials.read_private_file(path, kind="X.509 proxy") == b"chain"
    assert credentials.read_private_file(tmp_path / "proxy", kind="x", predictable=True) == (
        b"chain"
    )


def test_the_limit_bounds_what_is_read(tmp_path):
    path = _private(tmp_path / "big", b"x" * 11)
    assert credentials.read_private_file(path, kind="thing", limit=11) == b"x" * 11
    with pytest.raises(CredentialError, match=r"thing .* is larger than 10 bytes"):
        credentials.read_private_file(path, kind="thing", limit=10)


def test_the_kind_names_the_credential_in_a_refusal(tmp_path):
    path = _private(tmp_path / "keytab", mode=0o640)
    with pytest.raises(InsecureCredentialError, match=r"the SSS keytab .* readable by group"):
        credentials.read_private_file(path, kind="SSS keytab")
    with pytest.raises(FileNotFoundError):
        credentials.read_private_file(tmp_path / "absent", kind="SSS keytab")


def test_a_named_link_is_followed_and_a_predictable_one_refused(tmp_path):
    real = _private(tmp_path / "real")
    (tmp_path / "link").symlink_to(real)
    assert credentials.read_private_file(str(tmp_path / "link"), kind="t") == b"secret"
    with pytest.raises(InsecureCredentialError, match="symbolic link"):
        credentials.read_private_file(str(tmp_path / "link"), kind="t", predictable=True)
