"""Each tool's X.509 search order, and trust-anchor discovery."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import pytest

from xrdcore.errors import CredentialError
from xrdsec import credentials
from xrdsec import discovery as D


@pytest.fixture
def default_proxy(monkeypatch, tmp_path):
    """Where ``/tmp/x509up_u<uid>`` is, for the test: absent until created."""
    directory = tmp_path / "default"
    directory.mkdir()
    monkeypatch.setattr(credentials, "TMP_DIR", str(directory))
    return directory / f"x509up_u{os.geteuid()}"


@pytest.fixture
def home(tmp_path):
    directory = tmp_path / "home"
    directory.mkdir()
    return directory


def touch(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x")
    return str(path)


def pair(base: Path) -> tuple[str, str]:
    return touch(base / "usercert.pem"), touch(base / "userkey.pem")


def env(home: Path, **extra: object) -> dict[str, str]:
    return {"HOME": str(home), **{k: str(v) for k, v in extra.items()}}


def _located(*args: Any, **kwargs: Any) -> D.X509Location:
    """What :func:`~xrdsec.discovery.discover_x509` finds, where the test expects a find."""
    found = D.discover_x509(*args, **kwargs)
    assert found is not None
    return found


def test_searches_are_named():
    assert set(D.SEARCHES) == {"xrdclient", "gfal2", "gfal2-seed", "arc"}


def test_nothing_anywhere(default_proxy, home):
    for search in D.SEARCHES.values():
        assert D.discover_x509(search, environ=env(home)) is None


@pytest.mark.parametrize("search", list(D.SEARCHES.values()))
def test_a_named_proxy_wins(search, default_proxy, home, tmp_path):
    named = touch(tmp_path / "named")
    touch(default_proxy)
    found = _located(search, environ=env(home, X509_USER_PROXY=f" {named} "))
    assert found == D.X509Location(named, named, "X509_USER_PROXY", True)
    assert found.is_proxy
    assert D.discover_x509(search, proxy=named, environ=env(home)) == found


def test_a_missing_named_proxy_per_tool(default_proxy, home, tmp_path, caplog):
    missing = str(tmp_path / "missing")
    touch(default_proxy)
    environ = env(home, X509_USER_PROXY=missing)
    assert _located(D.XRDCLIENT, environ=environ).cert == missing
    assert _located(D.GFAL2_SEED, environ=environ).cert == missing
    with caplog.at_level(logging.WARNING):
        assert D.discover_x509(D.GFAL2, environ=environ) is None
        assert D.discover_x509(D.GFAL2, environ=environ) is None
    assert sum("does not exist" in r.getMessage() for r in caplog.records) == 1
    with pytest.raises(CredentialError, match="does not exist"):
        D.discover_x509(D.ARC, environ=environ)


def test_xrdclient_prefers_a_pair_to_the_default_proxy(default_proxy, home):
    touch(default_proxy)
    found = D.discover_x509(D.XRDCLIENT, cert="/c", key="/k", environ=env(home))
    assert found == D.X509Location("/c", "/k", "X509_USER_CERT and X509_USER_KEY", True)
    found = D.discover_x509(D.XRDCLIENT, environ=env(home))
    assert found == D.X509Location(
        str(default_proxy), str(default_proxy), "default proxy location", False
    )


def test_gfal2_prefers_the_default_proxy_and_wants_pairs_to_exist(default_proxy, home, tmp_path):
    cert, key = pair(tmp_path / "pair")
    environ = env(home, X509_USER_CERT=cert, X509_USER_KEY=key)
    assert _located(D.GFAL2, environ=environ).cert == cert
    touch(default_proxy)
    assert _located(D.GFAL2, environ=environ).cert == str(default_proxy)
    os.unlink(default_proxy)
    os.unlink(key)
    assert D.discover_x509(D.GFAL2, environ=environ) is None
    assert _located(D.GFAL2_SEED, environ=environ).key == key  # not checked


def test_gfal2_falls_back_to_dot_globus(default_proxy, home):
    cert, key = pair(home / ".globus")
    found = D.discover_x509(D.GFAL2, environ=env(home))
    assert found == D.X509Location(cert, key, "default certificate location", False)
    os.chmod(key, 0)
    if os.geteuid() != 0:
        assert D.discover_x509(D.GFAL2_SEED, environ=env(home)) is None


def test_arc_order(default_proxy, home, tmp_path):
    globus = pair(home / ".globus")
    assert _located(D.ARC, environ=env(home)).cert == globus[0]
    arc = pair(home / ".arc")
    assert _located(D.ARC, environ=env(home)).cert == arc[0]
    assert _located(D.ARC, cert="/c", key="/k", environ=env(home)).cert == "/c"
    tmpdir = tmp_path / "tmpdir"
    touch(tmpdir / f"x509up_u{os.geteuid()}")
    found = _located(D.ARC, environ=env(home, TMPDIR=tmpdir))
    assert found.source == "TMPDIR proxy location"
    touch(default_proxy)
    assert _located(D.ARC, environ=env(home, TMPDIR=tmpdir)).cert == str(default_proxy)


def test_userprofile_is_a_home(default_proxy, tmp_path):
    cert, _ = pair(tmp_path / "profile" / ".globus")
    found = _located(D.GFAL2, environ={"USERPROFILE": str(tmp_path / "profile")})
    assert found.cert == cert


def test_the_process_environment_is_the_default(default_proxy, monkeypatch, tmp_path):
    named = touch(tmp_path / "named")
    monkeypatch.setenv("X509_USER_PROXY", named)
    assert _located().cert == named


def test_ca_dir(home, tmp_path, monkeypatch):
    monkeypatch.setattr(credentials, "_candidates", lambda kind: (str(tmp_path / "grid"),))
    assert D.discover_ca_dir(environ=env(home)) is None
    (tmp_path / "grid").mkdir()
    assert D.discover_ca_dir(environ=env(home)) == str(tmp_path / "grid")
    (home / ".globus" / "certificates").mkdir(parents=True)
    assert D.discover_ca_dir(D.ARC, environ=env(home)) == str(home / ".globus" / "certificates")
    (home / ".arc" / "certificates").mkdir(parents=True)
    assert D.discover_ca_dir(D.ARC, environ=env(home)) == str(home / ".arc" / "certificates")
    assert D.discover_ca_dir(D.XRDCLIENT, environ=env(home)) == str(tmp_path / "grid")
    assert D.discover_ca_dir(environ=env(home, X509_CERT_DIR="/named")) == "/named"
    assert D.discover_ca_dir(configured="/configured", environ=env(home)) == "/configured"
    monkeypatch.setenv("X509_CERT_DIR", "/process")
    assert D.discover_ca_dir() == "/process"


def test_uid_names_the_default_proxy_files(default_proxy, home, tmp_path):
    """``uid=`` looks for another account's ``x509up_u<uid>``, in /tmp and $TMPDIR alike."""
    other = default_proxy.parent / "x509up_u4242"
    assert D.discover_x509(D.ARC, environ=env(home), uid=4242) is None
    touch(default_proxy)  # this process's proxy is not the one asked for
    assert D.discover_x509(D.XRDCLIENT, environ=env(home), uid=4242) is None
    touch(other)
    found = _located(D.GFAL2, environ=env(home), uid=4242)
    assert (found.cert, found.source) == (str(other), "default proxy location")
    assert _located(D.GFAL2, environ=env(home)).cert == str(default_proxy)
    other.unlink()
    tmpdir = tmp_path / "tmpdir"
    touch(tmpdir / "x509up_u4242")
    found = _located(D.ARC, environ=env(home, TMPDIR=tmpdir), uid=4242)
    assert found.cert == str(tmpdir / "x509up_u4242")


def test_ca_dir_grid_security_is_injectable(home, tmp_path, monkeypatch):
    """The grid-wide step reads the directories given, else the module attribute."""
    first, second = tmp_path / "first", tmp_path / "second"
    (second / "certificates").mkdir(parents=True)
    dirs = (str(first), str(second))
    expected = str(second / "certificates")
    assert D.discover_ca_dir(environ=env(home), grid_security=dirs) == expected
    assert D.discover_ca_dir(environ=env(home), grid_security=()) is None
    # A named directory and the per-user ones still come first.
    assert D.discover_ca_dir(environ=env(home, X509_CERT_DIR="/n"), grid_security=dirs) == "/n"
    (home / ".arc" / "certificates").mkdir(parents=True)
    arc = str(home / ".arc" / "certificates")
    assert D.discover_ca_dir(D.ARC, environ=env(home), grid_security=dirs) == arc
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", dirs)
    assert D.discover_ca_dir(environ=env(home)) == expected
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", ())
    assert D.discover_ca_dir(environ=env(home)) is None
