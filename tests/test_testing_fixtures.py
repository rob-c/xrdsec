"""xrdsec.testing.fixtures: the hermetic environment, its hook, the ambient opt-out, the PKI.

The plugin is loaded by this suite's own conftest, so the tests here run
under it twice over: directly (what it did to *this* test), and through
``pytester`` (a small suite of its own, with a conftest implementing the
hook, run in process after this test planted variables it must remove).
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

from xrdsec import credentials
from xrdsec.testing import fixtures
from xrdsec.testing.pki import PKI

#: What a developer's grid login node has in its environment.
_PLANTED = {
    "X509_USER_PROXY": "/tmp/x509up_u1000",
    "X509_VOMSES": "/etc/vomses",
    "BEARER_TOKEN": "a-real-token",
    "BEARER_TOKEN_FILE": "/run/user/1000/bt_u1000",
    "KRB5_KTNAME": "/etc/krb5.keytab",
    "SSL_CERT_FILE": "/etc/ssl/cert.pem",
    "SSL_CERT_DIR": "/etc/ssl/certs",
    "SUITE_OWN_SETTING": "the developer's",
}

_INNER_CONFTEST = """
pytest_plugins = ["xrdsec.testing.fixtures"]


def pytest_xrdsec_hermetic(hermetic):
    hermetic.unset("SUITE_OWN_SETTING")
    config = hermetic.directory("suite-config")
    hermetic.monkeypatch.setenv("SUITE_CONFIG_DIR", str(config))
"""

_INNER_TESTS = """
import os
from pathlib import Path

import pytest

from xrdsec import credentials

PLANTED = {planted!r}


def test_hermetic(hermetic, home, tmp_dir, grid_security):
    assert not set(PLANTED) & set(os.environ)
    assert os.environ["HOME"] == str(home) and not any(home.iterdir())
    assert Path(os.environ["XDG_RUNTIME_DIR"]).is_dir()
    assert os.environ["KRB5CCNAME"].startswith("FILE:")
    assert not Path(os.environ["KRB5CCNAME"][5:]).exists()
    assert not Path(os.environ["KRB5_CONFIG"]).exists()
    assert credentials.TMP_DIR == str(tmp_dir) and not any(tmp_dir.iterdir())
    assert credentials.GRID_SECURITY_DIRS == (str(grid_security),)
    assert not grid_security.exists()
    assert credentials.default_proxy_path({{}}).startswith(str(tmp_dir))
    assert Path(os.environ["SUITE_CONFIG_DIR"]).is_dir()


@pytest.mark.ambient
def test_ambient(hermetic):
    assert all(os.environ[name] == value for name, value in PLANTED.items())
    assert "SUITE_CONFIG_DIR" not in os.environ
    assert hermetic.home == Path.home()
    assert hermetic.tmp_dir == Path(credentials.TMP_DIR)
"""


def test_a_suite_under_the_plugin(pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch):
    for name, value in _PLANTED.items():
        monkeypatch.setenv(name, value)
    # Only the plugin under test: whatever else is installed (pytest-asyncio
    # warns about its own unset options) is not part of that suite.
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    pytester.makeconftest(_INNER_CONFTEST)
    pytester.makepyfile(_INNER_TESTS.format(planted=_PLANTED))
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "--strict-markers")
    result.assert_outcomes(passed=2)


def test_this_test_is_hermetic(hermetic: fixtures.Hermetic, home: Path, tmp_dir: Path):
    assert os.environ["HOME"] == str(home) == str(hermetic.home)
    assert str(tmp_dir) == credentials.TMP_DIR
    assert not any(name.startswith(fixtures.AMBIENT_PREFIXES[:2]) for name in os.environ)


def test_grid_env_puts_the_pki_in_the_environment(grid_env: PKI, pki: PKI):
    assert grid_env is pki
    assert os.environ["X509_USER_PROXY"] == str(pki.proxy_path)
    assert os.environ["X509_CERT_DIR"] == str(pki.ca_dir)


def test_the_pki_is_one_per_session(pki: PKI, request: pytest.FixtureRequest):
    assert request.getfixturevalue("pki") is pki
    assert pki.proxy_path.exists()


class _Cache(types.ModuleType):
    """A stand-in for a module with a process-wide cache."""

    def __init__(self) -> None:
        super().__init__("cache")
        self.cleared = 0

    def clear_cache(self) -> None:
        self.cleared += 1


def test_forget_cached_state_clears_only_imported_modules(monkeypatch: pytest.MonkeyPatch):
    for name in fixtures.CACHES:
        monkeypatch.delitem(sys.modules, name, raising=False)
    fixtures.forget_cached_state()  # nothing imported: nothing to clear, nothing imported
    assert not set(fixtures.CACHES) & set(sys.modules)
    cache = _Cache()
    monkeypatch.setitem(sys.modules, fixtures.CACHES[0], cache)
    fixtures.forget_cached_state()
    assert cache.cleared == 1
