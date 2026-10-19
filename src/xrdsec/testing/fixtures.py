"""A pytest plugin: the hermetic environment and grid PKI every suite on the stack runs with.

Each client's suite used to carry its own copy of the same fixtures - clear
the credential variables, give the test an empty ``$HOME``, point
:data:`xrdsec.credentials.TMP_DIR` somewhere empty, mint a PKI, put its
proxy in the environment - and each copy drifted (one forgot
``KRB5CCNAME``, one left ``/etc/grid-security`` visible). They exist once,
here. A suite loads the plugin from its top-level ``tests/conftest.py``::

    pytest_plugins = ["xrdsec.testing.fixtures"]

It is deliberately *not* a ``pytest11`` entry point: that would load it into
every pytest run of anyone who installs xrdsec, clearing their variables
in suites that never asked.

What every test gets (the autouse :func:`hermetic` fixture):

* every ``X509_*``, ``BEARER_TOKEN*`` and ``KRB5*`` variable, and
  ``SSL_CERT_FILE``/``SSL_CERT_DIR``, removed - a grid login node has most
  of them, and a test that passes there and fails on a laptop is testing the
  host;
* ``$HOME`` and ``$XDG_RUNTIME_DIR`` fresh empty directories, so no
  ``~/.globus``, ``~/.config`` dotfile or ``bt_u<uid>`` token is found;
* :data:`xrdsec.credentials.TMP_DIR` (the ``/tmp`` of ``x509up_u<uid>`` and
  ``bt_u<uid>``) an empty directory and
  :data:`~xrdsec.credentials.GRID_SECURITY_DIRS` one not-yet-created
  ``grid-security`` directory, so neither the developer's real proxy nor
  the host's CA directory is ever found;
* ``$KRB5CCNAME`` and ``$KRB5_CONFIG`` naming files that do not exist (unset,
  MIT would fall back to ``/tmp/krb5cc_<uid>`` and ``/etc/krb5.conf``);
* :mod:`xrdsec.tls`'s context cache and :mod:`xrdsec.krb5.client`'s
  service tickets emptied before and after, so no test is handed a context
  built for another's trust settings or logs in with another's ticket.

A suite adds what is its own - its configuration variables, its
system-configuration paths - by implementing :func:`HermeticSpec.pytest_xrdsec_hermetic`
in its conftest; the hook runs inside the same hermetic setup, so it is
skipped for the same tests. A test that must see the real environment (an
interop test using the developer's credentials) is marked ``ambient``.

The other fixtures: :func:`home`, :func:`tmp_dir` and :func:`grid_security`
(the three stand-in directories), :func:`pki` (one session-wide
:class:`~xrdsec.testing.pki.PKI`; a client with credential types of its own
overrides it with its :class:`~xrdsec.testing.pki.BasePKI` subclass) and
:func:`grid_env` (that PKI's proxy and CA directory in the environment, as a
login would set them).

Stability: public test API, versioned with the package. Importing it
needs pytest, which only a test run has; nothing in the library imports it.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from .. import credentials

if TYPE_CHECKING:
    from .pki import PKI, BasePKI

#: Prefixes of the variables every credential search reads: the X.509 and
#: VOMS locations, the WLCG bearer-token discovery, and MIT/Heimdal Kerberos.
AMBIENT_PREFIXES = ("X509_", "BEARER_TOKEN", "KRB5")
#: Whole names cleared as well: the OpenSSL trust overrides and the runtime
#: directory the token search looks in (set again, to an empty directory).
AMBIENT_NAMES = ("SSL_CERT_FILE", "SSL_CERT_DIR", "XDG_RUNTIME_DIR")
#: The marker that opts a test out of all of it.
AMBIENT_MARKER = "ambient"
#: Modules holding process-wide caches no test may inherit from another; each
#: has a ``clear_cache()``. The TLS contexts are keyed by trust settings a
#: test changes, and the Kerberos client remembers service tickets an
#: earlier test's KDC issued.
CACHES = ("xrdsec.tls", "xrdsec.krb5.client")


@dataclass(frozen=True)
class Hermetic:
    """One test's stand-in locations, and the tools a suite's hook extends them with.

    ``home`` is ``$HOME``; ``tmp_dir`` is :data:`xrdsec.credentials.TMP_DIR`
    (where the default proxy ``x509up_u<uid>`` and the last-resort token
    ``bt_u<uid>`` are looked for); ``grid_security`` is the one entry of
    :data:`~xrdsec.credentials.GRID_SECURITY_DIRS`, which does not exist
    until a test creates it. For an ``ambient`` test they are the real
    locations, and nothing was changed. ``monkeypatch`` and
    ``tmp_path_factory`` are the test's own, so whatever a hook changes
    through them is undone after the test like the rest.
    """

    home: Path
    tmp_dir: Path
    grid_security: Path
    monkeypatch: pytest.MonkeyPatch
    tmp_path_factory: pytest.TempPathFactory

    def unset(self, *names: str) -> None:
        """Remove each of ``names`` from the environment, for this test only."""
        for name in names:
            self.monkeypatch.delenv(name, raising=False)

    def directory(self, name: str) -> Path:
        """A new empty directory for this test, named after ``name``."""
        return self.tmp_path_factory.mktemp(name)


class HermeticSpec:
    """The hook a suite implements to extend the hermetic environment."""

    @pytest.hookspec
    def pytest_xrdsec_hermetic(self, hermetic: Hermetic) -> None:
        """Make this suite's own inputs hermetic, after xrdsec's are.

        Implemented in a ``conftest.py``; it applies to the tests under
        that conftest's directory, and is not called for an ``ambient``
        test. Change things through ``hermetic.monkeypatch``,
        :meth:`Hermetic.unset` and :meth:`Hermetic.directory`, so they are
        put back after the test.
        """


def pytest_addhooks(pluginmanager: pytest.PytestPluginManager) -> None:
    """Declare :meth:`HermeticSpec.pytest_xrdsec_hermetic`, so a conftest may implement it."""
    pluginmanager.add_hookspecs(HermeticSpec)


def pytest_configure(config: pytest.Config) -> None:
    """Register the ``ambient`` marker, so ``--strict-markers`` accepts it."""
    config.addinivalue_line(
        "markers",
        f"{AMBIENT_MARKER}: run with the developer's real environment and credentials "
        "(not hermetic); for interop tests against real services",
    )


def forget_cached_state() -> None:
    """Empty the cache of every module in :data:`CACHES` that has been imported.

    A module nobody imported has nothing cached, and importing it just to
    clear it would put TLS and the Kerberos client into every suite's
    process, which a suite measuring its own import cost would see.
    """
    for name in CACHES:
        module = sys.modules.get(name)
        if module is not None:
            module.clear_cache()


def _ambient(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> Hermetic:
    """The real locations, for a test that opted out with the ``ambient`` marker."""
    grid = credentials.GRID_SECURITY_DIRS or ("/etc/grid-security",)
    tmp_dir = Path(credentials.TMP_DIR)
    return Hermetic(Path.home(), tmp_dir, Path(grid[0]), monkeypatch, tmp_path_factory)


def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> Hermetic:
    """Clear the credential environment and point every default location somewhere empty."""
    for name in list(os.environ):
        if name.startswith(AMBIENT_PREFIXES) or name in AMBIENT_NAMES:
            monkeypatch.delenv(name)
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path_factory.mktemp("xdg-runtime")))
    krb5 = tmp_path_factory.mktemp("krb5")
    monkeypatch.setenv("KRB5CCNAME", f"FILE:{krb5 / 'no-cache'}")
    monkeypatch.setenv("KRB5_CONFIG", str(krb5 / "no-krb5.conf"))
    tmp_dir = tmp_path_factory.mktemp("tmp")
    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp_dir))
    # Not created: a test that wants a grid-wide directory makes one inside it.
    grid = tmp_path_factory.mktemp("etc") / "grid-security"
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", (str(grid),))
    return Hermetic(home, tmp_dir, grid, monkeypatch, tmp_path_factory)


@pytest.fixture(autouse=True)
def hermetic(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Hermetic]:
    """Every test, unless marked ``ambient``: no credential, trust or home from the host.

    Then the suite's own :meth:`HermeticSpec.pytest_xrdsec_hermetic`
    implementations run. The :data:`CACHES` are emptied either side of the
    test whatever its marker.
    """
    forget_cached_state()
    if request.node.get_closest_marker(AMBIENT_MARKER):
        yield _ambient(monkeypatch, tmp_path_factory)
    else:
        isolated = _isolate(monkeypatch, tmp_path_factory)
        request.node.ihook.pytest_xrdsec_hermetic(hermetic=isolated)
        yield isolated
    forget_cached_state()


@pytest.fixture
def home(hermetic: Hermetic) -> Path:
    """The test's ``$HOME``: an empty directory of its own."""
    return hermetic.home


@pytest.fixture
def tmp_dir(hermetic: Hermetic) -> Path:
    """The test's stand-in for ``/tmp``: where the default proxy and token file go."""
    return hermetic.tmp_dir


@pytest.fixture
def grid_security(hermetic: Hermetic) -> Path:
    """The test's stand-in for ``/etc/grid-security`` (absent until a test creates it)."""
    return hermetic.grid_security


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> PKI:
    """One throwaway grid PKI (CA directory, host, user, default proxy) for the session.

    Session-wide because minting is the slow part and nothing in it changes:
    the keys are fixed slots, so a test that writes another proxy beside it
    writes the same key. A test that installs a CRL or needs a second CA
    makes its own with :func:`~xrdsec.testing.pki.create_pki`.
    """
    from .pki import create_pki

    return create_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def grid_env(
    monkeypatch: pytest.MonkeyPatch, pki: BasePKI[Any, Any, Any]
) -> BasePKI[Any, Any, Any]:
    """The ``pki`` fixture's proxy and CA directory in the environment, as a login sets them.

    Whichever ``pki`` the suite has - a client that overrides it with its
    own view gets that view back.
    """
    for name, value in pki.environment().items():
        monkeypatch.setenv(name, value)
    return pki
