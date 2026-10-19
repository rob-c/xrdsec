"""Package-level contracts: lazy import, independence from the clients, cheap credentials."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

import xrdcore
import xrdsec
from xrdsec import credentials, discovery

#: The xrdsec under test, wherever it was imported from: ``src/`` in a
#: checkout, site-packages in a wheel install, a store path in a Nix build.
PACKAGE = Path(xrdsec.__file__).resolve().parent


def _child_path() -> list[str]:
    """The ``sys.path`` for a ``python -I`` child: this xrdsec and xrdcore, then the rest.

    ``-I`` drops ``PYTHONPATH``, which is where a Nix build puts every
    dependency, so the child is given this interpreter's own path instead,
    with the two packages' installed locations first so that it imports the
    very modules under test - never a sibling checkout - and without the
    tests directory.
    """
    tests = Path(__file__).resolve().parent
    first = [str(PACKAGE.parent), str(Path(xrdcore.__file__).resolve().parent.parent)]
    rest = [entry for entry in sys.path if entry and Path(entry).resolve() != tests]
    return list(dict.fromkeys(first + rest))


PATH = _child_path()
MODULES = sorted(
    "xrdsec." + p.relative_to(PACKAGE).with_suffix("").as_posix().replace("/", ".")
    for p in PACKAGE.rglob("*.py")
    if p.name != "__init__.py"
)


def test_version_and_dir():
    assert xrdsec.__version__
    assert {"proxies", "credentials", "voms_client"} <= set(dir(xrdsec))
    assert "globus" in xrdsec.proxies.PROFILES
    with pytest.raises(AttributeError):
        _ = xrdsec.nonexistent


def _imported_after(statement: str) -> set[str]:
    code = f"import sys; sys.path[:] = {PATH!r}; {statement}; print('\\n'.join(sys.modules))"
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], check=True, capture_output=True, text=True
    ).stdout
    return set(out.split())


def test_importing_the_package_imports_no_submodule():
    loaded = _imported_after("import xrdsec")
    assert not {m for m in loaded if m.startswith("xrdsec.") and m != "xrdsec._version"}
    assert "cryptography" not in loaded


def test_credentials_is_cheap():
    """It is on the import path of every transfer, through a client's configuration."""
    loaded = _imported_after("import xrdsec.credentials")
    assert not {"cryptography", "asn1crypto", "ssl"} & loaded


@pytest.mark.parametrize("module", MODULES)
def test_no_client_package_is_ever_imported(module):
    loaded = _imported_after(f"import {module}")
    clients = {"xrdclient", "xgfalclient", "xrdarc", "xrdhttp"}
    assert not {m for m in loaded if m.split(".")[0] in clients}


def _absolute_imports(path: Path) -> set[str]:
    """Every module an ``import``/``from ... import`` statement in ``path`` names absolutely."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module)
    return found


def test_only_the_gss_wrapper_imports_gssapi():
    """``krb5.gss`` is the one python-gssapi wrapper (the ``krb5`` extra).

    The clients' lint bans ``gssapi`` and names that module; ruff cannot ban
    it here in every module but that one without a per-file ignore, so this
    test draws the line instead - lazy imports inside functions included.
    """
    importers = {
        path.relative_to(PACKAGE).as_posix()
        for path in PACKAGE.rglob("*.py")
        if any(name.split(".")[0] == "gssapi" for name in _absolute_imports(path))
    }
    assert importers == {"krb5/gss.py"}


def test_standard_proxy_path_and_uid(monkeypatch):
    monkeypatch.setattr(credentials, "TMP_DIR", "/tmp")
    assert discovery._uid_suffix() == str(os.geteuid())
    assert discovery._standard_proxy_path() == f"/tmp/x509up_u{os.geteuid()}"
    assert discovery._standard_proxy_path() == credentials.default_proxy_path({})
    monkeypatch.setattr(sys, "platform", "win32")
    assert discovery._standard_proxy_path().endswith(f"x509up_u{os.geteuid()}")


def test_uid_suffix_without_a_uid(monkeypatch):
    monkeypatch.delattr(os, "geteuid")
    import getpass

    assert discovery._uid_suffix() == getpass.getuser()
