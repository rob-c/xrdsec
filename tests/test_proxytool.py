"""The proxy-making workflow (:mod:`xrdsec.proxytool`) without either command line around it.

``xrd-proxy`` (xrdclient) and ``xrdarc proxy`` test their spellings and
output; what both rely on is pinned here: which user certificate and key
are chosen under each tool's conventions, how ``VO[:FQAN]`` options become
requests, the ACs-before-proxy order and its hooks, the symbolic-link rule
for the proxy file, and reading a proxy back.
"""

from __future__ import annotations

import os
import pickle
import time
from collections.abc import Sequence
from pathlib import Path

import pytest

from xrdcore.errors import CredentialError, InsecureCredentialError
from xrdsec import credentials, proxytool
from xrdsec.proxies import describe_proxy, write_proxy
from xrdsec.proxytool import (
    ARCPROXY,
    VOMS_PROXY_INIT,
    ExpiredCredentialError,
    NoCredentialError,
    ProxyRequest,
    VOMSRequest,
)
from xrdsec.testing.proxygrid import FakeVOMS, Grid, ac_answer, build_grid, error_answer
from xrdsec.voms_client import VOMSRefusedError, VOMSServer, VOMSWarning


@pytest.fixture
def grid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Grid:
    """A grid whose ACs this machine trusts (``vomsdir``, CA directory)."""
    made = build_grid(tmp_path / "grid")
    monkeypatch.setenv("X509_VOMS_DIR", str(made.voms_dir))
    monkeypatch.setenv("X509_CERT_DIR", str(made.ca_dir))
    return made


class Recorder:
    """A :class:`~xrdsec.proxytool.Progress` that writes down every hook call."""

    def __init__(self) -> None:
        self.events: list[tuple[str, ...]] = []

    def contacting(self, request: VOMSRequest, servers: Sequence[VOMSServer]) -> None:
        self.events.append(("contacting", request.vo, servers[0].address))

    def contacted(self, request: VOMSRequest) -> None:
        self.events.append(("contacted", request.vo))

    def warned(self, message: str) -> None:
        self.events.append(("warned", message))


def _vomses(tmp_path: Path, fake: FakeVOMS, *vos: str) -> str:
    """A ``vomses`` file naming ``fake`` for each of ``vos``."""
    path = tmp_path / "vomses"
    path.write_text("".join(f'"{vo}" "127.0.0.1" "{fake.port}" "/CN=voms" "{vo}"\n' for vo in vos))
    return str(path)


def _pair(directory: Path, grid: Grid) -> tuple[str, str]:
    """``usercert.pem``/``userkey.pem`` copied into ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    cert, key = directory / "usercert.pem", directory / "userkey.pem"
    cert.write_bytes(grid.usercert.read_bytes())
    key.write_bytes(grid.userkey.read_bytes())
    key.chmod(0o600)
    return str(cert), str(key)


# ---------------------------------------------------------------------------
# The user certificate and key
# ---------------------------------------------------------------------------


def test_a_named_pair_is_used_as_named() -> None:
    for conventions in (VOMS_PROXY_INIT, ARCPROXY):
        assert proxytool.find_user_pair(conventions, cert="c", key="k", environ={}) == ("c", "k")
    # arcproxy: a certificate named alone holds its key too.
    assert proxytool.find_user_pair(ARCPROXY, cert="both.pem", environ={}) == (
        "both.pem",
        "both.pem",
    )


def test_voms_proxy_init_searches_for_what_was_not_named(grid: Grid, tmp_path: Path) -> None:
    env = {"X509_USER_CERT": "env-cert", "X509_USER_KEY": "env-key", "HOME": str(tmp_path)}
    assert proxytool.find_user_pair(VOMS_PROXY_INIT, environ=env) == ("env-cert", "env-key")
    # -cert alone: the key is searched for as if nothing had been named.
    assert proxytool.find_user_pair(VOMS_PROXY_INIT, cert="mine", environ=env) == (
        "mine",
        "env-key",
    )
    assert proxytool.find_user_pair(VOMS_PROXY_INIT, key="k", environ=env) == ("env-cert", "k")
    globus = _pair(tmp_path / ".globus", grid)
    assert proxytool.find_user_pair(VOMS_PROXY_INIT, environ={"HOME": str(tmp_path)}) == globus


def test_arcproxy_searches_its_settings_then_arc_then_globus(grid: Grid, tmp_path: Path) -> None:
    home = {"HOME": str(tmp_path)}
    globus = _pair(tmp_path / ".globus", grid)
    assert proxytool.find_user_pair(ARCPROXY, environ=home) == globus
    arc = _pair(tmp_path / ".arc", grid)
    assert proxytool.find_user_pair(ARCPROXY, environ=home) == arc
    configured = _pair(tmp_path / "configured", grid)
    assert proxytool.find_user_pair(ARCPROXY, configured=configured, environ=home) == configured
    # A configured pair that is not there is passed over, not chosen.
    missing = (str(tmp_path / "no-cert"), str(tmp_path / "no-key"))
    assert proxytool.find_user_pair(ARCPROXY, configured=missing, environ=home) == arc


@pytest.mark.parametrize(
    ("conventions", "cert", "homes"),
    [(VOMS_PROXY_INIT, "lone.pem", "in ~/.globus"), (ARCPROXY, None, "in ~/.arc or ~/.globus")],
)
def test_nothing_found_names_where_it_looked(
    conventions: proxytool.Conventions, cert: str | None, homes: str, tmp_path: Path
) -> None:
    with pytest.raises(NoCredentialError) as caught:
        proxytool.find_user_pair(conventions, cert=cert, environ={"HOME": str(tmp_path)})
    error = caught.value
    assert str(error).startswith("no user certificate found: ") and str(error).endswith(homes)
    assert isinstance(error, CredentialError) and isinstance(error, FileNotFoundError)
    assert error.errno == 2 and error.path == ""


def test_no_credential_error_pickles_with_its_path() -> None:
    error = NoCredentialError("there is no proxy at /p", "/p")
    copy = pickle.loads(pickle.dumps(error))
    assert (type(copy), str(copy), copy.path, copy.errno) == (
        NoCredentialError,
        str(error),
        "/p",
        2,
    )


# ---------------------------------------------------------------------------
# VOMS requests
# ---------------------------------------------------------------------------


def test_voms_options_become_requests_as_each_tool_groups_them() -> None:
    options = ["atlas:/atlas/Role=pilot", "cms", "atlas:/atlas/de", "atlas"]
    assert proxytool.voms_requests(options, VOMS_PROXY_INIT) == (
        VOMSRequest("atlas", ("/atlas/Role=pilot", "/atlas/de")),
        VOMSRequest("cms"),
    )
    assert proxytool.voms_requests(options, ARCPROXY) == (
        VOMSRequest("atlas", ("/atlas/Role=pilot",)),
        VOMSRequest("cms"),
        VOMSRequest("atlas", ("/atlas/de",)),
        VOMSRequest("atlas"),
    )
    assert proxytool.voms_requests([], ARCPROXY) == ()
    with pytest.raises(ValueError, match="needs a VO name: ':/atlas'"):
        proxytool.voms_requests([":/atlas"], VOMS_PROXY_INIT)


def test_no_voms_request_reads_no_configuration(grid: Grid) -> None:
    request = ProxyRequest(vomses=("/nowhere",))
    assert proxytool.fetch_acs(grid.credential(), request) == []


# ---------------------------------------------------------------------------
# Making the proxy
# ---------------------------------------------------------------------------


def test_make_proxy_asks_for_the_acs_and_embeds_them(grid: Grid, tmp_path: Path) -> None:
    answer = ac_answer(grid.make_ac(), "shortened to 1 hour")
    with FakeVOMS(grid, lambda query: answer) as fake:
        request = ProxyRequest(
            lifetime=7200,
            bits=1024,
            voms=proxytool.voms_requests(["atlas:/atlas/Role=pilot"], VOMS_PROXY_INIT),
            vomses=(_vomses(tmp_path, fake, "atlas"),),
            ca_path=str(grid.ca_dir),
        )
        hooks = Recorder()
        made = proxytool.make_proxy(grid.credential(), request, hooks)
        assert fake.requests[0][1] == {"fqans": ["/atlas/Role=pilot"], "lifetime": ["7200"]}
        address = f"127.0.0.1:{fake.port}"
    assert hooks.events[0] == ("contacting", "atlas", address)
    assert hooks.events[1][0] == "warned" and "shortened to 1 hour" in hooks.events[1][1]
    assert hooks.events[2] == ("contacted", "atlas")
    info = describe_proxy(made)
    assert info.voms[0].vo == "atlas" and info.strength == 1024
    assert 7100 < info.time_left <= 7200


def test_the_ac_lifetime_is_its_own_when_asked(grid: Grid, tmp_path: Path) -> None:
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake:
        request = ProxyRequest(
            bits=1024,
            voms=(VOMSRequest("atlas"),),
            voms_lifetime=600,
            vomses=(_vomses(tmp_path, fake, "atlas"),),
            ca_path=str(grid.ca_dir),
        )
        proxytool.make_proxy(grid.credential(), request, Recorder())
        assert fake.requests[0][1] == {"lifetime": ["600"]}


def test_warnings_reach_the_hooks_when_a_later_vo_fails(grid: Grid, tmp_path: Path) -> None:
    def answer(query: dict[str, list[str]]) -> tuple[int, bytes]:
        if "fqans" in query:
            return error_answer(403, "NoSuchUser", "who?")
        return ac_answer(grid.make_ac(), "note from the first")

    with FakeVOMS(grid, answer) as fake:
        request = ProxyRequest(
            bits=1024,
            voms=proxytool.voms_requests(["atlas", "cms:/cms"], ARCPROXY),
            vomses=(_vomses(tmp_path, fake, "atlas", "cms"),),
            ca_path=str(grid.ca_dir),
        )
        hooks = Recorder()
        with pytest.raises(VOMSRefusedError):
            proxytool.make_proxy(grid.credential(), request, hooks)
    kinds = [event[0] for event in hooks.events]
    assert kinds == ["contacting", "warned", "contacted", "contacting"]


def test_without_hooks_a_warning_stays_a_python_warning(grid: Grid, tmp_path: Path) -> None:
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac(), "heads up")) as fake:
        request = ProxyRequest(
            voms=(VOMSRequest("atlas"),),
            vomses=(_vomses(tmp_path, fake, "atlas"),),
            ca_path=str(grid.ca_dir),
        )
        with pytest.warns(VOMSWarning, match="heads up"):
            acs = proxytool.fetch_acs(grid.credential(), request)
    assert len(acs) == 1


def test_an_expired_signer_is_refused_before_any_server_is_asked(grid: Grid) -> None:
    signer = grid.credential()
    later = signer.chain[0].not_after + 1
    # vomses that do not exist: reading them would fail differently.
    request = ProxyRequest(voms=(VOMSRequest("atlas"),), vomses=("/nowhere",))
    with pytest.raises(ExpiredCredentialError, match="has expired; it cannot issue a proxy"):
        proxytool.make_proxy(signer, request, now=later)
    proxytool.require_alive(signer)


def test_make_proxy_passes_the_shape_through(grid: Grid) -> None:
    request = ProxyRequest(lifetime=3600, bits=1024, limited=True, profile="globus-legacy")
    info = describe_proxy(proxytool.make_proxy(grid.credential(), request))
    assert info.kind == "limited legacy globus proxy" and info.limited
    rfc = proxytool.make_proxy(grid.credential(), ProxyRequest(bits=1024, path_length=1))
    assert describe_proxy(rfc).path_length == 1


# ---------------------------------------------------------------------------
# The proxy file
# ---------------------------------------------------------------------------


def test_the_target_follows_a_link_only_where_somebody_named_it(tmp_path: Path) -> None:
    named = tmp_path / "mine"
    assert proxytool.proxy_target(named, environ={}) == (str(named), True)
    env = {"X509_USER_PROXY": str(named)}
    assert proxytool.proxy_target(None, environ=env) == (str(named), True)
    default = proxytool.proxy_target(environ={})
    assert default.path == os.path.join(credentials.TMP_DIR, f"x509up_u{os.geteuid()}")
    assert default.follow_symlinks is False


def test_read_proxy_info_reads_back_what_was_written(grid: Grid, tmp_path: Path) -> None:
    request = ProxyRequest(bits=1024)
    path = write_proxy(tmp_path / "x509up", proxytool.make_proxy(grid.credential(), request))
    now = time.time()
    info = proxytool.read_proxy_info(path, now=now)
    assert info.path == path and info.kind == "RFC3820 compliant impersonation proxy"
    assert info.time_left == pytest.approx(info.not_after - now)


def test_read_proxy_info_refusals(grid: Grid, tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(NoCredentialError, match="there is no proxy at") as absent:
        proxytool.read_proxy_info(missing)
    assert absent.value.path == str(missing)
    junk = tmp_path / "junk"
    junk.write_text("not a certificate")
    junk.chmod(0o600)
    with pytest.raises(CredentialError, match="there is no certificate in"):
        proxytool.read_proxy_info(junk)
    written = write_proxy(
        tmp_path / "real", proxytool.make_proxy(grid.credential(), ProxyRequest(bits=1024))
    )
    link = tmp_path / "link"
    link.symlink_to(written)
    assert proxytool.read_proxy_info(link).path == str(link)
    with pytest.raises(InsecureCredentialError, match="symbolic link"):
        proxytool.read_proxy_info(link, follow_symlinks=False)
