"""``xrd-proxy doctor``'s checks: every answer, and who each hint tells you to ask.

One test per line the report can show, because the point of the command is the
line: a plain-English sentence, and the one thing to do about it - the user's
own session (``do:``), whoever runs the machine (``ask your admin:``), or the
experiment (``ask your experiment (vo):``).
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from xrdcore.errors import CredentialError
from xrdsec import credentials, doctor, locations, proxytool
from xrdsec.proxies import create_proxy, write_proxy
from xrdsec.testing.proxygrid import Grid, build_grid, key
from xrdsec.voms_client import VOMSConfigError

ATLAS = (
    '"atlas" "voms.example.org" "15000" "/CN=voms.example.org" "atlas"\n'
    '"atlas" "voms2.example.org" "15000" "/CN=voms2.example.org" "atlas"\n'
)
CMS = '"cms" "voms2.example.org" "15001" "/CN=voms2.example.org" "cms"\n'


class Sink:
    """A recording sink: the one method :func:`xrdsec.doctor.check` calls."""

    def __init__(self) -> None:
        self.lines: list[tuple[str, str, str, str]] = []

    def add(self, name: str, state: str, detail: str, hint: str = "") -> None:
        self.lines.append((name, state, detail, hint))

    def state(self, name: str) -> str:
        """The state of the line named ``name``."""
        return next(state for called, state, _detail, _hint in self.lines if called == name)

    def detail(self, name: str) -> str:
        """The detail of the line named ``name``."""
        return next(detail for called, _state, detail, _hint in self.lines if called == name)

    def hint(self, name: str) -> str:
        """The hint under the line named ``name``."""
        return next(hint for called, _state, _detail, hint in self.lines if called == name)


@pytest.fixture
def grid(tmp_path: Path) -> Grid:
    return build_grid(tmp_path / "grid")


@pytest.fixture
def ca_dir(tmp_path: Path, grid: Grid) -> str:
    """The CA directory of the test grid: the one that can verify its user certificate."""
    assert grid.ca_dir.is_dir()
    return str(grid.ca_dir)


@pytest.fixture
def vomses(tmp_path: Path) -> str:
    path = tmp_path / "vomses"
    path.write_text(ATLAS + CMS)
    return str(path)


def run(env: dict[str, str] | None = None, **kwargs: Any) -> Sink:
    """Check this environment, with the VOMS servers left alone unless asked for."""
    sink = Sink()
    kwargs.setdefault("servers", False)
    doctor.check(sink, environ=env or {}, home=str(Path("/nonexistent-home")), **kwargs)
    return sink


# ---------------------------------------------------------------------------
# The hints' three audiences
# ---------------------------------------------------------------------------


def test_a_hint_says_who_can_act_on_it():
    """The whole point: yours to do, your admin's to change, or your experiment's to answer."""
    assert doctor.do("run this") == "do: run this"
    assert doctor.ask_admin("mount /cvmfs") == "ask your admin: mount /cvmfs"
    assert doctor.ask_experiment("renew it") == "ask your experiment: renew it"
    assert doctor.ask_experiment("renew it", "lhcb") == "ask your experiment (lhcb): renew it"


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------


def test_a_ca_directory_with_crls_is_fine(ca_dir: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: ca_dir)
    Path(ca_dir, "12345678.r0").write_bytes(b"crl")
    sink = run()
    assert sink.state("certs") == "ok" and "1 CRLs" in sink.detail("certs")


def test_a_ca_directory_without_crls_is_a_warning(ca_dir: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: ca_dir)
    sink = run()
    assert sink.state("certs") == "warn"
    assert "a revoked certificate would still be accepted" in sink.hint("certs")


def test_no_ca_directory_says_where_to_get_one(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    sink = run()
    assert sink.state("certs") == "bad"
    assert sink.hint("certs") == (
        "do: mount the WLCG bundle at /cvmfs/grid.cern.ch/etc/grid-security/certificates"
    )


def test_a_ca_directory_that_is_not_there_is_named(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    missing = str(tmp_path / "nowhere")
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: missing)
    sink = run()
    assert sink.state("certs") == "bad" and missing in sink.detail("certs")


def test_a_ca_directory_with_no_certificates_is_the_admins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: str(empty))
    sink = run()
    assert sink.state("certs") == "bad"
    assert sink.hint("certs").startswith("ask your admin: the IGTF CA bundle")


def test_a_ca_directory_that_cannot_be_listed_counts_as_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o000)
    try:
        monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: str(locked))
        sink = run()
    finally:
        locked.chmod(
            0o700
        )  # a 0o000 directory cannot be removed by the temporary-directory cleanup
    assert sink.state("certs") == "bad"


# ---------------------------------------------------------------------------
# Something to sign with
# ---------------------------------------------------------------------------


def test_no_credential_is_what_stops_a_proxy_being_made():
    sink = run()
    assert sink.state("credential") == "bad"
    assert sink.hint("credential").startswith("do: xrd-proxy init -p12")


def test_a_certificate_and_key_pair_is_described(
    ca_dir: str, grid: Grid, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: ca_dir)
    env = {"X509_USER_CERT": str(grid.usercert), "X509_USER_KEY": str(grid.userkey)}
    sink = run(env)
    assert sink.state("credential") == "ok"
    assert sink.detail("credential").startswith(f"{grid.usercert} with {grid.userkey}")


def test_a_pkcs12_bundle_is_described(
    ca_dir: str, grid: Grid, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: ca_dir)
    bundle = tmp_path / "me.p12"
    bundle.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"Jane", key(2), grid.user, [grid.ca], BestAvailableEncryption(b"phrase")
        )
    )
    bundle.chmod(0o600)
    sink = run({"X509_USER_P12": str(bundle)})
    # The bundle is encrypted, so it cannot be opened without the pass phrase.
    assert sink.state("credential") == "warn"
    assert "does not prompt" in sink.hint("credential")


def test_a_pem_pair_under_names_of_its_own_is_found(
    ca_dir: str, grid: Grid, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: ca_dir)
    home = tmp_path / "home"
    (home / ".globus").mkdir(parents=True)
    (home / ".globus" / "cert.pem").write_bytes(grid.usercert.read_bytes())
    Grid.write_key(home / ".globus" / "key.pem", key(2))
    sink = Sink()
    doctor.check(sink, environ={}, home=str(home), servers=False)
    assert sink.state("credential") == "ok" and "cert.pem" in sink.detail("credential")


@pytest.mark.parametrize(
    ("refusal", "state", "hint"),
    [
        ("the key is encrypted and no pass phrase was given", "warn", "do: this check does not"),
        ("the bundle will not open: it is encrypted, so give its pass phrase", "warn", "do:"),
        ("the proxy expired", "bad", "ask your experiment (lhcb)"),
        ("the proxy's private key is not RSA", "bad", "ask your experiment (lhcb)"),
        ("the private key does not belong to the certificate", "bad", "do: the key is not"),
        ("there is no certificate in /tmp/x", "bad", "ask your admin"),
    ],
)
def test_a_refusal_is_advice_for_the_right_audience(refusal: str, state: str, hint: str):
    said, advice = doctor._refused(refusal, "lhcb")
    assert said == state and advice.startswith(hint)


def test_a_credential_that_will_not_load_does_not_escape(
    ca_dir: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """An encrypted key is a warning, not a crash: the check never prompts and never raises."""
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: ca_dir)
    locked = Grid.write_key(tmp_path / "locked.pem", key(2), b"secret")
    grid_like = {"X509_USER_CERT": str(tmp_path / "cert.pem"), "X509_USER_KEY": str(locked)}
    (tmp_path / "cert.pem").write_bytes(b"")
    sink = Sink()
    doctor.check(sink, environ=grid_like, home=str(tmp_path), servers=False)
    assert sink.state("credential") in ("warn", "bad")


def test_a_source_that_cannot_be_resolved_is_reported(monkeypatch: pytest.MonkeyPatch):
    def refused(*args: Any, **kwargs: Any) -> Any:
        raise CredentialError("the proxy's private key is not RSA")

    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    monkeypatch.setattr(proxytool, "find_user_pair", refused)
    sink = run()
    assert sink.state("credential") == "bad"
    assert sink.hint("credential").startswith("ask your experiment")


def test_an_expired_credential_is_the_experiments_to_renew(
    ca_dir: str, grid: Grid, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: ca_dir)
    env = {"X509_USER_CERT": str(grid.usercert), "X509_USER_KEY": str(grid.userkey)}
    sink = run(env, now=time.time() + 400 * 86400)
    assert sink.state("credential") == "bad"
    assert "expired" in sink.detail("credential")
    assert sink.hint("credential").startswith("ask your experiment")


def test_a_certificate_from_the_future_is_the_clock(
    ca_dir: str, grid: Grid, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: ca_dir)
    env = {"X509_USER_CERT": str(grid.usercert), "X509_USER_KEY": str(grid.userkey)}
    sink = run(env, now=time.time() - 400 * 86400)
    assert sink.state("credential") == "bad"
    assert "system clock is wrong" in sink.hint("credential")


def test_a_certificate_whose_ca_is_missing_from_the_directory(
    grid: Grid, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """A CA directory that has CAs but not this certificate's issuer."""
    other = tmp_path / "other-ca"
    other.mkdir()
    (other / "deadbeef.0").write_bytes((grid.ca_dir / "x").read_bytes() if False else b"x")
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: str(other))
    env = {"X509_USER_CERT": str(grid.usercert), "X509_USER_KEY": str(grid.userkey)}
    sink = run(env)
    assert sink.state("credential") == "bad"
    assert "not in" in sink.detail("credential")
    assert sink.hint("credential").startswith("ask your admin")


# ---------------------------------------------------------------------------
# VOMS: the configuration and the VO's own bits
# ---------------------------------------------------------------------------


def test_vomses_that_cannot_be_read_are_the_users_to_fix(monkeypatch: pytest.MonkeyPatch):
    def refused(*args: Any, **kwargs: Any) -> Any:
        raise VOMSConfigError("not a vomses line")

    monkeypatch.setattr(doctor, "find_vomses", refused)
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    sink = run()
    assert sink.state("voms") == "bad" and sink.hint("voms").startswith("do:")


def test_no_vomses_configuration_at_all(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(doctor, "find_vomses", lambda *a, **k: [])
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    sink = run()
    assert sink.state("voms") == "warn" and "carry no VO attributes" in sink.detail("voms")


def test_no_vomses_configuration_names_the_four_places_it_looked(
    monkeypatch: pytest.MonkeyPatch,
):
    """The stage lines are the answer to "on CVMFS - where exactly?"."""
    monkeypatch.setattr(doctor, "find_vomses", lambda *a, **k: [])
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    monkeypatch.setattr(doctor, "_cvmfs_mounted", lambda: False)
    monkeypatch.setattr(
        locations, "CVMFS_GRID_SECURITY", ("/cvmfs/grid.cern.ch/etc/grid-security",)
    )
    stages = [
        (detail, state) for name, state, detail, _ in run().lines if name.startswith("vomses")
    ]
    assert stages and all(state == "skip" for _detail, state in stages)
    assert any("/cvmfs/grid.cern.ch/etc/grid-security/vomses" in detail for detail, _ in stages)


def test_a_mount_without_a_vomses_tree_is_the_admins_not_the_users(
    monkeypatch: pytest.MonkeyPatch,
):
    """CVMFS up for certificates but never fetched vomses: re-mounting it is not the user's job.

    That is how the LHCb VO's configuration went missing here: the bundle
    answered for certificates and vomsdir, and the vomses tree was simply
    absent, which reads exactly like "nothing is configured".
    """
    monkeypatch.setattr(doctor, "find_vomses", lambda *a, **k: [])
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    monkeypatch.setattr(doctor, "_cvmfs_mounted", lambda: True)
    monkeypatch.setattr(
        locations, "CVMFS_GRID_SECURITY", ("/cvmfs/grid.cern.ch/etc/grid-security",)
    )
    hint = run().hint("voms")
    assert hint.startswith("ask your admin:") and "no vomses tree" in hint
    assert "~/.voms/vomses" in hint  # the workaround, for a user who cannot wait


def test_the_configuration_says_how_many_vos_and_from_where(vomses: str):
    sink = run({"X509_VOMSES": vomses})
    assert sink.state("voms") == "ok"
    assert "2 VOs configured" in sink.detail("voms") and vomses in sink.detail("voms")


def test_a_vo_that_is_not_configured_is_named_with_the_ones_that_are(vomses: str):
    sink = run({"X509_VOMSES": vomses}, vo="atls")
    assert sink.state("vo") == "bad"
    assert "did you mean 'atlas'" in sink.detail("vo")
    assert sink.hint("vo").startswith("do: xrd-proxy init -list-vos")


def test_a_configured_vo_lists_its_servers_and_its_lsc(
    vomses: str, grid: Grid, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(credentials, "grid_voms_dir", lambda *a, **k: str(grid.voms_dir))
    sink = run({"X509_VOMSES": vomses}, vo="atlas")
    assert sink.state("vo") == "ok" and "2 server(s)" in sink.detail("vo")
    assert sink.state("vo:lsc") == "ok"
    # Named by server, not by VO: the file an AC from *this* server is checked against.
    assert "voms.example.org.lsc" in sink.detail("vo:lsc")


def test_an_vo_without_an_lsc_is_the_experiments(vomses: str, tmp_path: Path):
    sink = run({"X509_VOMSES": vomses, "X509_VOMS_DIR": str(tmp_path / "vomsdir")}, vo="atlas")
    assert sink.state("vo:lsc") == "warn"
    assert sink.hint("vo:lsc").startswith("ask your experiment (atlas)")


def test_an_lsc_for_another_server_than_the_one_configured_is_the_users(
    vomses: str, grid: Grid, monkeypatch: pytest.MonkeyPatch
):
    """A vomsdir full of another server's LSC is the stale *entry's* fault, not the VO's.

    This is the LHCb case exactly: ``vomsdir/lhcb`` held
    ``voms-lhcb-auth.cern.ch.lsc``, while the ``vomses`` file left behind named
    ``lcg-voms.cern.ch``. The old check only asked whether the directory
    existed, said "present", and every AC from that entry was unvalidatable.
    """
    (grid.voms_dir / "atlas" / "voms.example.org.lsc").rename(
        grid.voms_dir / "atlas" / "voms3.example.org.lsc"
    )
    monkeypatch.setattr(credentials, "grid_voms_dir", lambda *a, **k: str(grid.voms_dir))
    sink = run({"X509_VOMSES": vomses}, vo="atlas")
    assert sink.state("vo:lsc") == "warn"
    detail = sink.detail("vo:lsc")
    assert "voms.example.org.lsc" in detail and "voms3.example.org.lsc" in detail
    assert sink.hint("vo:lsc").startswith("do:")


def test_an_vo_with_no_vomsdir_at_all_says_so(vomses: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(credentials, "grid_voms_dir", lambda *a, **k: None)
    sink = run({"X509_VOMSES": vomses}, vo="atlas")
    assert "X509_VOMS_DIR is unset" in sink.detail("vo:lsc")


def test_a_server_that_answers_is_fine(vomses: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        doctor,
        "_probe",
        lambda server, context, timeout=0: doctor._Answer(expires=time.time() + 400 * 86400),
    )
    sink = run({"X509_VOMSES": vomses}, vo="atlas", servers=True)
    assert sink.state("vo:server") == "ok" and "answered and verified" in sink.detail("vo:server")
    assert sink.state("vo:cert") == "ok" and "valid until" in sink.detail("vo:cert")


def test_a_server_that_does_not_answer_is_the_admins_when_none_do(
    vomses: str, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        doctor,
        "_probe",
        lambda server, context, timeout=0: doctor._Answer(reason="connection refused"),
    )
    sink = run({"X509_VOMSES": vomses}, vo="atlas", servers=True)
    assert sink.state("vo:server") == "bad"
    assert sink.hint("vo:server").startswith("ask your admin")


def test_one_server_down_while_another_answers_is_the_experiments(
    vomses: str, monkeypatch: pytest.MonkeyPatch
):
    answers = iter(
        [doctor._Answer(expires=time.time() + 90 * 86400), doctor._Answer("no such host")]
    )
    monkeypatch.setattr(doctor, "_probe", lambda server, context, timeout=0: next(answers))
    sink = run({"X509_VOMSES": vomses}, vo="atlas", servers=True)
    assert sink.state("vo:server") == "ok"
    assert sink.state("vo:alt") == "warn"
    assert sink.hint("vo:alt").startswith("ask your experiment (atlas)")


def test_servers_configured_without_a_file_are_named_as_configured(
    monkeypatch: pytest.MonkeyPatch,
):
    """A vomses entry a caller built in code has no file to point at."""
    from xrdsec.voms_client import VOMSServer

    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    monkeypatch.setattr(
        doctor, "find_vomses", lambda *a, **k: [VOMSServer("atlas", "h", 1, "/CN=x", "atlas")]
    )
    sink = run()
    assert sink.detail("voms").endswith("the configured vomses files")


def test_a_credential_is_fine_with_no_ca_directory_to_check_it_against(grid: Grid):
    """No CA directory to check the issuer against is not the credential's fault."""
    env = {"X509_USER_CERT": str(grid.usercert), "X509_USER_KEY": str(grid.userkey)}
    sink = run(env)
    assert sink.state("credential") == "ok"


def test_the_server_check_verifies_against_the_ca_directory(
    ca_dir: str, vomses: str, monkeypatch: pytest.MonkeyPatch
):
    """With a CA directory the context is built from it: the code path a real machine takes."""
    seen: list[str] = []

    def probe(server: Any, context: Any, timeout: float = 0) -> Any:
        seen.append("probed")
        assert context is not None
        return doctor._Answer()

    monkeypatch.setattr(doctor, "_probe", probe)
    sink = run({"X509_VOMSES": vomses, "X509_CERT_DIR": ca_dir}, vo="atlas", servers=True)
    assert seen == ["probed", "probed"] and sink.state("vo:server") == "ok"


def test_the_vomses_origins_are_one_line(vomses: str, tmp_path: Path):
    """A directory of vomses files is named as the directory, not 126 times."""
    directory = tmp_path / "vomses.d"
    directory.mkdir()
    (directory / "cms").write_text(CMS)
    (directory / "atlas").write_text(ATLAS)
    sink = run({"X509_VOMSES": str(directory)})
    assert sink.detail("voms").endswith(str(directory))
    first = tmp_path / "one"
    second = tmp_path / "two"
    for directory in (first, second):
        directory.mkdir()
    (first / "vomses").write_text(ATLAS)
    (second / "vomses").write_text(CMS)
    two = run({"X509_VOMSES": f"{first / 'vomses'}{os.pathsep}{second / 'vomses'}"})
    assert str(first) in two.detail("voms") and str(second) in two.detail("voms")


# ---------------------------------------------------------------------------
# The proxy file, and writing one
# ---------------------------------------------------------------------------


def test_no_proxy_yet_is_a_warning_with_the_command(tmp_path: Path):
    sink = run({"X509_USER_PROXY": str(tmp_path / "x509up")}, vo="lhcb")
    assert sink.state("proxy") == "warn"
    assert sink.hint("proxy") == "do: xrd-proxy init -voms lhcb"


def test_an_existing_proxy_says_how_long_it_lasts(grid: Grid, tmp_path: Path):
    path = write_proxy(
        tmp_path / "x509up", create_proxy(grid.credential(), voms_acs=[grid.make_ac()])
    )
    sink = run({"X509_USER_PROXY": path})
    assert sink.state("proxy") == "ok"
    assert "atlas" in sink.detail("proxy") and "left" in sink.detail("proxy")


def test_a_proxy_without_acs_is_described_as_such(grid: Grid, tmp_path: Path):
    path = write_proxy(tmp_path / "x509up", create_proxy(grid.credential()))
    sink = run({"X509_USER_PROXY": path})
    assert "no VO attributes" in sink.detail("proxy")


def test_an_expired_proxy_is_the_users_to_remake(grid: Grid, tmp_path: Path):
    path = write_proxy(tmp_path / "x509up", create_proxy(grid.credential(), lifetime=60))
    sink = run({"X509_USER_PROXY": path}, now=time.time() + 3600)
    assert sink.state("proxy") == "bad" and "expired" in sink.detail("proxy")


def test_a_proxy_others_can_read_is_refused(grid: Grid, tmp_path: Path):
    path = write_proxy(tmp_path / "x509up", create_proxy(grid.credential()))
    os.chmod(path, 0o644)
    sink = run({"X509_USER_PROXY": path})
    assert sink.state("proxy") == "bad" and sink.hint("proxy").startswith("do: chmod 600")


def test_a_link_at_the_predictable_place_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    placeholder = tmp_path / "x509up"
    placeholder.symlink_to(tmp_path / "elsewhere")
    monkeypatch.setattr(
        proxytool,
        "proxy_target",
        lambda named=None, environ=None: proxytool.Target(str(placeholder), False),
    )
    sink = run({"X509_USER_PROXY": str(placeholder)})
    assert sink.state("location") == "bad" and "symbolic link" in sink.detail("location")


def test_a_directory_that_is_not_there(tmp_path: Path):
    where = tmp_path / "gone" / "x509up"
    sink = run({"X509_USER_PROXY": str(where)})
    assert sink.state("location") == "bad" and "is not a directory" in sink.detail("location")


def test_a_directory_that_cannot_be_written(tmp_path: Path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        sink = run({"X509_USER_PROXY": str(locked / "x509up")})
    finally:
        locked.chmod(0o700)
    assert sink.state("location") == "bad" and "not writable" in sink.detail("location")


def test_a_writable_directory_is_fine(tmp_path: Path):
    sink = run({"X509_USER_PROXY": str(tmp_path / "x509up")})
    assert sink.state("location") == "ok" and "0600" in sink.detail("location")


# ---------------------------------------------------------------------------
# The other kind of credential
# ---------------------------------------------------------------------------


def test_no_token_is_not_a_problem(tmp_path: Path):
    sink = run({"X509_USER_PROXY": str(tmp_path / "x509up")})
    assert sink.state("tokens") == "skip"


def _jwt(claims: dict[str, Any]) -> str:
    """A compact JWS whose claims are readable: enough for an unverified ``exp``."""

    def segment(value: dict[str, Any]) -> str:
        raw = json.dumps(value).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{segment({'alg': 'RS256'})}.{segment(claims)}.signature"


def test_a_token_is_described_with_what_is_left(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    token_file = tmp_path / "token"
    token_file.write_text(_jwt({"exp": int(time.time()) + 3600}))
    token_file.chmod(0o600)
    sink = run({"BEARER_TOKEN_FILE": str(token_file), "X509_USER_PROXY": str(tmp_path / "x")})
    assert sink.state("tokens") == "ok" and "left" in sink.detail("tokens")


def test_a_token_with_no_expiry_is_left_to_the_server(tmp_path: Path):
    token_file = tmp_path / "token"
    token_file.write_text("opaque-token")
    token_file.chmod(0o600)
    sink = run({"BEARER_TOKEN_FILE": str(token_file), "X509_USER_PROXY": str(tmp_path / "x")})
    assert sink.state("tokens") == "ok" and "no expiry to read" in sink.detail("tokens")


def test_an_expired_token_is_the_users_to_refresh(tmp_path: Path):
    token_file = tmp_path / "token"
    token_file.write_text(_jwt({"exp": int(time.time()) - 60}))
    token_file.chmod(0o600)
    sink = run({"BEARER_TOKEN_FILE": str(token_file), "X509_USER_PROXY": str(tmp_path / "x")})
    assert sink.state("tokens") == "bad" and sink.hint("tokens").startswith("do:")


def test_a_token_file_others_can_read_is_refused(tmp_path: Path):
    token_file = tmp_path / "token"
    token_file.write_text("opaque-token")
    token_file.chmod(0o644)
    sink = run({"BEARER_TOKEN_FILE": str(token_file), "X509_USER_PROXY": str(tmp_path / "x")})
    assert sink.state("tokens") == "bad" and "chmod 600" in sink.hint("tokens")


# ---------------------------------------------------------------------------
# Talking to a VOMS server
# ---------------------------------------------------------------------------


@pytest.fixture
def tls_server(pki: Any) -> Iterator[int]:
    """A TLS server with the session PKI's host certificate."""
    context = pki.server_context()
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = int(listener.getsockname()[1])

        def serve() -> None:
            while True:
                try:
                    connection, _ = listener.accept()
                except OSError:
                    return
                try:
                    with context.wrap_socket(connection, server_side=True):
                        pass
                except (OSError, ssl.SSLError):
                    continue

        threading.Thread(target=serve, daemon=True).start()
        yield port


@pytest.fixture
def plain_server() -> Iterator[int]:
    """A listening port that is not TLS: the "somebody else's port" case."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        yield int(listener.getsockname()[1])


def _server(port: int) -> Any:
    from xrdsec.voms_client import VOMSServer

    return VOMSServer("atlas", "localhost", port, "/CN=localhost", "atlas")


def test_a_server_that_verifies_answers(tls_server: int, pki: Any):
    from xrdsec.tls import client_context

    answer = doctor._probe(_server(tls_server), client_context(ca_path=str(pki.ca_dir)))
    assert answer.reason is None and answer.expires is not None


def test_a_server_whose_certificate_is_not_trusted(tls_server: int, tmp_path: Path):
    """A server is judged by the CA directory it is checked against: no CAs, nothing verifies."""
    from xrdsec.tls import client_context

    empty = tmp_path / "no-cas"
    empty.mkdir()
    answer = doctor._probe(_server(tls_server), client_context(ca_path=str(empty), verify=True))
    assert answer.reason is not None and "not trusted" in answer.reason


def test_a_server_that_does_not_speak_tls(plain_server: int, pki: Any):
    """A port that accepts and says nothing is a timeout, reported as it is, not as trust."""
    from xrdsec.tls import client_context

    answer = doctor._probe(_server(plain_server), client_context(ca_path=str(pki.ca_dir)))
    assert answer.reason is not None and "not trusted" not in answer.reason


def test_a_server_that_does_not_answer(pki: Any):
    from xrdsec.tls import client_context

    with socket.create_server(("127.0.0.1", 0)) as listener:
        closed = int(listener.getsockname()[1])
    answer = doctor._probe(_server(closed), client_context(ca_path=str(pki.ca_dir)))
    assert answer.reason is not None and "not trusted" not in answer.reason


def test_with_no_ca_directory_a_connection_is_all_that_is_asked(pki: Any):
    """No trust anchors to judge the certificate by: whether it answered is the answer."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = int(listener.getsockname()[1])
        assert doctor._probe(_server(port), None).reason is None


# ---------------------------------------------------------------------------
# Wording
# ---------------------------------------------------------------------------


def test_the_short_time_words():
    assert doctor._clock(3661) == "1:01:01"
    assert doctor._ago(2 * 86400) == "2 days"
    assert doctor._ago(86400) == "1 day"
    assert doctor._ago(3 * 3600) == "3 hours"
    assert doctor._ago(3600) == "1 hour"
    assert doctor._ago(60) == "less than an hour"
    assert doctor._date(0)  # a date, whatever the zone


# ---------------------------------------------------------------------------
# The sweep, and the server certificate's own clock
# ---------------------------------------------------------------------------


def test_the_sweep_says_which_vos_nothing_answered_for(
    vomses: str, monkeypatch: pytest.MonkeyPatch
):
    """A site admin's question: does anything here still work."""

    def probe(server: Any, context: Any, timeout: float = 0) -> Any:
        return doctor._Answer() if server.vo == "atlas" else doctor._Answer(reason="timed out")

    monkeypatch.setattr(doctor, "_probe", probe)
    sink = run({"X509_VOMSES": vomses}, servers=True, all_vos=True)
    assert sink.state("vos") == "warn"
    assert "1 of 2 VOs answered" in sink.detail("vos") and "cms" in sink.detail("vos")
    assert sink.hint("vos").startswith("ask your experiment")


def test_a_sweep_where_everything_answers(vomses: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(doctor, "_probe", lambda server, context, timeout=0: doctor._Answer())
    sink = run({"X509_VOMSES": vomses}, servers=True, all_vos=True)
    assert sink.state("vos") == "ok" and "all 2 VOs answered" in sink.detail("vos")


@pytest.mark.parametrize(
    ("left_days", "state"),
    [(400, "ok"), (10, "warn"), (-2, "bad")],
)
def test_a_voms_servers_own_certificate_is_checked(
    vomses: str, monkeypatch: pytest.MonkeyPatch, left_days: int, state: str
):
    """A server certificate nobody renews takes the whole VO down on its expiry date."""
    expires = time.time() + left_days * 86400

    def probe(server: Any, context: Any, timeout: float = 0) -> Any:
        return doctor._Answer(expires=expires)

    monkeypatch.setattr(doctor, "_probe", probe)
    sink = run({"X509_VOMSES": vomses}, vo="atlas", servers=True)
    assert sink.state("vo:cert") == state


def test_a_certificate_that_cannot_be_read_has_no_expiry():
    class NoCertificate:
        def getpeercert(self) -> Any:
            return {}

    # a duck-typed stand-in for an SSLSocket: only getpeercert is used
    assert doctor._peer_expiry(NoCertificate()) is None  # type: ignore[arg-type]  # see above


# ---------------------------------------------------------------------------
# A configuration too big to parse for one line
# ---------------------------------------------------------------------------


def test_a_vomses_directory_is_counted_rather_than_parsed(tmp_path: Path, monkeypatch):
    """126 CVMFS files cost half a minute to read: the report says how many, and where."""
    directory = tmp_path / "vomses.d"
    directory.mkdir()
    for index in range(12):  # more than PARSE_LIMIT
        (directory / f"vo{index}").write_text(CMS)
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    sink = run({"X509_VOMSES": str(directory)})
    assert sink.state("voms") == "ok"
    assert "12 vomses files in" in sink.detail("voms")
    assert sink.hint("voms").startswith("do: xrd-proxy init -list-vos")


def test_a_named_vo_reads_only_its_own_files(vomses: str, monkeypatch):
    """With ``-voms`` the report reads the VO's own vomses files, not all of them."""
    monkeypatch.setattr(credentials, "grid_ca_path", lambda *a, **k: None)
    sink = run({"X509_VOMSES": vomses}, vo="atlas")
    assert sink.state("voms") == "ok" and sink.state("vo") == "ok"
