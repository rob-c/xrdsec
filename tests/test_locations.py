"""The four stages every lookup goes through: env, local, CVMFS, then the working directory.

The order is a promise, so it is tested as one: what a machine found before
this module existed is still found first, and the new stages only ever add
somewhere to fall back to.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from xrdsec import credentials, locations


@pytest.fixture
def staged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real CVMFS and working-directory stages, which the suite neutralises by default."""
    monkeypatch.setattr(
        locations, "CVMFS_GRID_SECURITY", ("/cvmfs/grid.cern.ch/etc/grid-security",)
    )


def test_the_stages_are_the_four_asked_for():
    assert locations.STAGES == ("env", "local", "cvmfs", "cwd")


def test_the_environment_comes_first_then_the_machine_then_cvmfs_then_here(staged):
    found = locations.grid_security_directories(
        "certificates",
        {"X509_CERT_DIR": "/from/env"},
        workdir="/work",
    )
    assert [location.stage for location in found] == ["env", "local", "cvmfs", "cwd"]
    assert found[0].path == "/from/env" and found[0].origin == "$X509_CERT_DIR"
    assert found[-2].path == "/cvmfs/grid.cern.ch/etc/grid-security/certificates"
    assert found[-1].path == "/work/grid-security/certificates"


def test_a_blank_variable_is_not_a_stage(staged):
    """An exported-but-empty variable means "not configured", as everywhere else here."""
    assert locations.grid_security_directories("vomsdir", {"X509_VOMS_DIR": "  "})[0].stage != "env"


def test_every_artifact_kind_has_its_own_variable(staged):
    for kind, variable in (
        ("certificates", "X509_CERT_DIR"),
        ("vomsdir", "X509_VOMS_DIR"),
        ("vomses", "X509_VOMSES"),
    ):
        found = locations.grid_security_directories(kind, {variable: "/named"})
        assert found[0].path == "/named" and found[0].origin == f"${variable}"


def test_the_working_directory_is_pwd_when_there_is_one(staged):
    found = locations.grid_security_directories("vomses", {"PWD": "/from/pwd"})
    assert found[-1].path == "/from/pwd/grid-security/vomses"
    assert locations.cwd({"PWD": "/from/pwd"}) == "/from/pwd"


def test_the_working_directory_falls_back_to_the_process(tmp_path, monkeypatch):
    monkeypatch.setattr(locations, "WORKDIR", None)
    monkeypatch.chdir(tmp_path)
    assert locations.cwd({}) == os.getcwd()
    monkeypatch.setattr(locations, "WORKDIR", "/a/suite/said/so")
    assert locations.cwd({}) == "/a/suite/said/so"


def test_a_location_knows_whether_it_is_there(tmp_path: Path):
    present = locations.Location(str(tmp_path), "local", "here")
    missing = locations.Location(str(tmp_path / "gone"), "local", "here")
    assert present.exists() and present.is_dir()
    assert not missing.exists() and not missing.is_dir()


def test_the_first_present_location_is_the_answer(tmp_path: Path):
    found = locations.Location(str(tmp_path), "local", "here")
    assert (
        locations.first_present([locations.Location("/nonexistent", "env", "$X"), found]) == found
    )
    assert locations.first_present([locations.Location("/nonexistent", "env", "$X")]) is None


def test_the_machine_stage_is_exactly_what_a_tool_used_to_search(monkeypatch):
    """Stages 1 and 2 are the old list in the old order: nothing a machine had is lost."""
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", ("/etc/grid-security",))
    assert credentials.machine_grid_security("certificates") == ("/etc/grid-security/certificates",)
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", None)
    monkeypatch.setattr("sys.platform", "darwin")
    assert credentials.machine_grid_security("vomsdir") == (
        "/etc/grid-security/vomsdir",
        "/opt/homebrew/etc/grid-security/vomsdir",
        "/usr/local/etc/grid-security/vomsdir",
    )


def test_cvmfs_is_only_a_fallback(staged, monkeypatch, tmp_path: Path):
    """A machine directory that exists still wins over the shared bundle."""
    machine = tmp_path / "etc"
    (machine / "certificates").mkdir(parents=True)
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", (str(machine),))
    monkeypatch.setattr(
        locations, "CVMFS_GRID_SECURITY", ("/cvmfs/grid.cern.ch/etc/grid-security",)
    )
    monkeypatch.setenv("X509_CERT_DIR", "")
    assert credentials.grid_ca_path({}) == str(machine / "certificates")


def test_cvmfs_answers_when_the_machine_has_nothing(staged, monkeypatch):
    """With no machine directory and no bundle in a home, CVMFS is what is left."""
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", ())
    monkeypatch.setattr(os.path, "isdir", lambda _path: True)
    # No bundle in a home either, or that would be the answer instead.
    monkeypatch.delenv("HOME", raising=False)
    assert credentials.grid_ca_path({}) == "/cvmfs/grid.cern.ch/etc/grid-security/certificates"


def test_a_user_pair_from_the_working_directory_is_last(monkeypatch, tmp_path: Path):
    """A certificate unpacked where you are working is found, after the documented places."""
    monkeypatch.setattr(credentials, "GRID_SECURITY_DIRS", ())
    monkeypatch.setattr(locations, "WORKDIR", str(tmp_path))
    (tmp_path / "grid-security").mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    assert credentials.find_user_credential({}) is None
    (tmp_path / "usercert.pem").write_bytes(b"cert")
    (tmp_path / "userkey.pem").write_bytes(b"key")
    assert credentials.find_user_credential({}) == (
        str(tmp_path / "usercert.pem"),
        str(tmp_path / "userkey.pem"),
    )


def test_a_documented_pair_still_beats_the_working_directory(monkeypatch, tmp_path: Path):
    home = tmp_path / "home"
    (home / ".globus").mkdir(parents=True)
    (home / ".globus" / "usercert.pem").write_bytes(b"cert")
    (home / ".globus" / "userkey.pem").write_bytes(b"key")
    (tmp_path / "usercert.pem").write_bytes(b"other")
    (tmp_path / "userkey.pem").write_bytes(b"other")
    monkeypatch.setattr(locations, "WORKDIR", str(tmp_path))
    found = credentials.find_user_credential({"HOME": str(home)})
    assert found is not None and found[0].startswith(str(home))


def test_the_pairs_are_offered_in_stage_order(tmp_path: Path):
    pairs = locations.user_pairs(
        {"X509_USER_CERT": "/c", "X509_USER_KEY": "/k", "HOME": "/home"}, workdir="/work"
    )
    assert [pair[0].stage for pair in pairs] == ["env", "local", "cwd"]
    assert pairs[0][0].path == "/c" and pairs[1][0].path == "/home/.globus/usercert.pem"
    assert pairs[2][0].path == "/work/usercert.pem"
    # CVMFS is not a stage for a user's own key
    assert "cvmfs" not in [pair[0].stage for pair in pairs]


def test_the_proxy_may_be_named_then_in_tmpdir_then_in_tmp_then_here(tmp_path: Path):
    found = locations.proxy_candidates(
        {"X509_USER_PROXY": "/named/by/env", "TMPDIR": "/var/folders/x/"},
        uid=501,
        named="/named/on/the/command/line",
        workdir="/work",
    )
    assert [location.path for location in found] == [
        "/named/on/the/command/line",
        "/named/by/env",
        "/var/folders/x/x509up_u501",
        "/tmp/x509up_u501",
        "/work/x509up_u501",
    ]
    assert found[0].origin == "named on the command line"
    assert found[3].origin == "/tmp"


def test_a_proxy_search_without_a_uid_or_tmpdir(tmp_path: Path):
    found = locations.proxy_candidates({"HOME": str(tmp_path)}, uid=7, workdir="/work")
    assert [location.path for location in found] == ["/tmp/x509up_u7", "/work/x509up_u7"]


def test_the_wlcg_layout_alone_is_enough_with_no_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The layout that broke, reproduced exactly: one ``vomses`` file per *server*.

    A CVMFS bundle answers with ``vomses/<server host>`` (not ``vomses/<vo>``)
    and ``vomsdir/<vo>/<server host>.lsc``. With nothing in the environment and
    no ``~/.voms``, stage 3 alone must produce the VO's servers *and* the LSC
    each of them needs - which is what was missing when ``xrd-proxy init -voms
    lhcb`` said no VOMS server was configured anywhere.
    """
    from xrdsec.voms_client import find_vomses, lsc_names

    base = tmp_path / "cvmfs" / "grid.cern.ch" / "etc" / "grid-security"
    server = "voms-lhcb-auth.cern.ch"
    authority = "/DC=ch/DC=cern/CN=CERN Grid Certification Authority"
    dn = f"/DC=ch/DC=cern/OU=computers/CN={server}"
    (base / "vomses").mkdir(parents=True)
    (base / "vomses" / server).write_text(f'"lhcb" "{server}" 443 "{dn}" "lhcb"\n')
    (base / "vomsdir" / "lhcb").mkdir(parents=True)
    (base / "vomsdir" / "lhcb" / f"{server}.lsc").write_text(f"{dn}\n{authority}\n")
    monkeypatch.setattr(locations, "CVMFS_GRID_SECURITY", (str(base),))
    monkeypatch.setattr(credentials, "machine_grid_security", lambda kind: ())

    servers = find_vomses(environ={"HOME": str(tmp_path / "home")}, vo="lhcb")

    assert [each.address for each in servers] == [f"{server}:443"]
    assert lsc_names(servers) == [f"{server}.lsc"]
    assert (base / "vomsdir" / "lhcb" / lsc_names(servers)[0]).is_file()


def test_a_vomses_entry_whose_server_has_no_lsc_is_visible_as_such(tmp_path: Path):
    """The stale-entry shape: the VO's directory is full, but not for the server named.

    ``vomsdir/lhcb`` holding ``voms-lhcb-auth.cern.ch.lsc`` while the entry says
    ``lcg-voms.cern.ch`` is exactly how an out-of-date ``vomses`` file looked
    harmless: the directory was there, so every check that only asked about the
    directory said yes.
    """
    from xrdsec.voms_client import lsc_names, parse_vomses

    stale = parse_vomses('"lhcb" "lcg-voms.cern.ch" 15015 "/CN=lcg-voms.cern.ch" "lhcb"')
    folder = tmp_path / "vomsdir" / "lhcb"
    folder.mkdir(parents=True)
    (folder / "voms-lhcb-auth.cern.ch.lsc").write_text("/CN=voms-lhcb-auth.cern.ch\n")

    assert os.path.isdir(folder)  # what the old check asked
    assert lsc_names(stale) == ["lcg-voms.cern.ch.lsc"]  # what is actually needed
    assert not (folder / lsc_names(stale)[0]).exists()


def test_a_bundle_kept_in_the_home_directory_is_found() -> None:
    """An IGTF copy unpacked once is how a person has CAs without CVMFS."""
    env = {"HOME": "/Users/someone"}
    found = locations.grid_security_directories("certificates", env, workdir="/work")
    local = [place.path for place in found if place.stage == "local"]
    assert "/Users/someone/grid-ca/certificates" in local
    assert "/Users/someone/.grid-security/certificates" in local


def test_with_no_home_there_is_no_home_bundle() -> None:
    """A session without a home has nothing to look under."""
    assert locations.home_grid_security("certificates", {}) == []
    assert "/grid-ca/certificates" not in [
        place.path
        for place in locations.grid_security_directories("certificates", {}, workdir="/work")
    ]
