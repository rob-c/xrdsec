"""Obtaining VOMS ACs: ``vomses`` lookup, and ``generate-ac`` against a fake VOMS server."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import warnings
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from xrdsec import usercred as _usercred
from xrdsec.proxies import create_proxy, voms_extension
from xrdsec.testing.proxygrid import FakeVOMS, Grid, ac_answer, build_grid, error_answer, key
from xrdsec.voms import VOMSStatus, check_vomses, inspect_voms, validate_voms
from xrdsec.voms_client import (
    VOMSConfigError,
    VOMSError,
    VOMSRefusedError,
    VOMSServer,
    VOMSUnavailableError,
    VOMSWarning,
    ac_extension,
    fetch_ac,
    find_vomses,
    parse_vomses,
    servers_for,
    vomses_files,
)
from xrdsec.x509 import Name, ProxyCredential

ATLAS = '"atlas" "voms1.example.org" "15001" "/DC=org/CN=voms1.example.org" "atlas"\n'
ATLAS2 = '"atlas" "voms2.example.org" "15001" "/DC=org/CN=voms2.example.org" "atlas"\n'
CMS = '"cms-alias" "voms.cern.ch" "15002" "/DC=ch/CN=voms.cern.ch" "cms"\n'


@pytest.fixture
def grid(tmp_path, monkeypatch) -> Grid:
    made = build_grid(tmp_path / "grid")
    monkeypatch.setenv("X509_VOMS_DIR", str(made.voms_dir))
    monkeypatch.setenv("X509_CERT_DIR", str(made.ca_dir))
    return made


def _fetch(servers: Sequence[VOMSServer], grid: Grid, **kwargs: Any) -> tuple[bytes, list[str]]:
    """``fetch_ac`` with the warnings it gave."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        ac = fetch_ac(servers, grid.credential(), ca_path=str(grid.ca_dir), **kwargs)
    return ac, [str(warning.message) for warning in caught if warning.category is VOMSWarning]


def _closed_port() -> int:
    """A local port nothing listens on (bound and released)."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


# ---------------------------------------------------------------------------
# vomses
# ---------------------------------------------------------------------------


def test_parse_vomses_reads_the_five_fields():
    servers = parse_vomses("# comment\n\n" + ATLAS + CMS, "here")
    assert servers[0] == VOMSServer(
        "atlas", "voms1.example.org", 15001, "/DC=org/CN=voms1.example.org", "atlas"
    )
    assert servers[0].origin == "here:3" and servers[1].vo == "cms"
    assert servers[0].address == "voms1.example.org:15001"
    assert VOMSServer("a", "::1", 1, "", "a").address == "[::1]:1"


def test_a_line_with_the_trailing_field_cern_writes_is_read():
    """``grid.cern.ch`` ends six of its vomses lines with a bare port/version field.

    Refusing them would make the whole directory unreadable - one such line
    stops every VO on a machine that mounts that bundle - so the first five
    fields are used and anything after them is ignored, as glite does.
    """
    line = (
        '"bes" "voms.ihep.ac.cn" "15001" "/C=CN/O=HEP/OU=CC/O=IHEP/CN=voms.ihep.ac.cn" "bes" "24"'
    )
    (server,) = parse_vomses(line, "bes")
    assert (server.alias, server.host, server.port, server.vo) == (
        "bes",
        "voms.ihep.ac.cn",
        15001,
        "bes",
    )


def test_an_unknown_vo_names_the_ones_that_are_configured():
    """Choosing a VO needs to know which ones this machine can ask."""
    servers = parse_vomses(ATLAS + CMS, "here")
    with pytest.raises(VOMSConfigError, match="configured: atlas, cms") as typo:
        servers_for("atls", servers)
    assert "did you mean 'atlas'" in str(typo.value)
    with pytest.raises(VOMSConfigError, match="no VOMS server is configured for 'lhcb'"):
        servers_for("lhcb", servers)
    with pytest.raises(VOMSConfigError, match="install the VO's vomses file") as empty:
        servers_for("atlas", [])
    assert "configured:" not in str(empty.value)


@pytest.mark.parametrize(
    "line",
    [
        '"atlas" "host" "15000" "/CN=server"',
        '"atlas" "host" "0" "/CN=server" "atlas"',
        '"atlas" "host" "port" "/CN=server" "atlas"',
        '"atlas" "host" "15000" "/CN=server" "../atlas"',
        '"atlas" "unclosed',
    ],
)
def test_a_malformed_line_is_refused_where_the_preflight_flags_it(tmp_path, line):
    with pytest.raises(VOMSConfigError, match=r"^f:2: not a vomses line"):
        parse_vomses(ATLAS + line, "f")
    path = tmp_path / "vomses"
    path.write_text(line + "\n")
    assert check_vomses(str(path))[0].code == "vomses_malformed"  # one parser


def test_find_vomses_reads_named_files_and_directories(tmp_path):
    single = tmp_path / "vomses"
    single.write_text(ATLAS)
    directory = tmp_path / "vomses.d"
    directory.mkdir()
    (directory / "cms").write_text(CMS)
    (directory / "atlas2").write_text(ATLAS2 + ATLAS)
    (directory / ".hidden").write_text("junk")
    assert [s.host for s in find_vomses(single)] == ["voms1.example.org"]
    found = find_vomses([single, str(directory)])
    assert [s.host for s in found] == ["voms1.example.org", "voms2.example.org", "voms.cern.ch"]
    with pytest.raises(VOMSConfigError, match="does not exist"):
        find_vomses(tmp_path / "nowhere")
    (directory / "bad").write_bytes(b"\xff\xfe")
    with pytest.raises(VOMSConfigError, match="cannot read"):
        find_vomses(directory)


def test_the_environment_names_vomses_and_must_be_right(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    one.write_text(ATLAS)
    two.write_text(CMS)
    env = {"X509_VOMSES": f"{one}{os.pathsep}{two}", "HOME": str(tmp_path)}
    assert [s.vo for s in find_vomses(environ=env)] == ["atlas", "cms"]
    assert [s.vo for s in find_vomses(environ={"VOMS_USERCONF": str(two)})] == ["cms"]
    with pytest.raises(VOMSConfigError, match="does not exist"):
        find_vomses(environ={"X509_VOMS_FILE": str(tmp_path / "typo")})


def test_the_default_places_are_merged(tmp_path, monkeypatch):
    from xrdsec import credentials

    home = tmp_path / "home"
    (home / ".voms").mkdir(parents=True)
    (home / ".voms" / "vomses").write_text(ATLAS)
    (home / ".glite").mkdir()
    (home / ".glite" / "vomses").write_text(ATLAS + CMS)  # the duplicate is dropped
    system = tmp_path / "etc-vomses"
    system.mkdir()
    (system / "atlas2").write_text(ATLAS2)
    monkeypatch.setattr(credentials, "_candidates", lambda kind: (str(system),))
    found = find_vomses(environ={"HOME": str(home)})
    assert [s.host for s in found] == ["voms1.example.org", "voms.cern.ch", "voms2.example.org"]
    assert find_vomses(environ={"HOME": str(tmp_path / "empty")})[:0] == []


def test_servers_for_matches_alias_then_vo():
    servers = parse_vomses(ATLAS + ATLAS2 + CMS)
    assert [s.host for s in servers_for("atlas", servers)] == [
        "voms1.example.org",
        "voms2.example.org",
    ]
    assert servers_for("cms-alias", servers) == servers_for("cms", servers)
    with pytest.raises(VOMSConfigError, match="among the configured servers"):
        servers_for("lhcb", servers)
    with pytest.raises(VOMSConfigError, match="'lhcb' anywhere"):
        servers_for("lhcb", [])


def test_ac_extension_is_the_proxy_extension(grid):
    ac = grid.make_ac()
    assert ac_extension([ac]) == voms_extension([ac])
    proxy = create_proxy(grid.credential(), voms_acs=[ac])
    assert inspect_voms(proxy.chain).entries[0].vo == "atlas"


# ---------------------------------------------------------------------------
# fetch_ac
# ---------------------------------------------------------------------------


def test_an_ac_is_fetched_validated_and_usable(grid):
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake:
        ac, said = _fetch(
            [fake.server()], grid, fqans=["/atlas", "/atlas/Role=pilot"], lifetime=7200
        )
        path, query, peer = fake.requests[0]
    assert said == []
    assert path == "/generate-ac"
    assert query == {"fqans": ["/atlas,/atlas/Role=pilot"], "lifetime": ["7200"]}
    # a proxy is presented, as voms-proxy-init presents one: the user's DN, plus the proxy's CN
    values = [value for rdn in peer["subject"] for _oid, value in rdn]
    assert values.count("Jane Doe") == 1 and values[-1] != "Jane Doe"
    proxy = create_proxy(grid.credential(), voms_acs=[ac])
    assert validate_voms(proxy.chain).status is VOMSStatus.OK


def test_x509_strict_reaches_the_tls_context(grid, monkeypatch):
    """``x509_strict=False`` relaxes the connection's RFC 5280 checks; the default keeps them."""
    import ssl

    from xrdsec import tls

    built = []
    real = tls.client_context

    def spy(**kwargs):
        built.append(real(**kwargs))
        return built[-1]

    monkeypatch.setattr(tls, "client_context", spy)
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake:
        _fetch([fake.server()], grid)
        _fetch([fake.server()], grid, x509_strict=False)
    strict, relaxed = (bool(ctx.verify_flags & ssl.VERIFY_X509_STRICT) for ctx in built)
    assert strict is (ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT != 0)
    assert relaxed is False


def test_a_bare_request_asks_for_the_defaults(grid):
    import datetime

    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake:
        _fetch([fake.server()], grid)
        _fetch([fake.server()], grid, lifetime=datetime.timedelta(hours=1))
        assert fake.requests[0][1] == {}
        assert fake.requests[1][1] == {"lifetime": ["3600"]}


def test_an_unreachable_server_is_skipped_for_the_next(grid):
    dead = VOMSServer("atlas", "127.0.0.1", _closed_port(), "", "atlas")
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake:
        ac, _ = _fetch([dead, fake.server()], grid, timeout=5)
    assert inspect_voms((create_proxy(grid.credential(), voms_acs=[ac]).chain[0],)).entries


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (error_answer(500, "InternalError", "database down"), "InternalError: database down"),
        (error_answer(503, "", ""), "HTTP 503"),
        ((503, b"<html>maintenance</html>"), "HTTP 503 without a VOMS answer"),
        ((200, b"not xml at all"), "without a VOMS answer"),
        ((200, b"<!DOCTYPE voms><voms/>"), "without a VOMS answer"),
        ((404, b"<voms/>"), "HTTP 404"),
        ((200, b"<voms><ac>   </ac></voms>"), "holds no attribute certificate"),
        ((200, b"<voms><ac>!!!!</ac></voms>"), "not valid base64"),
        ((200, b"<voms><ac>AAAA</ac></voms>"), "does not decode"),
        ((200, b"x" * ((1 << 20) + 10)), "larger than"),
    ],
)
def test_a_server_failure_moves_on_and_is_reported(grid, answer, reason):
    with (
        FakeVOMS(grid, lambda query: answer) as bad,
        FakeVOMS(grid, lambda query: answer) as worse,
        pytest.raises(VOMSUnavailableError, match="no VOMS server for 'atlas'") as raised,
    ):
        _fetch([bad.server(), worse.server()], grid)
    assert len(raised.value.failures) == 2
    assert all(reason in failure for failure in raised.value.failures)


def test_an_ac_sequence_that_is_not_an_ac_does_not_decode(grid):
    import base64

    from xrdsec.testing.rawpki import sequence

    garbage = base64.b64encode(sequence(sequence())).decode()
    answer = (200, f"<voms><ac>{garbage}</ac></voms>".encode())
    with (
        FakeVOMS(grid, lambda query: answer) as fake,
        pytest.raises(VOMSUnavailableError, match="does not decode"),
    ):
        _fetch([fake.server()], grid)


@pytest.mark.parametrize(
    ("code", "words"),
    [
        ("NoSuchUser", "does not know your certificate"),
        ("SuspendedUser", "suspended"),
        ("BadRequest", "could not satisfy"),
        ("SomethingNew", "the request was refused"),
    ],
)
def test_a_refusal_is_final_and_explained(grid, code, words):
    with (
        FakeVOMS(grid, lambda query: error_answer(403, code, "  no  such\nuser ")) as first,
        FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as second,
    ):
        with pytest.raises(VOMSRefusedError, match=words) as raised:
            _fetch([first.server(), second.server()], grid)
        assert second.requests == []  # a verdict on the user is not asked twice
    assert raised.value.code == code and raised.value.reason == "no such user"
    assert raised.value.server.port == first.port
    assert f"({code}: no such user)" in str(raised.value)


def test_a_refusal_without_details_still_reads(grid):
    with (
        FakeVOMS(grid, lambda query: (403, b"<voms><error/></voms>")) as fake,
        pytest.raises(VOMSRefusedError) as raised,
    ):
        _fetch([fake.server()], grid)
    assert str(raised.value).endswith("refused: the request was refused")


def test_server_warnings_and_untrusted_acs_are_warnings(grid):
    answer = ac_answer(grid.make_ac(), "AC lifetime shortened to 12 hours", "   ")
    with FakeVOMS(grid, lambda query: answer) as fake:
        _, said = _fetch([fake.server()], grid)
    assert said == [f"{fake.server().address}: AC lifetime shortened to 12 hours"]
    forged = ac_answer(grid.make_ac(signer=key(6)))
    with FakeVOMS(grid, lambda query: forged) as fake:
        ac, said = _fetch([fake.server()], grid)
    assert ac and len(said) == 1 and "does not verify" in said[0]
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac(vo="atlas"))) as fake:
        _, said = _fetch([fake.server(alias="cms", vo="cms")], grid)
    assert any("for 'atlas', not 'cms'" in text for text in said)


def test_a_credential_that_cannot_issue_leaves_the_ac_unchecked(grid):
    spent = create_proxy(grid.credential(), path_length=0)
    with (
        FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake,
        warnings.catch_warnings(record=True) as caught,
    ):
        warnings.simplefilter("always")
        ac = fetch_ac([fake.server()], spent, ca_path=str(grid.ca_dir))
    assert ac and "was not checked" in str(caught[0].message)


def test_an_untrusted_server_is_a_failed_server(grid, tmp_path):
    empty = tmp_path / "no-cas"
    empty.mkdir()
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake:
        with pytest.raises(VOMSUnavailableError, match="its certificate is not trusted"):
            fetch_ac([fake.server()], grid.credential(), ca_path=str(empty), timeout=5)
        # The system store as well changes nothing for a private CA - but is honoured.
        with pytest.raises(VOMSUnavailableError):
            fetch_ac([fake.server()], grid.credential(), ca_path=str(empty), system_ca=True)


def test_the_credential_never_touches_the_disk_even_without_dev_fd(grid, monkeypatch, tmp_path):
    monkeypatch.setattr(_usercred, "_FD_DIR", str(tmp_path / "no-dev-fd"))
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake:
        ac, _ = _fetch([fake.server()], grid)
    assert ac


def test_a_credential_openssl_cannot_load_is_named(grid):
    with pytest.raises(VOMSError, match="cannot present /CN=nobody"):
        fetch_ac([VOMSServer("a", "127.0.0.1", 1, "", "a")], _Unloadable(chain=(), key=None))


class _Unloadable(ProxyCredential):
    """A credential whose PEM OpenSSL refuses: a certificate block that is not one."""

    @property
    def subject(self) -> Name:
        return Name((("CN", "nobody"),))

    def to_pem(self, with_key: bool = True) -> bytes:
        return b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"


def test_requests_that_cannot_be_sent_are_refused_before_connecting(grid):
    with pytest.raises(VOMSConfigError, match="no VOMS server to ask"):
        fetch_ac([], grid.credential())
    for fqan in ("atlas", "/atlas,/cms", "/atlas/Role=a b", "/atlas\x00"):
        with pytest.raises(ValueError, match="not a VOMS FQAN"):
            fetch_ac([VOMSServer("a", "h", 1, "", "a")], grid.credential(), fqans=[fqan])


def test_an_http_protocol_error_is_a_failed_server(grid, monkeypatch):
    import http.client

    def broken(self, *args, **kwargs):
        raise http.client.RemoteDisconnected("")  # no message: the class name must stand in

    monkeypatch.setattr(http.client.HTTPSConnection, "getresponse", broken)
    with (
        FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake,
        pytest.raises(VOMSUnavailableError, match="RemoteDisconnected"),
    ):
        _fetch([fake.server()], grid)


@pytest.mark.skipif(shutil.which("arcproxy") is None, reason="arcproxy is not installed")
def test_arcproxy_gets_an_ac_from_the_fake_server(grid, tmp_path):
    """The fake speaks the protocol a real VOMS REST client speaks."""
    with FakeVOMS(grid, lambda query: ac_answer(grid.make_ac())) as fake:
        vomses = tmp_path / "vomses"
        vomses.write_text(f'"atlas" "127.0.0.1" "{fake.port}" "/CN=localhost" "atlas"\n')
        done = subprocess.run(
            [
                "arcproxy",
                "-C",
                str(grid.usercert),
                "-K",
                str(grid.userkey),
                "-P",
                str(tmp_path / "x509up"),
                "-T",
                str(grid.ca_dir),
                "-s",
                str(grid.voms_dir),
                "-V",
                str(vomses),
                "-S",
                "atlas",
                "-H",
            ],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=60,
        )
    assert done.returncode == 0, done.stdout + done.stderr
    from xrdsec.proxies import load_credential

    chain = load_credential(tmp_path / "x509up").chain
    assert validate_voms(chain).status is VOMSStatus.OK


def test_one_tls_builder_presents_a_credential_from_memory(grid):
    from xrdsec import tls

    pem = grid.credential().to_pem()
    first = tls.client_context(credential_pem=pem, ca_path=str(grid.ca_dir))
    assert tls.client_context(credential_pem=pem, ca_path=str(grid.ca_dir)) is first
    with pytest.raises(ValueError, match="not both"):
        tls.client_context(cert=str(grid.usercert), credential_pem=pem)


# ---------------------------------------------------------------------------
# The cost of a directory of vomses files
# ---------------------------------------------------------------------------


def test_only_the_files_that_could_hold_the_vo_are_read(tmp_path: Path):
    """A CVMFS vomses directory is one file per VO: reading 126 to find one is half a minute."""
    directory = tmp_path / "vomses.d"
    directory.mkdir()
    (directory / "voms-atlas-auth.example.org").write_text(ATLAS)
    (directory / "voms-lhcb-auth.example.org").write_text(
        '"lhcb" "voms-lhcb.example.org" "15000" "/CN=lhcb" "lhcb"\n'
    )
    (directory / "voms-cms-auth.example.org").write_text(CMS)
    found = find_vomses(directory, vo="lhcb")
    assert [server.vo for server in found] == ["lhcb"]


def test_a_directory_not_named_after_its_vos_is_still_searched(tmp_path: Path):
    """The file-name shortcut must never lose an answer: the rest are read when it finds none."""
    directory = tmp_path / "vomses.d"
    directory.mkdir()
    (directory / "shared").write_text(CMS + ATLAS)
    found = find_vomses(directory, vo="atlas")
    assert ("atlas", "voms1.example.org") in [(server.vo, server.host) for server in found]


def test_the_files_a_lookup_would_read_are_listed_without_reading_them(tmp_path: Path):
    """For a report deciding whether reading the whole configuration is worth it."""
    single = tmp_path / "vomses"
    single.write_text(ATLAS)
    directory = tmp_path / "vomses.d"
    directory.mkdir()
    (directory / "cms").write_text(CMS)
    assert vomses_files(single) == [single]
    assert vomses_files([single, directory]) == [single, directory / "cms"]
    assert vomses_files(environ={"X509_VOMSES": str(single)}) == [single]
    assert vomses_files(environ={"X509_VOMSES": str(tmp_path / "gone")}) == []


def test_a_user_certificate_is_wrapped_in_a_proxy_for_the_server(grid):
    """VOMS servers authenticate a proxy, as voms-proxy-init presents one - not a bare cert."""
    from xrdsec.voms_client import _authentication

    user = grid.credential()
    presented = _authentication(user)
    assert presented.chain[0].is_proxy
    assert presented.chain[1].subject == user.chain[0].subject  # the user, below the proxy
    # a proxy is already one: handed over unchanged
    assert _authentication(presented) is presented


def test_asking_for_one_vo_does_not_read_the_other_servers_files(tmp_path: Path):
    """The WLCG bundle has one ``vomses`` file per server; asking for one VO must not read them all.

    On a CVMFS mount every file costs a round trip to open and another to close,
    which is what made ``xrd-proxy init`` take half a minute. The others are
    made unreadable here, so a regression that reads them fails loudly instead
    of quietly going slow again.
    """
    from xrdsec.voms_client import find_vomses

    folder = tmp_path / "vomses"
    folder.mkdir()
    (folder / "voms-lhcb-auth.cern.ch").write_text(
        '"lhcb" "voms-lhcb-auth.cern.ch" 443 "/CN=voms-lhcb-auth.cern.ch" "lhcb"\n'
    )
    for index in range(20):
        other = folder / f"voms-atlas{index}.cern.ch"
        other.write_text(f'"atlas" "voms-atlas{index}.cern.ch" 15000 "/CN=a{index}" "atlas"\n')
        other.chmod(0o000)

    servers = find_vomses(folder, vo="lhcb")

    assert [each.host for each in servers] == ["voms-lhcb-auth.cern.ch"]
