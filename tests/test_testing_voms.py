"""The VOMS test fixtures (:mod:`xrdsec.testing.voms`): ACs, trust files, the fake server.

Every AC minted here is checked by the library's own validator, so the
fixture and the decoder agree on the wire format - which is the point of
having one fixture for three test suites.
"""

from __future__ import annotations

import base64
import http.client
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from xrdcore import safexml
from xrdsec.testing.pki import PKI, Signer, host_certificate
from xrdsec.testing.voms import (
    ACSpec,
    Attribute,
    FakeVOMSServer,
    ac_sequence,
    lsc_text,
    make_ac,
    signature_algorithm,
    voms_error,
    voms_proxy,
    voms_reply,
    vomses_line,
    write_lsc,
)
from xrdsec.voms import VOMSStatus, inspect_voms, validate_voms
from xrdsec.x509 import certificate_data, load_proxy

USER = "/DC=org/DC=xrdsec/OU=People/CN=Test User"


def _validate(pki: PKI, tmp_path: Path, ac: bytes, voms: Signer | None = None):
    vomsdir = tmp_path / "vomsdir"
    write_lsc(vomsdir, "atlas", "voms.example", (voms or pki.host_signer).chain)
    proxy = load_proxy(str(voms_proxy(pki, [ac], path=tmp_path / "x509up")))
    return validate_voms(proxy.chain, ca_path=str(pki.ca_dir), voms_dir=str(vomsdir))


def test_the_default_ac_validates(pki: PKI, tmp_path: Path) -> None:
    voms = pki.host_signer
    ac = make_ac(pki.user_signer.der, voms.der, voms.key)
    result = _validate(pki, tmp_path, ac)
    assert result.status is VOMSStatus.OK
    assert result.fqans == ("/atlas/Role=production/Capability=NULL",)
    assert result.verified[0].digest == "sha256"


def test_fqans_attributes_and_targets(pki: PKI, tmp_path: Path) -> None:
    voms = pki.host_signer
    spec = ACSpec(
        fqans=("/atlas", "/atlas/higgs"),
        attributes=(Attribute("nickname", "alice", "atlas"),),
        targets=("se.example.org",),
    )
    holder = pki.user  # a cryptography certificate works as well as DER
    entry = inspect_voms(
        load_proxy(str(voms_proxy(pki, [make_ac(holder, voms.der, voms.key, spec)]))).chain
    ).entries[0]
    assert entry.fqans == ("/atlas", "/atlas/higgs")
    assert (entry.attributes[0].name, entry.attributes[0].value) == ("nickname", "alice")
    assert entry.attributes[0].qualifier == "atlas"
    assert entry._targets == ("se.example.org",)


@pytest.mark.parametrize(
    ("spec", "digest"),
    [
        (ACSpec(pss=True), "rsassa-pss"),
        (ACSpec(digest="sha512"), "sha512"),
        (ACSpec(digest="sha384", pss=True), "rsassa-pss"),
    ],
)
def test_rsa_signature_algorithms(pki: PKI, tmp_path: Path, spec: ACSpec, digest: str) -> None:
    voms = pki.host_signer
    result = _validate(pki, tmp_path, make_ac(pki.user_signer.der, voms.der, voms.key, spec))
    assert result.status is VOMSStatus.OK and result.verified[0].digest == digest


@pytest.mark.parametrize("kind", ["ecdsa", "ed25519"])
def test_ec_and_ed25519_signers(pki: PKI, tmp_path: Path, kind: str) -> None:
    if kind == "ecdsa":
        key = ec.generate_private_key(ec.SECP256R1())
        der = host_certificate((("CN", "voms.example"),), key, pki.ca_signer)
        voms = Signer((der, pki.ca_signer.der), key)
        result = _validate(pki, tmp_path, make_ac(pki.user_signer.der, der, key), voms)
        assert result.status is VOMSStatus.OK and result.verified[0].digest == "sha256"
    else:
        # cryptography's builder will not certify an Ed25519 key under an RSA CA
        # here, so check only the algorithm identifier and that the AC decodes.
        edwards = ed25519.Ed25519PrivateKey.generate()
        assert signature_algorithm(edwards) == bytes.fromhex("300506032b6570")
        ac = make_ac(pki.user_signer.der, pki.host_signer.der, edwards)
        assert (
            inspect_voms(load_proxy(str(voms_proxy(pki, [ac], path=tmp_path / "p"))).chain)
            .entries[0]
            .fqans
        )


def test_overrides_break_exactly_one_thing(pki: PKI, tmp_path: Path) -> None:
    voms = pki.host_signer
    spec = ACSpec(sign=lambda tbs: b"\x00" * 256, fqans=())
    assert (
        _validate(pki, tmp_path, make_ac(pki.user_signer.der, voms.der, voms.key, spec)).status
        is not VOMSStatus.OK
    )
    raw = make_ac(
        (b"\x30\x00", 9), voms.der, voms.key, ACSpec(fqans=None, holder_serial=10, version=2)
    )
    assert raw.startswith(b"\x30")


def test_ac_sequence_and_lsc(pki: PKI, tmp_path: Path) -> None:
    assert ac_sequence([b"\x30\x00"]) == bytes.fromhex("3004 3002 3000")
    text = lsc_text(pki.host_signer.chain)
    host = certificate_data(pki.host_signer.der)
    assert text == f"{host.subject}\n{host.issuer}\n"
    assert lsc_text(pki.host_signer.chain[:1]) == text  # the issuer comes from the leaf
    path = write_lsc(tmp_path, "atlas", "voms.example", pki.host_signer.chain)
    assert path == tmp_path / "atlas" / "voms.example.lsc" and path.read_text() == text
    assert vomses_line("atlas", "h", 15000, "/CN=h") == '"atlas" "h" "15000" "/CN=h" "atlas"\n'
    assert vomses_line("atlas", "h", 1, "/CN=h", alias="a").startswith('"a" ')


def test_reply_bodies() -> None:
    root = safexml.fromstring(voms_reply(b"\x30\x00", "shortened"))
    assert base64.b64decode(root.findtext("ac") or "") == b"\x30\x00"
    assert root.findtext("warning") == "shortened"
    assert safexml.fromstring(voms_reply(b"\x30\x00")).find("warning") is None
    error = safexml.fromstring(voms_error("NoSuchUser", "a < b"))
    assert (error.findtext("error/code"), error.findtext("error/message")) == (
        "NoSuchUser",
        "a < b",
    )
    assert safexml.fromstring(voms_error("X")).find("error/message") is None


# -- the server ---------------------------------------------------------------------------


def _get(pki: PKI, srv: FakeVOMSServer, query: str = "") -> tuple[int, ET.Element]:
    conn = http.client.HTTPSConnection(
        "localhost", srv.port, context=pki.client_context(), timeout=10
    )
    try:
        conn.request("GET", "/generate-ac" + query, headers={"Accept": "application/xml"})
        response = conn.getresponse()
        return response.status, safexml.fromstring(response.read())
    finally:
        conn.close()


def _ac(root: ET.Element) -> bytes:
    return base64.b64decode(root.findtext("ac") or "")


def test_server_mints_for_anyone_without_a_member_list(pki: PKI) -> None:
    with FakeVOMSServer(pki.host_signer, pki.server_context()) as srv:
        status, root = _get(pki, srv)
        assert status == 200
        status, root = _get(pki, srv, "?fqans=/atlas,/atlas/higgs&lifetime=60")
        assert srv.uri.startswith("127.0.0.1:") and len(srv.issued) == 2
    assert status == 200 and _ac(root) == srv.issued[-1]
    # The holder is the user certificate behind the proxy (its serial), not the
    # proxy - but only where the server can see the chain: ``ssl`` exposes the
    # peer's full chain from Python 3.13; before that the server sees just the
    # leaf (the proxy), which is why FakeVOMSServer.holder can be set by hand.
    if sys.version_info >= (3, 13):
        serial = certificate_data(pki.user_signer.der).serial
        assert serial.to_bytes((serial.bit_length() + 8) // 8, "big") in srv.issued[-1]
    proxy = voms_proxy(pki, srv.issued, path=pki.directory / "x509up_server")
    entries = inspect_voms(load_proxy(str(proxy)).chain).entries
    assert [entry.fqans for entry in entries] == [("/atlas",), ("/atlas", "/atlas/higgs")]


def test_server_checks_membership(pki: PKI) -> None:
    members = {USER: ("/atlas", "/atlas/Role=production")}
    with FakeVOMSServer(pki.host_signer, pki.server_context(), members=members) as srv:
        assert _get(pki, srv)[0] == 200
        assert inspect_voms_fqans(srv.issued[-1], pki) == ("/atlas", "/atlas/Role=production")
        status, root = _get(pki, srv, "?fqans=/cms")
        assert (status, root.findtext("error/code")) == (403, "NoSuchAttribute")
        status, root = _get(pki, srv, "?lifetime=soon")
        assert (status, root.findtext("error/code")) == (400, "BadRequest")
        status, root = _get(pki, srv, "?lifetime=999999")
        assert status == 200 and "86400" in (root.findtext("warning") or "")
        srv.members = {"/CN=someone else": ()}
        status, root = _get(pki, srv)
        assert (status, root.findtext("error/code")) == (403, "NoSuchUser")
        srv.members = {USER: ()}
        assert _get(pki, srv)[0] == 200
        assert inspect_voms_fqans(srv.issued[-1], pki) == ("/atlas",)


def inspect_voms_fqans(ac: bytes, pki: PKI) -> tuple[str, ...]:
    proxy = voms_proxy(pki, [ac], path=pki.directory / "x509up_fqans")
    return inspect_voms(load_proxy(str(proxy)).chain).entries[0].fqans


def test_server_refusals_and_holder_override(pki: PKI) -> None:
    with FakeVOMSServer(pki.host_signer, pki.server_context()) as srv:
        srv.refuse("SuspendedUser", "go away", status=403)
        status, root = _get(pki, srv)
        assert (status, root.findtext("error/code")) == (403, "SuspendedUser")
        srv.holder = (b"\x30\x00", 77)
        assert _get(pki, srv)[0] == 200
    assert b"\x02\x01\x4d" in srv.issued[-1]  # INTEGER 77, the holder serial


def test_anonymous_callers_are_refused(pki: PKI) -> None:
    with FakeVOMSServer(pki.host_signer) as srv:
        conn = http.client.HTTPConnection(*srv.address, timeout=10)
        conn.request("GET", "/generate-ac")
        response = conn.getresponse()
        root = safexml.fromstring(response.read())
        conn.close()
    assert (response.status, root.findtext("error/code")) == (403, "NoSuchUser")


def test_a_proxy_only_chain_names_the_leaf(pki: PKI) -> None:
    """Before Python 3.13 the server sees only the proxy; without ``holder`` it is named."""
    from xrdsec.testing.https import PeerIdentity, Request

    leaf = pki.credential().certificate.der
    request = Request("GET", "/", "/", {}, {}, b"", PeerIdentity((leaf,)))
    assert FakeVOMSServer._end_entity(request) == leaf


def test_a_full_chain_names_the_end_entity(pki: PKI) -> None:
    """From Python 3.13 the server sees the whole chain; the AC then names the user, not a proxy.

    Built by hand so every interpreter covers it - before 3.13 a real
    handshake never shows the server more than the leaf.
    """
    from xrdsec.testing.https import PeerIdentity, Request

    proxy = pki.credential()
    chain = tuple(link.der for link in proxy.chain)
    request = Request("GET", "/", "/", {}, {}, b"", PeerIdentity(chain))
    assert FakeVOMSServer._end_entity(request) == pki.user_signer.der
