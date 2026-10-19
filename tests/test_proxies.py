"""The one proxy issuer: profiles, the rules every profile obeys, files and inspection."""

from __future__ import annotations

import datetime
import hashlib
import itertools
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
    PrivateKeyTypes,
)

from xrdcore.errors import CredentialError, InsecureCredentialError
from xrdsec import der, proxies
from xrdsec.delegation import (
    DelegationError,
    ProxyRequest,
    parse_proxy_request,
    proxy_path_length,
)
from xrdsec.proxies import (
    PROFILES,
    ProxyError,
    ProxyInfo,
    create_proxy,
    describe_proxy,
    issue_proxy,
    load_credential,
    voms_extension,
    write_proxy,
)
from xrdsec.rsa import RSAPrivateKey
from xrdsec.testing.proxygrid import CA_NAME, Grid, build_grid, certificate, key, pem, usage
from xrdsec.testing.rawpki import oid, sequence, tlv
from xrdsec.voms import VOMS_AC_OID, VOMSStatus, inspect_voms, validate_voms
from xrdsec.x509 import (
    INHERIT_ALL_OID,
    LIMITED_PROXY_OID,
    PROXY_CERT_INFO_OID,
    Certificate,
    Extension,
    Name,
    ProxyCredential,
    certificate_fields,
    extensions_of,
    load_certificates,
    parse_certificate,
    proxy_identity,
    proxy_policy,
)

KEY_USAGE_OID = "2.5.29.15"


@pytest.fixture
def grid(tmp_path: Path) -> Grid:
    return build_grid(tmp_path / "grid")


@pytest.fixture
def user(grid: Grid) -> ProxyCredential:
    return grid.credential()


def _spki(private: PrivateKeyTypes) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _extensions(certificate: Certificate) -> dict[str, Extension]:
    return {ext.oid: ext for ext in extensions_of(certificate.der)}


def _policy(certificate: Certificate) -> str | None:
    values = {ext.oid: (ext.critical, ext.value) for ext in extensions_of(certificate.der)}
    return proxy_policy(values)


def _depth(certificate: Certificate) -> int | None:
    return proxy_path_length(_extensions(certificate)[PROXY_CERT_INFO_OID])


def _request(
    private: CertificateIssuerPrivateKeyTypes, name: cx509.Name | None = None
) -> ProxyRequest:
    """A self-signed PKCS#10 request for ``private``'s key, with one extension."""
    from cryptography.hazmat.primitives import hashes

    subject = name or cx509.Name.from_rfc4514_string("CN=ignored")
    built = cx509.CertificateSigningRequestBuilder().subject_name(subject)
    built = built.add_extension(usage(), critical=True)
    return parse_proxy_request(
        built.sign(private, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    )


# ---------------------------------------------------------------------------
# The profiles
# ---------------------------------------------------------------------------


def test_the_rfc3820_profile_is_what_voms_proxy_init_makes(user):
    moment = float(int(time.time()))
    issued = issue_proxy(user, _spki(key(5)), now=moment)
    leaf = user.chain[0]
    assert issued.issuer == leaf.subject
    assert issued.subject.rdns[:-1] == leaf.subject.rdns
    assert issued.subject.rdns[-1] == ("CN", str(issued.serial))
    assert 0 < issued.serial < 1 << 31
    assert issued.not_before == moment - proxies.NOT_BEFORE_SKEW
    assert issued.not_after == min(link.not_after for link in user.chain)
    # The issuer name is the signer's subject byte for byte (string types kept).
    assert certificate_fields(issued.der)["issuer"] == certificate_fields(leaf.der)["subject"]


def test_the_rfc3820_extensions_are_key_usage_and_proxy_cert_info(user):
    issued = issue_proxy(user, _spki(key(5)))
    found = _extensions(issued)
    assert list(found) == [KEY_USAGE_OID, PROXY_CERT_INFO_OID]
    assert found[KEY_USAGE_OID].critical
    assert found[PROXY_CERT_INFO_OID].critical
    assert found[KEY_USAGE_OID].value == bytes.fromhex("030205a0")
    assert (_policy(issued), _depth(issued)) == (INHERIT_ALL_OID, None)


def test_the_arc_profile_has_a_63_bit_serial(user):
    serials = {issue_proxy(user, _spki(key(5)), profile="arc").serial for _ in range(4)}
    assert any(serial >= 1 << 31 for serial in serials)
    assert all(serial < 1 << 63 and serial & 1 for serial in serials)


def test_the_xrootd_profile_copies_the_signer_and_does_not_backdate(user):
    moment = float(int(time.time()))
    issued = issue_proxy(user, _spki(key(5)), profile="xrootd", now=moment)
    assert issued.not_before == moment
    oids = list(_extensions(issued))
    # basicConstraints and keyUsage come from the user certificate; its
    # e-mail subjectAltName, key identifiers and the CA's AKI do not.
    assert oids == ["2.5.29.19", KEY_USAGE_OID, PROXY_CERT_INFO_OID]
    assert (
        _extensions(issued)[KEY_USAGE_OID].value == _extensions(user.chain[0])[KEY_USAGE_OID].value
    )


def test_the_xrootd_profile_takes_the_name_from_the_request(user):
    leaf = cx509.load_der_x509_certificate(user.chain[0].der).subject
    cn = cx509.NameAttribute(cx509.oid.NameOID.COMMON_NAME, "777")
    request = _request(key(5), cx509.Name([*leaf.rdns, cx509.RelativeDistinguishedName([cn])]))
    issued = issue_proxy(user, request, profile="xrootd")
    assert issued.serial == 777 and issued.subject.rdns[-1] == ("CN", "777")
    with pytest.raises(DelegationError, match="CN=<serial>"):
        issue_proxy(user, _request(key(5)), profile="xrootd")


def test_other_profiles_ignore_a_request_subject_but_check_its_signature(user):
    request = _request(key(5))
    issued = issue_proxy(user, request, profile="arc")
    assert issued.subject.rdns[:-1] == user.chain[0].subject.rdns
    assert certificate_fields(issued.der)["spki"] == request.spki
    forged = ProxyRequest(
        request.subject, request.subject_der, _spki(key(6)), None, request.extensions, request.der
    )
    with pytest.raises(ProxyError, match="not signed by the key it carries"):
        issue_proxy(user, forged, profile="arc")


def test_the_globus_legacy_profile_names_the_proxy(user):
    issued = issue_proxy(user, _spki(key(5)), profile="globus-legacy")
    assert issued.subject.rdns[-1] == ("CN", "proxy")
    assert PROXY_CERT_INFO_OID not in issued.extensions
    assert issued.serial == proxies._key_serial(_spki(key(5)))
    limited = issue_proxy(user, _spki(key(5)), profile="globus-legacy", limited=True)
    assert limited.subject.rdns[-1] == ("CN", "limited proxy")
    assert describe_proxy((limited, *user.chain)).kind == "limited legacy globus proxy"
    # A GT2 child of a GT2 proxy inherits its limitation by name.
    signer = ProxyCredential(
        chain=(limited, *user.chain), key=RSAPrivateKey.from_cryptography(key(5))
    )
    child = issue_proxy(signer, _spki(key(6)), profile="globus-legacy")
    assert child.subject.rdns[-1] == ("CN", "limited proxy")


def test_a_legacy_proxy_cannot_hide_an_rfc_constraint(user):
    rfc = create_proxy(user)
    with pytest.raises(ProxyError, match="legacy"):
        issue_proxy(rfc, _spki(key(5)), profile="globus-legacy")
    with pytest.raises(ProxyError, match="legacy"):
        issue_proxy(user, _spki(key(5)), profile="globus-legacy", path_length=1)


def test_a_zero_key_hash_still_gives_a_positive_serial(monkeypatch):
    class Zero:
        def digest(self):
            return b"\x00" * 20

    monkeypatch.setattr(hashlib, "sha1", lambda *a, **k: Zero())
    assert proxies._key_serial(b"x") == 1


def test_an_unknown_profile_is_refused(user):
    with pytest.raises(ProxyError, match="unknown proxy profile 'gt4'"):
        # Not a ``Profile`` literal on purpose: the runtime refusal is under test.
        issue_proxy(user, _spki(key(5)), profile="gt4")  # type: ignore[arg-type]
    assert set(PROFILES) == set(proxies._PROFILES)


# ---------------------------------------------------------------------------
# The rules every profile obeys
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["rfc3820", "arc", "xrootd"])
def test_a_limited_signer_only_issues_limited_proxies(user, profile):
    limited = create_proxy(user, limited=True)
    assert _policy(limited.chain[0]) == LIMITED_PROXY_OID
    for asked in (None, False):
        child = issue_proxy(limited, _spki(key(5)), profile=profile, limited=asked)
        assert _policy(child) == LIMITED_PROXY_OID


@pytest.mark.parametrize("profile", ["rfc3820", "arc", "xrootd"])
def test_path_lengths_only_ever_shrink(user, profile):
    two = create_proxy(user, path_length=2)
    assert _depth(two.chain[0]) == 2
    assert _depth(issue_proxy(two, _spki(key(5)), profile=profile)) == 1
    assert _depth(issue_proxy(two, _spki(key(5)), profile=profile, path_length=0)) == 0
    assert _depth(issue_proxy(two, _spki(key(5)), profile=profile, path_length=9)) == 1
    zero = create_proxy(user, path_length=0)
    with pytest.raises(ProxyError, match="path length forbids"):
        issue_proxy(zero, _spki(key(5)), profile=profile)
    with pytest.raises(ProxyError, match="cannot be negative"):
        issue_proxy(user, _spki(key(5)), profile=profile, path_length=-1)


def test_validity_never_outlives_the_chain_nor_predates_the_signer(user, grid):
    moment = time.time()
    short = issue_proxy(user, _spki(key(5)), lifetime=datetime.timedelta(minutes=5), now=moment)
    assert short.not_after == float(int(moment + 300))
    shorter = issue_proxy(user, _spki(key(5)), lifetime=60, now=moment)
    assert shorter.not_after == float(int(moment + 60))
    long = issue_proxy(user, _spki(key(5)), lifetime=10**9)
    assert long.not_after == min(link.not_after for link in user.chain)
    fresh = issue_proxy(user, _spki(key(5)), now=user.chain[0].not_before + 1, not_before_skew=3600)
    assert fresh.not_before == user.chain[0].not_before
    for bad in (0, -5, datetime.timedelta(0)):
        with pytest.raises(ProxyError, match="must be positive"):
            issue_proxy(user, _spki(key(5)), lifetime=bad)
    with pytest.raises(ProxyError, match="cannot be negative"):
        issue_proxy(user, _spki(key(5)), not_before_skew=-1)


def test_a_signer_must_be_alive_hold_its_key_and_have_a_certificate(user):
    with pytest.raises(ProxyError, match="has expired"):
        issue_proxy(user, _spki(key(5)), now=user.chain[0].not_after)
    stranger = ProxyCredential(chain=user.chain, key=RSAPrivateKey.from_cryptography(key(5)))
    with pytest.raises(ProxyError, match="does not belong"):
        issue_proxy(stranger, _spki(key(6)))
    with pytest.raises(ProxyError, match="no certificate"):
        issue_proxy(ProxyCredential(chain=(), key=user.key), _spki(key(6)))
    with pytest.raises(ProxyError, match="Ed25519PrivateKey"):
        issue_proxy(
            ProxyCredential(chain=user.chain, key=ed25519.Ed25519PrivateKey.generate()),
            _spki(key(6)),
        )


def test_an_ec_signer_signs_with_ecdsa(user):
    ec_proxy = create_proxy(user, key_type="ec")
    assert isinstance(ec_proxy.key, ec.EllipticCurvePrivateKey)
    child = issue_proxy(ec_proxy, _spki(key(5)))
    signature = der.parse(der.raw_children(child.der)[1])[0].children()[0]
    assert der.oid_string(signature) == "1.2.840.10045.4.3.2"


def test_an_uncertifiable_key_is_a_proxy_error(user):
    odd = sequence(sequence(oid("1.2.3.4")), tlv(0x03, b"\x00\x01"))
    with pytest.raises(ProxyError, match="cannot issue the proxy"):
        issue_proxy(user, odd)


@pytest.mark.parametrize(
    ("extension", "message"),
    [
        (sequence(oid(PROXY_CERT_INFO_OID), tlv(0x04, b"\x30\x00")), "ProxyCertInfo"),
        (sequence(oid("1.3.6.1.4.1.3536.1.222"), tlv(0x04, b"\x30\x00")), "ProxyCertInfo"),
        (sequence(oid("2.5.29.17"), tlv(0x04, b"\x30\x00")), "alternative names"),
        (sequence(oid("2.5.29.18"), tlv(0x04, b"\x30\x00")), "alternative names"),
        (sequence(oid("2.5.29.19"), tlv(0x04, sequence(tlv(0x01, b"\xff")))), "cannot be a CA"),
        (sequence(oid(KEY_USAGE_OID), tlv(0x04, tlv(0x03, b"\x07\x80"))), "appear twice"),
    ],
)
def test_extensions_rfc3820_forbids_are_refused(user, extension, message):
    with pytest.raises(ProxyError, match=message):
        issue_proxy(user, _spki(key(5)), extra_extensions=[extension])


def test_harmless_extensions_are_appended(user):
    not_ca = sequence(oid("2.5.29.19"), tlv(0x04, sequence()))
    explicit_false = sequence(oid("2.5.29.19"), tlv(0x04, sequence(tlv(0x01, b"\x00"))))
    policies = sequence(oid("2.5.29.32"), tlv(0x04, sequence(sequence(oid("1.2.3.4")))))
    for extra in (not_ca, explicit_false):
        issued = issue_proxy(user, _spki(key(5)), extra_extensions=[extra, policies])
        assert list(_extensions(issued))[-2:] == ["2.5.29.19", "2.5.29.32"]


# ---------------------------------------------------------------------------
# VOMS attribute certificates
# ---------------------------------------------------------------------------


def test_create_proxy_embeds_acs_and_they_verify(user, grid):
    proxy = create_proxy(user, voms_acs=[grid.make_ac()])
    result = validate_voms(proxy.chain, ca_path=str(grid.ca_dir), voms_dir=str(grid.voms_dir))
    assert result.status is VOMSStatus.OK
    assert result.entries[0].fqans == ("/atlas/Role=NULL/Capability=NULL",)
    extension = _extensions(proxy.chain[0])[VOMS_AC_OID]
    assert not extension.critical


@pytest.mark.parametrize("profile", ["rfc3820", "arc", "globus-legacy", "xrootd"])
def test_acs_are_carried_forward_unless_asked_not_to(user, grid, profile):
    voms = create_proxy(user, voms_acs=[grid.make_ac()], profile="arc")
    if profile == "globus-legacy":
        voms = create_proxy(user, voms_acs=[grid.make_ac()], profile="globus-legacy")
    child = issue_proxy(voms, _spki(key(5)), profile=profile)
    assert VOMS_AC_OID in child.extensions
    bare = issue_proxy(voms, _spki(key(5)), profile=profile, copy_voms=False)
    assert VOMS_AC_OID not in bare.extensions
    # One supplied explicitly replaces the carried one instead of doubling it.
    other = voms_extension([grid.make_ac(("/atlas/de",))])
    replaced = issue_proxy(voms, _spki(key(5)), profile=profile, extra_extensions=[other])
    entries = inspect_voms((replaced, *voms.chain)).entries
    assert entries[0].fqans == ("/atlas/de",)


def test_the_nearest_ac_in_the_chain_is_the_one_carried(user, grid):
    voms = create_proxy(user, voms_acs=[grid.make_ac(("/atlas/near",))])
    plain = issue_proxy(voms, _spki(key(5)), copy_voms=False)
    signer = ProxyCredential(
        chain=(plain, *voms.chain), key=RSAPrivateKey.from_cryptography(key(5))
    )
    child = issue_proxy(signer, _spki(key(6)))
    assert inspect_voms((child,)).entries[0].fqans == ("/atlas/near",)


def test_the_voms_extension_is_checked_before_it_is_written(grid):
    ac = grid.make_ac()
    assert der.parse_one(voms_extension([ac])).tag == der.TAG_SEQUENCE
    for bad in ([], [ac] * 33):
        with pytest.raises(ValueError, match="1 to 32"):
            voms_extension(bad)
    for damaged in (ac + b"\x00", tlv(0x04, b"x")):
        with pytest.raises(ValueError):
            voms_extension([damaged])


# ---------------------------------------------------------------------------
# create_proxy
# ---------------------------------------------------------------------------


def test_create_proxy_makes_a_fresh_credential_in_memory(user):
    proxy = create_proxy(user, bits=1024)
    assert isinstance(proxy.key, RSAPrivateKey) and proxy.key.size == 128  # bytes
    assert proxy.chain[1:] == user.chain
    assert proxy.identity == str(user.chain[0].subject)
    assert proxy.chain[0].not_after <= time.time() + 12 * 3600 + 1
    for curve, bits in ((ec.SECP256R1, None), (ec.SECP384R1, 384), (ec.SECP521R1, 521)):
        made = create_proxy(user, key_type="ec", bits=bits)
        assert isinstance(made.key, ec.EllipticCurvePrivateKey)
        assert isinstance(made.key.curve, curve)
    with pytest.raises(ValueError, match="at least 1024"):
        create_proxy(user, bits=512)
    with pytest.raises(ValueError, match="256, 384 or 521"):
        create_proxy(user, key_type="ec", bits=2048)
    with pytest.raises(ValueError, match="unknown proxy key type"):
        # Not a key-type literal on purpose: the runtime refusal is under test.
        create_proxy(user, key_type="dsa")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


def test_to_pem_is_certificate_key_chain_without_anchors(user, grid):
    proxy = create_proxy(user)
    text = proxy.to_pem()
    labels = re.findall(rb"-----BEGIN ([A-Z ]+)-----", text)
    assert labels == [b"CERTIFICATE", b"RSA PRIVATE KEY", b"CERTIFICATE"]
    assert pem(grid.ca) not in text
    assert proxy.to_pem(with_key=False) == proxy.chain[0].pem() + proxy.chain[1].pem()
    ec_text = create_proxy(user, key_type="ec").to_pem()
    assert b"-----BEGIN EC PRIVATE KEY-----" in ec_text
    other = ProxyCredential(chain=user.chain, key=ed25519.Ed25519PrivateKey.generate())
    assert b"-----BEGIN PRIVATE KEY-----" in other.to_pem()
    library = ProxyCredential(chain=user.chain, key=key(2))
    assert b"-----BEGIN RSA PRIVATE KEY-----" in library.to_pem()


def test_write_proxy_is_private_and_atomic(user, tmp_path):
    tmp_path = tmp_path / "out"
    tmp_path.mkdir()
    target = tmp_path / "x509up"
    target.write_bytes(b"old")
    os.chmod(target, 0o644)
    written = write_proxy(target, create_proxy(user))
    assert written == str(target)
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    again = load_credential(target)
    assert again.identity == str(user.chain[0].subject) and again.path == str(target)
    assert [p.name for p in tmp_path.iterdir()] == ["x509up"]  # no temporary left behind


def test_write_proxy_refuses_or_follows_a_symlink(user, tmp_path):
    real = tmp_path / "store" / "proxy.pem"
    real.parent.mkdir()
    real.write_bytes(b"old")
    link = tmp_path / "x509up"
    link.symlink_to(real)
    with pytest.raises(InsecureCredentialError, match="symbolic link"):
        write_proxy(link, create_proxy(user))
    assert real.read_bytes() == b"old"
    written = write_proxy(link, create_proxy(user), follow_symlinks=True)
    assert written == os.path.realpath(real) and link.is_symlink()
    assert load_credential(link).chain[1:] == user.chain[:1]


def test_another_users_file_in_the_way_is_named(user, tmp_path, monkeypatch):

    tmp_path = tmp_path / "out"
    tmp_path.mkdir()
    target = tmp_path / "x509up"
    target.write_bytes(b"theirs")

    def refuse(*args):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "replace", refuse)
    real_lstat = os.lstat
    owner = {"uid": os.geteuid() + 1}

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if str(path) == str(target):
            return os.stat_result((info.st_mode, 0, 0, 0, owner["uid"], 0, 0, 0, 0, 0))
        return info

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(InsecureCredentialError, match="belongs to uid"):
        write_proxy(target, create_proxy(user))
    owner["uid"] = os.geteuid()  # ours, and still refused: an ordinary permission problem
    with pytest.raises(PermissionError) as raised:
        write_proxy(target, create_proxy(user))
    assert not isinstance(raised.value, InsecureCredentialError)
    target.unlink()  # nothing there to blame
    with pytest.raises(PermissionError) as raised:
        write_proxy(target, create_proxy(user))
    assert not isinstance(raised.value, InsecureCredentialError)
    assert [p.name for p in tmp_path.iterdir()] == []


def test_a_failed_write_leaves_nothing_behind(user, tmp_path, monkeypatch):

    tmp_path = tmp_path / "out"
    tmp_path.mkdir()

    def cross_device(*args):
        raise OSError(18, "Invalid cross-device link")

    monkeypatch.setattr(os, "replace", cross_device)
    with pytest.raises(OSError, match="cross-device"):
        write_proxy(tmp_path / "x509up", create_proxy(user))
    assert list(tmp_path.iterdir()) == []


def test_the_xrdcrypto_constraint_helper_refuses_a_spent_signer():
    from xrdsec import delegation

    with pytest.raises(DelegationError, match="path length forbids"):
        delegation._proxy_cert_info(0)
    assert proxy_path_length(der_extension(delegation._proxy_cert_info(3))) == 2


def der_extension(raw: bytes):
    from xrdsec.x509 import parse_extension

    return parse_extension(raw)


def test_load_credential_reads_a_user_pair(grid):
    pair = load_credential(grid.usercert, grid.userkey)
    assert isinstance(pair.key, RSAPrivateKey) and pair.path == str(grid.usercert)
    assert load_credential(str(grid.usercert), str(grid.userkey)).chain == pair.chain
    os.chmod(grid.userkey, 0o644)
    with pytest.raises(InsecureCredentialError, match="chmod 600"):
        load_credential(grid.usercert, grid.userkey)


def test_an_encrypted_key_needs_its_pass_phrase(grid, tmp_path):
    locked = Grid.write_key(tmp_path / "locked.pem", key(2), b"secret")
    for password in (b"secret", "secret", lambda: "secret", lambda: b"secret"):
        assert load_credential(grid.usercert, locked, password=password).chain
    for missing in (None, lambda: None, ""):
        with pytest.raises(CredentialError, match="encrypted and no pass phrase"):
            load_credential(grid.usercert, locked, password=missing)
    with pytest.raises(CredentialError, match="wrong password"):
        load_credential(grid.usercert, locked, password="nope")


def test_load_credential_refuses_mismatches_and_junk(grid, tmp_path):
    other = Grid.write_key(tmp_path / "other.pem", key(5))
    with pytest.raises(CredentialError, match="does not belong"):
        load_credential(grid.usercert, other)
    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"nothing here")
    with pytest.raises(CredentialError, match="no certificate"):
        load_credential(empty, grid.userkey)
    junk = Grid.write_key(tmp_path / "junk.pem", key(5))
    junk.write_bytes(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    with pytest.raises(CredentialError, match="cannot use the private key"):
        load_credential(grid.usercert, junk)
    huge = tmp_path / "huge.pem"
    huge.write_bytes(b"x" * ((1 << 20) + 1))
    with pytest.raises(CredentialError, match="larger than"):
        load_credential(huge, grid.userkey)
    with pytest.raises(FileNotFoundError):
        load_credential(tmp_path / "missing.pem", grid.userkey)


def test_an_ec_credential_keeps_the_library_key(user, tmp_path):
    path = write_proxy(tmp_path / "ec", create_proxy(user, key_type="ec"))
    assert isinstance(load_credential(path).key, ec.EllipticCurvePrivateKey)


# ---------------------------------------------------------------------------
# describe_proxy and the identity rule
# ---------------------------------------------------------------------------


def test_describe_proxy_says_what_voms_proxy_info_says(user, grid):
    proxy = create_proxy(user, voms_acs=[grid.make_ac()], path_length=3)
    info = describe_proxy(proxy, path="/tmp/x", now=proxy.chain[0].not_after - 60)
    assert info.kind == "RFC3820 compliant impersonation proxy"
    assert (info.is_proxy, info.limited, info.path_length) == (True, False, 3)
    assert (info.identity, info.strength) == (str(user.chain[0].subject), 2048)
    assert info.key_usage == ("Digital Signature", "Key Encipherment")
    assert (info.time_left, info.path) == (60, "/tmp/x")
    data = info.as_dict()
    assert (data["type"], data["voms"][0]["vo"]) == (info.kind, "atlas")
    assert data["voms"][0]["fqans"] == ["/atlas/Role=NULL/Capability=NULL"]
    assert describe_proxy(proxy.chain, now=proxy.chain[0].not_after + 5).time_left == 0


def test_describe_proxy_tells_limited_plain_and_ec_apart(user):
    limited = describe_proxy(create_proxy(user, limited=True))
    assert (limited.kind, limited.limited) == ("RFC3820 compliant limited proxy", True)
    plain = describe_proxy(user)
    assert (plain.kind, plain.is_proxy) == ("end entity credential", False)
    assert plain.key_usage == ("Digital Signature", "Non Repudiation", "Key Encipherment")
    assert describe_proxy(create_proxy(user, key_type="ec", bits=384)).strength == 384
    with pytest.raises(ValueError, match="no certificate"):
        describe_proxy(())


def _signed_with(
    user: ProxyCredential,
    *extensions: tuple[cx509.ExtensionType, bool],
    public: CertificatePublicKeyTypes | None = None,
) -> Certificate:
    """A proxy-shaped certificate under ``user`` with exactly ``extensions``."""
    leaf = cx509.load_der_x509_certificate(user.chain[0].der)
    subject = cx509.Name(
        [
            *leaf.subject.rdns,
            cx509.RelativeDistinguishedName(
                [cx509.NameAttribute(cx509.oid.NameOID.COMMON_NAME, "42")]
            ),
        ]
    )
    made = certificate(
        subject,
        leaf.subject,
        public or key(5).public_key(),
        key(2),
        serial=42,
        extensions=extensions,
    )
    return parse_certificate(made.public_bytes(serialization.Encoding.DER))


def _unrecognised(dotted: str, value: bytes) -> tuple[cx509.ExtensionType, bool]:
    return cx509.UnrecognizedExtension(cx509.ObjectIdentifier(dotted), value), True


def test_describe_proxy_reads_every_style(user):
    def kind(
        *extensions: tuple[cx509.ExtensionType, bool],
        public: CertificatePublicKeyTypes | None = None,
    ) -> ProxyInfo:
        return describe_proxy((_signed_with(user, *extensions, public=public), *user.chain))

    draft = kind(_unrecognised("1.3.6.1.4.1.3536.1.222", sequence(sequence(oid(INHERIT_ALL_OID)))))
    assert draft.kind == "Proxy draft (pre-RFC) compliant impersonation proxy"
    independent = kind(
        _unrecognised(PROXY_CERT_INFO_OID, sequence(sequence(oid("1.3.6.1.5.5.7.21.2"))))
    )
    assert independent.kind == "RFC3820 compliant independent proxy"
    restricted = kind(_unrecognised(PROXY_CERT_INFO_OID, sequence(sequence(oid("1.2.3.4")))))
    assert restricted.kind == "RFC3820 compliant restricted proxy"
    damaged = kind(_unrecognised(PROXY_CERT_INFO_OID, sequence(tlv(0x02, b""))))
    assert damaged.path_length is None
    for value in (b"\x05\x00", b"\x03"):  # not a BIT STRING; truncated
        assert kind(_unrecognised(KEY_USAGE_OID, value)).key_usage == ()
    edwards = kind(public=ed25519.Ed25519PrivateKey.generate().public_key())
    assert edwards.strength == 0


def test_strength_is_zero_for_an_unreadable_key(user, monkeypatch):
    from xrdsec import _proxyinfo

    monkeypatch.setattr(_proxyinfo, "certificate_fields", lambda der: {"spki": b"\x30\x00"})
    assert _proxyinfo._strength(user.chain[0]) == 0


def test_the_identity_is_the_end_entity_or_the_stripped_leaf(user):
    proxy = create_proxy(user)
    second = create_proxy(proxy)
    assert proxy_identity(second.chain) == user.chain[0].subject
    alone = proxy_identity(second.chain[:2])
    assert alone == user.chain[0].subject
    assert proxy_identity(()) == Name(())
    named = Name((("CN", "Jane"), ("CN", "-12"), ("CN", "limited proxy"), ("CN", "proxy")))
    bare = _signed_with(user)
    looks = type(bare)(named, named, 1, 0.0, 1.0, None, (PROXY_CERT_INFO_OID,), b"")
    assert proxy_identity((looks,)) == Name((("CN", "Jane"),))


# ---------------------------------------------------------------------------
# Interoperability, where the tools are installed
# ---------------------------------------------------------------------------


def _openssl_verifies_proxies() -> bool:
    if shutil.which("openssl") is None:
        return False
    done = subprocess.run(["openssl", "verify", "-help"], capture_output=True, text=True)
    return "-allow_proxy_certs" in done.stdout + done.stderr


@pytest.mark.skipif(
    not _openssl_verifies_proxies(),
    reason="no OpenSSL with -allow_proxy_certs on PATH (absent, or LibreSSL)",
)
@pytest.mark.parametrize("profile", ["rfc3820", "arc", "xrootd"])
def test_openssl_verifies_every_rfc_profile_two_deep(user, grid, tmp_path, profile):
    first = create_proxy(user, profile=profile, voms_acs=[grid.make_ac()])
    second = create_proxy(first, profile=profile)
    (tmp_path / "ca.pem").write_bytes(pem(grid.ca))
    (tmp_path / "chain.pem").write_bytes(first.chain[0].pem() + pem(grid.user))
    (tmp_path / "leaf.pem").write_bytes(second.chain[0].pem())
    done = subprocess.run(
        [
            "openssl",
            "verify",
            "-allow_proxy_certs",
            "-CAfile",
            str(tmp_path / "ca.pem"),
            "-untrusted",
            str(tmp_path / "chain.pem"),
            str(tmp_path / "leaf.pem"),
        ],
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_cryptography_verifies_each_link(user):
    proxy = create_proxy(create_proxy(user, profile="arc"), profile="xrootd")
    links = [cx509.load_der_x509_certificate(link.der) for link in proxy.chain]
    for child, parent in itertools.pairwise(links):
        child.verify_directly_issued_by(parent)


@pytest.mark.skipif(shutil.which("arcproxy") is None, reason="arcproxy is not installed")
def test_arcproxy_reads_our_voms_proxy(user, grid, tmp_path):
    path = write_proxy(tmp_path / "x509up", create_proxy(user, voms_acs=[grid.make_ac()]))
    done = subprocess.run(
        ["arcproxy", "-I", "-P", path, "-T", str(grid.ca_dir), "-s", str(grid.voms_dir)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"Identity: {user.chain[0].subject}" in done.stdout
    assert "RFC compliant impersonation proxy" in done.stdout
    assert "VO        : atlas" in done.stdout and "ERROR" not in done.stdout + done.stderr


@pytest.mark.skipif(shutil.which("arcproxy") is None, reason="arcproxy is not installed")
def test_we_read_a_proxy_arcproxy_made(grid, tmp_path):
    path = tmp_path / "arc_made"
    done = subprocess.run(
        [
            "arcproxy",
            "-C",
            str(grid.usercert),
            "-K",
            str(grid.userkey),
            "-P",
            str(path),
            "-T",
            str(grid.ca_dir),
            "-S",
            "",
        ],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    info = describe_proxy(load_credential(path))
    assert info.kind == "RFC3820 compliant impersonation proxy"
    assert info.identity == str(grid.credential().chain[0].subject)


@pytest.mark.skipif(
    shutil.which("voms-proxy-info") is None, reason="voms-proxy-info is not installed"
)
def test_voms_proxy_info_reads_our_proxy(user, grid, tmp_path):
    path = write_proxy(tmp_path / "x509up", create_proxy(user, voms_acs=[grid.make_ac()]))
    done = subprocess.run(
        ["voms-proxy-info", "-all", "-file", path],
        capture_output=True,
        text=True,
        env={**os.environ, "X509_CERT_DIR": str(grid.ca_dir), "X509_VOMS_DIR": str(grid.voms_dir)},
        timeout=60,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "VO        : atlas" in done.stdout


def test_the_ca_name_fixture_is_what_the_ca_says(grid):
    assert grid.ca.subject == CA_NAME
    assert (
        load_certificates(Path(grid.usercert).read_bytes())[0].issuer
        == parse_certificate(grid.ca.public_bytes(serialization.Encoding.DER)).subject
    )


def test_the_writer_refuses_or_follows_a_link_by_predictability(user, tmp_path):
    from xrdsec import credentials

    link = tmp_path / "link"
    link.symlink_to(tmp_path / "real")
    with pytest.raises(InsecureCredentialError, match="symbolic link"):
        credentials.write_private_file(str(link), b"x", kind="X", predictable=True)
    written = credentials.write_private_file(str(link), b"x", kind="X")
    assert written == os.path.realpath(tmp_path / "real")
    assert credentials.write_private_file(tmp_path / "p", b"y", kind="X") == str(tmp_path / "p")
