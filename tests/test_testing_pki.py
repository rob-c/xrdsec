"""The shared test PKI (:mod:`xrdsec.testing.pki`): files, proxies, CRLs and contexts.

It is public test API that xgfalclient's and xrdarc's suites stand on, so
its layout and its proxy rules are pinned here rather than assumed.
"""

from __future__ import annotations

import shutil
import ssl
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from xrdsec.rsa import RSAPrivateKey
from xrdsec.testing import pki as pki_module
from xrdsec.testing.pki import (
    KEYS,
    PKI,
    BasePKI,
    Signer,
    create_pki,
    key_pem,
    proxy_certificate,
    subject_hash,
    test_key,
    test_key_pem,
    user_certificate,
)
from xrdsec.x509 import LIMITED_PROXY_OID, certificate_data, encode_name, proxy_policy


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> PKI:
    return create_pki(tmp_path_factory.mktemp("pki"))


def test_layout(pki: PKI) -> None:
    for path in (pki.ca_file, pki.host_cert_path, pki.user_cert_path, pki.proxy_path):
        assert path.exists()
    for secret in (pki.host_key_path, pki.user_key_path, pki.proxy_path):
        assert oct(secret.stat().st_mode & 0o777) == "0o600"
    hashed = pki.ca_dir / f"{pki.ca_hash}.0"
    assert hashed.read_bytes() == pki.ca_file.read_bytes()
    assert hashed.with_suffix(".signing_policy").read_text() == (
        "access_id_CA X509 '/DC=org/DC=xrdsec/CN=xrdsec Test CA'\n"
        "pos_rights globus CA:sign\n"
        "cond_subjects globus '\"/DC=org/DC=xrdsec/*\"'\n"
    )
    assert pki.environment() == {
        "X509_USER_PROXY": str(pki.proxy_path),
        "X509_CERT_DIR": str(pki.ca_dir),
    }
    assert "xrdsec Test CA" in repr(pki) and "PRIVATE" not in repr(pki)


def test_views_are_cryptography_objects(pki: PKI) -> None:
    assert isinstance(pki.ca, x509.Certificate)
    assert pki.host_key is pki.host_signer.key
    assert pki.ca_signer.der == pki.ca.public_bytes(serialization.Encoding.DER)
    assert pki.user_credential.identity == "/DC=org/DC=xrdsec/OU=People/CN=Test User"
    proxy = pki.credential()
    assert proxy.certificate.is_proxy
    assert proxy.identity == pki.user_credential.identity
    names = pki.host.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ["localhost"]


def test_keys_are_frozen_cached_and_distinct() -> None:
    assert len(KEYS) == 8
    assert test_key(3) is test_key(3)
    numbers = {test_key(slot).private_numbers().d for slot in range(len(KEYS))}
    assert len(numbers) == len(KEYS)
    assert test_key_pem(0).startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    loaded = serialization.load_pem_private_key(test_key_pem(0), None)
    assert isinstance(loaded, rsa.RSAPrivateKey)
    assert loaded.private_numbers() == test_key(0).private_numbers()
    assert key_pem(test_key(0)) == test_key_pem(0)
    with pytest.raises(IndexError):
        test_key(len(KEYS))


def test_key_pem_writes_ec_keys_in_their_traditional_form() -> None:
    assert key_pem(ec.generate_private_key(ec.SECP256R1())).startswith(
        b"-----BEGIN EC PRIVATE KEY-----"
    )


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")
def test_subject_hash_matches_openssl(pki: PKI) -> None:
    result = subprocess.run(
        ["openssl", "x509", "-hash", "-noout", "-in", str(pki.ca_file)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == pki.ca_hash


def test_subject_hash_folds_case_and_space() -> None:
    upper = encode_name((("CN", "  Some   CA "),))
    assert subject_hash(upper) == subject_hash(encode_name((("CN", "some ca"),)))


def test_proxy_kinds(pki: PKI, tmp_path: Path) -> None:
    limited = pki.credential(pki.proxy("limited", path=tmp_path / "limited"))
    leaf = certificate_data(limited.chain[0].der)
    assert proxy_policy(leaf.extension_values) == LIMITED_PROXY_OID
    # A proxy of a limited proxy is limited, whatever was asked for.
    child = pki.credential(pki.proxy("rfc", issuer=limited, key_slot=5, path=tmp_path / "c"))
    assert len(child.chain) == 3
    assert proxy_policy(certificate_data(child.chain[0].der).extension_values) == LIMITED_PROXY_OID
    legacy = pki.credential(pki.proxy("legacy", lifetime=60))
    assert legacy.certificate.subject.cn == "proxy"
    assert legacy.certificate.not_after <= legacy.certificate.not_before + 60 + 300 + 1
    # A GT2 issuer begets a GT2 child.
    grandchild = pki.credential(pki.proxy("limited", issuer=legacy, path=tmp_path / "g"))
    assert grandchild.certificate.subject.cn == "limited proxy"


def test_a_gt2_issuer_passes_on_its_limitation(pki: PKI, tmp_path: Path) -> None:
    """Asked for an RFC proxy, a GT2 issuer still begets GT2 - limited if it is limited."""
    legacy = pki.credential(pki.proxy("legacy", path=tmp_path / "gt2"))
    limited = pki.credential(pki.proxy("limited", issuer=legacy, path=tmp_path / "gt2-limited"))
    plain_child = pki.credential(pki.proxy("rfc", issuer=legacy, path=tmp_path / "plain"))
    limited_child = pki.credential(pki.proxy("rfc", issuer=limited, path=tmp_path / "child"))
    assert plain_child.certificate.subject.cn == "proxy"
    assert limited_child.certificate.subject.cn == "limited proxy"
    assert proxy_policy(certificate_data(limited_child.chain[0].der).extension_values) is None


def test_any_signer_may_issue_a_proxy(pki: PKI, tmp_path: Path) -> None:
    """A :class:`Signer` is used as it is - here the host's, not the default user's."""
    host_proxy = pki.credential(pki.proxy(issuer=pki.host_signer, path=tmp_path / "host"))
    assert host_proxy.certificate.is_proxy
    assert host_proxy.certificate.issuer == pki.host_signer.leaf.subject


def test_a_proxy_never_outlives_its_issuer(pki: PKI) -> None:
    proxy = proxy_certificate(test_key(4), pki.user_signer, lifetime=10 * 365 * 86400)
    assert certificate_data(proxy).not_after == certificate_data(pki.user_signer.der).not_after


def test_proxy_refuses_unknown_kinds_and_keys(pki: PKI) -> None:
    with pytest.raises(ValueError, match="unknown proxy kind"):
        proxy_certificate(test_key(4), pki.user_signer, kind="independent")

    class Odd:
        chain = pki.credential().chain
        key = ed25519.Ed25519PrivateKey.generate()

    with pytest.raises(TypeError, match="Ed25519"):
        pki.proxy(issuer=Odd())


def test_a_client_rsa_view_can_issue(pki: PKI, tmp_path: Path) -> None:
    class Viewed:
        chain = pki.credential().chain
        key = RSAPrivateKey.from_cryptography(test_key(3))

    assert pki.credential(pki.proxy(issuer=Viewed(), path=tmp_path / "v")).certificate.is_proxy


def test_crls(pki: PKI) -> None:
    clean = x509.load_pem_x509_crl(pki.crl())
    ca_key = pki.ca.public_key()
    assert isinstance(ca_key, rsa.RSAPublicKey)
    assert list(clean) == [] and clean.is_signature_valid(ca_key)
    path = pki.install_crl([pki.host.serial_number])
    assert path.name == f"{pki.ca_hash}.r0"
    revoked = x509.load_pem_x509_crl(path.read_bytes())
    assert revoked.get_revoked_certificate_by_serial_number(pki.host.serial_number) is not None


def test_tls_contexts_interoperate(pki: PKI) -> None:
    assert pki.server_context(require_client=False).verify_mode == ssl.CERT_NONE
    pairs = (
        (pki.client_context(), pki.server_context()),
        (
            ssl.create_default_context(capath=str(pki.ca_dir)),
            pki.server_context(require_client=False),
        ),
    )
    for client, server in pairs:
        incoming, outgoing, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
        c = client.wrap_bio(incoming, outgoing, server_hostname="localhost")
        s = server.wrap_bio(s_in, s_out, server_side=True)
        done: set[str] = set()
        for _ in range(10):
            for label, side, out, peer_in in (("c", c, outgoing, s_in), ("s", s, s_out, incoming)):
                try:
                    side.do_handshake()
                    done.add(label)
                except ssl.SSLWantReadError:
                    pass
                peer_in.write(out.read())
        assert done == {"c", "s"}


def test_second_pki_and_custom_hosts(tmp_path: Path) -> None:
    other = create_pki(tmp_path, hosts=("se.example.org", "10.0.0.1"), key_slots=(5, 6, 7))
    names = other.host.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert names.get_values_for_type(x509.DNSName) == ["se.example.org"]
    assert [str(ip) for ip in names.get_values_for_type(x509.IPAddress)] == ["10.0.0.1"]


def test_a_certificate_never_outlives_its_ca(pki: PKI) -> None:
    der = user_certificate((("CN", "Late"),), test_key(7), pki.ca_signer, lifetime=1e9)
    assert certificate_data(der).not_after == certificate_data(pki.ca_signer.der).not_after


def test_a_subclass_chooses_names_and_views(tmp_path: Path) -> None:
    """The base class is generic: the hooks are all a different view needs."""

    class Raw(BasePKI[bytes, bytes, str]):
        CA_SUBJECT = (("CN", "Raw CA"),)

        def _certificate_view(self, der: bytes) -> bytes:
            return der

        def _key_view(self, key: pki_module.PrivateKey) -> bytes:
            return key_pem(key)

        def _load_credential(self, cert_path: str, key_path: str | None) -> str:
            return cert_path

    raw = Raw.create(tmp_path)
    assert raw.ca == raw.ca_signer.der and raw.ca_key.startswith(b"-----BEGIN RSA")
    assert raw.credential() == str(raw.proxy_path)
    assert "'/CN=Raw CA'" in raw.signing_policy().decode()


def test_the_base_class_has_no_view(tmp_path: Path) -> None:
    ca = Signer((pki_module.ca_certificate((("CN", "x"),), test_key(0)),), test_key(0))
    with pytest.raises(NotImplementedError):
        BasePKI(tmp_path, ca, ca, ca)
    bare = object.__new__(BasePKI)
    with pytest.raises(NotImplementedError):
        bare._key_view(test_key(0))
    with pytest.raises(NotImplementedError):
        bare._load_credential("cert", None)


def test_client_contexts_are_fresh_and_may_present_nothing_or_skip_the_name(pki: PKI) -> None:
    """Every call is a new context a test may change; ``anonymous`` loads no credential."""
    first, second = pki.client_context(), pki.client_context()
    assert first is not second and first.check_hostname
    loose = pki.client_context(anonymous=True, check_hostname=False)
    assert not loose.check_hostname and loose.verify_mode == ssl.CERT_REQUIRED
    server = pki.server_context()  # demands a client certificate the anonymous side lacks
    incoming, outgoing, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    c = loose.wrap_bio(incoming, outgoing, server_hostname="anything")
    s = server.wrap_bio(s_in, s_out, server_side=True)
    refused = False
    for _ in range(10):
        for side, out, peer_in in ((c, outgoing, s_in), (s, s_out, incoming)):
            try:
                side.do_handshake()
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError:
                refused = True
            peer_in.write(out.read())
    assert refused
