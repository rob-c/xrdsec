"""xgfalclient's shared-core tests (tests/test_shared_core.py), run against xrdsec.

These pin the crypto behaviour both clients rely on - CBC and padding edges,
RSA recovery, proxy detection and identity, certificate and extension shapes,
CA-name canonicalisation, proxy PEM. They run on a PKI viewed through the
same three hooks xgfalclient's ``testing.pki.PKI`` uses, rebuilt here on
xrdsec's :class:`~xrdsec.testing.pki.BasePKI`, which is also the check that
xgfalclient's subclass fits on xrdsec unchanged. The three tests about
xgfalclient's own import aliases are xgfalclient's and are not carried.
"""

from __future__ import annotations

import pickle
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from xrdsec import x509
from xrdsec.rsa import RSAPrivateKey
from xrdsec.testing.pki import BasePKI, PrivateKey
from xrdsec.testing.pki import test_key as _library_key
from xrdsec.x509 import Certificate, Name, ProxyCredential, certificate_data, load_proxy

_VIEWS: dict[int, RSAPrivateKey] = {}


def test_key(slot: int) -> RSAPrivateKey:
    found = _VIEWS.get(slot)
    if found is None:
        found = _VIEWS[slot] = RSAPrivateKey.from_cryptography(_library_key(slot))
    return found


test_key.__dict__["__test__"] = False


class PKI(BasePKI[Certificate, RSAPrivateKey, ProxyCredential]):
    def _certificate_view(self, der: bytes) -> Certificate:
        return certificate_data(der)

    def _key_view(self, key: PrivateKey) -> RSAPrivateKey:
        return RSAPrivateKey.from_cryptography(cast("rsa.RSAPrivateKey", key))

    def _load_credential(self, cert_path: str, key_path: str | None) -> ProxyCredential:
        return load_proxy(cert_path, key_path)


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> PKI:
    """xgfalclient's view of the test PKI (overrides the suite's own ``pki``)."""
    return PKI.create(tmp_path_factory.mktemp("gfal-view-pki"))


def test_shared_value_objects_remain_pickleable():
    name = x509.Name((("CN", "A physicist"),), b"preserved")
    restored = pickle.loads(pickle.dumps(name))
    assert restored == name
    assert restored.der == name.der


@pytest.mark.parametrize("data", [b"", b"short", b"a" * 16])
def test_shared_padding_error_boundaries(data):
    from xrdsec.aes import pkcs7_unpad

    with pytest.raises(ValueError):
        pkcs7_unpad(data)


@pytest.mark.parametrize("pad", [False, True])
def test_shared_cbc_modes(pad):
    from xrdsec.aes import cbc_decrypt, cbc_encrypt

    key = bytes(range(16))
    plain = b"a" * 32
    encrypted = cbc_encrypt(key, plain, pad=pad)
    assert cbc_decrypt(key, encrypted, pad=pad) == plain


@pytest.mark.parametrize("data", [b"", b"short"])
def test_shared_cbc_rejects_incomplete_ciphertext(data):
    from xrdsec.aes import cbc_decrypt

    with pytest.raises(ValueError):
        cbc_decrypt(bytes(16), data)


@pytest.mark.parametrize("kind", ["header", "short-padding", "wrong-padding"])
def test_shared_rsa_recovery_rejects_invalid_padding(kind):
    key = test_key(0)
    blocks = {
        "header": b"\x00\x02" + b"\xff" * 8 + b"\x00",
        "short-padding": b"\x00\x01" + b"\xff" * 7 + b"\x00",
        "wrong-padding": b"\x00\x01" + b"\xff" * 7 + b"x\x00",
    }
    plain = blocks[kind].ljust(key.size, b"x")
    signature = key._power(int.from_bytes(plain, "big")).to_bytes(key.size, "big")
    with pytest.raises(ValueError, match="padding"):
        key.public.recover(signature)


def test_shared_rsa_public_decryption_preserves_raw_gsi_contract():
    key = test_key(0)
    assert key.public.decrypt_public(key.sign(b"one") + key.sign(b"two")) == b"onetwo"
    for invalid in (b"", b"short"):
        with pytest.raises(ValueError, match="whole number"):
            key.public.decrypt_public(invalid)


@pytest.mark.parametrize("extensions", [(), ("1.3.6.1.5.5.7.1.14",), ("1.3.6.1.4.1.3536.1.222",)])
def test_shared_proxy_detection_extensions(pki, extensions):
    from dataclasses import replace

    from xrdsec.x509 import parse_certificate

    user = parse_certificate(pki.user.der)
    assert replace(user, extensions=extensions).is_proxy == bool(extensions)
    assert not replace(user, subject=Name(), extensions=()).is_proxy
    proxy_name = Name((*user.issuer.rdns, ("CN", "proxy")))
    assert replace(user, subject=proxy_name, extensions=()).is_proxy


@pytest.mark.parametrize(
    "rdns", [(), (("O", "lab"),), (("CN", "physicist"),), (("CN", "proxy"),), (("CN", "123"),)]
)
def test_shared_proxy_identity_stops_at_the_end_entity(pki, rdns):
    from dataclasses import replace

    from xrdsec.x509 import ProxyCredential, parse_certificate

    certificate = replace(parse_certificate(pki.user.der), subject=Name(rdns))
    proxy = ProxyCredential((certificate,), pki.user_key)
    expected = str(Name(rdns))
    if rdns in ((("CN", "proxy"),), (("CN", "123"),)):
        expected = ""
    assert proxy.identity == expected


@pytest.mark.parametrize("anchors_only", [False, True])
def test_shared_proxy_wire_chain_keeps_anchor_fallback(pki, anchors_only):
    from xrdsec.x509 import ProxyCredential, parse_certificate

    ca = parse_certificate(pki.ca.der)
    user = parse_certificate(pki.user.der)
    chain = (ca,) if anchors_only else (user, ca)
    proxy = ProxyCredential(chain, pki.user_key)
    assert proxy.pem() == (ca.pem() if anchors_only else user.pem())


@pytest.mark.parametrize("empty", [False, True])
def test_shared_certificate_body_policy(pki, empty):
    from xrdsec import der
    from xrdsec.x509 import certificate_fields, parse_certificate

    outer = der.raw_children(pki.user.der)
    fields = der.raw_children(outer[0])
    fields = [] if empty else fields[1:]
    altered = der.sequence(der.sequence(*fields), *outer[1:])
    if empty:
        with pytest.raises(der.DERError, match="required fields"):
            parse_certificate(altered)
        with pytest.raises(der.DERError, match="required fields"):
            certificate_fields(altered)
    else:
        assert parse_certificate(altered).serial == pki.user.serial
        assert certificate_fields(altered)["spki"] == pki.user.spki
        fields[0] = der.null()
        malformed_serial = der.sequence(der.sequence(*fields), *outer[1:])
        assert parse_certificate(malformed_serial).serial == 0


@pytest.mark.parametrize("spki", [b"\x30\x00", b"\x30\x04\x05\x00\x05\x00"])
def test_shared_certificate_key_shape_is_bounded(spki):
    from xrdsec import der
    from xrdsec.x509 import _certificate_key

    assert _certificate_key(der.parse_one(spki)) is None


@pytest.mark.parametrize(
    "raw",
    [
        b"\x30\x00",
        b"\x30\x04\x05\x00\x04\x00",
        b"\x30\x06\x06\x02\x2a\x03\x05\x00",
    ],
)
def test_shared_extension_parser_rejects_bad_shapes(raw):
    from xrdsec.der import DERError
    from xrdsec.x509 import parse_extension

    with pytest.raises(DERError, match="malformed"):
        parse_extension(raw)


@pytest.mark.parametrize("critical", [b"\x01\x01\xff", b"\x01\x01\x00", b"\x05\x00", b""])
def test_shared_extension_critical_flag(critical):
    from xrdsec import der
    from xrdsec.x509 import parse_extension

    raw = der.sequence(der.oid("1.2.3"), critical, der.octet_string(b"content"))
    assert parse_extension(raw).critical == (critical == b"\x01\x01\xff")


@pytest.mark.parametrize("signature", [b"\x05\x00", b"\x03\x02\x01x"])
def test_shared_signed_object_checks_bitstring_shape(pki, signature):
    from xrdsec import der
    from xrdsec.x509 import verify_signed

    parts = der.raw_children(pki.user.der)
    assert not verify_signed(der.sequence(*parts[:2], signature), pki.ca_key.public)


@pytest.mark.parametrize(
    "tag, encoding, value",
    [
        (0x0C, "utf-8", "  Ångström  LAB "),
        (0x13, "ascii", " Example \t CA "),
        (0x12, "ascii", "12 34"),
    ],
)
def test_shared_ca_name_canonicalisation(tag, encoding, value):
    from xrdsec import der
    from xrdsec.x509 import _canonical_value, name_hashes

    encoded = der.tlv(tag, value.encode(encoding))
    canonical = _canonical_value(tag, value.encode(encoding))
    if tag == 0x12:
        assert canonical == encoded
    else:
        expected = "Ångström lab" if tag == 0x0C else "example ca"
        assert der.parse_one(canonical).value.decode("utf-8") == expected
    original_name = der.sequence(der.set_of(der.sequence(der.oid("2.5.4.3"), encoded)))
    hashes = name_hashes(original_name)
    assert len(hashes[0]) == 8
    assert len(hashes[1]) == 8


@pytest.mark.parametrize("with_key", [True, False])
def test_shared_proxy_pem_leaves_trust_anchors_out(pki, with_key):
    """``ProxyCredential.to_pem``: chain without the CA, the key only when asked."""
    from xrdsec.x509 import ProxyCredential, load_certificates, parse_certificate

    ca = parse_certificate(pki.ca.der)
    user = parse_certificate(pki.user.der)
    proxy = load_certificates(pki.proxy_path.read_bytes())[0]
    text = ProxyCredential((proxy, user, ca), pki.user_key).to_pem(with_key=with_key)
    assert text.startswith(proxy.pem()) and user.pem() in text and ca.pem() not in text
    assert (b"PRIVATE KEY" in text) is with_key


@pytest.mark.parametrize("kind", ["rsa", "ec", "ed25519"])
def test_shared_private_key_pem_prefers_the_traditional_forms(kind):
    """RSA and EC keys are written in OpenSSL's traditional PEM; others as PKCS#8."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    from xrdsec import x509 as shared

    key = {
        "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=1024),
        "ec": lambda: ec.generate_private_key(ec.SECP256R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate,
    }[kind]()
    header = {"rsa": b"RSA PRIVATE KEY", "ec": b"EC PRIVATE KEY", "ed25519": b"BEGIN PRIVATE KEY"}
    assert header[kind] in shared._private_key_pem(key)


@pytest.mark.parametrize(
    ("extensions", "expected"),
    [((), False), (("1.3.6.1.5.5.7.1.14",), True), (("1.3.6.1.4.1.3536.1.222",), True)],
)
def test_shared_strict_proxy_detection_reads_both_proxy_extensions(pki, extensions, expected):
    """The Globus reading: RFC 3820's or the draft ProxyCertInfo, or a GT2 name."""
    from dataclasses import replace

    from xrdsec.x509 import is_proxy_certificate, parse_certificate

    user = parse_certificate(pki.user.der)
    assert is_proxy_certificate(replace(user, extensions=extensions)) is expected


def test_shared_proxy_identity_is_the_end_entity_behind_a_proxy(pki):
    """A recognisable proxy over its user certificate names the user, exactly."""
    from dataclasses import replace

    from xrdsec.x509 import ProxyCredential, parse_certificate

    user = parse_certificate(pki.user.der)
    proxy = replace(
        user,
        subject=Name((*user.subject.rdns, ("CN", "42"))),
        extensions=("1.3.6.1.5.5.7.1.14",),
    )
    assert ProxyCredential((proxy, user), pki.user_key).identity == str(user.subject)
