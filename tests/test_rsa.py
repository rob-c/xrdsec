"""RSA: key loading, and the two signature shapes GSI and RFC 8017 want."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from xrdsec.der import DERError, parse
from xrdsec.rsa import (
    RSA_OID,
    RSAPrivateKey,
    RSAPublicKey,
    _type1_block,
    load_library_key,
    load_private_key,
    load_public_key,
    pem_blocks,
    public_key_from_bitstring,
)
from xrdsec.testing.rawpki import (
    integer,
    oid,
    pem,
    pkcs8_pem,
    private_key_pem,
    public_key_info,
    sequence,
    throwaway_key,
    tlv,
)


@pytest.fixture(scope="module")
def key():
    return throwaway_key(0)


def test_pem_blocks_splits_a_combined_file():
    data = pem("CERTIFICATE", b"\x30\x00") + pem("RSA PRIVATE KEY", b"\x30\x01\x02")
    assert [label for label, _ in pem_blocks(data)] == ["CERTIFICATE", "RSA PRIVATE KEY"]
    assert pem_blocks(data)[1][1] == b"\x30\x01\x02"


def test_pem_blocks_accepts_text_as_well_as_bytes():
    text = pem("CERTIFICATE", b"\x30\x00").decode()
    assert pem_blocks(text) == pem_blocks(text.encode())


def test_a_corrupt_block_does_not_lose_the_good_ones():
    """A proxy file with one unreadable member must still yield the rest."""
    broken = b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n"
    data = broken + pem("RSA PRIVATE KEY", b"\x30\x01\x02")
    assert [label for label, _ in pem_blocks(data)] == ["RSA PRIVATE KEY"]


def test_unterminated_and_mismatched_blocks_are_dropped():
    assert pem_blocks("-----BEGIN CERTIFICATE-----\nAAAA\n") == []
    assert pem_blocks("-----BEGIN CERTIFICATE-----\nAAAA\n-----END OTHER-----\n") == []


def test_pkcs1_and_pkcs8_load_to_the_same_key(key):
    assert load_private_key(private_key_pem(key)) == key
    loaded = load_private_key(pkcs8_pem(key))
    assert (loaded.n, loaded.e, loaded.d) == (key.n, key.e, key.d)


def test_raw_der_is_accepted_without_pem_armour(key):
    import base64

    der = base64.b64decode(b"".join(private_key_pem(key).splitlines()[1:-1]))
    assert load_private_key(der) == key


def test_a_label_selects_between_blocks(key):
    other = throwaway_key(1)
    data = pem("PRIVATE KEY", b"\x30\x00") + private_key_pem(key)
    assert load_private_key(data, "RSA PRIVATE KEY") == key
    assert other != key  # the fixture keys really are distinct


def test_an_encrypted_key_is_refused_by_name():
    """The fix is to decrypt it, so say that rather than 'parse error'."""
    with pytest.raises(DERError, match="encrypted"):
        load_private_key(pem("ENCRYPTED PRIVATE KEY", b"\x30\x00"))


def test_a_file_with_no_key_is_refused():
    with pytest.raises(DERError, match="no RSA private key"):
        load_private_key(pem("CERTIFICATE", b"\x30\x00"))


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pem_of(
    key: PrivateKeyTypes,
    encryption: serialization.KeySerializationEncryption | None = None,
    private_format: serialization.PrivateFormat | None = None,
) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        private_format or serialization.PrivateFormat.PKCS8,
        encryption or serialization.NoEncryption(),
    )


def test_a_non_rsa_key_names_its_algorithm():
    with pytest.raises(DERError, match="key is EC, not RSA"):
        load_private_key(_pem_of(_ec_key()))


def test_any_private_key_loads_through_the_library_loader():
    assert isinstance(load_library_key(_pem_of(_ec_key())), ec.EllipticCurvePrivateKey)


@pytest.mark.parametrize(
    "body",
    [
        sequence(integer(0), integer(1)),  # truncated PKCS#1
        sequence(*(integer(value) for value in (1, 2, 3, 4, 5, 6))),  # nonsense numbers
    ],
)
def test_a_malformed_key_body_is_refused_as_unreadable(body):
    with pytest.raises(DERError, match="unreadable private key"):
        load_private_key(pem("RSA PRIVATE KEY", body))


def test_an_encrypted_pkcs8_key_loads_with_its_password(key):
    locked = _pem_of(key.to_cryptography(), serialization.BestAvailableEncryption(b"open sesame"))
    assert load_private_key(locked, password="open sesame") == key
    assert load_private_key(locked, password=b"open sesame") == key
    with pytest.raises(DERError, match="encrypted; pass its password"):
        load_private_key(locked)
    with pytest.raises(DERError, match="wrong password"):
        load_private_key(locked, password="guess")


def test_a_legacy_openssl_encrypted_key_loads_with_its_password(key):
    """``Proc-Type: 4,ENCRYPTED`` lives in PEM headers, so the PEM text is what loads."""
    locked = _pem_of(
        key.to_cryptography(),
        serialization.BestAvailableEncryption(b"pw"),
        serialization.PrivateFormat.TraditionalOpenSSL,
    )
    assert b"Proc-Type: 4,ENCRYPTED" in locked
    indented = b"\n".join(b"  " + line for line in locked.splitlines())
    assert load_private_key(indented, password="pw") == key
    with pytest.raises(DERError, match="encrypted; pass its password"):
        load_private_key(locked)


def test_an_encrypted_der_key_without_a_password_says_so(key):
    der = key.to_cryptography().private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"pw"),
    )
    with pytest.raises(DERError, match="encrypted; pass its password"):
        load_private_key(der)
    assert load_private_key(der, password="pw") == key


def test_a_password_for_an_unencrypted_key_is_refused(key):
    with pytest.raises(DERError, match="not encrypted"):
        load_private_key(private_key_pem(key), password="pw")


def test_public_keys_load_from_subject_public_key_info(key):
    loaded = load_public_key(pem("PUBLIC KEY", public_key_info(key.public)))
    assert loaded == key.public
    assert loaded.size == key.size == 256  # 2048 bits


def test_public_keys_load_from_a_bare_pkcs1_body(key):
    from xrdsec.testing.rawpki import integer, sequence

    body = sequence(integer(key.n), integer(key.e))
    assert load_public_key(pem("RSA PUBLIC KEY", body)) == key.public


def test_a_non_rsa_public_key_is_refused():
    from xrdsec.testing.rawpki import bitstring, oid, sequence, tlv

    der = sequence(sequence(oid("1.2.840.10045.2.1"), tlv(0x05, b"")), bitstring(b"\x30\x00"))
    with pytest.raises(DERError, match="not RSA"):
        load_public_key(pem("PUBLIC KEY", der))
    with pytest.raises(DERError, match="not an RSA public key"):
        load_public_key(pem("PUBLIC KEY", sequence(b"")))


def test_raw_signatures_are_what_gsi_verifies(key):
    """``digest=None`` puts the message straight inside the padding."""
    tag = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    signature = key.sign(tag)
    assert len(signature) == key.size
    assert key.public.verify(tag, signature)
    assert not key.public.verify(b"\x00" * 8, signature)


@pytest.mark.parametrize("digest", ["sha1", "sha256", "sha384", "sha512"])
def test_digest_signatures_follow_rfc_8017(key, digest):
    signature = key.sign(b"payload", digest=digest)
    assert key.public.verify(b"payload", signature, digest=digest)
    assert not key.public.verify(b"payload", signature)  # the wrapper matters


def test_the_padding_block_has_the_documented_shape():
    block = _type1_block(b"\x01\x02", 64)
    assert block[:2] == b"\x00\x01"
    assert block[-3:] == b"\x00\x01\x02"
    assert set(block[2:-3]) == {0xFF}
    assert len(block) == 64


def test_an_oversized_message_is_refused(key):
    with pytest.raises(ValueError, match="does not fit"):
        key.sign(b"x" * 256)
    with pytest.raises(ValueError, match="unsupported digest"):
        key.sign(b"x", digest="md5")


def test_a_wrong_length_signature_is_rejected_not_raised(key):
    assert not key.public.verify(b"tag", b"\x00" * 8)


def test_the_crt_path_agrees_with_the_plain_one(key):
    """``p``/``q`` are an optimisation; dropping them must not change output."""
    slow = RSAPrivateKey(n=key.n, e=key.e, d=key.d)
    assert slow.sign(b"tag") == key.sign(b"tag")
    # The library needs the CRT form; the primes are recovered from d for it.
    assert slow.sign(b"tag", digest="sha256") == key.sign(b"tag", digest="sha256")
    assert slow.public == key.public


def test_generate_produces_a_usable_key():
    fresh = RSAPrivateKey.generate(1024)
    assert fresh.n.bit_length() == 1024
    assert fresh.e == 65537
    assert fresh.p * fresh.q == fresh.n
    assert fresh.public.verify(b"tag", fresh.sign(b"tag"))


@pytest.mark.parametrize("bits", [512, 1025])
def test_generate_refuses_unusable_sizes(bits):
    with pytest.raises(ValueError, match="at least 1024"):
        RSAPrivateKey.generate(bits)


def test_the_raw_signature_is_blinded_and_still_exact(key, monkeypatch):
    """Blinding changes what the secret exponent is applied to, never the result.

    The first draw is a factor of ``n``, which has no inverse; it is redrawn.
    """
    import secrets

    draws = iter([key.p - 2, 5 - 2])
    monkeypatch.setattr(secrets, "randbelow", lambda bound: next(draws))
    block = int.from_bytes(_type1_block(b"tag", key.size), "big")
    assert key._blinded_power(block) == key._power(block)


def test_the_library_views_round_trip(key):
    assert RSAPrivateKey.from_cryptography(key.to_cryptography()) == key
    assert (
        key.to_cryptography().public_key().public_numbers().n
        == key.public.to_cryptography().public_numbers().n
    )


def test_a_raw_verify_of_an_oversized_or_garbage_block_is_false(key):
    assert not key.public.verify(b"x" * key.size, key.sign(b"tag"))
    assert not key.public.verify(b"tag", bytes(key.size))


def test_recover_refuses_what_is_not_type_one_padding(key):
    with pytest.raises(ValueError, match="not PKCS#1"):
        key.public.recover(bytes(key.size))
    with pytest.raises(ValueError, match="key is 256"):
        key.public.recover(b"short")


def test_an_invalid_public_key_verifies_nothing():
    assert not RSAPublicKey(n=257, e=1).verify(b"m", b"\x01\x00", digest="sha256")


def test_reprs_do_not_leak_the_private_exponent(key):
    assert repr(key) == "RSAPrivateKey(bits=2048, d=<redacted>)"
    assert str(key.d) not in repr(key)
    assert repr(key.public) == f"RSAPublicKey(bits=2048, e={key.e})"


def test_a_pkcs8_body_with_the_key_before_the_version_is_refused():
    """Field order is not decoration: an OCTET STRING first is not PKCS#8."""
    der = sequence(tlv(0x04, b"\x00"), sequence(oid(RSA_OID)), tlv(0x04, b"\x00"))
    with pytest.raises(DERError, match="unreadable private key"):
        load_private_key(der)


@pytest.mark.parametrize(
    ("element", "message"),
    [
        (tlv(0x02, b"\x01"), "non-empty BIT STRING"),
        (tlv(0x03, b""), "non-empty BIT STRING"),
        (tlv(0x03, b"\x03" + sequence(integer(3), integer(3))), "3 unused bits"),
        (tlv(0x03, b"\x00" + sequence(integer(3))), "has 1 fields"),
    ],
)
def test_a_subject_public_key_that_is_not_an_rsa_key_is_rejected(element, message):
    """``public_key_from_bitstring`` is reached from certificates too."""
    parsed, _ = parse(element)
    with pytest.raises(DERError, match=message):
        public_key_from_bitstring(parsed)


def test_the_algorithm_oid_is_the_published_one():
    assert RSA_OID == "1.2.840.113549.1.1.1"
    assert RSAPublicKey(n=1 << 1023, e=3).size == 128


def test_a_private_key_exports_as_der_and_pem_and_needs_its_primes():
    from xrdsec import rsa

    key = throwaway_key(0)
    assert rsa.load_private_key(rsa.private_key_der(key)).public == key.public
    assert rsa.load_private_key(rsa.private_key_pem(key)).public == key.public
    for incomplete in (rsa.RSAPrivateKey(1, 2, 3), rsa.RSAPrivateKey(1, 2, 3, p=5)):
        with pytest.raises(ValueError, match="needs its primes"):
            rsa.private_key_der(incomplete)
