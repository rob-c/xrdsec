"""Known-answer and rejection tests for VOMS signature primitives."""

from __future__ import annotations

import pytest

from xrdsec import ed25519, p256

ED25519_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


@pytest.mark.parametrize(("secret", "public", "message", "signature"), ED25519_VECTORS)
def test_ed25519_rfc8032(secret, public, message, signature):
    secret_bytes = bytes.fromhex(secret)
    message_bytes = bytes.fromhex(message)
    assert ed25519.public_key(secret_bytes).hex() == public
    assert ed25519.sign(secret_bytes, message_bytes).hex() == signature
    assert ed25519.verify(bytes.fromhex(public), message_bytes, bytes.fromhex(signature))


def test_ed25519_rejects_bad_signatures():
    secret = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = ed25519.public_key(secret)
    good = ed25519.sign(secret, b"hi")
    assert not ed25519.verify(public, b"hi", good[:-1])
    tampered = bytearray(good)
    tampered[0] ^= 1
    assert not ed25519.verify(public, b"hi", bytes(tampered))
    assert not ed25519.verify(public, b"hi", good[:32] + (ed25519.L + 1).to_bytes(32, "little"))
    assert not ed25519.verify(public, b"hi", b"\xff" * 32 + good[32:])
    assert not ed25519.verify(b"\xff" * 32, b"hi", good)


def test_ed25519_rejects_bad_seed():
    with pytest.raises(ValueError, match="32 bytes"):
        ed25519.public_key(b"short")


P256_SECRET = int("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
_P256_UX = int("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16)
_P256_UY = int("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16)
P256_SIGNATURES = {
    b"sample": (
        int("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", 16),
        int("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", 16),
    ),
    b"test": (
        int("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", 16),
        int("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", 16),
    ),
}
P256_PUBLIC = (_P256_UX, _P256_UY)


def test_p256_public_key():
    assert p256.public_key(P256_SECRET) == P256_PUBLIC


@pytest.mark.parametrize("message", list(P256_SIGNATURES))
def test_p256_rfc6979(message):
    signature = p256.sign(P256_SECRET, message)
    assert signature == P256_SIGNATURES[message]
    assert p256.verify(P256_PUBLIC, message, *signature)


def test_p256_point_encoding_round_trip():
    blob = p256.encode_point(P256_PUBLIC)
    assert p256.decode_point(blob) == P256_PUBLIC
    with pytest.raises(ValueError, match="uncompressed"):
        p256.decode_point(b"\x02" + b"\x00" * 32)
    with pytest.raises(ValueError, match="not on P-256"):
        p256.decode_point(b"\x04" + b"\x00" * 64)


def test_p256_rejects_bad_scalars_and_signatures():
    with pytest.raises(ValueError, match="out of range"):
        p256.public_key(0)
    with pytest.raises(ValueError, match="out of range"):
        p256.public_key(p256.N)
    assert not p256.verify(P256_PUBLIC, b"sample", 0, 1)
    assert not p256.verify(P256_PUBLIC, b"sample", 1, 0)
    assert not p256.verify(P256_PUBLIC, b"other", *p256.sign(P256_SECRET, b"sample"))
