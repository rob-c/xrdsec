"""AES, against FIPS-197 and NIST SP 800-38A.

Every vector here is copied from a published document, because a cipher
tested only against itself is tested against nothing.
"""

import pytest

from xrdsec import aes as _aes
from xrdsec.aes import AES, BLOCK_SIZE, cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad

#: FIPS-197 appendix C: one plaintext, the three key sizes.
FIPS_197 = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8ea2b7ca516745bfeafc49904b496089",
    ),
]
FIPS_197_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")

#: SP 800-38A F.2.1, CBC-AES128.Encrypt.
SP800_38A_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
SP800_38A_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
SP800_38A_PLAIN = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
SP800_38A_CIPHER = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)


@pytest.mark.parametrize("key_hex, cipher_hex", FIPS_197)
def test_fips_197_block_vectors(key_hex, cipher_hex):
    cipher = AES(bytes.fromhex(key_hex))
    encrypted = cipher.encrypt_block(FIPS_197_PLAINTEXT)
    assert encrypted.hex() == cipher_hex
    assert cipher.decrypt_block(encrypted) == FIPS_197_PLAINTEXT


def test_sp_800_38a_cbc_vector():
    """The mode, not just the block function — chaining is where CBC goes wrong."""
    assert cbc_encrypt(SP800_38A_KEY, SP800_38A_PLAIN, SP800_38A_IV, pad=False) == SP800_38A_CIPHER
    assert cbc_decrypt(SP800_38A_KEY, SP800_38A_CIPHER, SP800_38A_IV, pad=False) == SP800_38A_PLAIN


@pytest.mark.parametrize("size", [16, 24, 32])
def test_key_sizes_round_trip_arbitrary_data(size):
    key = bytes(range(size))
    data = b"the quick brown fox jumps over the lazy dog" * 3
    assert cbc_decrypt(key, cbc_encrypt(key, data)) == data


def test_gsi_uses_a_zero_iv_by_default():
    """XrdSecgsi encrypts with no IV at all, so the default must be zeros."""
    key = bytes(range(16))
    assert cbc_encrypt(key, b"payload") == cbc_encrypt(key, b"payload", bytes(16))


def test_padding_always_adds_at_least_one_byte():
    assert pkcs7_pad(b"") == bytes([16]) * 16
    assert pkcs7_pad(b"a" * 16)[-1] == 16
    assert len(pkcs7_pad(b"a" * 15)) == 16
    assert pkcs7_unpad(pkcs7_pad(b"a" * 15)) == b"a" * 15
    assert pkcs7_unpad(pkcs7_pad(b"")) == b""


@pytest.mark.parametrize(
    "data, message",
    [
        (b"", "whole number of blocks"),
        (b"\x00" * 15, "whole number of blocks"),
        (b"\x00" * 16, "corrupt"),
        (b"\x01" * 15 + b"\x11", "corrupt"),
        (b"\x00" * 14 + b"\x01\x02", "corrupt"),
    ],
)
def test_corrupt_padding_is_refused(data, message):
    with pytest.raises(ValueError, match=message):
        pkcs7_unpad(data)


@pytest.mark.parametrize("length", [0, 15, 17, 33])
def test_bad_key_lengths_are_refused(length):
    with pytest.raises(ValueError, match="16, 24 or 32 bytes"):
        AES(bytes(length))


def test_short_blocks_are_refused():
    cipher = AES(bytes(16))
    with pytest.raises(ValueError, match="16 bytes"):
        cipher.encrypt_block(b"short")
    with pytest.raises(ValueError, match="16 bytes"):
        cipher.decrypt_block(b"short")


def test_bad_iv_and_unaligned_input_are_refused():
    with pytest.raises(ValueError, match="IV must be"):
        cbc_encrypt(bytes(16), b"x", bytes(8))
    with pytest.raises(ValueError, match="IV must be"):
        cbc_decrypt(bytes(16), bytes(16), bytes(8))
    with pytest.raises(ValueError, match="whole number of blocks"):
        cbc_encrypt(bytes(16), b"x" * 17, pad=False)
    with pytest.raises(ValueError, match="whole number of blocks"):
        cbc_decrypt(bytes(16), b"x" * 17)
    with pytest.raises(ValueError, match="whole number of blocks"):
        cbc_decrypt(bytes(16), b"")


def test_a_one_bit_change_propagates_through_the_chain():
    """CBC's whole point: block N depends on every block before it."""
    key = bytes(range(16))
    plain = bytes(BLOCK_SIZE * 4)
    baseline = cbc_encrypt(key, plain, pad=False)
    altered = cbc_encrypt(key, b"\x01" + plain[1:], pad=False)
    assert baseline[:BLOCK_SIZE] != altered[:BLOCK_SIZE]
    assert baseline[BLOCK_SIZE:] != altered[BLOCK_SIZE:]


def test_repr_does_not_leak_the_key():
    assert repr(AES(bytes(range(32)))) == "AES(bits=256, key=<redacted>)"
    assert "1f" not in repr(AES(bytes(range(32))))


@pytest.mark.parametrize("size", [16, 24, 32])
def test_ctr_preserves_partial_block_state(size):
    key = bytes(range(size))
    iv = bytes(range(16))
    plain = b"a partial block followed by another partial block"
    cipher = _aes.CTR(key, iv)
    encrypted = cipher.update(plain[:7]) + cipher.update(memoryview(plain[7:]))
    assert _aes.CTR(key, iv).update(bytearray(encrypted)) == plain
    with pytest.raises(ValueError, match="16 bytes"):
        _aes.CTR(key, b"short")
