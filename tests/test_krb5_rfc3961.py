"""Kerberos encryption, pinned to every vector its RFCs publish.

The n-fold vectors are RFC 3961 appendix A.1; the PBKDF2 string-to-key and
CBC-CTS vectors RFC 3962 appendix B; the key derivation, encryption,
checksum and PRF vectors RFC 8009 appendix A. None of these is produced by
this package, so a shared misunderstanding between encoder and decoder
cannot pass them. The live proof - a real MIT KDC and a real xrootd
accepting what this code builds - is in ``test_krb5_interop.py``.
"""

from __future__ import annotations

import pytest

from xrdsec.krb5 import rfc3961
from xrdsec.krb5.rfc3961 import (
    IntegrityError,
    UnsupportedEnctypeError,
    cts_decrypt,
    cts_encrypt,
    get_enctype,
    nfold,
)


def h(text: str) -> bytes:
    """Hex as the RFCs print it: in groups, over several lines."""
    return bytes.fromhex("".join(text.split()))


# -- RFC 3961 A.1: n-fold ----------------------------------------------------

NFOLD = [
    (64, b"012345", "be072631276b1955"),
    (56, b"password", "78a07b6caf85fa"),
    (64, b"Rough Consensus, and Running Code", "bb6ed30870b7f0e0"),
    (168, b"password", "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"),
    (
        192,
        b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
        "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
    ),
    (168, b"Q", "518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15"),
    (168, b"ba", "fb25d531 ae897449 9f52fd92 ea9857c4 ba24cf29 7e"),
    (64, b"kerberos", "6b657262 65726f73"),
    (128, b"kerberos", "6b657262 65726f73 7b9b5b2b 93132b93"),
    (168, b"kerberos", "8372c236 344e5f15 50cd0747 e15d62ca 7a5a3bce a4"),
    (
        256,
        b"kerberos",
        "6b657262 65726f73 7b9b5b2b 93132b93 5c9bdcda d95c9899 c4cae4de e6d6cae4",
    ),
]


@pytest.mark.parametrize("bits, data, expected", NFOLD)
def test_nfold_matches_rfc3961(bits, data, expected):
    assert nfold(data, bits // 8) == h(expected)


# -- RFC 3962 appendix B: PBKDF2 string-to-key -------------------------------

#: (iterations, pass phrase, salt, 128-bit key, 256-bit key), all hex.
STRING_TO_KEY = [
    (
        1,
        "70617373776f7264",
        "415448454e412e4d49542e4544557261656275726e",
        "42263c6e89f4fc28b8df68ee09799f15",
        "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
    ),
    (
        2,
        "70617373776f7264",
        "415448454e412e4d49542e4544557261656275726e",
        "c651bf29e2300ac27fa469d693bdda13",
        "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
    ),
    (
        1200,
        "70617373776f7264",
        "415448454e412e4d49542e4544557261656275726e",
        "4c01cd46d632d01e6dbe230a01ed642a",
        "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
    ),
    (
        5,
        "70617373776f7264",
        "1234567878563412",
        "e9b23d52273747dd5c35cb55be619d8e",
        "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31",
    ),
    (
        1200,
        "58" * 64,
        "706173732070687261736520657175616c7320626c6f636b2073697a65",
        "59d1bb789a828b1aa54ef9c2883f69ed",
        "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34",
    ),
    (
        1200,
        "58" * 65,
        "7061737320706872617365206578636565647320626c6f636b2073697a65",
        "cb8005dc5f90179a7f02104c0018751d",
        "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b",
    ),
    (
        50,
        "f09d849e",
        "4558414d504c452e434f4d7069616e697374",
        "f149c1f2e154a73452d43e7fe62a56e5",
        "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e",
    ),
]


@pytest.mark.parametrize("iterations, password, salt, key128, key256", STRING_TO_KEY)
def test_aes_sha1_string_to_key_matches_rfc3962(iterations, password, salt, key128, key256):
    aes128, aes256 = get_enctype(17), get_enctype(18)
    assert aes128.string_to_key(h(password), h(salt), iterations) == h(key128)
    assert aes256.string_to_key(h(password), h(salt), iterations) == h(key256)


def test_the_default_iteration_count_is_rfc3962s():
    """4096 is the RFC 3962 default; MIT uses it unless the KDC says otherwise."""
    aes128 = get_enctype(17)
    assert aes128.string_to_key(b"password", b"salt") == aes128.string_to_key(
        b"password", b"salt", 4096
    )


# -- RFC 3962 appendix B: CBC with ciphertext stealing -----------------------

CTS_KEY = "636869636b656e207465726979616b69"

#: (input, output, next IV) - the zero-IV vectors, 17 to 64 bytes long.
CTS = [
    (
        "4920776f756c64206c696b652074686520",
        "c6353568f2bf8cb4d8a580362da7ff7f97",
        "c6353568f2bf8cb4d8a580362da7ff7f",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
        "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
        "fc00783e0efdb2c1d445d4c8eff7ed22",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
        "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
        "39312523a78662d5be7fcbcc98ebf5a8",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c",
        "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
        "b3fffd940c16a18c1b5549d2f838029e",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20",
        "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
        "9dad8bbb96c4cdc03bc103e1a194bbd8",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
        "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
        "4807efe836ee89a526730dbc2f7bc840",
    ),
]


@pytest.mark.parametrize("plain, cipher, next_iv", CTS)
def test_cts_matches_rfc3962(plain, cipher, next_iv):
    out = cts_encrypt(h(CTS_KEY), h(plain))
    assert out == h(cipher)
    assert cts_decrypt(h(CTS_KEY), out) == h(plain)
    # The "next IV" is the last full CBC block, which CTS moved second-last.
    tail = len(out) % 16 or 16
    assert out[-(16 + tail) : -tail] == h(next_iv)


def test_cts_of_one_block_is_plain_cbc():
    from xrdsec.aes import AES

    block = bytes(range(16))
    out = cts_encrypt(h(CTS_KEY), block)
    assert out == AES(h(CTS_KEY)).encrypt_block(block)
    assert cts_decrypt(h(CTS_KEY), out) == block


def test_cts_refuses_less_than_a_block():
    with pytest.raises(ValueError, match="at least one block"):
        cts_encrypt(h(CTS_KEY), b"short")
    with pytest.raises(ValueError, match="at least one block"):
        cts_decrypt(h(CTS_KEY), b"short")


# -- RFC 8009 appendix A -----------------------------------------------------

S2K_SALT = h("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61") + b"ATHENA.MIT.EDUraeburn"

SHA256_BASE = h("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C")
SHA384_BASE = h(
    "6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 9800 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52"
)


def test_aes_sha2_string_to_key_matches_rfc8009():
    assert get_enctype(19).string_to_key(b"password", S2K_SALT) == h(
        "08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7"
    )
    assert get_enctype(20).string_to_key(b"password", S2K_SALT) == h(
        "45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22"
        "36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67"
    )


@pytest.mark.parametrize(
    "number, base, kc, ke, ki",
    [
        (
            19,
            SHA256_BASE,
            "B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3",
            "9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E",
            "9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C",
        ),
        (
            20,
            SHA384_BASE,
            "EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D",
            "56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7"
            "A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49",
            "69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F",
        ),
    ],
)
def test_aes_sha2_key_derivation_matches_rfc8009(number, base, kc, ke, ki):
    enctype = get_enctype(number)
    assert enctype.derive(base, 2, 0x99) == h(kc)
    assert enctype.derive(base, 2, 0xAA) == h(ke)
    assert enctype.derive(base, 2, 0x55) == h(ki)


PLAINS = [
    "",
    "00 01 02 03 04 05",
    "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
    "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14",
]

#: (enctype, base key, plaintext, confounder, ciphertext) for key usage 2.
ENCRYPTIONS = [
    (
        19,
        SHA256_BASE,
        PLAINS[0],
        "7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48",
        "EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D"
        "AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18",
    ),
    (
        19,
        SHA256_BASE,
        PLAINS[1],
        "7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24",
        "84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF"
        "B5 54 02 CE F7 E6 87 7C E9 9E 24 7E 52 D1 6E D4"
        "42 1D FD F8 97 6C",
    ),
    (
        19,
        SHA256_BASE,
        PLAINS[2],
        "56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F",
        "35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A"
        "E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2"
        "95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3",
    ),
    (
        19,
        SHA256_BASE,
        PLAINS[3],
        "A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC",
        "72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36"
        "C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC"
        "E1 E6 D0 72 C1 86 B3 9A 41 3C 2F 92 CA 9B 83 34"
        "A2 87 FF CB FC",
    ),
    (
        20,
        SHA384_BASE,
        PLAINS[0],
        "F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4",
        "41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0"
        "58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74"
        "8B 9B BF BE 7E B4 CE 3C",
    ),
    (
        20,
        SHA384_BASE,
        PLAINS[1],
        "B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A",
        "4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7"
        "B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60"
        "92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2",
    ),
    (
        20,
        SHA384_BASE,
        PLAINS[2],
        "53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63",
        "BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B"
        "BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6"
        "8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E"
        "40 C4 FF 25 5B 36 A2 66",
    ),
    (
        20,
        SHA384_BASE,
        PLAINS[3],
        "76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1",
        "40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE"
        "10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2"
        "B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A"
        "1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62",
    ),
]


@pytest.mark.parametrize("number, base, plain, confounder, cipher", ENCRYPTIONS)
def test_aes_sha2_encryption_matches_rfc8009(number, base, plain, confounder, cipher):
    enctype = get_enctype(number)
    assert enctype.encrypt(base, 2, h(plain), confounder=h(confounder)) == h(cipher)
    assert enctype.decrypt(base, 2, h(cipher)) == h(plain)


@pytest.mark.parametrize(
    "number, base, expected",
    [
        (19, SHA256_BASE, "D7 83 67 18 66 43 D6 7B 41 1C BA 91 39 FC 1D EE"),
        (
            20,
            SHA384_BASE,
            "45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D 43 C3 BF A0 66 99 67 2A",
        ),
    ],
)
def test_aes_sha2_checksums_match_rfc8009(number, base, expected):
    assert get_enctype(number).checksum(base, 2, h(PLAINS[3])) == h(expected)


@pytest.mark.parametrize(
    "number, base, expected",
    [
        (
            19,
            SHA256_BASE,
            "9D 18 86 16 F6 38 52 FE 86 91 5B B8 40 B4 A8 86"
            "FF 3E 6B B0 F8 19 B4 9B 89 33 93 D3 93 85 42 95",
        ),
        (
            20,
            SHA384_BASE,
            "98 01 F6 9A 36 8C 2B F6 75 E5 95 21 E1 77 D9 A0"
            "7F 67 EF E1 CF DE 8D 3C 8D 6F 6A 02 56 E3 B1 7D"
            "B3 C1 B6 2A D1 B8 55 33 60 D1 73 67 EB 15 14 D2",
        ),
    ],
)
def test_aes_sha2_prf_matches_rfc8009(number, base, expected):
    assert get_enctype(number).prf(base, b"test") == h(expected)


# -- the parts no RFC pins, pinned by round trip and by tampering ------------


@pytest.mark.parametrize("number", [17, 18, 19, 20])
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 100])
def test_every_enctype_round_trips(number, size):
    enctype = get_enctype(number)
    key = enctype.random_key()
    plain = bytes(range(size))
    sealed = enctype.encrypt(key, 11, plain)
    assert len(sealed) == 16 + size + enctype.mac_size
    assert enctype.decrypt(key, 11, sealed) == plain
    # A fresh confounder every time is what makes two sealings unlinkable.
    assert enctype.encrypt(key, 11, plain) != sealed


@pytest.mark.parametrize("number", [17, 18, 19, 20])
def test_the_wrong_usage_or_a_flipped_bit_fails_the_integrity_check(number):
    enctype = get_enctype(number)
    key = enctype.random_key()
    sealed = enctype.encrypt(key, 7, b"authenticator")
    with pytest.raises(IntegrityError, match="usage 11"):
        enctype.decrypt(key, 11, sealed)
    flipped = bytes([sealed[0] ^ 1]) + sealed[1:]
    with pytest.raises(IntegrityError, match="integrity check failed"):
        enctype.decrypt(key, 7, flipped)
    with pytest.raises(IntegrityError, match="too short"):
        enctype.decrypt(key, 7, sealed[:20])


def test_aes_sha1_checksum_is_a_truncated_hmac_under_the_derived_key():
    """No RFC vector exists for this one; its definition is short enough to restate."""
    import hashlib
    import hmac

    enctype = get_enctype(18)
    key = bytes(range(32))
    kc = enctype.derive(key, 6, 0x99)
    assert enctype.checksum(key, 6, b"body") == hmac.new(kc, b"body", hashlib.sha1).digest()[:12]


def test_a_key_of_the_wrong_size_is_refused():
    with pytest.raises(ValueError, match="32-byte key"):
        get_enctype(18).encrypt(bytes(16), 1, b"")


@pytest.mark.parametrize(
    "number, reason",
    [
        (1, "single DES"),
        (3, "single DES"),
        (16, "triple DES"),
        (23, "MD4"),
        (26, "Camellia|camellia"),
        (99, "not one this client implements"),
    ],
)
def test_legacy_enctypes_are_refused_with_the_reason(number, reason):
    with pytest.raises(UnsupportedEnctypeError, match=reason) as info:
        get_enctype(number)
    assert "aes256-cts-hmac-sha1-96" in str(info.value)


def test_the_supported_list_is_strongest_first():
    assert rfc3961.SUPPORTED_ENCTYPES == (20, 18, 19, 17)
    assert get_enctype(18).name == "aes256-cts-hmac-sha1-96"
