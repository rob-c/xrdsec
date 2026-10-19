"""Kerberos 5 encryption: the RFC 3961 framework and the AES enctypes.

Kerberos never uses a key directly. Every message is protected under keys
*derived* from the long-term or session key and a "key usage" number, so
that a ciphertext made for one purpose (an authenticator, say) can never be
replayed as another (a ticket). This module is that machinery for the four
enctypes a modern KDC issues:

* ``aes128-cts-hmac-sha1-96`` (17) and ``aes256-cts-hmac-sha1-96`` (18),
  RFC 3962: keys derived with the RFC 3961 ``DK`` function (n-fold and
  AES), integrity from a truncated HMAC-SHA1 over the plaintext.
* ``aes128-cts-hmac-sha256-128`` (19) and ``aes256-cts-hmac-sha384-192``
  (20), RFC 8009: keys derived with an SP 800-108 HMAC counter-mode KDF,
  integrity from a truncated HMAC-SHA2 over the ciphertext.

Both families encrypt a random 16-byte confounder followed by the message
with AES in CBC mode with ciphertext stealing (CBC-CS3), so a ciphertext is
exactly as long as its plaintext plus the confounder and the MAC.

DES, triple-DES, RC4 and Camellia are refused by :func:`get_enctype` with an
error that says why: the first three are deprecated by RFC 6649 and RFC 8429,
RC4 would need MD4 (which many ``hashlib`` builds no longer have), and a
KDC that issues Camellia only is rare enough not to justify the code.

Nothing here is a data path: a Kerberos exchange encrypts a few hundred
bytes, once per login. The block cipher and the CBC chaining are
``cryptography``'s (through :mod:`xrdsec.aes`); only the
ciphertext-stealing rearrangement of the last two blocks is done here.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import struct
from dataclasses import dataclass

from ..aes import AES, BLOCK_SIZE, cbc_decrypt, cbc_encrypt

__all__ = [
    "AES128_CTS_HMAC_SHA1_96",
    "AES128_CTS_HMAC_SHA256_128",
    "AES256_CTS_HMAC_SHA1_96",
    "AES256_CTS_HMAC_SHA384_192",
    "SUPPORTED_ENCTYPES",
    "Enctype",
    "IntegrityError",
    "UnsupportedEnctypeError",
    "cts_decrypt",
    "cts_encrypt",
    "get_enctype",
    "nfold",
]

#: The enctype numbers of RFC 3961 section 8 and RFC 8009.
AES128_CTS_HMAC_SHA1_96 = 17
AES256_CTS_HMAC_SHA1_96 = 18
AES128_CTS_HMAC_SHA256_128 = 19
AES256_CTS_HMAC_SHA384_192 = 20

#: Enctypes a KDC might issue that this module will not implement, and why.
#: The message is what a user sees, so it says what to change.
_REFUSED = {
    1: "des-cbc-crc is single DES, withdrawn by RFC 6649",
    2: "des-cbc-md4 is single DES, withdrawn by RFC 6649",
    3: "des-cbc-md5 is single DES, withdrawn by RFC 6649",
    16: "des3-cbc-sha1 is triple DES, deprecated by RFC 8429",
    23: "rc4-hmac is RC4, deprecated by RFC 8429, and needs MD4, which hashlib often lacks",
    24: "rc4-hmac-exp is export-grade RC4, withdrawn by RFC 6649",
    25: "camellia128-cts-cmac is not implemented by this client",
    26: "camellia256-cts-cmac is not implemented by this client",
}


class IntegrityError(ValueError):
    """A ciphertext failed its integrity check: wrong key, wrong usage, or tampered."""


class UnsupportedEnctypeError(ValueError):
    """The KDC or the credential cache used an enctype this client will not do."""


def nfold(data: bytes, size: int) -> bytes:
    """RFC 3961 section 5.1: stretch or shrink ``data`` to ``size`` bytes.

    The input is repeated, each copy rotated a further 13 bits right, until
    the total is a common multiple of both lengths; that string is then cut
    into ``size``-byte pieces and summed with ones'-complement addition, so
    every input bit influences every output byte.
    """
    inbits = len(data) * 8
    value = int.from_bytes(data, "big")
    mask = (1 << inbits) - 1
    total_len = len(data) * size // math.gcd(len(data), size)
    stream = bytearray()
    for index in range(total_len // len(data)):
        shift = (13 * index) % inbits
        rotated = ((value >> shift) | (value << (inbits - shift))) & mask
        stream += rotated.to_bytes(len(data), "big")
    outbits = size * 8
    outmask = (1 << outbits) - 1
    acc = 0
    for offset in range(0, total_len, size):
        acc += int.from_bytes(stream[offset : offset + size], "big")
    # The end-around carry of ones'-complement addition, folded until none is left.
    while acc > outmask:
        acc = (acc & outmask) + (acc >> outbits)
    return acc.to_bytes(size, "big")


def _xor(left: bytes, right: bytes) -> bytes:
    """Bytewise XOR, as long as the shorter input (the CTS tail is short)."""
    return bytes(a ^ b for a, b in zip(left, right, strict=False))


def cts_encrypt(key: bytes, data: bytes, iv: bytes = bytes(BLOCK_SIZE)) -> bytes:
    """AES-CBC with ciphertext stealing, the RFC 3962 variant (CBC-CS3).

    The last two blocks are always swapped, even when the input is a whole
    number of blocks, and the final block is truncated to the input length.
    A single block is plain CBC. Kerberos never encrypts less than a block,
    because the confounder alone is one.
    """
    if len(data) < BLOCK_SIZE:
        raise ValueError(f"CTS needs at least one block, got {len(data)} bytes")
    if len(data) == BLOCK_SIZE:
        return cbc_encrypt(key, data, iv, pad=False)
    tail = len(data) % BLOCK_SIZE or BLOCK_SIZE
    # Zero-pad the last block and chain the lot as ordinary CBC; stealing is
    # then only a matter of which bytes of the last two blocks are sent.
    chained = cbc_encrypt(key, data + bytes(BLOCK_SIZE - tail), iv, pad=False)
    head = chained[: -2 * BLOCK_SIZE]
    penultimate = chained[-2 * BLOCK_SIZE : -BLOCK_SIZE]
    return head + chained[-BLOCK_SIZE:] + penultimate[:tail]


def cts_decrypt(key: bytes, data: bytes, iv: bytes = bytes(BLOCK_SIZE)) -> bytes:
    """The inverse of :func:`cts_encrypt`."""
    if len(data) < BLOCK_SIZE:
        raise ValueError(f"CTS needs at least one block, got {len(data)} bytes")
    if len(data) == BLOCK_SIZE:
        return cbc_decrypt(key, data, iv, pad=False)
    tail = len(data) % BLOCK_SIZE or BLOCK_SIZE
    cut = len(data) - BLOCK_SIZE - tail
    # Everything before the last two (swapped) blocks is ordinary CBC.
    body = data[:cut]
    out = cbc_decrypt(key, body, iv, pad=False) if body else b""
    previous = body[-BLOCK_SIZE:] if body else iv
    cipher = AES(key)
    decrypted = cipher.decrypt_block(data[cut : cut + BLOCK_SIZE])
    # The stolen bytes of the penultimate ciphertext block are the tail of
    # ``decrypted`` - the last plaintext block was zero-padded before chaining.
    full = data[cut + BLOCK_SIZE :] + decrypted[tail:]
    return out + _xor(cipher.decrypt_block(full), previous) + _xor(decrypted[:tail], full)


def _usage_constant(usage: int, kind: int) -> bytes:
    """The RFC 3961 well-known constant: the usage number and a purpose byte."""
    return struct.pack(">IB", usage, kind)


#: The purpose bytes: checksum key, encryption key, integrity key.
_KC, _KE, _KI = 0x99, 0xAA, 0x55


@dataclass(frozen=True, slots=True)
class Enctype:
    """One AES enctype: its number, key size and integrity parameters.

    ``sha2`` selects the RFC 8009 construction; otherwise RFC 3962. The
    instance is stateless - keys are passed to each call - so the four
    module-level instances are all there ever need to be.
    """

    #: The IANA enctype number the KDC and tickets name it by (17-20).
    number: int
    #: The IANA name, also the PBKDF2 salt prefix in RFC 8009.
    name: str
    #: Key length in bytes: 16 for AES-128, 32 for AES-256.
    key_size: int
    #: Bytes of the truncated HMAC appended to each ciphertext.
    mac_size: int
    #: The matching keyed checksum type (RFC 3962 / RFC 8009 numbers).
    checksum_type: int
    #: RFC 8009 (SHA-2 KDF, MAC over ciphertext) rather than RFC 3962.
    sha2: bool
    #: The ``hashlib`` name used for HMAC and, under RFC 8009, PBKDF2.
    digest: str

    # -- key derivation ---------------------------------------------------

    def _dr(self, key: bytes, constant: bytes, length: int) -> bytes:
        """RFC 3961 ``DR``: encrypt the n-folded constant, repeatedly, to ``length``."""
        cipher = AES(key)
        block = nfold(constant, BLOCK_SIZE)
        out = b""
        while len(out) < length:
            block = cipher.encrypt_block(block)
            out += block
        return out[:length]

    def _kdf(self, key: bytes, label: bytes, bits: int, context: bytes = b"") -> bytes:
        """RFC 8009 ``KDF-HMAC-SHA2``: one round of SP 800-108 counter mode.

        One round is always enough: SHA-256 and SHA-384 produce at least as
        many bits as any key, MAC or PRF output of their enctype needs.
        """
        message = struct.pack(">I", 1) + label + b"\x00" + context + struct.pack(">I", bits)
        return hmac.new(key, message, self.digest).digest()[: bits // 8]

    def derive(self, key: bytes, usage: int, kind: int) -> bytes:
        """The key for ``usage`` and purpose ``kind`` (checksum, encryption, integrity)."""
        constant = _usage_constant(usage, kind)
        if not self.sha2:
            return self._dr(key, constant, self.key_size)
        bits = self.key_size * 8 if kind == _KE else self.mac_size * 8
        return self._kdf(key, constant, bits)

    def string_to_key(self, password: bytes, salt: bytes, iterations: int | None = None) -> bytes:
        """The long-term key for a password: PBKDF2, then a derivation.

        MIT's default salt is the realm followed by the principal's name
        components, concatenated. The iteration counts are the RFCs' defaults.
        """
        if self.sha2:
            count = 32768 if iterations is None else iterations
            salted = self.name.encode() + b"\x00" + salt
            seed = hashlib.pbkdf2_hmac(self.digest, password, salted, count, self.key_size)
            return self._kdf(seed, b"kerberos", self.key_size * 8)
        count = 4096 if iterations is None else iterations
        seed = hashlib.pbkdf2_hmac("sha1", password, salt, count, self.key_size)
        return self._dr(seed, b"kerberos", self.key_size)

    # -- encryption and integrity -----------------------------------------

    def _check_key(self, key: bytes) -> None:
        """Refuse a key of the wrong length before it is derived from."""
        if len(key) != self.key_size:
            raise ValueError(f"{self.name} needs a {self.key_size}-byte key, got {len(key)}")

    def encrypt(
        self, key: bytes, usage: int, plaintext: bytes, confounder: bytes | None = None
    ) -> bytes:
        """Encrypt ``plaintext`` for ``usage``: confounder, CTS, then the MAC.

        ``confounder`` is for reproducing published test vectors; leave it
        out and a fresh random one is used, which is what makes two
        encryptions of the same message unlinkable.
        """
        self._check_key(key)
        conf = os.urandom(BLOCK_SIZE) if confounder is None else confounder
        ke = self.derive(key, usage, _KE)
        ki = self.derive(key, usage, _KI)
        ciphertext = cts_encrypt(ke, conf + plaintext)
        # RFC 8009 MACs the ciphertext (with the zero IV in front); RFC 3962
        # MACs the plaintext. Getting this backwards fails only against a KDC.
        signed = bytes(BLOCK_SIZE) + ciphertext if self.sha2 else conf + plaintext
        mac = hmac.new(ki, signed, self.digest).digest()[: self.mac_size]
        return ciphertext + mac

    def decrypt(self, key: bytes, usage: int, ciphertext: bytes) -> bytes:
        """Check and decrypt; raises :class:`IntegrityError` on any mismatch."""
        self._check_key(key)
        if len(ciphertext) < BLOCK_SIZE + self.mac_size:
            raise IntegrityError(f"{self.name} ciphertext of {len(ciphertext)} bytes is too short")
        body, mac = ciphertext[: -self.mac_size], ciphertext[-self.mac_size :]
        ke = self.derive(key, usage, _KE)
        ki = self.derive(key, usage, _KI)
        plain = cts_decrypt(ke, body)
        signed = bytes(BLOCK_SIZE) + body if self.sha2 else plain
        expected = hmac.new(ki, signed, self.digest).digest()[: self.mac_size]
        if not hmac.compare_digest(mac, expected):
            raise IntegrityError(f"{self.name} integrity check failed (key usage {usage})")
        return plain[BLOCK_SIZE:]

    def checksum(self, key: bytes, usage: int, data: bytes) -> bytes:
        """The keyed checksum of ``data`` for ``usage`` (``Kc``, truncated HMAC)."""
        self._check_key(key)
        kc = self.derive(key, usage, _KC)
        return hmac.new(kc, data, self.digest).digest()[: self.mac_size]

    def prf(self, key: bytes, data: bytes) -> bytes:
        """The RFC 8009 pseudo-random function, for the SHA-2 enctypes.

        Nothing in an AP-REQ needs it; it is here because RFC 8009 publishes
        vectors for it, and they pin the KDF from a second direction. The
        RFC 3962 PRF has no published vector, so it is not implemented
        rather than implemented untested.
        """
        if not self.sha2:
            raise NotImplementedError(f"the {self.name} PRF is not implemented")
        return self._kdf(key, b"prf", len(hashlib.new(self.digest).digest()) * 8, data)

    def random_key(self) -> bytes:
        """A fresh key; for AES, random-to-key is the identity."""
        return os.urandom(self.key_size)


_ENCTYPES = {
    e.number: e
    for e in (
        Enctype(AES128_CTS_HMAC_SHA1_96, "aes128-cts-hmac-sha1-96", 16, 12, 15, False, "sha1"),
        Enctype(AES256_CTS_HMAC_SHA1_96, "aes256-cts-hmac-sha1-96", 32, 12, 16, False, "sha1"),
        Enctype(
            AES128_CTS_HMAC_SHA256_128, "aes128-cts-hmac-sha256-128", 16, 16, 19, True, "sha256"
        ),
        Enctype(
            AES256_CTS_HMAC_SHA384_192, "aes256-cts-hmac-sha384-192", 32, 24, 20, True, "sha384"
        ),
    )
}

#: The enctype numbers this module implements, strongest first.
SUPPORTED_ENCTYPES: tuple[int, ...] = (
    AES256_CTS_HMAC_SHA384_192,
    AES256_CTS_HMAC_SHA1_96,
    AES128_CTS_HMAC_SHA256_128,
    AES128_CTS_HMAC_SHA1_96,
)


def get_enctype(number: int) -> Enctype:
    """The :class:`Enctype` for ``number``, or a clear refusal."""
    found = _ENCTYPES.get(number)
    if found is not None:
        return found
    reason = _REFUSED.get(number, "it is not one this client implements")
    raise UnsupportedEnctypeError(
        f"Kerberos enctype {number} is not supported: {reason}; "
        "ask for an AES key (aes256-cts-hmac-sha1-96 or aes256-cts-hmac-sha384-192)"
    )
