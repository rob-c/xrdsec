"""AES as the XRootD protocols use it: CBC with PKCS#7 for GSI, raw blocks, CTR.

GSI encrypts its handshake buckets, and ``kXR_sigver`` its signatures, with
AES-CBC under the Diffie-Hellman session key, padded PKCS#7 the way
OpenSSL's ``EVP_*`` defaults do; :func:`cbc_encrypt` / :func:`cbc_decrypt`
are that, byte for byte. The zero IV default is not a shortcut: it is what an
unsigned-DH XrdSecgsi peer uses and expects (the IV-bearing shape prepends a
random IV instead, and callers pass it). Kerberos (:mod:`.rfc3961`) needs
single-block AES for its own CTS mode and key derivation, and xgfalclient's
SSH transport needs AES-CTR.

All of it is ``cryptography`` underneath, so the block cipher runs in
constant-time C (AES-NI where available) instead of table-driven Python; this
module only fixes the shapes and the error messages. Every error is a
``ValueError``, which callers treat as "this ciphertext is wrong" - never as
a reason to retry with different parameters.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ["AES", "BLOCK_SIZE", "CTR", "cbc_decrypt", "cbc_encrypt", "pkcs7_pad", "pkcs7_unpad"]

#: The AES block size in bytes (also the IV size for CBC and CTR).
BLOCK_SIZE = 16


class AES:
    """Single-block AES, for the protocols that build their own modes on it.

    RFC 3961 key derivation and the CTS tail are the users; anything that is
    plain CBC or CTR uses :func:`cbc_encrypt` / :class:`CTR`, which chain in C.
    """

    __slots__ = ("_cipher", "key_size")

    def __init__(self, key: bytes) -> None:
        """Key the cipher; ``key`` must be 16, 24 or 32 bytes (AES-128/192/256)."""
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        # ECB over exactly one block is the raw block permutation, which is
        # what the callers' own modes need; it is never used on longer input.
        self._cipher = Cipher(algorithms.AES(key), modes.ECB())
        self.key_size = len(key)

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt exactly one 16-byte block; any other length is a ``ValueError``."""
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"AES block must be {BLOCK_SIZE} bytes, got {len(block)}")
        return self._cipher.encryptor().update(block)

    def decrypt_block(self, block: bytes) -> bytes:
        """Decrypt exactly one 16-byte block; any other length is a ``ValueError``."""
        if len(block) != BLOCK_SIZE:
            raise ValueError(f"AES block must be {BLOCK_SIZE} bytes, got {len(block)}")
        return self._cipher.decryptor().update(block)

    def __repr__(self) -> str:
        """Key size only: a repr must never leak a session key into a log."""
        return f"AES(bits={self.key_size * 8}, key=<redacted>)"


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Pad ``data`` to a whole number of blocks (RFC 5652 section 6.3).

    Always adds 1 to ``block_size`` bytes, so an already-aligned input gains a
    full block - which is what makes the padding unambiguous to remove.
    """
    context = padding.PKCS7(block_size * 8).padder()
    return context.update(data) + context.finalize()


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Strip PKCS#7 padding, refusing anything that is not well-formed padding.

    The check is ``cryptography``'s, which inspects the padding bytes in
    constant time. Both failure messages are deliberately generic, and both
    are ``ValueError``: telling a peer *which* way its padding was wrong is
    the oracle a padding-oracle attack needs.
    """
    if not data or len(data) % block_size:
        raise ValueError("PKCS#7 input is not a whole number of blocks")
    context = padding.PKCS7(block_size * 8).unpadder()
    try:
        return context.update(data) + context.finalize()
    except ValueError as exc:
        raise ValueError("PKCS#7 padding is corrupt") from exc


def cbc_encrypt(
    key: bytes, data: bytes, iv: bytes = bytes(BLOCK_SIZE), *, pad: bool = True
) -> bytes:
    """AES-CBC encrypt ``data`` under ``key`` (16, 24 or 32 bytes).

    ``pad=False`` is for input already block-aligned by the protocol, such as
    a SHA-256 digest that must encrypt to exactly two blocks. The IV is not
    included in the result; callers that send one prepend it themselves.
    """
    if len(iv) != BLOCK_SIZE:
        raise ValueError("AES IV must be 16 bytes")
    plain = pkcs7_pad(data) if pad else data
    if len(plain) % BLOCK_SIZE:
        raise ValueError("unpadded CBC input must be a whole number of blocks")
    context = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return context.update(plain) + context.finalize()


def cbc_decrypt(
    key: bytes, data: bytes, iv: bytes = bytes(BLOCK_SIZE), *, pad: bool = True
) -> bytes:
    """AES-CBC decrypt ``data``; the inverse of :func:`cbc_encrypt` with the same options.

    Ragged or empty ciphertext and bad padding are ``ValueError``. CBC has no
    integrity of its own: a successful decrypt only means the padding looked
    right, so callers still check what they decrypted (GSI parses buckets,
    ``kXR_sigver`` compares a digest).
    """
    if len(iv) != BLOCK_SIZE:
        raise ValueError("AES IV must be 16 bytes")
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("CBC input must be a whole number of blocks")
    context = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plain = context.update(data) + context.finalize()
    return pkcs7_unpad(plain) if pad else plain


class CTR:
    """AES-CTR as a stream: successive updates continue the keystream, partial blocks included.

    Used by xgfalclient's SSH transport (``aes*-ctr``).
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        """Start the keystream at counter block ``iv`` (16 bytes, big-endian counter)."""
        if len(iv) != 16:
            raise ValueError("the CTR counter block is 16 bytes")
        self._context = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    def update(self, data: bytes | bytearray | memoryview) -> bytes:
        """Encrypt (or, identically, decrypt) the next ``len(data)`` bytes of the stream."""
        return self._context.update(data)
