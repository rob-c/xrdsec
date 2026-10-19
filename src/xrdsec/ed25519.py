"""Ed25519 (RFC 8032) over raw 32-byte keys, backed by cryptography.

The callers are SSH code paths - xgfalclient's ``ssh-ed25519`` host and user
keys - which carry keys and signatures as raw byte strings rather than as
PEM or DER, so this adapter takes and returns exactly that. All the
arithmetic is ``cryptography``'s constant-time implementation.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

__all__ = ["L", "public_key", "sign", "verify"]

#: The order of the Ed25519 base point (RFC 8032 section 5.1). Kept for
#: callers that range-check the ``S`` half of a signature themselves.
L = 2**252 + 27742317777372353535851937790883648493


def public_key(secret: bytes) -> bytes:
    """Return the raw public key for a 32-byte secret seed."""
    return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


def sign(secret: bytes, message: bytes) -> bytes:
    """The 64-byte signature of ``message`` under the 32-byte seed ``secret``."""
    return Ed25519PrivateKey.from_private_bytes(secret).sign(message)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Check a signature, treating malformed keys/signatures as invalid."""
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
