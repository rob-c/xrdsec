"""ECDSA over NIST P-256 with SHA-256, as integers and SEC1 points.

xgfalclient's SSH layer (``ecdsa-sha2-nistp256`` keys and ECDH) and its key
file readers work with the curve as numbers: a private scalar ``d``, a public
point ``(x, y)`` and a signature ``(r, s)``. This module keeps that interface
while curve arithmetic, nonce generation and verification are done by
``cryptography``, in constant time and with deterministic RFC 6979 nonces -
the two things a hand-written implementation most often gets wrong.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

__all__ = ["G", "N", "P", "decode_point", "encode_point", "public_key", "sign", "verify"]

# The curve's field prime, group order and base point (SEC 2, ``secp256r1``),
# for callers that range-check scalars or points before using them.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def encode_point(point: tuple[int, int]) -> bytes:
    """Return the SEC1 uncompressed encoding."""
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def decode_point(data: bytes) -> tuple[int, int]:
    """Parse an uncompressed point, rejecting values outside P-256."""
    if len(data) != 65 or data[0] != 4:
        raise ValueError("expected an uncompressed P-256 point")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)
    except ValueError as exc:
        raise ValueError("point is not on P-256") from exc
    numbers = key.public_numbers()
    return numbers.x, numbers.y


def _private(d: int) -> ec.EllipticCurvePrivateKey:
    """The library key for scalar ``d``, refusing 0 and anything ``>= N``."""
    if not 0 < d < N:
        raise ValueError("private scalar out of range")
    return ec.derive_private_key(d, ec.SECP256R1())


def public_key(d: int) -> tuple[int, int]:
    """The public point ``d * G`` for private scalar ``d``."""
    numbers = _private(d).public_key().public_numbers()
    return numbers.x, numbers.y


def sign(d: int, message: bytes) -> tuple[int, int]:
    """Return a deterministic RFC 6979 ECDSA-SHA256 signature."""
    signature = _private(d).sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return utils.decode_dss_signature(signature)


def verify(public: tuple[int, int], message: bytes, r: int, s: int) -> bool:
    """Whether ``(r, s)`` is a valid signature of ``message`` by ``public``.

    ``r`` and ``s`` outside ``[1, N-1]`` are rejected before the library
    sees them (FIPS 186-4 requires it, and it is cheaper than encoding them);
    a point not on the curve is simply an invalid signature, not an error.
    """
    if not (0 < r < N and 0 < s < N):
        return False
    try:
        key = ec.EllipticCurvePublicNumbers(*public, ec.SECP256R1()).public_key()
        key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True
