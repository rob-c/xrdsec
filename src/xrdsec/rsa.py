"""RSA for GSI: the one operation ``cryptography`` will not do, and adapters to it.

Everything ordinary - loading keys (encrypted ones included), PKCS#1 v1.5
signatures over a hash, checking them, recovering what a public key
"decrypts", generating keys - is ``cryptography``'s, and the two classes here
are thin, immutable views over its keys that the rest of the client and
xgfalclient pass around.

What is left by hand is one private-key operation. GSI's proof of possession
(``XrdCryptosslRSA::EncryptPrivate``) is :rfc:`8017` EMSA-PKCS1-v1_5 *with no
DigestInfo* - the raw message inside type-1 padding - and ``cryptography``
only signs a hash it has wrapped in a DigestInfo itself. So
:meth:`RSAPrivateKey.sign` with ``digest=None`` pads and exponentiates here.
Python's ``pow`` is not constant-time, so the exponentiation is *blinded*: the
padded block is multiplied by ``r^e`` for a fresh random ``r`` before the
private exponent is applied and by ``r^-1`` after, which leaves the result
unchanged and makes the timing of the secret-dependent part independent of
the message. It runs once per connection on a random tag.
"""

from __future__ import annotations

import functools
import hmac
import math
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from .der import (
    TAG_BIT_STRING,
    TAG_NULL,
    DERError,
    Element,
    encode,
    encode_integer,
    encode_oid,
    oid_string,
    parse,
    read_integer,
    sequence,
)

__all__ = [
    "RSA_OID",
    "RSAPrivateKey",
    "RSAPublicKey",
    "load_library_key",
    "load_private_key",
    "load_public_key",
    "pem_blocks",
    "private_key_der",
    "private_key_pem",
    "public_key_from_bitstring",
]

#: ``rsaEncryption``, the algorithm identifier a PKCS#8 RSA key carries.
RSA_OID = "1.2.840.113549.1.1.1"

#: The hashes PKCS#1 v1.5 signatures are made and checked with.
_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


def _hash(digest: str) -> hashes.HashAlgorithm:
    """The ``cryptography`` hash called ``digest`` (``"sha256"``, ``"SHA-256"``...).

    SHA-1 is still accepted here, unlike in :mod:`.delegation`: verifying an
    old signature or a server's SHA-1 GSI handshake is not the same as issuing
    something new with it.
    """
    factory = _HASHES.get(digest.lower().replace("-", ""))
    if factory is None:
        raise ValueError(f"unsupported digest {digest!r} for PKCS#1 v1.5")
    return factory()


def pem_blocks(data: bytes | str) -> list[tuple[str, bytes]]:
    """Every ``-----BEGIN X-----`` block in ``data`` as ``(label, DER)``.

    A GSI proxy is one file holding a certificate, a key, and the issuer
    chain, so splitting on labels is how everything downstream starts.
    """
    import base64

    text = data.decode("ascii", "replace") if isinstance(data, bytes) else data
    out: list[tuple[str, bytes]] = []
    label: str | None = None
    body: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if _pem_boundary(line, "BEGIN"):
            label, body = line[11:-5].strip(), []
        elif _pem_boundary(line, "END"):
            decoded = _decoded_pem(label, line[9:-5].strip(), body, base64.b64decode)
            if decoded is not None:
                out.append(decoded)
            label, body = None, []
        elif label is not None:
            body.append(line)
    return out


def _pem_boundary(line: str, kind: str) -> bool:
    """Whether ``line`` is a ``-----BEGIN X-----`` / ``-----END X-----`` marker."""
    return line.startswith(f"-----{kind} ") and line.endswith("-----")


def _decoded_pem(
    label: str | None, end: str, body: list[str], decode: Callable[[str], bytes]
) -> tuple[str, bytes] | None:
    """One finished PEM block as ``(label, DER)``, or ``None`` if it must be skipped.

    A block whose END label does not match its BEGIN, or whose base64 is
    corrupt, is dropped rather than raised, so a damaged trailing certificate
    cannot hide the proxy and key in front of it. ``decode`` is passed in so
    ``base64`` is imported only by :func:`pem_blocks`, on first use.
    """
    if label is None or end != label:
        return None
    try:
        return label, decode("".join(body))
    except ValueError:  # a corrupt block must not lose the good ones
        return None


@functools.lru_cache(maxsize=64)
def _library_public(n: int, e: int) -> _rsa.RSAPublicKey:
    """The ``cryptography`` public key for ``(n, e)``, cached.

    The same few keys - a server's, a CA's - come back on every connection,
    and building and validating the OpenSSL key object is the expensive part.
    """
    return _rsa.RSAPublicNumbers(e, n).public_key()


@functools.lru_cache(maxsize=16)
def _library_private(n: int, e: int, d: int, p: int, q: int) -> _rsa.RSAPrivateKey:
    """The ``cryptography`` key for these numbers, validated once and then reused.

    Keys built from bare ``(n, e, d)`` - an SSH agent's, a test's - get their
    primes back from ``d`` first; OpenSSL needs the CRT form.
    """
    if not (p and q):
        p, q = _rsa.rsa_recover_prime_factors(n, e, d)
    numbers = _rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=_rsa.rsa_crt_dmp1(d, p),
        dmq1=_rsa.rsa_crt_dmq1(d, q),
        iqmp=_rsa.rsa_crt_iqmp(p, q),
        public_numbers=_rsa.RSAPublicNumbers(e, n),
    )
    return numbers.private_key()


@dataclass(frozen=True, slots=True)
class RSAPublicKey:
    """An RSA public key: modulus and public exponent."""

    n: int
    e: int

    @property
    def size(self) -> int:
        """The modulus length in bytes — the size of every signature block."""
        return (self.n.bit_length() + 7) // 8

    def to_cryptography(self) -> _rsa.RSAPublicKey:
        """The same key as a ``cryptography`` object (cached; raises ``ValueError`` if invalid)."""
        return _library_public(self.n, self.e)

    def verify(self, message: bytes, signature: bytes, *, digest: str | None = None) -> bool:
        """True if ``signature`` is this key's PKCS#1 v1.5 signature over ``message``.

        ``digest=None`` is GSI's raw form: ``message`` itself inside the
        padding. Naming a hash checks the ordinary :rfc:`8017` signature.
        """
        if digest is None:
            try:
                return hmac.compare_digest(self.recover(signature), message)
            except ValueError:
                return False
        algorithm = _hash(digest)
        try:
            self.to_cryptography().verify(signature, message, padding.PKCS1v15(), algorithm)
        except (InvalidSignature, ValueError):
            return False
        return True

    def recover(self, block: bytes) -> bytes:
        """What the private key signed into ``block``: the inverse of :meth:`RSAPrivateKey.sign`.

        OpenSSL's ``RSA_public_decrypt`` with PKCS#1 v1.5 padding - the
        "decrypt with the public key" GSI uses to check the peer signed its
        Diffie-Hellman parameters. Raises :class:`ValueError` if the block is
        not a type-1 padded message under this key.
        """
        if len(block) != self.size:
            raise ValueError(f"RSA block of {len(block)} bytes, key is {self.size}")
        try:
            return self.to_cryptography().recover_data_from_signature(
                block, padding.PKCS1v15(), None
            )
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("the RSA block is not PKCS#1 v1.5 signature padding") from exc

    def decrypt_public(self, data: bytes) -> bytes:
        """:meth:`recover` over each key-sized block of ``data``, concatenated.

        ``XrdCryptosslRSA::DecryptPublic``: a message longer than one block
        was signed a block at a time, and comes back the same way.
        """
        if not data or len(data) % self.size:
            raise ValueError(f"{len(data)} bytes is not a whole number of {self.size}-byte blocks")
        return b"".join(
            self.recover(data[at : at + self.size]) for at in range(0, len(data), self.size)
        )

    def der(self) -> bytes:
        """The ``SubjectPublicKeyInfo`` DER - what a certificate or request carries."""
        inner = sequence(encode_integer(self.n), encode_integer(self.e))
        return sequence(
            sequence(encode_oid(RSA_OID), encode(TAG_NULL, b"")),
            encode(TAG_BIT_STRING, b"\x00" + inner),
        )

    def pem(self) -> bytes:
        """``-----BEGIN PUBLIC KEY-----``, byte for byte as ``PEM_write_bio_PUBKEY`` writes it.

        The GSI server compares the key a signed-DH client announces with the
        one in its certificate *as text*, so the layout matters, not only the key.
        """
        import base64
        import textwrap

        body = "\n".join(textwrap.wrap(base64.b64encode(self.der()).decode("ascii"), 64))
        return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n".encode("ascii")

    def __repr__(self) -> str:
        """Size and exponent only; the modulus is long and identifies nothing by eye."""
        return f"RSAPublicKey(bits={self.n.bit_length()}, e={self.e})"


@dataclass(frozen=True, slots=True)
class RSAPrivateKey:
    """An RSA private key. ``p``/``q`` enable the CRT path when present."""

    n: int
    e: int
    d: int
    p: int = 0
    q: int = 0

    @property
    def size(self) -> int:
        """The modulus length in bytes: the size of every signature this key makes."""
        return (self.n.bit_length() + 7) // 8

    @property
    def public(self) -> RSAPublicKey:
        """The matching public key."""
        return RSAPublicKey(self.n, self.e)

    @classmethod
    def from_cryptography(cls, key: _rsa.RSAPrivateKey) -> RSAPrivateKey:
        """The view of a ``cryptography`` RSA key."""
        numbers = key.private_numbers()
        public = numbers.public_numbers
        return cls(n=public.n, e=public.e, d=numbers.d, p=numbers.p, q=numbers.q)

    def to_cryptography(self) -> _rsa.RSAPrivateKey:
        """The same key as a ``cryptography`` object (cached; raises ``ValueError`` if invalid)."""
        return _library_private(self.n, self.e, self.d, self.p, self.q)

    @classmethod
    def generate(cls, bits: int = 2048, *, e: int = 65537) -> RSAPrivateKey:
        """A fresh key pair from ``cryptography`` (OpenSSL's generator).

        ``bits`` must be even and at least 1024: OpenSSL refuses smaller keys,
        and an odd size is never what was meant.
        """
        if bits < 1024 or bits % 2:
            raise ValueError("RSA key size must be an even number of bits, at least 1024")
        return cls.from_cryptography(_rsa.generate_private_key(public_exponent=e, key_size=bits))

    def sign(self, message: bytes, *, digest: str | None = None) -> bytes:
        """PKCS#1 v1.5 signature over ``message``.

        ``digest=None`` signs the message bytes with no DigestInfo wrapper,
        which is what GSI's proof of possession expects - done here, blinded,
        because ``cryptography`` has no such operation. Naming a hash
        (``"sha256"``) gives the ordinary :rfc:`8017` construction, by
        ``cryptography``.
        """
        if digest is not None:
            return self.to_cryptography().sign(message, padding.PKCS1v15(), _hash(digest))
        block = int.from_bytes(_type1_block(message, self.size), "big")
        return self._blinded_power(block).to_bytes(self.size, "big")

    def encrypt_private(self, data: bytes) -> bytes:
        """``XrdCryptosslRSA::EncryptPrivate``: :meth:`sign` a block at a time.

        Each block holds at most ``size - 11`` bytes of ``data``, the most
        PKCS#1 v1.5 padding leaves room for; the signatures are concatenated.
        """
        if not data:
            raise ValueError("nothing to encrypt")
        room = self.size - 11
        return b"".join(self.sign(data[at : at + room]) for at in range(0, len(data), room))

    def _blinded_power(self, value: int) -> int:
        """``value ** d mod n`` computed on ``value * r^e`` and unblinded with ``r^-1``.

        ``(m * r^e)^d = m^d * r`` because ``e*d = 1`` mod the group order, so
        multiplying by ``r^-1`` afterwards leaves exactly ``m^d``; what the
        secret exponent is applied to is uniformly random whatever ``m`` was.
        """
        n = self.n
        r = secrets.randbelow(n - 2) + 2
        while math.gcd(r, n) != 1:  # only if r hit a prime factor of n
            r = secrets.randbelow(n - 2) + 2
        blinded = value * pow(r, self.e, n) % n
        return self._power(blinded) * pow(r, -1, n) % n

    def _power(self, value: int) -> int:
        """``value ** d mod n``, by CRT when the primes are known. Not blinded."""
        if self.p and self.q:
            mp = pow(value % self.p, self.d % (self.p - 1), self.p)
            mq = pow(value % self.q, self.d % (self.q - 1), self.q)
            coefficient = pow(self.q, -1, self.p)
            return (mq + self.q * ((coefficient * (mp - mq)) % self.p)) % self.n
        return pow(value, self.d, self.n)

    def __repr__(self) -> str:
        """Never the private numbers: a key must not reach a log or a traceback."""
        return f"RSAPrivateKey(bits={self.n.bit_length()}, d=<redacted>)"


def _type1_block(message: bytes, size: int) -> bytes:
    """``0x00 0x01 0xFF... 0x00 || message``: EMSA-PKCS1-v1_5 with no DigestInfo."""
    if len(message) + 11 > size:
        raise ValueError(f"message of {len(message)} bytes does not fit a {size}-byte key")
    return b"\x00\x01" + b"\xff" * (size - len(message) - 3) + b"\x00" + message


# ---------------------------------------------------------------------------
# Loading private keys
# ---------------------------------------------------------------------------

#: One whole PEM block, label captured, as OpenSSL writes it.
_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)


def _private_pem_blocks(data: bytes) -> list[tuple[str, bytes]]:
    """Each ``... PRIVATE KEY`` block of ``data`` as ``(label, normalised PEM)``.

    Kept as PEM rather than decoded because the legacy OpenSSL encryption
    (``Proc-Type: 4,ENCRYPTED``) lives in header lines the DER does not carry.
    Lines are stripped so an indented paste still loads.
    """
    out: list[tuple[str, bytes]] = []
    for match in _PEM_BLOCK.finditer(data):
        label = match.group(1).decode("ascii")
        if label.endswith("PRIVATE KEY"):
            lines = [line.strip() for line in match.group(0).splitlines()]
            out.append((label, b"\n".join(lines) + b"\n"))
    return out


def _encrypted(label: str, block: bytes) -> bool:
    """Whether a PEM private key block needs a password to load.

    PKCS#8 says so in its label; OpenSSL's legacy encryption keeps the
    ``RSA PRIVATE KEY`` label and says so in a ``Proc-Type`` header instead.
    """
    return label == "ENCRYPTED PRIVATE KEY" or b"Proc-Type: 4,ENCRYPTED" in block


def load_library_key(
    data: bytes | str,
    label: str | None = None,
    *,
    password: bytes | str | None = None,
) -> PrivateKeyTypes:
    """Any private key ``cryptography`` reads, from PEM or raw DER.

    The first ``... PRIVATE KEY`` block (or the one called ``label``) is used:
    PKCS#1, PKCS#8, SEC1 ``EC PRIVATE KEY``, and their encrypted forms - PKCS#8
    ``ENCRYPTED PRIVATE KEY`` or OpenSSL's legacy ``Proc-Type`` headers - when
    ``password`` is given. Raises :class:`DERError` saying what is wrong; an
    encrypted key without a password says so by name, because the fix is to
    supply one, not to look for a parse error.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    secret = password.encode("utf-8") if isinstance(password, str) else password
    if b"-----BEGIN " not in raw:
        return _load(serialization.load_der_private_key, raw, secret)
    for name, block in _private_pem_blocks(raw):
        if label is not None and name != label:
            continue
        if secret is None and _encrypted(name, block):
            raise DERError("the private key is encrypted; pass its password (password=...)")
        return _load(serialization.load_pem_private_key, block, secret)
    raise DERError("no RSA private key in the PEM given")


def _load(
    loader: Callable[[bytes, bytes | None], PrivateKeyTypes], blob: bytes, secret: bytes | None
) -> PrivateKeyTypes:
    """Run a ``cryptography`` key loader; its failures become a ``DERError`` saying what to do.

    ``cryptography`` reports a missing or unexpected password as ``TypeError``
    and everything else - including a wrong password - as ``ValueError``; the
    messages here name the likely cause for each case.
    """
    try:
        return loader(blob, secret)
    except TypeError as exc:
        # cryptography's way of saying the password and the key disagree.
        if secret is None:
            raise DERError(
                "the private key is encrypted; pass its password (password=...)"
            ) from exc
        raise DERError("a password was given but the private key is not encrypted") from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        if secret is not None:
            raise DERError(f"cannot decrypt the private key (wrong password?): {exc}") from exc
        raise DERError(f"unreadable private key: {exc}") from exc


def load_private_key(
    data: bytes | str,
    label: str | None = None,
    *,
    password: bytes | str | None = None,
) -> RSAPrivateKey:
    """Load an RSA private key from PEM or raw DER, encrypted if ``password`` is given.

    See :func:`load_library_key` for the formats; a key of another type is
    refused by naming it.
    """
    key = load_library_key(data, label, password=password)
    if not isinstance(key, _rsa.RSAPrivateKey):
        kind = type(key).__name__.removesuffix("PrivateKey")  # "EC", "Ed25519", "DSA"
        raise DERError(f"the private key is {kind}, not RSA")
    return RSAPrivateKey.from_cryptography(key)


def load_public_key(data: bytes | str) -> RSAPublicKey:
    """Load an RSA public key from a ``SubjectPublicKeyInfo`` or PKCS#1 body."""
    blocks = pem_blocks(data)
    der = blocks[0][1] if blocks else (data if isinstance(data, bytes) else data.encode())
    element, _ = parse(der)
    fields = element.children()
    if len(fields) == 2 and fields[1].tag == TAG_BIT_STRING:
        algorithm = oid_string(fields[0].children()[0])
        if algorithm != RSA_OID:
            raise DERError(f"public key is {algorithm}, not RSA")
        return public_key_from_bitstring(fields[1])
    if len(fields) == 2:
        return RSAPublicKey(read_integer(fields[0]), read_integer(fields[1]))
    raise DERError("not an RSA public key")


def public_key_from_bitstring(element: Element) -> RSAPublicKey:
    """Decode the ``RSAPublicKey`` inside a ``subjectPublicKey`` BIT STRING."""
    if element.tag != TAG_BIT_STRING or not element.value:
        raise DERError("expected a non-empty BIT STRING")
    if element.value[0]:
        raise DERError(f"subjectPublicKey has {element.value[0]} unused bits")
    inner, _ = parse(element.value[1:])
    fields = inner.children()
    if len(fields) != 2:
        raise DERError(f"RSAPublicKey has {len(fields)} fields, expected 2")
    return RSAPublicKey(read_integer(fields[0]), read_integer(fields[1]))


def private_key_der(key: RSAPrivateKey) -> bytes:
    """PKCS#1 ``RSAPrivateKey`` DER, with the CRT fields OpenSSL expects."""
    from .der import integer, sequence

    if not (key.p and key.q):
        raise ValueError("encoding a private key needs its primes")
    return sequence(
        integer(0),
        integer(key.n),
        integer(key.e),
        integer(key.d),
        integer(key.p),
        integer(key.q),
        integer(key.d % (key.p - 1)),
        integer(key.d % (key.q - 1)),
        integer(pow(key.q, -1, key.p)),
    )


def private_key_pem(key: RSAPrivateKey) -> bytes:
    """``-----BEGIN RSA PRIVATE KEY-----``: the unencrypted form proxies use."""
    import base64
    import textwrap

    body = "\n".join(textwrap.wrap(base64.b64encode(private_key_der(key)).decode("ascii"), 64))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n".encode()
