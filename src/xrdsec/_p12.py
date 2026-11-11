"""PKCS#12 bundles as credentials: one file, one pass phrase, no ``~/.globus``.

A grid user certificate usually arrives as a PKCS#12 bundle (``.p12``,
``.pfx``): the certificate and its private key in one encrypted file, which
is what a certificate authority's portal hands out and what people keep. This
turns one into the same :class:`~xrdsec.x509.ProxyCredential` that
:func:`xrdsec.proxies.load_credential` makes from a PEM certificate and a
separate key file, so anything that signs - ``xrd-proxy init``,
``arcproxy``, a delegated proxy - needs no ``usercert.pem``/``userkey.pem``
layout and no second file.

The bundle holds a private key, so it is read under the same rules as any
other key (:func:`xrdsec.credentials.read_private_file`): a regular file,
ours, with no group or other permission bits, and the bytes that were checked
are the bytes that are parsed. A pass phrase is a value or a callable, and a
callable is called only when the bundle turns out to need one - an
unencrypted bundle never prompts, and a wrong pass phrase is reported as
such rather than as a corrupt file.

What the bundle carries beyond the user certificate (its issuing CAs, say) is
kept, in the bundle's own order, after the end-entity certificate: it is what
a GSI chain on the wire is made of.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12

from xrdcore.errors import CredentialError

from ._proxyfiles import Password
from .credentials import read_private_file
from .delegation import _holds_key
from .rsa import RSAPrivateKey
from .x509 import ProxyCredential, load_certificates

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
    from cryptography.x509 import Certificate as _BundledCertificate

__all__ = ["credential_from_p12", "load_p12"]

#: How a refusal names the file, as ``read_private_file`` takes it.
_P12_KIND = "PKCS#12 bundle"


def load_p12(
    path: str | os.PathLike[str],
    *,
    password: Password = None,
) -> ProxyCredential:
    """The credential in the PKCS#12 bundle at ``path``.

    ``password`` is the bundle's pass phrase, or a callable that returns it -
    called only if the bundle is encrypted. Raises
    :class:`FileNotFoundError` when there is no file,
    :class:`~xrdcore.errors.InsecureCredentialError` when it is readable by
    others or not ours, and :class:`~xrdcore.errors.CredentialError` for a
    file that is not a bundle this can read, a missing or wrong pass phrase,
    a bundle with no certificate or no private key, or a key that does not
    belong to its certificate.
    """
    name = os.fspath(path)
    return credential_from_p12(
        read_private_file(name, kind=_P12_KIND), path=name, password=password
    )


def credential_from_p12(
    data: bytes,
    *,
    path: str = "",
    password: Password = None,
) -> ProxyCredential:
    """The credential in ``data``, parsed as PKCS#12.

    The in-memory half of :func:`load_p12`, for bytes that did not come from
    a file (a secret store, a test). ``path`` only names the bundle in
    messages and ends up as :attr:`~xrdsec.x509.ProxyCredential.path`.
    """
    key, certificate, extras = _opened(data, path, password)
    chain = load_certificates(certificate.public_bytes(Encoding.PEM))
    for extra in extras or ():
        chain += load_certificates(extra.public_bytes(Encoding.PEM))
    if not _holds_key(chain[0], key):
        raise CredentialError(
            f"the private key in {path or 'the bundle'} does not belong to "
            f"the certificate in {path or 'the bundle'}"
        )
    held: object = key
    if isinstance(key, rsa.RSAPrivateKey):
        held = RSAPrivateKey.from_cryptography(key)  # GSI signs with the RSA view
    return ProxyCredential(chain=tuple(chain), key=held, path=path)


def _opened(
    data: bytes, path: str, password: Password
) -> tuple[PrivateKeyTypes, _BundledCertificate, list[_BundledCertificate] | None]:
    """``data`` opened as a bundle, asking for a pass phrase only if it is refused.

    A callable ``password`` is not called for a bundle that opens without
    one, so an unencrypted bundle never prompts; it is called once, and once
    only, for one that needs a phrase, because a prompt that a wrong answer
    could follow with another prompt is a prompt in a loop.
    """
    phrase: bytes | None = None if callable(password) else _as_bytes(password)
    try:
        return _unpacked(data, phrase)
    except ValueError as refused:
        if not callable(password):
            raise _unreadable(path, phrase, refused) from refused
        phrase = _as_bytes(password())
    try:
        return _unpacked(data, phrase)
    except ValueError as refused:
        raise _unreadable(path, phrase, refused) from refused


def _unpacked(
    data: bytes, phrase: bytes | None
) -> tuple[PrivateKeyTypes, _BundledCertificate, list[_BundledCertificate] | None]:
    """The bundle's key, certificate and extra certificates; ``ValueError`` if it will not open."""
    key, certificate, extras = pkcs12.load_key_and_certificates(data, phrase)
    if certificate is None:
        # A key with no certificate cannot sign a proxy; say so, not "corrupt".
        raise CredentialError("there is no certificate in the PKCS#12 bundle")
    if key is None:
        raise CredentialError("there is no private key in the PKCS#12 bundle")
    return key, certificate, extras


def _unreadable(path: str, phrase: bytes | None, refused: ValueError) -> CredentialError:
    """What to say when a bundle will not open: which one, and why in one line."""
    what = f"{path or 'the PKCS#12 bundle'} will not open"
    if phrase is None:
        return CredentialError(f"{what}: it is encrypted, so give its pass phrase")
    return CredentialError(f"{what}: the pass phrase is wrong, or the file is not PKCS#12")


def _as_bytes(password: Password) -> bytes | None:
    """A pass phrase as the bytes ``cryptography`` wants; ``None`` stays ``None``."""
    if password is None:
        return None
    if isinstance(password, bytes):
        return password
    return str(password).encode("utf-8")
