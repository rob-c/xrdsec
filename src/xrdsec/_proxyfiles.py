"""Proxy credentials to and from files, with the private-file rules applied.

The two file operations of :mod:`xrdsec.proxies`, which re-exports
both: :func:`load_credential` reads a proxy file, or a user certificate and its
(possibly encrypted) key, into a :class:`~xrdsec.x509.ProxyCredential`;
:func:`write_proxy` writes one out as ``voms-proxy-init`` would.

Both go through :mod:`xrdsec.credentials`, so the refusals are the same
as for every other credential this package reads: a key file that is not a
regular file, not ours, or readable by group or others is not used, and the
bytes checked are the bytes used. A certificate file on its own is public and
is read plainly. Nothing here prompts: a pass phrase is a value or a callable
the caller supplies (the ``xrd-proxy`` command passes one that asks on the
terminal), and it is only asked for when the key turns out to be encrypted.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from xrdcore.errors import CredentialError

from .credentials import MAX_CREDENTIAL_SIZE, read_private_file, write_private_file
from .delegation import _holds_key
from .der import DERError
from .rsa import RSAPrivateKey, load_library_key
from .x509 import ProxyCredential, load_certificates

__all__ = ["Password", "load_credential", "write_proxy"]

#: A pass phrase, or something to call for one only if it turns out to be
#: needed (a prompt, a keyring lookup); ``None`` from the callable declines.
Password = bytes | str | Callable[[], bytes | str | None] | None

#: How a refusal names each kind of file.
_PROXY_KIND = "X.509 proxy"
_KEY_KIND = "X.509 user key"


def load_credential(
    cert: str | os.PathLike[str],
    key: str | os.PathLike[str] | None = None,
    *,
    password: Password = None,
) -> ProxyCredential:
    """The credential in ``cert`` (and ``key``), ready to sign or present.

    With ``key`` left out (or naming the same file) ``cert`` is a proxy file
    holding its own key - so it is read under the private-file checks. With
    ``key``, ``cert`` is a user certificate (public, read plainly) and
    ``key`` its private key (checked). Both may be symbolic links: these are
    paths the caller named.

    An encrypted key needs ``password``; a callable is called once, only
    then. The key must belong to the first certificate. Raises
    :class:`FileNotFoundError` for a missing file,
    :class:`~xrdcore.errors.InsecureCredentialError` for a key others can
    read or that is not ours, and :class:`~xrdcore.errors.CredentialError`
    for a file with no certificate, an unreadable or wrongly-decrypted key,
    a missing pass phrase, or a key that does not match.
    """
    cert_path = os.fspath(cert)
    key_path = cert_path if key is None else os.fspath(key)
    if key_path == cert_path:
        data = read_private_file(cert_path, kind=_PROXY_KIND)
        key_data = data
    else:
        data = _read_public(cert_path)
        key_data = read_private_file(key_path, kind=_KEY_KIND)
    chain = load_certificates(data)
    if not chain:
        raise CredentialError(f"there is no certificate in {cert_path}")
    loaded = _private_key(key_data, key_path, password)
    if not _holds_key(chain[0], loaded):
        raise CredentialError(
            f"the private key in {key_path} does not belong to the certificate in {cert_path}"
        )
    held: object = loaded
    if isinstance(loaded, rsa.RSAPrivateKey):
        held = RSAPrivateKey.from_cryptography(loaded)  # GSI signs with the RSA view
    return ProxyCredential(chain=tuple(chain), key=held, path=cert_path)


def write_proxy(
    path: str | os.PathLike[str], credential: ProxyCredential, *, follow_symlinks: bool = False
) -> str:
    """Write ``credential`` to ``path`` as a proxy file: atomically, mode ``0600``.

    The contents are :meth:`~xrdsec.x509.ProxyCredential.to_pem`
    (certificate, key, chain). The file is created fresh beside ``path`` and
    renamed into place (see
    :func:`~xrdsec.credentials.write_private_file`), so it is never
    readable by anyone else and a reader never sees half of it. A symbolic
    link at ``path`` is refused unless ``follow_symlinks=True``, which a
    caller passes for a path the user named (``-out``,
    ``$X509_USER_PROXY``) and not for ``/tmp/x509up_u<uid>``. Returns the
    path written.
    """
    return write_private_file(
        path, credential.to_pem(), kind=_PROXY_KIND, predictable=not follow_symlinks
    )


def _read_public(path: str) -> bytes:
    """A certificate file's bytes: public material, so no ownership checks, but bounded."""
    with open(path, "rb") as handle:
        data = handle.read(MAX_CREDENTIAL_SIZE + 1)
    if len(data) > MAX_CREDENTIAL_SIZE:
        raise CredentialError(f"{path} is larger than {MAX_CREDENTIAL_SIZE} bytes")
    return data


def _private_key(data: bytes, path: str, password: Password) -> PrivateKeyTypes:
    """The ``cryptography`` private key in ``data``, decrypted if it has to be.

    ``ENCRYPTED`` anywhere in the PEM is how both encrypted spellings
    announce themselves (PKCS#8's block label, OpenSSL's ``Proc-Type``
    header), and is the rule :mod:`xrdsec.usercred` uses too.
    """
    secret: bytes | str | None = None
    if b"ENCRYPTED" in data:
        secret = password() if callable(password) else password
        if not secret:
            raise CredentialError(
                f"the private key in {path} is encrypted and no pass phrase was given"
            )
    try:
        return load_library_key(data, password=secret)
    except DERError as exc:
        raise CredentialError(f"cannot use the private key in {path}: {exc}") from exc
