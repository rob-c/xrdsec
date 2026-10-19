"""A separate user certificate and key, presented without splicing them into one file.

A proxy is a certificate and its key in one file, and everything that
presents one - GSI, HTTPS client authentication - takes that one file. A user
who has only ``usercert.pem`` and ``userkey.pem`` (a service account, a
robot certificate, a CI job) used to have to splice them into one file
first, and a grid tool doing that for them wrote the *private key* into a
temporary file that stayed behind whenever it crashed. This module presents
the pair as it is:

* **HTTPS / ``roots://``.** The certificate goes to OpenSSL by name; the key
  is read here, through the private-file checks of
  :func:`~xrdsec.credentials.read_private_file` (ours, ``0600`` or tighter, a
  regular file), and handed to OpenSSL through a pipe - the bytes that were
  checked are the bytes used, and none of them touch the disk
  (:func:`load_pair`, :func:`present`). A credential that exists only in
  memory - a proxy just made - goes the same way (:func:`load_memory`).
* **GSI.** The key is read the same way and signs a short-lived proxy made
  in memory (:func:`memory_proxy`, :func:`xrdsec.userproxy.user_proxy`) -
  what ``XrdSecgsi``'s ``createpxy`` does, without the file.

Where the pass phrase comes from is the caller's business: ``password`` is
the text, its bytes, or a callable asked at the moment the key turns out to
be encrypted - a terminal prompt, a GUI, a keyring - so nothing sits in a
configuration. Which credential wins (a named proxy, this pair, the default
proxy) is :mod:`xrdsec.discovery`'s; :func:`wanted` is the common rule.
"""

from __future__ import annotations

import contextlib
import os
import threading
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from xrdcore.errors import CredentialError

from .credentials import read_private_file

if TYPE_CHECKING:
    import ssl

    from .x509 import ProxyCredential

__all__ = [
    "KIND",
    "Password",
    "encrypted",
    "load_memory",
    "load_pair",
    "memory_proxy",
    "pass_phrase",
    "password_supplier",
    "present",
    "wanted",
]

#: What supplies a pass phrase: the text, its bytes, or a callable asked only
#: when the key turns out to be encrypted (``None``/``""`` from it declines).
Password = str | bytes | Callable[[], "str | bytes | None"]

#: How the key is named in a refusal.
KIND = "X.509 user key"

#: Where an open descriptor can be named as a file, for OpenSSL to read the
#: key from without it ever being written anywhere.
_FD_DIR = "/dev/fd"


def encrypted(data: bytes) -> bool:
    """Whether a PEM private key is protected by a pass phrase.

    Both spellings: PKCS#8's ``ENCRYPTED PRIVATE KEY`` block, and the
    traditional OpenSSL header ``Proc-Type: 4,ENCRYPTED``.
    """
    return b"ENCRYPTED" in data


def load_pair(
    ctx: ssl.SSLContext,
    certificate: str,
    key: str,
    password: Callable[[], bytes] | None,
) -> None:
    """Load a certificate and its separate key into ``ctx``, the key never touching the disk.

    The key is read through :func:`~xrdsec.credentials.read_private_file`
    (ours, ``0600``, a regular file - :class:`InsecureCredentialError`
    otherwise) and handed to OpenSSL through a pipe, so the bytes checked
    are the bytes used. ``password`` is called only for an encrypted key,
    by OpenSSL, at the moment it needs it; ``None`` there is a
    :class:`~xrdcore.errors.CredentialError` naming the key, as is a
    certificate and key OpenSSL will not pair.
    """
    data = read_private_file(key, kind=KIND)
    locked = encrypted(data)
    if locked and password is None:
        raise CredentialError(
            f"the {KIND} {key} is encrypted and no pass phrase was given: pass key_password="
        )
    try:
        with _as_file(data, key) as keyfile:
            ctx.load_cert_chain(certificate, keyfile, password=password if locked else None)
    except CredentialError:
        raise  # the pass phrase supplier's own refusal, already worded for the user
    except OSError as exc:
        reason = exc.strerror or str(exc)
        raise CredentialError(
            f"cannot use the X.509 certificate {certificate} with the key {key}: {reason}"
        ) from exc


def load_memory(ctx: ssl.SSLContext, pem: bytes) -> None:
    """Load a credential held in memory - chain and key in one PEM - into ``ctx``.

    What a proxy made by :func:`xrdsec.proxies.create_proxy` (or a
    user credential from ``load_credential``) is before anything writes it:
    ``ProxyCredential.to_pem()``. OpenSSL opens the certificate file and the
    key file separately and a pipe can be read only once, so the same PEM
    goes down two pipes (each reader skips the blocks it does not want, as
    for a proxy file). Where ``/dev/fd`` does not exist (no supported
    platform) the PEM is written to a ``0700`` temporary directory, removed
    as soon as OpenSSL has read it. Raises :class:`ssl.SSLError` (an
    :class:`OSError`) for a PEM OpenSSL will not load.
    """
    with _memory_files(pem) as (chain, key):
        ctx.load_cert_chain(chain, key)


@contextlib.contextmanager
def _memory_files(pem: bytes) -> Iterator[tuple[str, str]]:
    """Two names OpenSSL can open for ``pem``: pipes, else files in a private directory."""
    if os.path.isdir(_FD_DIR):
        with _as_file(pem, "") as chain, _as_file(pem, "") as key:
            yield chain, key
        return
    import tempfile

    with tempfile.TemporaryDirectory(prefix="xrd-credential-") as directory:
        names = os.path.join(directory, "chain.pem"), os.path.join(directory, "key.pem")
        for name in names:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with open(descriptor, "wb") as handle:
                handle.write(pem)
        yield names


def password_supplier(
    answer: str | bytes | Callable[[], str | bytes] | None, path: str
) -> Callable[[], bytes] | None:
    """A pass phrase given as text, bytes or a callable, as what :func:`load_pair` takes.

    The public :func:`xrdsec.tls.client_context` accepts all three (a
    callable lets a keyring or a GUI be asked only when the key is
    encrypted). An empty answer is a :class:`~xrdcore.errors.CredentialError`
    naming ``path``: OpenSSL would only say the decryption failed.
    """
    if answer is None:
        return None

    def supply() -> bytes:
        """Ask now - OpenSSL calls this only for an encrypted key."""
        value = answer() if callable(answer) else answer
        if not value:
            raise CredentialError(f"the {KIND} {path} is encrypted and the pass phrase is empty")
        return value.encode("utf-8") if isinstance(value, str) else value

    return supply


@contextlib.contextmanager
def _as_file(data: bytes, path: str) -> Iterator[str]:
    """A name OpenSSL can open to read ``data``: a pipe, or ``path`` itself.

    The pipe is filled by a thread of its own, so a key bigger than the
    pipe's buffer cannot stall the open that drains it. Where descriptors
    cannot be opened by name the checked file is named instead, which costs
    only the guarantee that the bytes OpenSSL reads are the ones checked.
    """
    if not os.path.isdir(_FD_DIR):
        yield path
        return
    readable, writable = os.pipe()
    feeder = threading.Thread(target=_feed, args=(writable, data), daemon=True)
    feeder.start()
    try:
        yield f"{_FD_DIR}/{readable}"
    finally:
        os.close(readable)  # a feeder still writing then fails, and stops
        feeder.join()


def _feed(fd: int, data: bytes) -> None:
    """Write all of ``data`` into the pipe ``fd``, then close it."""
    view = memoryview(data)
    try:
        while view:
            view = view[os.write(fd, view) :]
    except OSError:
        pass  # the reader is gone: what it got is what it gets
    finally:
        os.close(fd)


def wanted(usercert: str | None, userkey: str | None, proxy: str | None = None) -> bool:
    """Whether a pair should be presented: both halves set, and no proxy named."""
    return bool(usercert and userkey and not proxy)


def pass_phrase(path: str, password: Password | None) -> bytes:
    """The pass phrase for the encrypted key at ``path``, from ``password``.

    Raises :class:`~xrdcore.errors.CredentialError` when there is no
    ``password`` or it gives no answer.
    """
    answer = password() if callable(password) else password
    if not answer:
        raise CredentialError(
            f"the {KIND} {path} is encrypted and no pass phrase was given: supply one, "
            "or decrypt the key with openssl"
        )
    return answer.encode("utf-8") if isinstance(answer, str) else answer


def present(
    ctx: ssl.SSLContext, usercert: str, userkey: str, *, password: Password | None = None
) -> None:
    """Load the user certificate and key into ``ctx``, for TLS client authentication.

    :func:`load_pair` with the paths ``~``-expanded and the pass phrase from
    :func:`pass_phrase` - asked for only if the key turns out to be encrypted.
    """
    path = os.path.expanduser(userkey)
    load_pair(ctx, os.path.expanduser(usercert), path, lambda: pass_phrase(path, password))


def memory_proxy(
    usercert: str, userkey: str, *, password: Password | None = None
) -> ProxyCredential:
    """A short-lived proxy for GSI, made in memory from the user certificate and key.

    Raises :class:`FileNotFoundError` for a missing file and
    :class:`~xrdcore.errors.InsecureCredentialError` for a key others may
    read, as reading a proxy does, and :class:`ValueError` for files that are
    not a certificate and its key.
    """
    from .rsa import RSAPrivateKey, load_private_key
    from .userproxy import user_proxy
    from .x509 import load_certificates

    path = os.path.expanduser(userkey)
    data = read_private_file(path, kind=KIND)
    certificate = os.path.expanduser(usercert)
    with open(certificate, "rb") as handle:
        chain = load_certificates(handle.read())
    if not chain:
        raise ValueError(f"no certificate in {certificate}")
    key: RSAPrivateKey = load_private_key(
        data, password=pass_phrase(path, password) if encrypted(data) else None
    )
    return user_proxy(chain, key)
