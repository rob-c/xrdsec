"""A user certificate and key, presented without a combined file."""

from __future__ import annotations

import os
import ssl
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from xrdcore.errors import CredentialError, InsecureCredentialError
from xrdsec import usercred
from xrdsec.testing.pki import PKI
from xrdsec.x509 import verify_issued

from tests._handshake import handshake


def encrypted_key(pki: PKI, tmp_path: Path, password: bytes = b"s3cret") -> Path:
    pem = pki.user_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    path = tmp_path / "encrypted.pem"
    path.write_bytes(pem)
    os.chmod(path, 0o600)
    return path


def test_wanted():
    assert usercred.wanted("c", "k")
    assert not usercred.wanted("c", "k", "proxy")
    assert not usercred.wanted("c", None)


def test_encrypted():
    assert usercred.encrypted(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert usercred.encrypted(b"Proc-Type: 4,ENCRYPTED")
    assert not usercred.encrypted(b"-----BEGIN RSA PRIVATE KEY-----")


def test_pass_phrase():
    assert usercred.pass_phrase("k", lambda: "abc") == b"abc"
    assert usercred.pass_phrase("k", lambda: b"abc") == b"abc"
    for password in (None, lambda: None, lambda: ""):
        with pytest.raises(CredentialError, match="no pass phrase"):
            usercred.pass_phrase("k", password)


def test_present_authenticates_with_the_pair(pki):
    ctx = ssl.create_default_context(cafile=str(pki.ca_file))
    usercred.present(ctx, str(pki.user_cert_path), str(pki.user_key_path))
    handshake(ctx, pki.server_context())


def test_present_decrypts_an_encrypted_key(pki, tmp_path):
    key = encrypted_key(pki, tmp_path)
    ctx = ssl.create_default_context(cafile=str(pki.ca_file))
    usercred.present(ctx, str(pki.user_cert_path), str(key), password=lambda: "s3cret")
    handshake(ctx, pki.server_context())
    with pytest.raises(CredentialError):
        usercred.present(ctx, str(pki.user_cert_path), str(key), password=lambda: "wrong")


def test_present_refuses_a_shared_key(pki, tmp_path):
    shared = tmp_path / "userkey.pem"  # a copy: the session's PKI stays as minted
    shared.write_bytes(pki.user_key_path.read_bytes())
    os.chmod(shared, 0o644)
    ctx = ssl.create_default_context()
    with pytest.raises(InsecureCredentialError):
        usercred.present(ctx, str(pki.user_cert_path), str(shared))


def test_present_names_both_files_when_they_do_not_match(pki):
    ctx = ssl.create_default_context()
    with pytest.raises(CredentialError, match="with the key"):
        usercred.present(ctx, str(pki.host_cert_path), str(pki.user_key_path))


def test_without_dev_fd_the_checked_file_is_named(pki, monkeypatch):
    monkeypatch.setattr(usercred, "_FD_DIR", "/nonexistent-fd-dir")
    ctx = ssl.create_default_context(cafile=str(pki.ca_file))
    usercred.present(ctx, str(pki.user_cert_path), str(pki.user_key_path))


def test_a_reader_that_goes_away_stops_the_feeder():
    readable, writable = os.pipe()
    os.close(readable)
    usercred._feed(writable, b"x" * 100000)  # EPIPE is swallowed, the fd closed


def test_memory_proxy(pki, tmp_path):
    user = pki.user_credential.certificate
    proxy = usercred.memory_proxy(str(pki.user_cert_path), str(pki.user_key_path))
    assert proxy.certificate.issuer == user.subject
    assert verify_issued(proxy.certificate, user)
    key = encrypted_key(pki, tmp_path)
    proxy = usercred.memory_proxy(str(pki.user_cert_path), str(key), password=lambda: "s3cret")
    assert proxy.chain[1] == user


def _supplied(supplier: Callable[[], bytes] | None) -> bytes:
    """What a pass-phrase supplier gives, where the test expects one."""
    assert supplier is not None
    return supplier()


def test_password_supplier_and_memory_credentials(pki):
    assert usercred.password_supplier(None, "k") is None
    assert _supplied(usercred.password_supplier("abc", "k")) == b"abc"
    assert _supplied(usercred.password_supplier(lambda: b"abc", "k")) == b"abc"
    with pytest.raises(CredentialError, match="pass phrase is empty"):
        _supplied(usercred.password_supplier(lambda: "", "k"))
    ctx = ssl.create_default_context(cafile=str(pki.ca_file))
    usercred.load_memory(ctx, pki.credential().to_pem())
    handshake(ctx, pki.server_context())


def test_memory_credentials_without_dev_fd_use_a_private_directory(pki, monkeypatch):
    monkeypatch.setattr(usercred, "_FD_DIR", "/nonexistent-fd-dir")
    ctx = ssl.create_default_context(cafile=str(pki.ca_file))
    usercred.load_memory(ctx, pki.credential().to_pem())
    handshake(ctx, pki.server_context())


def test_memory_proxy_needs_a_certificate(pki, tmp_path):
    empty = tmp_path / "empty.pem"
    empty.write_text("")
    with pytest.raises(ValueError, match="no certificate"):
        usercred.memory_proxy(str(empty), str(pki.user_key_path))
    with pytest.raises(FileNotFoundError):
        usercred.memory_proxy(str(pki.user_cert_path), str(tmp_path / "missing"))
