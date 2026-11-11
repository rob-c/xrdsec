"""PKCS#12 bundles: the credential in one file, and what it refuses.

Everything here is made with ``cryptography``'s own PKCS#12 writer from the
suite's throwaway grid, and the assertions are about what a caller gets: the
chain in the bundle's order, the RSA view GSI signs with, a pass phrase asked
for only when it is needed, and a refusal that says which of the things that
can be wrong is wrong.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    pkcs12,
)

from xrdcore.errors import CredentialError, InsecureCredentialError
from xrdsec import _p12
from xrdsec.proxies import create_proxy, describe_proxy, load_p12
from xrdsec.rsa import RSAPrivateKey
from xrdsec.testing.proxygrid import Grid, build_grid, certificate, key


@pytest.fixture
def grid(tmp_path: Path) -> Grid:
    return build_grid(tmp_path / "grid")


def bundle(
    grid: Grid,
    path: Path,
    *,
    phrase: bytes | None = b"phrase",
    private: Any = None,
    subject_certificate: Any = None,
    extras: Any = None,
) -> Path:
    """A PKCS#12 file ``0600``, as a certificate portal would hand one out."""
    encryption = NoEncryption() if phrase is None else BestAvailableEncryption(phrase)
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"Jane Doe",
            key(2) if private is None else private,
            grid.user if subject_certificate is None else subject_certificate,
            [grid.ca] if extras is None else extras,
            encryption,
        )
    )
    os.chmod(path, 0o600)
    return path


def test_a_bundle_is_the_credential_its_certificate_and_key_describe(
    grid: Grid, tmp_path: Path
) -> None:
    """The RSA view GSI needs, the chain in the bundle's order, and where it came from."""
    credential = load_p12(bundle(grid, tmp_path / "usercred.p12"), password="phrase")
    expected = grid.credential()
    assert credential.identity == expected.identity
    assert [holder.subject for holder in credential.chain] == [
        holder.subject for holder in expected.chain
    ]
    assert isinstance(credential.key, RSAPrivateKey)
    assert credential.path.endswith("usercred.p12")


def test_an_unencrypted_bundle_never_asks_for_a_pass_phrase(grid: Grid, tmp_path: Path) -> None:
    asked: list[int] = []
    load_p12(bundle(grid, tmp_path / "plain.p12", phrase=None), password=lambda: asked.append(1))
    assert asked == []


def test_an_encrypted_bundle_asks_once_and_signs_with_the_answer(
    grid: Grid, tmp_path: Path
) -> None:
    asked: list[int] = []

    def phrase() -> bytes:
        asked.append(1)
        return b"phrase"

    credential = load_p12(bundle(grid, tmp_path / "usercred.p12"), password=phrase)
    assert asked == [1] and credential.identity == grid.credential().identity


def test_a_bundle_that_needs_a_pass_phrase_says_so(grid: Grid, tmp_path: Path) -> None:
    with pytest.raises(CredentialError, match="it is encrypted, so give its pass phrase"):
        load_p12(bundle(grid, tmp_path / "usercred.p12"))


def test_a_wrong_pass_phrase_says_which_it_may_be(grid: Grid, tmp_path: Path) -> None:
    with pytest.raises(CredentialError, match="the pass phrase is wrong"):
        load_p12(bundle(grid, tmp_path / "usercred.p12"), password=b"wrong")


def test_a_prompt_answered_wrongly_says_the_same(grid: Grid, tmp_path: Path) -> None:
    """Asked once, and the answer is used as it is: no prompt loop on a typo."""
    asked: list[int] = []

    def phrase() -> bytes:
        asked.append(1)
        return b"wrong"

    with pytest.raises(CredentialError, match="the pass phrase is wrong"):
        load_p12(bundle(grid, tmp_path / "usercred.p12"), password=phrase)
    assert asked == [1]


def test_bytes_that_are_not_a_bundle_are_refused() -> None:
    with pytest.raises(CredentialError, match="the PKCS#12 bundle will not open"):
        _p12.credential_from_p12(b"not a bundle")


def test_a_bundle_others_can_read_is_refused(grid: Grid, tmp_path: Path) -> None:
    """A bundle holds a private key, so it is held to the proxy file's rules."""
    path = bundle(grid, tmp_path / "usercred.p12")
    os.chmod(path, 0o644)
    with pytest.raises(InsecureCredentialError, match="chmod"):
        load_p12(path, password=b"phrase")


def test_a_bundle_with_no_certificate_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pkcs12, "load_key_and_certificates", lambda data, phrase: (key(2), None, None)
    )
    with pytest.raises(CredentialError, match="no certificate"):
        _p12.credential_from_p12(b"any")


def test_a_bundle_with_no_private_key_is_refused(
    grid: Grid, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        pkcs12, "load_key_and_certificates", lambda data, phrase: (None, grid.user, None)
    )
    with pytest.raises(CredentialError, match="no private key"):
        _p12.credential_from_p12(b"any")


def test_a_bundle_whose_key_is_not_its_certificate_is_refused(
    grid: Grid, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``cryptography`` will not write one, so the refusal is given one to make."""
    path = bundle(grid, tmp_path / "usercred.p12")
    monkeypatch.setattr(
        pkcs12, "load_key_and_certificates", lambda data, phrase: (key(4), grid.user, None)
    )
    with pytest.raises(CredentialError, match="does not belong to the certificate"):
        load_p12(path, password=b"phrase")


def test_a_bundle_of_a_key_gsi_cannot_use_keeps_the_key_as_it_is(
    grid: Grid, tmp_path: Path
) -> None:
    """An EC bundle loads; refusing it is the proxy issuer's job, not this one's."""
    elliptic = ec.generate_private_key(ec.SECP256R1())
    holder = certificate(
        grid.user.subject, grid.ca.subject, elliptic.public_key(), key(1), serial=12
    )
    path = bundle(
        grid, tmp_path / "ec.p12", private=elliptic, subject_certificate=holder, extras=[]
    )
    credential = load_p12(path, password=b"phrase")
    loaded = credential.key
    assert not isinstance(loaded, RSAPrivateKey) and isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert loaded.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == elliptic.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_a_bundle_signs_a_proxy_the_grid_would_accept(grid: Grid, tmp_path: Path) -> None:
    credential = load_p12(bundle(grid, tmp_path / "usercred.p12"), password=b"phrase")
    info = describe_proxy(create_proxy(credential, lifetime=3600))
    assert info.kind == "RFC3820 compliant impersonation proxy"
    assert info.subject.startswith(f"{grid.credential().identity}/CN=")
