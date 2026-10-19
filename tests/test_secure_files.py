"""Credential files: read only when they are this user's alone, checked on the open file."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from xrdcore.errors import CredentialError, InsecureCredentialError
from xrdsec.credentials import MAX_CREDENTIAL_SIZE, read_private_file


def _private(path: Path, data: bytes = b"secret") -> str:
    path.write_bytes(data)
    path.chmod(0o600)
    return str(path)


def test_a_private_file_is_read(tmp_path):
    assert read_private_file(_private(tmp_path / "f"), kind="thing") == b"secret"


@pytest.mark.parametrize("mode", [0o400, 0o600, 0o700])
def test_owner_only_modes_are_fine(tmp_path, mode):
    path = _private(tmp_path / "f")
    os.chmod(path, mode)
    assert read_private_file(path, kind="thing") == b"secret"


@pytest.mark.parametrize(
    ("mode", "word"),
    [
        (0o640, "readable"),
        (0o604, "readable"),
        (0o610, "readable"),
        (0o620, "writable"),
        (0o602, "writable"),
        (0o666, "writable"),
    ],
)
def test_group_or_other_access_is_refused_with_the_fix(tmp_path, mode, word):
    path = _private(tmp_path / "f")
    os.chmod(path, mode)
    with pytest.raises(InsecureCredentialError) as refused:
        read_private_file(path, kind="bearer token file")
    message = str(refused.value)
    assert f"the bearer token file {path} is {word} by group or others" in message
    assert f"(mode {mode:04o})" in message and f"run: chmod 600 {path}" in message
    assert refused.value.path == path
    assert isinstance(refused.value, PermissionError) and isinstance(refused.value, CredentialError)
    assert "secret" not in message


def test_a_file_belonging_to_someone_else_is_refused(tmp_path, monkeypatch):
    """Including for root: a root daemon must not pick up a proxy another user planted."""
    path = _private(tmp_path / "f")
    me = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: me + 1)
    with pytest.raises(InsecureCredentialError, match=f"belongs to uid {me}, not to you"):
        read_private_file(path, kind="X.509 proxy")


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_anything_but_a_regular_file_is_refused_without_blocking(tmp_path, kind):
    path = tmp_path / "f"
    if kind == "directory":
        path.mkdir(mode=0o700)
    else:
        os.mkfifo(path, 0o600)  # would hang a blocking open with no writer
    with pytest.raises(InsecureCredentialError, match="is not a regular file"):
        read_private_file(str(path), kind="SSS keytab")


def test_a_link_is_refused_where_links_are_not_followed(tmp_path):
    link = tmp_path / "link"
    link.symlink_to(_private(tmp_path / "real"))
    assert read_private_file(str(link), kind="thing") == b"secret"
    with pytest.raises(InsecureCredentialError, match="is a symbolic link"):
        read_private_file(str(link), kind="thing", predictable=True)


def test_a_followed_link_is_judged_by_the_file_it_reaches(tmp_path):
    real = _private(tmp_path / "real")
    os.chmod(real, 0o644)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(InsecureCredentialError, match="readable by group or others"):
        read_private_file(str(link), kind="thing")


@pytest.mark.parametrize("predictable", [True, False])
def test_a_missing_file_is_the_ordinary_error(tmp_path, predictable):
    with pytest.raises(FileNotFoundError):
        read_private_file(str(tmp_path / "absent"), kind="thing", predictable=predictable)


def test_an_enormous_file_is_not_read_into_memory(tmp_path):
    path = _private(tmp_path / "big", b"x" * (MAX_CREDENTIAL_SIZE + 1))
    with pytest.raises(CredentialError, match="larger than"):
        read_private_file(path, kind="thing")
    exact = _private(tmp_path / "exact", b"x" * MAX_CREDENTIAL_SIZE)
    assert len(read_private_file(exact, kind="thing")) == MAX_CREDENTIAL_SIZE
