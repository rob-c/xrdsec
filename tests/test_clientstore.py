"""Where a client id lives: one file, owner-only, keyed by issuer."""

from __future__ import annotations

import json
import os
import stat

import pytest

from xrdsec import clientstore


def test_the_store_sits_under_the_configuration_directory(tmp_path: pytest.TempPathFactory) -> None:
    """``$XDG_CONFIG_HOME`` decides, as it does for every other tool."""
    env = {"XDG_CONFIG_HOME": str(tmp_path)}
    assert clientstore.path(env) == os.path.join(str(tmp_path), "xrdsec", "token-clients.json")


def test_without_xdg_it_goes_under_the_home_directory(tmp_path: pytest.TempPathFactory) -> None:
    """A session with no XDG setting still has a home."""
    env = {"HOME": str(tmp_path)}
    assert clientstore.path(env).startswith(str(tmp_path))


def test_an_absent_store_remembers_nothing(tmp_path: pytest.TempPathFactory) -> None:
    """Nothing has been registered yet, which is not an error."""
    assert clientstore.read({"HOME": str(tmp_path)}) == {}
    assert clientstore.remembered("https://iam.example", {"HOME": str(tmp_path)}) == ""


def test_a_registered_client_is_remembered_and_read_back(tmp_path: pytest.TempPathFactory) -> None:
    """What was registered is found again, under the issuer it was registered with."""
    env = {"HOME": str(tmp_path)}
    written = clientstore.remember("https://iam.example/", "abc-123", name="xrd-auth", environ=env)
    assert clientstore.remembered("https://iam.example", env) == "abc-123"
    assert stat.S_IMODE(os.stat(written).st_mode) == 0o600


def test_trailing_slashes_are_the_same_issuer(tmp_path: pytest.TempPathFactory) -> None:
    """An issuer's URL may be written with or without its slash."""
    env = {"HOME": str(tmp_path)}
    clientstore.remember("https://iam.example/", "abc", environ=env)
    assert clientstore.remembered("https://iam.example/", env) == "abc"


def test_a_broken_store_reads_as_empty(tmp_path: pytest.TempPathFactory) -> None:
    """A half-written or edited file must not stop the tool."""
    env = {"HOME": str(tmp_path)}
    destination = clientstore.path(env)
    os.makedirs(os.path.dirname(destination))
    with open(destination, "w", encoding="utf-8") as written:
        written.write("{not json")
    assert clientstore.read(env) == {}


def test_a_store_that_is_not_an_object_reads_as_empty(tmp_path: pytest.TempPathFactory) -> None:
    """The file is ours, but a JSON list in it is still not a store."""
    env = {"HOME": str(tmp_path)}
    destination = clientstore.path(env)
    os.makedirs(os.path.dirname(destination))
    with open(destination, "w", encoding="utf-8") as written:
        json.dump(["not", "a", "store"], written)
    assert clientstore.read(env) == {}


def test_an_entry_without_a_client_id_remembers_nothing(tmp_path: pytest.TempPathFactory) -> None:
    """A malformed entry is an entry with no client to use."""
    env = {"HOME": str(tmp_path)}
    destination = clientstore.path(env)
    os.makedirs(os.path.dirname(destination))
    with open(destination, "w", encoding="utf-8") as written:
        json.dump({"https://iam.example": {"client_name": "x"}}, written)
    assert clientstore.remembered("https://iam.example", env) == ""


def test_an_entry_that_is_not_an_object_remembers_nothing(
    tmp_path: pytest.TempPathFactory,
) -> None:
    """Anything else in the file is not a registration."""
    env = {"HOME": str(tmp_path)}
    destination = clientstore.path(env)
    os.makedirs(os.path.dirname(destination))
    with open(destination, "w", encoding="utf-8") as written:
        json.dump({"https://iam.example": "abc"}, written)
    assert clientstore.remembered("https://iam.example", env) == ""


def test_an_empty_client_id_is_refused(tmp_path: pytest.TempPathFactory) -> None:
    """Writing nothing would make the store lie about what it holds."""
    with pytest.raises(ValueError, match="not empty"):
        clientstore.remember("https://iam.example", "", environ={"HOME": str(tmp_path)})


def test_two_issuers_live_side_by_side(tmp_path: pytest.TempPathFactory) -> None:
    """The store is keyed by issuer, so registering twice keeps both."""
    env = {"HOME": str(tmp_path)}
    clientstore.remember("https://a.example", "one", environ=env)
    clientstore.remember("https://b.example", "two", environ=env)
    assert clientstore.remembered("https://a.example", env) == "one"
    assert clientstore.remembered("https://b.example", env) == "two"


def test_a_failed_write_leaves_no_temporary_behind(
    tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A store that cannot be written must not leave a half-file next to it."""
    env = {"HOME": str(tmp_path)}
    directory = os.path.dirname(clientstore.path(env))
    os.makedirs(directory)

    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken)
    with pytest.raises(OSError, match="disk full"):
        clientstore.remember("https://iam.example", "abc", environ=env)
    assert os.listdir(directory) == []
