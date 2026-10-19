"""The credential in use now: providers, lifetime assessment, and the watch over them.

Ported from xrdwms's own tests of these classes (which moved here in 0.4.0),
plus the assessment order and the watch's once-per-expiry and per-consumer
rules, which xrdwms's manager and xrdarc's submission checks rely on.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

import pytest

from xrdsec.lifetime import (
    BearerToken,
    Credential,
    CredentialWatch,
    Lifetime,
    ProxyFile,
    assess,
    chain_expiry,
)


def jwt(claims: dict[str, object]) -> str:
    """An unsigned JWT with ``claims``: enough for the unverified reading done here."""

    def part(data: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


# -- providers ---------------------------------------------------------------------------------


def test_a_proxy_file_by_path_and_by_search(pki):
    found = ProxyFile(str(pki.proxy_path)).current()
    assert found is not None and found.kind == "proxy" and found.expires_at
    assert found.path == str(pki.proxy_path)
    assert "Test User" in (found.identity or "")
    searched = ProxyFile(environ={"X509_USER_PROXY": str(pki.proxy_path)}).current()
    assert searched == found


def test_no_usable_proxy_is_none(tmp_path):
    assert ProxyFile(str(tmp_path / "missing")).current() is None
    broken = tmp_path / "broken"
    broken.write_text("not a proxy")
    broken.chmod(0o600)
    assert ProxyFile(str(broken)).current() is None
    # Nothing named, nothing at the default location (conftest empties it).
    assert ProxyFile(environ={}).current() is None


def test_a_proxy_others_can_read_is_no_proxy(pki):
    pki.proxy_path.chmod(0o644)
    assert ProxyFile(str(pki.proxy_path)).current() is None


def test_of_proxy_takes_the_chains_earliest_expiry(pki):
    proxy = pki.credential()
    seen = Credential.of_proxy(proxy)
    assert seen.expires_at == min(link.not_after for link in proxy.chain)
    assert seen.path == str(pki.proxy_path) and seen.identity == proxy.identity
    assert Credential.of_proxy(proxy, path="/elsewhere").path == "/elsewhere"


def test_a_bearer_token():
    token = jwt({"sub": "alice", "exp": 2_000_000_000})
    found = BearerToken(token).current()
    assert found == Credential("token", None, 2_000_000_000.0, "alice", token=token)
    assert token not in repr(found)
    opaque = BearerToken("opaque-token").current()
    assert opaque is not None and opaque.identity is None and opaque.expires_at is None
    assert BearerToken(environ={}).current() is None


def test_a_token_file_must_be_private(tmp_path):
    token = jwt({"sub": "alice", "exp": 2_000_000_000})
    loose = tmp_path / "tok"
    loose.write_text(token)
    loose.chmod(0o644)
    assert BearerToken(token_file=str(loose), environ={}).current() is None
    loose.chmod(0o600)
    from_file = BearerToken(token_file=str(loose), environ={}).current()
    assert from_file is not None and from_file.path == str(loose)


def test_an_unreadable_token_is_none(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr("xrdsec.credentials.find_bearer_token", broken)
    assert BearerToken().current() is None


# -- lifetime ----------------------------------------------------------------------------------


@dataclass
class Link:
    not_after: float


def test_chain_expiry_is_the_earliest_link():
    assert chain_expiry([Link(30.0), Link(10.0), Link(20.0)]) == 10.0
    with pytest.raises(ValueError):
        chain_expiry([])


def test_remaining_and_generation():
    proxy = Credential("proxy", "/p", 100.0)
    assert proxy.remaining(now=40.0) == 60.0
    assert proxy.remaining(now=140.0) == -40.0
    left = proxy.remaining()
    assert left is not None and left < 0
    assert Credential("token").remaining() is None
    assert proxy.generation == ("/p", 100.0)


@pytest.mark.parametrize(
    ("left", "expected"),
    [
        (None, Lifetime.OK),
        (-5.0, Lifetime.EXPIRED),
        (0.0, Lifetime.EXPIRED),
        (50.0, Lifetime.SHORT),
        (150.0, Lifetime.LOW),
        (500.0, Lifetime.OK),
    ],
)
def test_assess_orders_expired_short_low(left, expected):
    assert assess(left, minimum=100.0, warn_below=200.0) is expected


def test_assess_without_thresholds_only_refuses_the_expired():
    assert assess(1.0) is Lifetime.OK
    assert assess(0.0) is Lifetime.EXPIRED


# -- the watch ---------------------------------------------------------------------------------


class Answers:
    """A provider that answers from a list, then repeats its last answer."""

    def __init__(self, *answers: Credential | None) -> None:
        self.answers = list(answers)

    def current(self) -> Credential | None:
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


def test_the_watch_warns_once_per_expiry():
    old = Credential("proxy", "/p", 100.0)
    watch = CredentialWatch(Answers(old, old, Credential("proxy", "/p", 150.0)))
    first = watch.check("a", warn_below=1000.0, now=50.0)
    assert first is not None and first.warn and first.lifetime is Lifetime.LOW
    assert first.left == 50.0
    again = watch.check("b", warn_below=1000.0, now=60.0)
    assert again is not None and not again.warn  # the same expiry, another consumer
    remade = watch.check("a", warn_below=1000.0, now=70.0)
    assert remade is not None and remade.warn  # a new expiry, still low


def test_a_healthy_credential_is_never_warned_about():
    watch = CredentialWatch(Answers(Credential("token", None, None)))
    seen = watch.check()
    assert seen is not None and not seen.warn and seen.lifetime is Lifetime.OK


def test_renewal_is_per_consumer_and_never_the_first_sighting():
    a, b = Credential("proxy", "/a", 5e12), Credential("proxy", "/b", 5e12)
    watch = CredentialWatch(Answers(a, a, b, b, b))

    def renewed(consumer: str) -> bool:
        seen = watch.check(consumer)
        assert seen is not None
        return seen.renewed

    assert not renewed("ce1")  # first sighting
    assert not renewed("ce2")  # first sighting for this consumer
    assert renewed("ce1")  # a -> b
    assert renewed("ce2")  # its own a -> b
    assert not renewed("ce1")  # b again


def test_no_credential_is_no_sighting():
    assert CredentialWatch(Answers(None)).check() is None


def test_the_watch_keeps_its_provider():
    provider = Answers(None)
    assert CredentialWatch(provider).provider is provider


def test_lifetime_needs_no_x509_stack():
    """Watching only tokens must not import the crypto stack (ProxyFile imports it lazily)."""
    import subprocess
    import sys

    code = (
        "import sys, xrdsec.lifetime as m; m.BearerToken('x').current();"
        "print('cryptography' in sys.modules, 'ssl' in sys.modules)"
    )
    out = subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, text=True)
    assert out.stdout.split() == ["False", "False"]
