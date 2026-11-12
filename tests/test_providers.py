"""The named token providers, and the precedence that always lets the environment win."""

from __future__ import annotations

import pytest

from xrdsec import providers


def test_every_profile_is_an_https_issuer_with_a_name():
    for one in providers.PROVIDERS.values():
        assert one.issuer.startswith("https://"), one.name
        assert one.name == one.name.lower()
        assert one.scope


def test_the_profiles_are_the_ones_the_wlcg_lists():
    """Probed 11 Nov 2026: these answered their discovery document with every grant."""
    assert {"lhcb", "atlas", "cms", "alice", "wlcg", "cern", "egi", "dune", "fermilab"} <= set(
        providers.names()
    )
    assert providers.PROVIDERS["lhcb"].issuer == "https://lhcb-auth.cern.ch/"
    assert providers.PROVIDERS["wlcg"].storage is True  # it advertises storage.* scopes


def test_every_profile_asks_only_for_scopes_its_issuer_advertises():
    """A scope an issuer does not advertise is refused as `invalid_scope`: never suggest one."""
    advertised = {
        "lhcb": {"openid", "profile", "offline_access", "wlcg", "wlcg.groups"},
        "atlas": {"openid", "profile", "offline_access", "wlcg", "wlcg.groups"},
        "cms": {"openid", "profile", "offline_access", "wlcg", "wlcg.groups", "storage.read:/"},
        "alice": {"openid", "profile", "offline_access", "wlcg", "wlcg.groups"},
        "wlcg": {
            "openid",
            "profile",
            "offline_access",
            "wlcg.groups",
            "storage.read:/",
            "storage.modify:/",
            "storage.stage:/",
        },
        "cern": {"openid", "profile", "offline_access"},
        "egi": {"openid", "profile", "offline_access"},
        "dune": {"openid", "profile", "offline_access"},
        "fermilab": {"openid", "profile", "offline_access"},
    }
    for name, known in advertised.items():
        asked = set(providers.PROVIDERS[name].scope.split())
        assert asked <= known, f"{name} asks for {asked - known}"


def test_a_profile_is_named_in_a_list_and_chosen():
    assert providers.names() == sorted(providers.names())
    assert providers.chosen("LHCB").name == "lhcb"  # case is not a thing here
    assert "lhcb" in providers.describe()[0] or any("lhcb" in line for line in providers.describe())


def test_a_mis_typed_profile_is_answered_with_the_one_meant():
    with pytest.raises(providers.ProviderError, match="did you mean 'lhcb'"):
        providers.chosen("lhbc")


def test_a_name_that_resembles_nothing_gets_the_list(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(providers, "names", lambda: ["lhcb", "wlcg"])
    from xrdcore import suggest

    monkeypatch.setattr(suggest, "closest", lambda word, accepted: None)
    with pytest.raises(providers.ProviderError, match="try one of: lhcb, wlcg"):
        providers.chosen("zzzzzz")


def test_a_profile_supplies_the_issuer_and_its_scope():
    said = providers.resolve("lhcb")
    assert said.issuer == "https://lhcb-auth.cern.ch/"
    assert said.scope.startswith("openid")  # what LHCb's IAM advertises
    assert said.audience == providers.AUDIENCE
    assert (said.from_issuer, said.from_scope, said.from_audience) == (
        "profile",
        "profile",
        "default",
    )
    assert said.as_dict()["provider"] == "lhcb"


@pytest.mark.parametrize(
    ("env", "attribute", "expected", "source"),
    [
        ({"WLCG_TOKEN_ISSUER": "https://mine/"}, "issuer", "https://mine/", "env"),
        ({"WLCG_TOKEN_SCOPE": "storage.read:/x"}, "scope", "storage.read:/x", "env"),
        ({"WLCG_TOKEN_AUDIENCE": "https://aud/"}, "audience", "https://aud/", "env"),
    ],
    ids=["issuer", "scope", "audience"],
)
def test_the_environment_overrides_the_profile(
    env: dict[str, str], attribute: str, expected: str, source: str
):
    said = providers.resolve("lhcb", environ=env)
    assert getattr(said, attribute) == expected
    assert getattr(said, f"from_{attribute}") == source


def test_what_was_typed_overrides_the_environment():
    said = providers.resolve(
        "lhcb",
        issuer="https://typed/",
        scope="storage.read:/typed",
        audience="https://typed-aud/",
        environ={
            "WLCG_TOKEN_ISSUER": "https://mine/",
            "WLCG_TOKEN_SCOPE": "x",
            "WLCG_TOKEN_AUDIENCE": "y",
        },
    )
    assert said.issuer == "https://typed/" and said.from_issuer == "flag"
    assert said.scope == "storage.read:/typed" and said.from_scope == "flag"
    assert said.audience == "https://typed-aud/" and said.from_audience == "flag"


def test_no_profile_and_no_environment_leaves_the_issuer_to_the_caller():
    said = providers.resolve(environ={})
    assert said.issuer == "" and said.from_issuer == ""
    assert said.scope == providers.DEFAULT_SCOPE and said.from_scope == "default"
    assert said.as_dict()["provider"] == ""


def test_a_profile_with_an_empty_field_falls_through_to_nothing():
    """A profile only speaks for the fields it has: an empty one is not an answer."""
    empty = providers.Provider(name="x", issuer="", scope="", storage=False, who="nobody")
    assert providers._first("", {}, "WLCG_TOKEN_ISSUER", empty, "") == ("", "")


def test_lhcb_s_diracx_is_a_profile_of_its_own() -> None:
    """LHCb's CEs believe their DiracX, so it has to be nameable."""
    profile = providers.chosen("lhcbdiracx")
    assert profile.issuer == "https://lhcbdiracx.app.cern.ch/"
    assert "vo:lhcb" in profile.scope


def test_the_variables_lhcb_s_own_clients_use_are_honoured() -> None:
    """DIRACX_URL and DIRACX_CLIENT_ID mean what ours mean, so a session set up for
    LHCb's client works here without being configured twice."""
    said = providers.resolve(environ={"DIRACX_URL": "https://lhcbdiracx.app.cern.ch/"})
    assert said.issuer == "https://lhcbdiracx.app.cern.ch/"
    assert said.from_issuer == "env:DIRACX_URL"


def test_our_own_variable_still_wins_over_the_alias() -> None:
    """WLCG_TOKEN_ISSUER is ours: it beats a DIRACX_URL in the same session."""
    said = providers.resolve(
        environ={
            "WLCG_TOKEN_ISSUER": "https://iam.example",
            "DIRACX_URL": "https://lhcbdiracx.app.cern.ch/",
        }
    )
    assert said.issuer == "https://iam.example"


def test_lhcb_s_diracx_publishes_the_client_its_own_front_end_uses() -> None:
    """A device flow needs a client id; the issuer's own web client carries one, and
    it is public - so a person should not have to invent it."""
    profile = providers.chosen("lhcbdiracx")
    assert profile.client_id == "myDIRACClientID"
    # DiracX rejects `openid`; `vo:`/`group:` are its own scope names.
    assert profile.scope == "vo:lhcb"
    assert "openid" not in profile.scope
