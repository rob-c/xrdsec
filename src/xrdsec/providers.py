"""The token issuers a WLCG person actually meets, as named profiles.

Each entry was taken from the WLCG AuthZ working group's list of production
issuers - the closest thing to a registry that exists, since WLCG has no
central VO-to-issuer service - and then *probed* rather than trusted: on
11 November 2026 every issuer below answered its OpenID Provider
configuration with an issuer id, a token endpoint, a device authorization
endpoint, and the ``client_credentials``, ``device_code`` and
``token-exchange`` grants. The ``scope`` a profile suggests comes from that
issuer's own ``scopes_supported``.

None of this is authoritative. What a *service* accepts is that service's
``/.well-known/wlcg-token``; what an issuer calls itself is its own discovery
document; and **the environment always wins**: ``WLCG_TOKEN_ISSUER``,
``WLCG_TOKEN_AUDIENCE``, ``WLCG_TOKEN_SCOPE`` and ``WLCG_CLIENT_ID`` override
whatever a profile says, and a command-line option overrides both. A profile
is a shorthand for typing a URL, nothing more.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from xrdcore.errors import XrdError

__all__ = [
    "PROVIDERS",
    "Provider",
    "ProviderError",
    "Settings",
    "chosen",
    "describe",
    "names",
    "resolve",
]

#: The audience every WLCG storage service accepts (the Common JWT Profile).
AUDIENCE = "https://wlcg.cern.ch/jwt/v1/any"

#: What to ask for when a profile does not say and the environment does not either.
DEFAULT_SCOPE = "storage.read:/ storage.modify:/ wlcg.groups"


class ProviderError(XrdError):
    """A profile was named that this does not know."""


@dataclass(frozen=True, slots=True)
class Provider:
    """One issuer, as a person would name it."""

    #: The short name: ``xrd-proxy token init --provider lhcb``.
    name: str
    #: The issuer identifier, which is what the token's ``iss`` will carry.
    issuer: str
    #: The scope this issuer's own ``scopes_supported`` makes worth asking for.
    scope: str
    #: Whether the issuer advertises ``storage.*`` scopes (advisory: an IAM may
    #: still grant them, and a service cares about what is *in* the token).
    storage: bool
    #: Who runs it, in a few words.
    who: str


#: The profiles, in the order a person is likely to want them.
PROVIDERS: Mapping[str, Provider] = {
    provider.name: provider
    for provider in (
        Provider(
            name="lhcb",
            issuer="https://lhcb-auth.cern.ch/",
            scope="storage.read:/ storage.modify:/ wlcg.groups",
            storage=False,
            who="LHCb's own IAM at CERN",
        ),
        Provider(
            name="atlas",
            issuer="https://atlas-auth.cern.ch/",
            scope="storage.read:/ storage.modify:/ wlcg.groups",
            storage=False,
            who="ATLAS's own IAM at CERN",
        ),
        Provider(
            name="cms",
            issuer="https://cms-auth.cern.ch/",
            scope="storage.read:/ storage.modify:/ wlcg.groups",
            storage=True,
            who="CMS's own IAM at CERN",
        ),
        Provider(
            name="alice",
            issuer="https://alice-auth.cern.ch/",
            scope="storage.read:/ storage.modify:/ wlcg.groups",
            storage=False,
            who="ALICE's own IAM at CERN",
        ),
        Provider(
            name="wlcg",
            issuer="https://wlcg.cloud.cnaf.infn.it/",
            scope="storage.read:/ storage.modify:/ storage.stage:/ wlcg.groups",
            storage=True,
            who="the WLCG reference IAM (INFN CNAF)",
        ),
        Provider(
            name="cern",
            issuer="https://auth.cern.ch/auth/realms/cern",
            scope="openid profile offline_access",
            storage=False,
            who="CERN single sign-on (Keycloak)",
        ),
        Provider(
            name="egi",
            issuer="https://aai.egi.eu/auth/realms/egi",
            scope="openid profile offline_access",
            storage=False,
            who="EGI Check-in (Keycloak)",
        ),
        Provider(
            name="dune",
            issuer="https://cilogon.org/dune",
            scope="openid profile offline_access",
            storage=False,
            who="CILogon, DUNE tenant",
        ),
        Provider(
            name="fermilab",
            issuer="https://cilogon.org/fermilab",
            scope="openid profile offline_access",
            storage=False,
            who="CILogon, Fermilab tenant",
        ),
    )
}


@dataclass(frozen=True, slots=True)
class Settings:
    """What a command will actually ask an issuer for, once everything is considered."""

    #: The issuer's base URL: nothing, the environment's, or the profile's.
    issuer: str
    #: The audience to request.
    audience: str
    #: The scope to request.
    scope: str
    #: The profile it came from, when one was named.
    provider: str = ""
    #: Where each setting came from, for a report: ``flag``, ``env`` or ``profile``.
    from_issuer: str = ""
    from_audience: str = ""
    from_scope: str = ""

    def as_dict(self) -> dict[str, str]:
        """Plain values, for ``--json`` - including where each one came from."""
        return {
            "issuer": self.issuer,
            "audience": self.audience,
            "scope": self.scope,
            "provider": self.provider,
            "issuer_from": self.from_issuer,
            "audience_from": self.from_audience,
            "scope_from": self.from_scope,
        }


def names() -> list[str]:
    """Every profile name, alphabetically, for a list and for a suggestion."""
    return sorted(PROVIDERS)


def chosen(name: str) -> Provider:
    """The profile called ``name``, or a refusal naming the one that was meant."""
    wanted = name.strip().lower()
    if wanted in PROVIDERS:
        return PROVIDERS[wanted]
    from xrdcore.suggest import closest

    offered = closest(wanted, names())
    hint = f"; did you mean {offered!r}?" if offered else f" (try one of: {', '.join(names())})"
    raise ProviderError(f"no token provider is called {name!r}{hint}")


def describe() -> list[str]:
    """One line per profile, as ``xrd-proxy token providers`` prints them."""
    width = max(len(one.name) for one in PROVIDERS.values())
    return [
        f"{one.name.ljust(width)}  {one.issuer}"
        f"{'' if one.storage else '  (storage.* not advertised)'}  - {one.who}"
        for one in sorted(PROVIDERS.values(), key=lambda entry: entry.name)
    ]


def resolve(
    provider: str = "",
    *,
    issuer: str = "",
    audience: str = "",
    scope: str = "",
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """What to ask for: a command-line value, else the environment, else the profile.

    This is the precedence the whole stack uses - what a person typed, then what
    a session configured, then what a profile suggests - and it is checked here,
    in one place, so no command can quietly disagree with another.
    """
    env = os.environ if environ is None else environ
    profile = chosen(provider) if provider else None
    said_issuer, source_issuer = _first(issuer, env, "WLCG_TOKEN_ISSUER", profile)
    # No profile suggests an audience: every WLCG issuer above accepts the one
    # in the profile, which is what `AUDIENCE` is for.
    said_audience, source_audience = _first(audience, env, "WLCG_TOKEN_AUDIENCE", None, AUDIENCE)
    said_scope, source_scope = _first(scope, env, "WLCG_TOKEN_SCOPE", profile, DEFAULT_SCOPE)
    return Settings(
        issuer=said_issuer,
        audience=said_audience,
        scope=said_scope,
        provider=profile.name if profile else "",
        from_issuer=source_issuer,
        from_audience=source_audience,
        from_scope=source_scope,
    )


def _first(
    given: str, env: Mapping[str, str], variable: str, profile: Provider | None, fallback: str = ""
) -> tuple[str, str]:
    """The first of: what was typed, what the environment says, what the profile suggests."""
    if given:
        return given, "flag"
    from_env = (env.get(variable) or "").strip()
    if from_env:
        return from_env, "env"
    if profile is not None:
        mine = getattr(profile, _FIELD[variable])
        if mine:
            return mine, "profile"
    if fallback:
        return fallback, "default"
    return "", ""


#: Which profile field each variable falls back to.
_FIELD = {"WLCG_TOKEN_ISSUER": "issuer", "WLCG_TOKEN_SCOPE": "scope"}
