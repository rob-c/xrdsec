"""Kerberos 5 for grid clients: a pure-Python ticket client, and GSS-API through python-gssapi.

Two ways to authenticate with the tickets ``kinit`` left, because grid
protocols want both:

* **the portable client** - pure Python, ``cryptography`` for the ciphers,
  nothing else installed. It reads the credential cache, asks the KDC for a
  service ticket when the cache holds only the TGT, and builds the raw
  AP-REQ and KRB-CRED messages itself, which is what XRootD's ``krb5``
  plugin wants (it never calls GSS-API). Start at :mod:`.client`;
  underneath it:

  * :mod:`.model` - principals and credentials, the vocabulary of the rest;
  * :mod:`.rfc3961` - the AES enctypes (RFC 3961, 3962, 8009);
  * :mod:`.asn1` - the DER encoding of the RFC 4120 messages involved;
  * :mod:`.ccache` - the MIT/Heimdal FILE credential cache, keys included,
    and the marshalled principal and credential every cache type shares;
  * :mod:`.kcm` - ``KCM:`` caches, over the KCM daemon's Unix socket;
  * :mod:`.keyring` - ``KEYRING:`` caches, in Linux kernel keyrings;
  * :mod:`.caches` - opening a cache by name, whichever of those it is;
  * :mod:`.profile` - ``krb5.conf``: realms, KDCs, the domain mapping;
  * :mod:`.kdc` - talking to a KDC over UDP and TCP;
  * :mod:`.tgs` - the TGS exchange, and the AP-REQ and KRB-CRED themselves.

* **the system library** - :mod:`.gss`, GSS-API contexts through
  python-gssapi (the ``xrdsec[krb5]`` extra): the token exchanges dCache's
  ``kdcap`` and LFC's Csec speak, every cache type the platform has
  (macOS ``API:`` included), and a raw AP-REQ for XRootD from those caches.

The portable client does not do the initial (AS) exchange - that is
``kinit``'s job, and needs a password or a keytab a library should never
hold - nor cross-realm tickets, DNS KDC discovery, or single-DES,
triple-DES and RC4 keys; each refusal says so, and the system library
handles all of them.

What stays with each client is its protocol and its policy: xrdclient frames
the AP-REQ for ``kXR_auth`` and decides, by ``$XRD_KRB5_BACKEND``, which of
the two to try first; xgfalclient turns :class:`.gss.KerberosError` into
gfal2's ``GError``. Errors here are :mod:`xrdcore.errors`'
(``CredentialError``) and :class:`.gss.KerberosError` (an
``AuthenticationError`` carrying an ``errno``).

Importing this package imports none of the modules: each loads when first
named, and nothing imports ``gssapi`` until a GSS context is made.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import (
        asn1,
        caches,
        ccache,
        client,
        gss,
        kcm,
        kdc,
        keyring,
        model,
        profile,
        rfc3961,
        tgs,
    )

__all__ = [
    "asn1",
    "caches",
    "ccache",
    "client",
    "gss",
    "kcm",
    "kdc",
    "keyring",
    "model",
    "profile",
    "rfc3961",
    "tgs",
]


def __getattr__(name: str) -> ModuleType:
    """Import a submodule the first time it is named as an attribute."""
    if name in __all__:
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """The submodules, including those not yet imported."""
    return sorted(__all__)
