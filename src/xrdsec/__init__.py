"""xrdsec: grid security and credential handling, shared by every grid client.

X.509 certificates and RFC 3820 proxies, delegation, VOMS, bearer tokens,
credential discovery and client TLS - the pieces xrdclient, xgfalclient and
xrdarc each need, written once on top of ``cryptography`` and ``asn1crypto``:

* :mod:`.der`, :mod:`.rsa`, :mod:`.aes`, :mod:`.p256`, :mod:`.ed25519`,
  :mod:`.signatures` - the encoding and the primitives, as grid protocols
  shape them;
* :mod:`.x509` - reading certificates and proxy files, and the building
  blocks of new ones;
* :mod:`.proxies` - the one proxy issuer, with its ``rfc3820``, ``arc``,
  ``xrootd``, ``globus`` and ``globus-legacy`` profiles, proxy files and
  ``voms-proxy-info``-style descriptions; :mod:`.delegation` (the request
  parser and certificate builder, and XrdCrypto's request signer) and
  :mod:`.userproxy` (an in-memory proxy from a user certificate) are thin
  profiles of it;
* :mod:`.trust` - is this server who it says it is, before delegating to it;
* :mod:`.voms` - VOMS attribute certificates, inspected and validated;
  :mod:`.voms_client` - obtaining them: ``vomses`` and the VOMS REST client;
* :mod:`.proxytool` - the workflow of ``voms-proxy-init``,
  ``voms-proxy-info`` and ``arcproxy`` on top of those: which user
  certificate signs, the ACs, the proxy, its file and its description;
* :mod:`.credentials` - where the proxy, the user certificate and key, the
  bearer token and the CA directory are, and reading or writing a
  credential file safely; :mod:`.tokens` (a URL's own token in front of the
  WLCG search, unverified JWT expiry), :mod:`.usercred` (a separate key,
  presented without a combined file) and :mod:`.discovery` (each tool's
  whole search order, as data) build on it; :mod:`.lifetime` is the
  credential in use *now* - providers re-read on every ask, the expiry
  assessment every tool shares, and a watch that warns once and notices a
  renewed credential;
* :mod:`.tls` - client ``SSLContext``\\ s from all of the above, cached;
* :mod:`.gsi` - GSI itself: the Globus GSS mechanism (:mod:`.gsi.gss`),
  httpg (:mod:`.gsi.httpg`) and XrdSecgsi (:mod:`.gsi.secgsi`);
* :mod:`.krb5` - Kerberos 5: a pure-Python client that reads ``FILE:``,
  ``DIR:``, ``KCM:`` and ``KEYRING:`` caches, asks the KDC for service
  tickets and builds AP-REQ and KRB-CRED messages (:mod:`.krb5.client`), and
  GSS-API contexts through python-gssapi, the ``krb5`` extra
  (:mod:`.krb5.gss`);
* :mod:`.testing` - a throwaway grid PKI (:mod:`.testing.pki`), VOMS ACs and
  a fake VOMS server (:mod:`.testing.voms`), and the HTTPS test server every
  fake is built on (:mod:`.testing.https`).

Errors are :mod:`xrdcore.errors`' (``CredentialError``,
``InsecureCredentialError``, ``TokenExpiredError``), plus
:class:`~xrdsec.delegation.DelegationError` (``proxies.ProxyError``) and
:class:`~xrdsec.voms_client.VOMSError` and its kinds.

Importing this package imports none of them: each is loaded when first
named, so ``import xrdsec`` costs nothing a ``--help`` would notice.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import TYPE_CHECKING

from ._version import __version__

if TYPE_CHECKING:
    from . import (
        aes,
        credentials,
        delegation,
        der,
        discovery,
        ed25519,
        gsi,
        krb5,
        lifetime,
        p256,
        proxies,
        proxytool,
        rsa,
        signatures,
        testing,
        tls,
        tokens,
        trust,
        usercred,
        userproxy,
        voms,
        voms_client,
        x509,
    )

__all__ = [
    "__version__",
    "aes",
    "credentials",
    "delegation",
    "der",
    "discovery",
    "ed25519",
    "gsi",
    "krb5",
    "lifetime",
    "p256",
    "proxies",
    "proxytool",
    "rsa",
    "signatures",
    "testing",
    "tls",
    "tokens",
    "trust",
    "usercred",
    "userproxy",
    "voms",
    "voms_client",
    "x509",
]

_SUBMODULES = frozenset(__all__) - {"__version__"}


def __getattr__(name: str) -> ModuleType:
    """Import a submodule the first time it is named as an attribute."""
    if name in _SUBMODULES:
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """The public names, including submodules not yet imported."""
    return sorted(__all__)
