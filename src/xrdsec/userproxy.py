"""A short-lived proxy made in memory from a user certificate and its key.

What ``XrdSecgsi`` does for a client that has ``usercert.pem`` and
``userkey.pem`` but no proxy (its ``createpxy`` option, on by default), and
what ``grid-proxy-init`` does on disk: a fresh key pair, and an RFC 3820
proxy certificate for it signed by the user's own key - one ``CN=<serial>``
below the user's subject, valid for a few hours and never past the user
certificate. GSI then logs in with that proxy as with any other.

The difference from both is where it lives. Nothing here touches the disk:
the user's key is read once (through the private-file checks of
:func:`xrdsec.credentials.read_private_file`), the proxy and its new key exist only in this
process, and they die with it. A grid tool that copied the user's key into a
temporary file to hand it to a library left that file behind whenever it
crashed; this is the API that makes such a file unnecessary.

:func:`user_proxy` is the ``"rfc3820"`` profile of
:func:`xrdsec.proxies.create_proxy` - the one issuer every proxy in
this package comes from - kept under its own name and signature for its
caller, :mod:`xrdsec.usercred`, which makes the GSI proxy.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from .proxies import create_proxy
from .rsa import RSAPrivateKey
from .x509 import Certificate, ProxyCredential

__all__ = ["PROXY_BITS", "PROXY_HOURS", "user_proxy"]

#: How long a made proxy lasts, as ``XrdSecgsi``'s ``createpxy`` default.
PROXY_HOURS = 12.0
#: The size of its key, as ``grid-proxy-init``'s and ``XrdSecgsi``'s default.
PROXY_BITS = 2048


def user_proxy(
    chain: Sequence[Certificate],
    key: RSAPrivateKey,
    *,
    hours: float = PROXY_HOURS,
    bits: int = PROXY_BITS,
    now: float | None = None,
) -> ProxyCredential:
    """A new proxy below ``chain[0]`` (the user certificate), signed with ``key``.

    ``chain`` is the user certificate first and, optionally, the authorities
    above it - as ``usercert.pem`` holds it. The result's chain is the proxy
    followed by ``chain``, and its key is the proxy's fresh one; ``key``
    signs the proxy and is not kept. The proxy is an RFC 3820 impersonation
    proxy valid from five minutes ago (never before the user certificate)
    for ``hours``, never past any certificate in ``chain``. Raises
    :class:`ValueError` (a :class:`~xrdsec.delegation.DelegationError`
    from the issuer) when the key does not belong to the certificate, or the
    certificate has expired.
    """
    if not chain:
        raise ValueError("a user proxy needs the user certificate to sign it")
    user = chain[0]
    moment = time.time() if now is None else now
    if user.not_after <= moment:
        raise ValueError(f"the user certificate {user.subject} has expired")
    signer = ProxyCredential(chain=tuple(chain), key=key)
    return create_proxy(signer, lifetime=hours * 3600, bits=bits, now=moment)
