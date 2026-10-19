"""GSI, both of the grid's protocols by that name, written once for every client.

"GSI" names two unrelated wire protocols, and grid clients need both:

* :mod:`.gss` - **Globus GSI GSS-API**: a TLS handshake carried in opaque
  tokens, then a delegation byte and (optionally) a proxy delegation. GridFTP
  (``ADAT``), LFC's Csec, dCache's dcap tunnel and SRM's httpg all speak it;
  :class:`~.gss.SecurityContext` is the state machine, both initiator and
  acceptor.
* :mod:`.httpg` - **httpg**, Globus' "HTTP over GSI": the same handshake
  straight on a socket, then the delegation byte, then plain HTTP/1.1, as an
  ``http.client`` connection class (SRM's transport).
* :mod:`.secgsi` - **XrdSecgsi**, XRootD's own ``gsi`` authentication
  protocol: XrdSut bucket messages, a Diffie-Hellman exchange over the
  server's group, an AES session cipher, and proxy delegation by signing the
  server's request. :class:`~.secgsi.SecgsiClient` drives a login; xrdclient
  plugs it into its ``kXR_auth`` framework.

The acceptor sides the in-process test servers need (token loops, the httpg
preamble, an XrdSecgsi server) are in :mod:`xrdsec.testing.gsi`.

Before 0.4.0 these lived in the clients: the GSS mechanism and httpg in
xgfalclient (``crypto/gsi.py``, ``plugins/srm/transport.py``), XrdSecgsi in
xrdclient (``auth/gsi.py``). Importing this package imports none of the
submodules; each is loaded when first named.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import gss, httpg, secgsi

__all__ = ["gss", "httpg", "secgsi"]


def __getattr__(name: str) -> ModuleType:
    """Import a submodule the first time it is named as an attribute."""
    if name in __all__:
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """The submodules, including those not yet imported."""
    return sorted(__all__)
