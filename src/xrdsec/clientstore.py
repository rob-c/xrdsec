"""Where a client id that ``xrd-auth`` registered for itself is kept.

An IAM that allows self-service registration (RFC 7591) hands back a client id
when asked - the WLCG reference IAM does, and LHCb's does not. Keeping it means
the device flow can be run again without registering twice, and without a person
having to store an identifier in their shell.

The file is ``token-clients.json`` under ``$XDG_CONFIG_HOME/xrdsec`` (or
``~/.config/xrdsec``), written owner-only. It holds no secrets: a public client
has none.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from typing import Any

#: The file the store lives in, inside the configuration directory.
FILENAME = "token-clients.json"


def directory(environ: Mapping[str, str] | None = None) -> str:
    """The configuration directory: ``$XDG_CONFIG_HOME/xrdsec``, else under ``$HOME``."""
    env = os.environ if environ is None else environ
    base = env.get("XDG_CONFIG_HOME") or os.path.join(env.get("HOME", ""), ".config")
    return os.path.join(base, "xrdsec")


def path(environ: Mapping[str, str] | None = None) -> str:
    """The store's own path."""
    return os.path.join(directory(environ), FILENAME)


def read(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Everything the store holds, keyed by issuer; an absent or broken file is empty."""
    try:
        with open(path(environ), encoding="utf-8") as handle:
            found = json.load(handle)
    except (OSError, ValueError):
        return {}
    return found if isinstance(found, dict) else {}


def remembered(issuer: str, environ: Mapping[str, str] | None = None) -> str:
    """The client id registered for ``issuer``, or ``""``."""
    entry = read(environ).get(issuer.strip("/"))
    if isinstance(entry, dict):
        client_id = entry.get("client_id")
        return client_id if isinstance(client_id, str) else ""
    return ""


def remember(
    issuer: str,
    client_id: str,
    *,
    name: str = "",
    environ: Mapping[str, str] | None = None,
) -> str:
    """Keep ``client_id`` for ``issuer`` and return the store's path.

    Written to a temporary file in the same directory and renamed, so a reader
    never sees half a file, and ``0600`` because the directory may hold more later.
    """
    if not client_id:
        raise ValueError("a client id is not empty")
    holdings = read(environ)
    holdings[issuer.strip("/")] = {"client_id": client_id, "client_name": name}
    destination = path(environ)
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=os.path.dirname(destination))
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as written:
            json.dump(holdings, written, indent=2, sort_keys=True)
            written.write("\n")
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, destination)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    return destination
