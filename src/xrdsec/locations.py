"""Where every grid artifact is looked for, in stages: the environment, the machine, CVMFS, here.

Every tool on the stack resolves the same handful of things - the CA
directory, the VOMS LSC directory, the ``vomses`` configuration, a user
certificate and key, the proxy file, a bearer token - and each of them used
to spell its own list. This is that list, once, as data:

1. **env** - a variable somebody set: ``$X509_CERT_DIR``, ``$X509_VOMS_DIR``,
   ``$X509_VOMSES``, ``$X509_USER_CERT``/``$X509_USER_KEY``,
   ``$X509_USER_PROXY``, ``$BEARER_TOKEN_FILE``. A location named here is
   *used as named*, present or not: a typo is an error to report, not
   something to paper over with the next stage.
2. **local** - the machine's conventional places: ``/etc/grid-security/<kind>``
   (and Homebrew's prefix on a Mac), ``~/.globus``, ``/tmp/x509up_u<uid>``.
3. **cvmfs** - the WLCG bundle that a grid machine already mounts:
   ``/cvmfs/grid.cern.ch/etc/grid-security/<kind>``, then the configuration
   repository ``/cvmfs/cvmfs-config.cern.ch/etc/grid-security/<kind>``.
4. **cwd** - ``grid-security/<kind>`` under the working directory: a test rig,
   an unpacked tarball, a checkout that carries its own trust material.

Nothing here reads a file except to answer :meth:`Location.exists`; the
single-answer lookups (``credentials.grid_ca_path`` and friends) are the first
stage whose location is there, and the ordered lists are what a diagnosis
prints so an admin can see every place a tool *would* look.

Order is a promise: everything a machine found before this module existed is
still found first, in the same place, because stages 1 and 2 are the old
lists in the old order. Stages 3 and 4 only ever add somewhere to fall back
to.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

__all__ = [
    "CVMFS_GRID_SECURITY",
    "STAGES",
    "Location",
    "cwd",
    "grid_security_directories",
    "proxy_candidates",
    "user_pairs",
]

#: The stages, in the order they are tried; a location's ``stage`` is one of these.
STAGES = ("env", "local", "cvmfs", "cwd")

#: The CVMFS ``grid-security`` trees, most authoritative first: the WLCG bundle
#: itself, then the configuration repository that carries defaults for it.
CVMFS_GRID_SECURITY = (
    "/cvmfs/grid.cern.ch/etc/grid-security",
    "/cvmfs/cvmfs-config.cern.ch/etc/grid-security",
)

#: The variable each kind of artifact is named by in the environment.
_VARIABLES = {
    "certificates": "X509_CERT_DIR",
    "vomsdir": "X509_VOMS_DIR",
    "vomses": "X509_VOMSES",
}

#: The conventional token files, after ``$BEARER_TOKEN_FILE``.
TOKEN_NAMES = ("bt_u{uid}",)

#: ``/tmp`` and the per-user temporary directory a proxy and a token may live in.
TMP_DIR = "/tmp"


@dataclass(frozen=True, slots=True)
class Location:
    """One place a thing may be, and which stage put it there."""

    path: str
    #: One of :data:`STAGES`.
    stage: str
    #: What named this place - a variable, a conventional path, a directory.
    origin: str

    def exists(self) -> bool:
        """Whether anything is at :attr:`path` (a file or a directory)."""
        return os.path.exists(self.path)

    def is_dir(self) -> bool:
        """Whether :attr:`path` is a directory."""
        return os.path.isdir(self.path)


#: Where the ``cwd`` stage points when ``$PWD`` says nothing: the process's directory,
#: unless a suite of tests says otherwise (so no test depends on where it ran).
WORKDIR: str | None = None


def cwd(environ: Mapping[str, str] | None = None) -> str:
    """The working directory a ``cwd`` stage is relative to (``$PWD``, else :data:`WORKDIR`)."""
    named = ((os.environ if environ is None else environ).get("PWD") or "").strip()
    return named or WORKDIR or os.getcwd()


def grid_security_directories(
    kind: str, environ: Mapping[str, str] | None = None, *, workdir: str | None = None
) -> list[Location]:
    """Every ``grid-security/<kind>`` in stage order: env, machine, CVMFS, working directory.

    ``kind`` is ``"certificates"``, ``"vomsdir"`` or ``"vomses"``; ``workdir``
    overrides ``$PWD`` for the last stage, for a caller asking about a
    directory it is not in.
    """
    from . import credentials

    env = os.environ if environ is None else environ
    variable = _VARIABLES[kind]
    named = (env.get(variable) or "").strip()
    locations = [Location(named, "env", f"${variable}")] if named else []
    locations += [Location(path, "local", path) for path in credentials.machine_grid_security(kind)]
    locations += [Location(os.path.join(base, kind), "cvmfs", base) for base in CVMFS_GRID_SECURITY]
    here = workdir or cwd(env)
    locations.append(
        Location(os.path.join(here, "grid-security", kind), "cwd", "the working directory")
    )
    return locations


def user_pairs(
    environ: Mapping[str, str] | None = None, *, workdir: str | None = None
) -> list[tuple[Location, Location]]:
    """Candidate ``(certificate, key)`` pairs, in stage order.

    ``$X509_USER_CERT`` with ``$X509_USER_KEY`` is the ``env`` stage; the
    machine's ``~/.globus/usercert.pem`` with ``userkey.pem`` is ``local``;
    and the working directory is ``cwd``, so a certificate unpacked where you
    are working is found without naming it. CVMFS is not a stage here: a
    bundle of trust anchors is public, a user's key is not.
    """
    env = os.environ if environ is None else environ
    home = (env.get("HOME") or os.path.expanduser("~")).rstrip("/")
    cert, key = (env.get("X509_USER_CERT") or "").strip(), (env.get("X509_USER_KEY") or "").strip()
    pairs: list[tuple[Location, Location]] = []
    if cert and key:
        pairs.append(
            (
                Location(cert, "env", "$X509_USER_CERT"),
                Location(key, "env", "$X509_USER_KEY"),
            )
        )
    pairs.append(
        (
            Location(f"{home}/.globus/usercert.pem", "local", "~/.globus"),
            Location(f"{home}/.globus/userkey.pem", "local", "~/.globus"),
        )
    )
    here = workdir or cwd(env)
    pairs.append(
        (
            Location(os.path.join(here, "usercert.pem"), "cwd", "the working directory"),
            Location(os.path.join(here, "userkey.pem"), "cwd", "the working directory"),
        )
    )
    return pairs


def proxy_candidates(
    environ: Mapping[str, str] | None = None,
    uid: int | None = None,
    *,
    named: str | None = None,
    workdir: str | None = None,
) -> list[Location]:
    """Where a proxy file may be: the one named, ``$X509_USER_PROXY``, ``$TMPDIR``, ``/tmp``, here.

    The last two are ``x509up_u<uid>`` under the per-user temporary directory
    and under ``/tmp`` - where every grid tool puts one - and then the working
    directory, for a job that carries its own.
    """
    env = os.environ if environ is None else environ
    who = os.getuid() if uid is None else uid
    name = f"x509up_u{who}"
    locations: list[Location] = []
    if named:
        locations.append(Location(named, "env", "named on the command line"))
    variable = (env.get("X509_USER_PROXY") or "").strip()
    if variable:
        locations.append(Location(variable, "env", "$X509_USER_PROXY"))
    tmp = (env.get("TMPDIR") or "").rstrip("/")
    if tmp:
        locations.append(Location(f"{tmp}/{name}", "local", "$TMPDIR"))
    locations.append(Location(f"{TMP_DIR}/{name}", "local", TMP_DIR))
    here = workdir or cwd(env)
    locations.append(Location(os.path.join(here, name), "cwd", "the working directory"))
    return locations


def first_present(locations: Sequence[Location]) -> Location | None:
    """The first location that is there, or ``None`` - what a single-answer lookup returns."""
    return next((location for location in locations if location.exists()), None)
