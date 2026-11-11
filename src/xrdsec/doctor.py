"""Can this machine make and use a grid proxy? One plain-English line per question.

What ``xrd-proxy doctor`` prints:

    certs        ok   138 CAs, 134 CRLs in /cvmfs/grid.cern.ch/etc/grid-security/certificates
    credential   ok   /Users/me/.globus/usercert.pem with userkey.pem, valid until 3 Oct 2026
                       -> identity /DC=ch/DC=cern/.../CN=Jane Doe
    voms         ok   68 VOs configured, from /cvmfs/grid.cern.ch/etc/grid-security/vomses
    vo:lhcb      ok   2 servers: voms-lhcb-auth.cern.ch:443, voms2-lhcb-auth.cern.ch:443
                       -> ask your experiment (lhcb): the second server is gone from DNS
    proxy        !!   no proxy at /tmp/x509up_u501
                       -> do: xrd-proxy init -voms lhcb
    location     ok   a proxy can be written to /tmp/x509up_u501 (0600)
    tokens       --   no bearer token (a proxy is what this machine uses)

The order is the order things bite: trust anchors, then something to sign
with, then the VOMS configuration the AC comes from, then the VO's own bits,
then the proxy file, then whether one could be written at all. The first
``!!`` is the thing to fix and the ones after it are consequences.

**Every hint names who can act on it.** A line ending in ``do:`` is something
the user can do in their own session; ``ask your admin:`` is a machine or
network setting they cannot change (a missing CA directory, a firewall, a
directory they cannot write); ``ask your experiment (vo):`` is something only
the VO can answer - membership, an LSC, a certificate renewal, a server that
has gone away. That is the whole point of the command: the useful part of a
grid-error message is almost never in the error.

Nothing here prompts, changes anything or spends a proxy: files are read under
the same rules a login applies, and the only network traffic is opening the
VOMS servers' HTTPS ports (``servers=False`` skips that).

The checks are functions over a mutable :class:`_Run` that append lines
through :meth:`_Run.add`; the call order in :func:`check` *is* the report
order. A caller can pass ``environ``/``home``/``now`` to ask about another
environment than this process's.
"""

from __future__ import annotations

import os
import platform
import socket
import ssl
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Protocol

from xrdcore.errors import CredentialError, InsecureCredentialError, XrdError

from . import credentials, proxytool, tokens
from .voms_client import (
    VOMSConfigError,
    VOMSServer,
    find_vomses,
    lsc_names,
    servers_for,
    vomses_files,
)
from .x509 import Certificate, ProxyCredential, issuer_hashes

__all__ = ["Sink", "ask_admin", "ask_experiment", "check", "do"]

#: How long a VOMS server may take to answer, in seconds: long enough for a
#: slow proxy, short enough that a firewall drop is a line rather than a wait.
TIMEOUT = 10.0

#: The same, for a sweep of every VO on the machine, where 60 dead servers must
#: not add up to ten minutes: an unreachable server is an unreachable server.
SWEEP_TIMEOUT = 5.0

#: How close to expiry a server's certificate is worth mentioning, in days.
EXPIRY_WARNING = 30

#: How many ``vomses`` files a report reads before it settles for counting them.
#: A ``vomses`` directory on CVMFS has one per VO - 126 in the WLCG bundle -
#: and each costs a network round trip to close (~190 ms on this Mac), so
#: reading them all is half a minute's work for a line that says "68 VOs".
PARSE_LIMIT = 8

#: The clock may be this far ahead of a certificate's ``notBefore`` before the
#: certificate is called "not yet valid" rather than "the clock is wrong"
#: (:data:`xrdsec.proxies.NOT_BEFORE_SKEW`'s reason, one order up).
SKEW = 300


class Sink(Protocol):
    """What a check writes to: one line per question, as ``xrdclient.doctor`` reports it."""

    def add(self, name: str, state: str, detail: str, hint: str = "") -> None:
        """Append ``name``/``state``/``detail``, and ``hint`` under it."""


def do(action: str) -> str:
    """A hint for something the user can do in their own session."""
    return f"do: {action}"


def ask_admin(action: str) -> str:
    """A hint for a machine or network setting the user cannot change."""
    return f"ask your admin: {action}"


def ask_experiment(action: str, vo: str = "") -> str:
    """A hint for something only the experiment's computing support can answer."""
    who = f" ({vo})" if vo else ""
    return f"ask your experiment{who}: {action}"


def check(
    sink: Sink,
    *,
    vo: str | None = None,
    proxy: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: str | None = None,
    now: float | None = None,
    servers: bool = True,
    all_vos: bool = False,
) -> None:
    """Ask every question a proxy needs, in the order they bite; write each answer to ``sink``.

    ``vo`` is the VO whose servers and LSC to look at (:func:`_chosen_vo`);
    ``proxy`` names a proxy file to describe instead of the default one
    (``-file``); ``servers=False`` leaves the VOMS servers alone (a firewall,
    a batch job, a test).
    """
    run = _Run(
        sink=sink,
        env=os.environ if environ is None else environ,
        home=home,
        vo=vo,
        now=time.time() if now is None else now,
        servers=servers,
        all_vos=all_vos,
    )
    _host(run)
    _certs(run)
    _credential(run)
    _voms(run)
    _proxy(run, proxy)
    _location(run, proxy)
    _tokens(run)


@dataclass
class _Run:
    """What the checks share: the environment asked about, and where answers go."""

    sink: Sink
    env: Mapping[str, str]
    home: str | None
    vo: str | None
    now: float
    servers: bool
    #: The CA directory, once :func:`_certs` has found one.
    ca_dir: str = ""
    #: The credential :func:`_credential` could load, if any.
    credential: ProxyCredential | None = field(default=None, repr=False)
    #: Whether to ask every configured VOs' servers, not just the named VO's.
    all_vos: bool = False

    def add(self, name: str, state: str, detail: str, hint: str = "") -> None:
        """One line: ``state`` is ``ok``, ``bad``, ``warn`` or ``skip``."""
        self.sink.add(name, state, detail, hint)


# ---------------------------------------------------------------------------
# What this machine has
# ---------------------------------------------------------------------------


def _host(run: _Run) -> None:
    """The one line a bug report needs first: what machine, which tools, whose session."""
    version = ".".join(str(part) for part in sys.version_info[:3])
    system = f"{sys.platform} {platform.machine() or 'unknown'}".strip()
    home = run.env.get("HOME") or "?"
    run.add("host", "ok", f"python {version} on {system}, uid {os.getuid()}, HOME {home}")


def _stages(run: _Run, prefix: str, kind: str) -> None:
    """Every place ``grid-security/<kind>`` is looked for, one line per stage.

    This is the map an admin needs: stage 1 is what the environment says,
    stage 2 the machine's own directory, stage 3 the shared CVMFS bundle,
    stage 4 the working directory. ``ok`` is a stage that has something in
    it, ``skip`` one that is simply not there - which is only a problem if no
    stage has anything, and that is the line above's job to say.
    """
    from . import locations

    seen: dict[str, int] = {}
    for location in locations.grid_security_directories(kind, run.env):
        seen[location.stage] = seen.get(location.stage, 0) + 1
        repeat = seen[location.stage]
        stage = f"{prefix}:{location.stage}" + (f"{repeat}" if repeat > 1 else "")
        if not location.exists():
            run.add(stage, "skip", f"{location.path} (not there)")
            continue
        found = _count(location.path, ".0") or len(_entries(location.path))
        run.add(stage, "ok", f"{location.path} ({found} entries)")


def _entries(path: str) -> list[str]:
    """What is in ``path``, or nothing when it cannot be listed."""
    try:
        return os.listdir(path)
    except OSError:
        return []


def _certs(run: _Run) -> None:
    """The trust anchors: a CA directory with certificates in it, and CRLs if possible."""
    path = credentials.grid_ca_path(run.env)
    if path is None:
        run.add(
            "certs",
            "bad",
            "no grid CA directory: X509_CERT_DIR is unset and no usual directory is there",
            do("mount the WLCG bundle at /cvmfs/grid.cern.ch/etc/grid-security/certificates"),
        )
        return
    if not os.path.isdir(path):
        run.add(
            "certs",
            "bad",
            f"X509_CERT_DIR names {path}, which is not a directory",
            do("unset X509_CERT_DIR for the default, or point it at a CA directory"),
        )
        return
    run.ca_dir = path
    authorities = _count(path, ".0")
    if not authorities:
        run.add(
            "certs",
            "bad",
            f"{path} holds no CA certificates",
            ask_admin("the IGTF CA bundle is not installed in the CA directory"),
        )
        return
    _stages(run, "certs", "certificates")
    revoked = _count(path, ".r0")
    if revoked:
        run.add("certs", "ok", f"{authorities} CAs, {revoked} CRLs in {path}")
        return
    run.add(
        "certs",
        "warn",
        f"{authorities} CAs, no CRLs in {path}",
        do("a revoked certificate would still be accepted: use a bundle that carries CRLs"),
    )


def _count(directory: str, suffix: str) -> int:
    """How many files in ``directory`` end with ``suffix``."""
    try:
        return sum(1 for name in os.listdir(directory) if name.endswith(suffix))
    except OSError:
        return 0


def _credential(run: _Run) -> None:
    """Something to sign with, and whether a server would accept what it says."""
    try:
        source = _source(run)
    except (CredentialError, InsecureCredentialError, OSError) as refused:
        state, hint = _refused(str(refused), run.vo)
        run.add("credential", state, f"a credential cannot be used: {refused}", hint)
        return
    if source is None:
        run.add(
            "credential",
            "bad",
            "no user certificate: no bundle, and no certificate and key found",
            do("xrd-proxy init -p12 myCert.p12, or usercert.pem and userkey.pem in ~/.globus"),
        )
        return
    described, load = source
    try:
        run.credential = load()
    except (InsecureCredentialError, CredentialError, OSError) as refused:
        state, hint = _refused(str(refused), run.vo)
        run.add("credential", state, f"{described}: {refused}", hint)
        return
    _describe(run, described, run.credential)


def _source(run: _Run) -> tuple[str, Callable[[], ProxyCredential]] | None:
    """What ``xrd-proxy init`` would sign with, described, and how to load it without prompting."""
    from .proxies import load_credential, load_p12

    bundle = (run.env.get("X509_USER_P12") or "").strip()
    if bundle and os.path.isfile(bundle):
        return f"bundle {bundle}", lambda: load_p12(bundle)
    try:
        cert, key = proxytool.find_user_pair(proxytool.VOMS_PROXY_INIT, environ=run.env)
    except proxytool.NoCredentialError:
        pair, _note = credentials.globus_pem_pair(run.env, home=run.home)
        if pair is None:
            return None
        cert, key = pair
    return f"{cert} with {key}", lambda: load_credential(cert, key)


def _refused(refusal: str, vo: str | None) -> tuple[str, str]:
    """What a credential that would not load means for the user: state and who can fix it."""
    lowered = refusal.lower()
    if "pass phrase" in lowered:
        return "warn", do(
            "this check does not prompt: xrd-proxy init asks for the pass phrase once"
        )
    if "expired" in lowered:
        return "bad", ask_experiment("your user certificate has expired: renew it", vo or "")
    if "rsa" in lowered:
        return "bad", ask_experiment("GSI needs an RSA key, and this one is not", vo or "")
    if "does not belong" in lowered:
        return "bad", do("the key is not this certificate's: check which pair you are pointing at")
    return "bad", ask_admin("the credential cannot be read: check its permissions and format")


def _describe(run: _Run, described: str, credential: ProxyCredential) -> None:
    """A credential that loaded: is it in date, and can a server verify its issuer?"""
    certificate = credential.chain[0]
    if certificate.not_after <= run.now:
        run.add(
            "credential",
            "bad",
            f"{described}: expired {_ago(run.now - certificate.not_after)} ago",
            ask_experiment("renew your user certificate", run.vo or ""),
        )
        return
    if certificate.not_before > run.now + SKEW:
        run.add(
            "credential",
            "bad",
            f"{described}: not valid until {_date(certificate.not_before)}",
            do("a certificate that is not yet valid usually means the system clock is wrong"),
        )
        return
    missing = _untrusted(run, certificate)
    if missing:
        run.add(
            "credential",
            "bad",
            f"{described}: its issuer {certificate.issuer} is not in {run.ca_dir}",
            ask_admin("add the CA that issued this certificate to the CA directory"),
        )
        return
    run.add(
        "credential",
        "ok",
        f"{described}: identity {credential.identity}, until {_date(certificate.not_after)}",
    )


def _untrusted(run: _Run, certificate: Certificate) -> bool:
    """Whether neither of the certificate's issuer hashes is a file in the CA directory."""
    if not run.ca_dir:
        return False
    return not any(
        os.path.exists(os.path.join(run.ca_dir, f"{name}.0")) for name in issuer_hashes(certificate)
    )


# ---------------------------------------------------------------------------
# VOMS: where an AC comes from, and the VO's own bits
# ---------------------------------------------------------------------------


def _voms(run: _Run) -> None:
    """The ``vomses`` configuration, and - when a VO was named - that VO in detail."""
    files = vomses_files(environ=run.env)
    if run.vo is None and not run.all_vos and len(files) > PARSE_LIMIT:
        _voms_counted(run, files)
        return
    try:
        # ``vo=``: only the files that could hold the VO asked about, when one was
        servers = find_vomses(environ=run.env, vo=None if run.all_vos else run.vo)
    except (VOMSConfigError, OSError) as refused:
        run.add(
            "voms",
            "bad",
            f"the VOMS configuration cannot be read: {refused}",
            do("fix or remove the vomses file that X509_VOMSES names"),
        )
        return
    if not servers:
        run.add(
            "voms",
            "warn",
            "no VOMS server configured: a proxy would carry no VO attributes",
            _no_vomses(run),
        )
        _stages(run, "vomses", "vomses")
        return
    vos = sorted({server.vo for server in servers})
    _stages(run, "vomses", "vomses")
    run.add("voms", "ok", f"{_count_vos(len(vos))} configured, from {_origins(servers)}")
    if run.vo is not None:
        _chosen_vo(run, servers)
    if run.all_vos:
        _sweep(run, servers)


def _cvmfs_mounted() -> bool:
    """Whether this machine has a CVMFS mount at all (the WLCG bundle lives there)."""
    return os.path.isdir("/cvmfs")


def _no_vomses(run: _Run) -> str:
    """Why nothing was found, and whose job it is: a missing CVMFS tree is the admin's.

    A mount that answers for ``certificates`` but has never fetched ``vomses``
    looks exactly like "nothing is configured", and the cure - re-mount the
    bundle, or fetch that tree - is not the user's to apply. Saying so is the
    difference between "install a file" and "ask your admin".
    """
    from . import locations

    yours = do(
        "install the VO's line in ~/.voms/vomses/<vo> (a file per VO), or point X509_VOMSES at one"
    )
    cvmfs = [
        location.path
        for location in locations.grid_security_directories("vomses", run.env)
        if location.stage == "cvmfs"
    ]
    stale = _cvmfs_mounted() and cvmfs and not any(os.path.isdir(one) for one in cvmfs)
    if not stale:
        return yours
    return ask_admin(
        f"/cvmfs is mounted but carries no vomses tree ({', '.join(cvmfs)}):"
        " re-mount the bundle (unmount, then restart the mount daemon),"
        f" or fetch the VO's file into ~/.voms/vomses - {yours.removeprefix('do: ')}"
    )


def _voms_counted(run: _Run, files: Sequence[Path]) -> None:
    """A configuration too big to parse for one line: say where it is and how big.

    The stage lines above already say which of the four places answered; this
    is the one that would otherwise read every file to count the VOs in it.
    """
    directory = str(files[0].parent) if files else "?"
    run.add(
        "voms",
        "ok",
        f"{len(files)} vomses files in {directory}",
        do("xrd-proxy init -list-vos names the VOs; -voms VO reads only that one"),
    )


def _origins(servers: Sequence[VOMSServer]) -> str:
    """Where the configuration was read from: one file, or the directory holding them.

    A ``vomses`` *directory* has one file per VO - 126 of them in the WLCG
    bundle - so naming every file would be a paragraph; the directory says
    the same thing in one word.
    """
    files = sorted({server.origin.rsplit(":", 1)[0] for server in servers if server.origin})
    if not files:
        return "the configured vomses files"
    if len(files) == 1:
        return files[0]
    directories = sorted({os.path.dirname(name) or "." for name in files})
    if len(directories) == 1:
        return directories[0]
    shown = ", ".join(directories[:2])
    return f"{shown} and {len(directories) - 2} more" if len(directories) > 2 else shown


def _chosen_vo(run: _Run, servers: Sequence[VOMSServer]) -> None:
    """The VO asked about: its servers, its LSC, and whether they answer."""
    name = "vo"
    try:
        chosen = servers_for(str(run.vo), servers)
    except VOMSConfigError as refused:
        run.add(name, "bad", str(refused), do("xrd-proxy init -list-vos shows what can be asked"))
        return
    run.add(name, "ok", f"{run.vo}: {len(chosen)} server(s), {_addresses(chosen)}")
    _lsc(run, name, chosen)
    if run.servers:
        _answers(run, chosen)


def _sweep(run: _Run, servers: Sequence[VOMSServer]) -> None:
    """Every configured VO, one line: which ones no server answered for.

    A site admin's question is not "does atlas work" but "does anything here
    still work", so every server is asked at once (:func:`xrdcore.fanout.run_all`)
    with :data:`SWEEP_TIMEOUT` each - one slow VO with five servers must not
    take five times as long as its neighbours. A VO counts as fine when one of
    its servers answers, which is what ``fetch_ac`` needs.

    ``warn``, not ``bad``: another VO's server being gone does not stop *this*
    user making a proxy - it stops theirs. ``--strict`` is how a monitoring
    check turns it into a failure.
    """
    from xrdcore.fanout import run_all

    context = _context(run)
    answers = run_all(
        [partial(_answering, server, context) for server in servers], name="xrd-doctor-sweep"
    )
    served: dict[str, bool] = {}
    for server, answered in zip(servers, answers, strict=True):
        served[server.vo] = served.get(server.vo, False) or answered
    silent = sorted(vo for vo, answered in served.items() if not answered)
    if not silent:
        run.add("vos", "ok", f"all {len(served)} VOs answered")
        return
    shown = ", ".join(silent[:4])
    more = f" and {len(silent) - 4} more" if len(silent) > 4 else ""
    run.add(
        "vos",
        "warn",
        f"{len(served) - len(silent)} of {len(served)} VOs answered; nothing answered"
        f" for {shown}{more}",
        ask_experiment("those VOs' servers did not answer: ask whether they have moved", ""),
    )


def _answering(server: VOMSServer, context: ssl.SSLContext | None) -> bool:
    """Whether ``server`` answered within :data:`SWEEP_TIMEOUT`."""
    return _probe(server, context, timeout=SWEEP_TIMEOUT).reason is None


def _count_vos(count: int) -> str:
    """``68 VOs``, or ``1 VO``: the line reads as English either way."""
    return f"{count} VO" if count == 1 else f"{count} VOs"


def _addresses(chosen: Sequence[VOMSServer]) -> str:
    """The VO's servers as ``host:port``, in the order they will be tried."""
    return ", ".join(server.address for server in chosen)


def _lsc(run: _Run, name: str, chosen: Sequence[VOMSServer]) -> None:
    """The LSC for the servers that were configured, not merely the VO's directory.

    A ``vomsdir/<vo>`` directory that exists proves nothing: the files in it are
    named for the *server* (``<CN of its certificate>.lsc``), so a ``vomses``
    line that still names an obsolete server leaves the directory full, the
    check green, and every AC that server issues unvalidatable. That is how the
    LHCb configuration went wrong here once this very check said "present".
    """
    directory = credentials.grid_voms_dir(run.env)
    vo = str(run.vo)
    if not directory:
        run.add(
            "vo:lsc",
            "warn",
            f"no LSC for {vo}: X509_VOMS_DIR is unset",
            ask_experiment("sites cannot validate an AC without the VO's LSC", vo),
        )
        return
    folder = os.path.join(directory, vo)
    present = sorted(_entries(folder))
    wanted = lsc_names(chosen)
    found = [one for one in wanted if one in present]
    if found:
        run.add("vo:lsc", "ok", f"{vo}: {', '.join(found)} in {folder}")
        return
    if not present:
        # The site has no LSC for the VO at all: only the VO can supply it.
        run.add(
            "vo:lsc",
            "warn",
            f"no LSC for {vo} in {directory}",
            ask_experiment("sites cannot validate an AC without the VO's LSC", vo),
        )
        return
    # The directory is there and names other servers: the entry read is stale.
    run.add(
        "vo:lsc",
        "warn",
        f"{vo}: no LSC for the configured server(s) - expected {' or '.join(wanted)}"
        f" in {folder}, which has {', '.join(present[:4])}",
        do("check that the vomses entry names the VO's current server, not one it has left"),
    )


@dataclass(frozen=True, slots=True)
class _Answer:
    """What a VOMS server said: nothing, or why it did not, and when its certificate lapses."""

    #: Why the server could not be used, or ``None`` when it answered.
    reason: str | None = None
    #: The server certificate's ``notAfter``, when there was a handshake to read it from.
    expires: float | None = None


def _answers(run: _Run, chosen: Sequence[VOMSServer]) -> None:
    """Whether the VO's servers answer, and which of them do not.

    One working server is enough - ``fetch_ac`` tries them in order - so that
    is an ``ok``; a server that does not answer while another does is a
    ``warn`` naming it, because the experiment is the only one who can say
    whether it moved, and the day the first one goes too it matters.
    """
    context = _context(run)
    answered: list[VOMSServer] = []
    refusals: list[str] = []
    expires: float | None = None
    for server in chosen:
        answer = _probe(server, context)
        if answer.reason is None:
            answered.append(server)
            expires = answer.expires or expires
        else:
            refusals.append(f"{server.address}: {answer.reason}")
    if not answered:
        run.add(
            "vo:server",
            "bad",
            "; ".join(refusals),
            ask_admin("a firewall or proxy is stopping the VOMS servers"),
        )
        return
    run.add("vo:server", "ok", f"{answered[0].address} answered and verified")
    _expiry(run, expires)
    if refusals:
        run.add(
            "vo:alt",
            "warn",
            "; ".join(refusals),
            ask_experiment("that server did not answer: ask if it has moved", str(run.vo)),
        )


def _context(run: _Run) -> ssl.SSLContext | None:
    """The client TLS context to verify a VOMS server with, or ``None`` if there are no CAs."""
    from .tls import client_context

    if not run.ca_dir:
        return None
    return client_context(ca_path=run.ca_dir)


def _expiry(run: _Run, expires: float | None) -> None:
    """A server certificate about to lapse is the experiment's to renew, and nobody else's."""
    if expires is None:
        return
    left = (expires - run.now) / 86400
    if left < 0:
        run.add(
            "vo:cert",
            "bad",
            f"the server's certificate expired {_ago(run.now - expires)} ago",
            ask_experiment("the VOMS server certificate is not being renewed", str(run.vo or "")),
        )
        return
    if left < EXPIRY_WARNING:
        run.add(
            "vo:cert",
            "warn",
            f"the server's certificate expires in {int(left)} day(s), {_date(expires)}",
            ask_experiment("renew the VOMS server certificate", str(run.vo or "")),
        )
        return
    run.add("vo:cert", "ok", f"the server's certificate is valid until {_date(expires)}")


def _probe(
    server: VOMSServer, context: ssl.SSLContext | None, *, timeout: float = TIMEOUT
) -> _Answer:
    """Connect to ``server`` and verify its certificate: what went wrong, and when it lapses."""
    try:
        with socket.create_connection((server.host, server.port), timeout=timeout) as raw:
            if context is None:
                return _Answer()  # no CAs to judge it by; the connection is the answer
            with context.wrap_socket(raw, server_hostname=server.host) as tls:
                return _Answer(expires=_peer_expiry(tls))
    except ssl.SSLError as refused:
        return _Answer(reason=f"its certificate is not trusted ({refused})")
    except OSError as refused:
        return _Answer(reason=str(refused))


def _peer_expiry(tls: ssl.SSLSocket) -> float | None:
    """The ``notAfter`` of the certificate a TLS peer presented, or ``None`` if unreadable."""
    try:
        presented = tls.getpeercert() or {}
        stamp = presented["notAfter"]
        return float(ssl.cert_time_to_seconds(stamp)) if isinstance(stamp, str) else None
    except (KeyError, TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# The proxy file itself
# ---------------------------------------------------------------------------


def _proxy(run: _Run, named: str | None) -> None:
    """A proxy that is already there: how long it lasts, and which VOs it carries."""
    target = proxytool.proxy_target(named, environ=run.env)
    try:
        info = proxytool.read_proxy_info(
            target.path, follow_symlinks=target.follow_symlinks, now=run.now
        )
    except proxytool.NoCredentialError:
        run.add(
            "proxy",
            "warn",
            f"no proxy at {target.path}",
            do(f"xrd-proxy init{' -voms ' + run.vo if run.vo else ''}"),
        )
        return
    except (CredentialError, InsecureCredentialError) as refused:
        run.add(
            "proxy",
            "bad",
            f"{target.path}: {refused}",
            do("chmod 600 the proxy, or make a new one with xrd-proxy init"),
        )
        return
    if info.time_left <= 0:
        run.add(
            "proxy",
            "bad",
            f"{target.path} expired {_ago(-info.time_left)} ago",
            do(f"xrd-proxy init{' -voms ' + run.vo if run.vo else ''}"),
        )
        return
    vos = ", ".join(entry.vo for entry in info.voms) or "no VO attributes"
    run.add(
        "proxy",
        "ok",
        f"{target.path}: {info.kind}, {_clock(info.time_left)} left, {vos}",
    )


def _location(run: _Run, named: str | None) -> None:
    """Whether a proxy could be written where it goes, and refused if it is a planted link."""
    target = proxytool.proxy_target(named, environ=run.env)
    directory = os.path.dirname(target.path) or "."
    if os.path.islink(target.path) and not target.follow_symlinks:
        run.add(
            "location",
            "bad",
            f"{target.path} is a symbolic link, which a proxy is never written through",
            do("remove the link, or name the proxy with -out or X509_USER_PROXY"),
        )
        return
    if not os.path.isdir(directory):
        run.add(
            "location",
            "bad",
            f"{directory} is not a directory",
            do("set X509_USER_PROXY to a path whose directory exists"),
        )
        return
    if not os.access(directory, os.W_OK):
        run.add(
            "location",
            "bad",
            f"{directory} is not writable by you",
            do("set X509_USER_PROXY to a path you can write, such as $HOME/x509up"),
        )
        return
    run.add("location", "ok", f"a proxy can be written to {target.path} (0600)")


def _tokens(run: _Run) -> None:
    """The other kind of credential, so that "no proxy" is not reported as the whole story."""
    try:
        token = tokens.discover_token(environ=run.env)
    except InsecureCredentialError as refused:
        run.add(
            "tokens",
            "bad",
            f"the token file cannot be used: {refused}",
            do("chmod 600 the token file, or unset BEARER_TOKEN_FILE"),
        )
        return
    if token is None:
        run.add("tokens", "skip", "no bearer token: a proxy is how this machine authenticates")
        return
    try:
        tokens.check_token(token, now=run.now)
    except XrdError as refused:
        run.add(
            "tokens",
            "bad",
            f"the bearer token is not usable: {refused}",
            do("get a new token, or unset BEARER_TOKEN / BEARER_TOKEN_FILE"),
        )
        return
    expiry = tokens.token_expiry(token)
    left = "no expiry to read" if expiry is None else f"{_clock(expiry - run.now)} left"
    run.add("tokens", "ok", f"a bearer token from {'$BEARER_TOKEN_FILE'}, {left}")


# ---------------------------------------------------------------------------
# Wording
# ---------------------------------------------------------------------------


def _date(moment: float) -> str:
    """A local date without the clock time: ``3 Oct 2026``."""
    return time.strftime("%d %b %Y", time.localtime(moment))


def _clock(seconds: float) -> str:
    """``H:MM:SS``, as the proxy tools print time left."""
    whole = max(0, int(seconds))
    return f"{whole // 3600}:{whole % 3600 // 60:02d}:{whole % 60:02d}"


def _ago(seconds: float) -> str:
    """A span of time in the largest unit that is still exact enough to act on."""
    days, rest = divmod(int(max(0.0, seconds)), 86400)
    if days:
        return f"{days} day{'s' if days != 1 else ''}"
    hours = rest // 3600
    return f"{hours} hour{'s' if hours != 1 else ''}" if hours else "less than an hour"
