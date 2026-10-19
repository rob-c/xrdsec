"""Obtaining VOMS attribute certificates: ``vomses`` lookup and the VOMS REST client.

A VOMS-enabled proxy carries an attribute certificate (AC) in which a VO's
VOMS server vouches for the user's groups and roles. The rest of the package
can inspect and validate such an AC (:mod:`xrdsec.voms`); this
module *obtains* one, which is the half of ``voms-proxy-init`` (and of
``arcproxy -S``) that talks to a server:

1. **Which servers.** :func:`find_vomses` reads the ``vomses`` configuration
   - ``"alias" "host" "port" "server DN" "vo"`` per line - from
   ``$X509_VOMSES`` (or ``$VOMS_USERCONF``, ``$X509_VOMS_FILE``) when set,
   else from every one of the usual places that exists; :func:`servers_for`
   picks a VO's servers by alias, then by VO name. The line syntax is
   :func:`xrdsec._voms.vomses.vomses_fields`, the same parser the
   ``check_vomses`` preflight uses.
2. **Asking.** :func:`fetch_ac` sends
   ``GET https://<host>:<port>/generate-ac?fqans=<...>&lifetime=<seconds>``
   over TLS, authenticating with the caller's credential, and reads the
   ``<voms><ac>base64</ac></voms>`` answer. That is the REST interface VOMS
   servers (2.x and later) and INDIGO IAM's VOMS attribute authority serve
   on their usual port, and what the Java ``voms-proxy-init`` and
   ``arcproxy`` speak by default; the legacy GSI socket protocol is not
   implemented. Servers are tried in order; one that cannot be reached, or
   fails on its side, is skipped for the next, while an explicit refusal
   ("you are not a member") is final - every replica of a VO shares one
   membership database, so asking the next would only repeat it.
3. **Checking.** The returned AC is validated against the local trust
   (``vomsdir``, CA directory) as the proxy carrying it will be. A failure is
   a :class:`VOMSWarning`, not an error - ``voms-proxy-init`` warns too, since
   the machine making the proxy is often not the one that must trust it -
   but an AC that does not even decode is treated as a failed server.

The credential is presented from memory, through the package's one TLS
builder (:func:`xrdsec.tls.client_context`, ``credential_pem=``): its
chain and key go to OpenSSL through pipes (``/dev/fd``), so no private key
is written to disk to make a TLS connection. :func:`ac_extension` turns
the ACs into the proxy extension that :func:`xrdsec.proxies.create_proxy` embeds.

Errors are :class:`VOMSError` (a :class:`~xrdcore.errors.CredentialError`)
subclasses, one per thing a user does differently: fix the configuration
(:class:`VOMSConfigError`), ask the VO admin (:class:`VOMSRefusedError`), or
try later / check the network (:class:`VOMSUnavailableError`).
"""

from __future__ import annotations

import base64
import binascii
import datetime
import http.client
import os
import ssl
import urllib.parse
import warnings
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

from xrdcore.errors import CredentialError
from xrdcore.safexml import UnsafeXML, fromstring

from . import credentials
from . import voms as _voms
from ._version import __version__
from ._voms.vomses import vomses_fields
from .proxies import ProxyError, issue_proxy, voms_extension
from .x509 import ProxyCredential, certificate_fields

__all__ = [
    "DEFAULT_TIMEOUT",
    "VOMSConfigError",
    "VOMSError",
    "VOMSRefusedError",
    "VOMSServer",
    "VOMSUnavailableError",
    "VOMSWarning",
    "ac_extension",
    "fetch_ac",
    "find_vomses",
    "parse_vomses",
    "servers_for",
]

#: Seconds allowed for each server's connection and answer.
DEFAULT_TIMEOUT = 30.0
#: Far more than any AC answer (a few kilobytes); a bigger one is not read.
_MAX_ANSWER = 1 << 20
#: Error codes after which the next server is worth asking: the failure was
#: the server's, not a verdict on the user.
_RETRYABLE = frozenset({"InternalError"})
#: What the VOMS REST error codes mean for the person reading the message.
_EXPLAINED = {
    "NoSuchUser": "the server does not know your certificate as a member of the VO",
    "SuspendedUser": "your membership of the VO is suspended",
    "BadRequest": "the server could not satisfy the request (check the group and role asked for)",
}
#: The environment variables that name ``vomses`` files or directories, in
#: the order they are honoured: ``voms-proxy-init``'s, then ``arcproxy``'s.
_VOMSES_VARIABLES = ("X509_VOMSES", "VOMS_USERCONF", "X509_VOMS_FILE")


class VOMSError(CredentialError):
    """Obtaining a VOMS attribute certificate failed."""


class VOMSConfigError(VOMSError):
    """The ``vomses`` configuration is missing, unreadable, malformed, or lacks the VO."""


class VOMSRefusedError(VOMSError):
    """A VOMS server answered, and said no: not a member, suspended, no such role...

    :attr:`code` is the server's error code (``NoSuchUser``...), :attr:`reason`
    its own message, and :attr:`server` the :class:`VOMSServer` that said it.
    """

    def __init__(self, server: VOMSServer, code: str, reason: str) -> None:
        """Compose the message from the server, its code and its explanation."""
        explained = _EXPLAINED.get(code, "the request was refused")
        detail = ": ".join(part for part in (code, reason) if part)
        super().__init__(
            f"VOMS server {server.address} for {server.vo!r} refused: {explained}"
            + (f" ({detail})" if detail else "")
        )
        self.server = server
        self.code = code
        self.reason = reason


class VOMSUnavailableError(VOMSError):
    """No server could be asked, or none gave a usable answer; :attr:`failures` says why."""

    def __init__(self, vo: str, failures: Sequence[str]) -> None:
        """One sentence naming the VO, then each server's own failure."""
        super().__init__(
            f"no VOMS server for {vo!r} issued an attribute certificate: " + "; ".join(failures)
        )
        self.failures = tuple(failures)


class VOMSWarning(UserWarning):
    """Something a person should hear about, that does not stop the proxy being made.

    A server's own ``<warning>`` (an AC shortened to the VO's maximum
    lifetime), or an AC that does not validate against the local trust.
    """


class _Retry(Exception):
    """This server failed; the next one may not. Internal to :func:`fetch_ac`."""


@dataclass(frozen=True, slots=True)
class VOMSServer:
    """One ``vomses`` entry: ``"alias" "host" "port" "server DN" "vo"``."""

    alias: str
    host: str
    port: int
    #: The server's certificate subject, as configured (informational: the
    #: TLS connection is authenticated by CA and host name, as the Java
    #: ``voms-proxy-init`` does it).
    dn: str
    vo: str
    #: Where the entry was read (``file:line``), for messages; not compared.
    origin: str = field(default="", compare=False)

    @property
    def address(self) -> str:
        """``host:port``, an IPv6 literal in brackets."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


def parse_vomses(text: str, origin: str = "vomses") -> list[VOMSServer]:
    """The servers ``text`` (one ``vomses`` file) configures, in file order.

    Blank lines and ``#`` comments are skipped. A malformed line raises
    :class:`VOMSConfigError` naming ``origin`` and the line number: a broken
    configuration is fixed, not half-used.
    """
    servers: list[VOMSServer] = []
    for number, line in enumerate(text.splitlines(), 1):
        try:
            fields = vomses_fields(line)
        except ValueError:
            raise VOMSConfigError(
                f"{origin}:{number}: not a vomses line; expected five quoted fields "
                '"ALIAS" "HOST" "PORT" "SERVER DN" "VO" with a port from 1 to 65535'
            ) from None
        if fields is not None:
            servers.append(VOMSServer(*fields, origin=f"{origin}:{number}"))
    return servers


def find_vomses(
    paths: str | os.PathLike[str] | Sequence[str | os.PathLike[str]] | None = None,
    environ: Mapping[str, str] | None = None,
) -> list[VOMSServer]:
    """Every configured VOMS server, from ``paths`` or the standard places.

    ``paths`` (one path or several) names ``vomses`` files or directories of
    them; each must exist. Without it, ``$X509_VOMSES``, ``$VOMS_USERCONF``
    and ``$X509_VOMS_FILE`` (each may list several, ``os.pathsep``-separated)
    are used when any is set, and must exist too; otherwise every one of
    ``~/.voms/vomses``, ``~/.glite/vomses``, ``~/.arc/vomses``,
    ``/etc/vomses`` and ``grid-security/vomses`` that exists is read, and the
    servers merged, user files first. Duplicates are dropped. An empty list
    means nothing is configured; :func:`servers_for` turns that into a
    message saying where to put the file. Raises :class:`VOMSConfigError`
    for a named path that is missing, or any file that is unreadable or
    malformed.
    """
    env = os.environ if environ is None else environ
    if paths is not None:
        named = [paths] if isinstance(paths, str | os.PathLike) else list(paths)
        locations, required = [os.fspath(path) for path in named], True
    else:
        locations, required = _configured(env)
    found: list[VOMSServer] = []
    for location in locations:
        for server in _read_location(Path(location), required):
            if server not in found:
                found.append(server)
    return found


def _configured(environ: Mapping[str, str]) -> tuple[list[str], bool]:
    """The ``vomses`` locations to read, and whether each must exist.

    A location named in the environment is a statement that it is there, so
    a typo in it is an error; the defaults are only candidates.
    """
    named = [
        part.strip()
        for variable in _VOMSES_VARIABLES
        for part in environ.get(variable, "").split(os.pathsep)
        if part.strip()
    ]
    if named:
        return named, True
    home = environ.get("HOME") or os.path.expanduser("~")
    defaults = [f"{home}/.voms/vomses", f"{home}/.glite/vomses", f"{home}/.arc/vomses"]
    defaults += ["/etc/vomses", *credentials._candidates("vomses")]
    return defaults, False


def _read_location(location: Path, required: bool) -> list[VOMSServer]:
    """The servers in one ``vomses`` file, or in every visible file of a directory."""
    if location.is_dir():
        files = _voms._trust_files(location)
    elif location.is_file():
        files = [location]
    elif required:
        raise VOMSConfigError(f"the vomses configuration {location} does not exist")
    else:
        return []
    servers: list[VOMSServer] = []
    for file in files:
        try:
            text = file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise VOMSConfigError(f"cannot read the vomses file {file}: {exc}") from exc
        servers.extend(parse_vomses(text, str(file)))
    return servers


def servers_for(name: str, servers: Iterable[VOMSServer]) -> list[VOMSServer]:
    """The servers to ask for ``name``: those with that alias, else that VO name.

    ``voms-proxy-init -voms atlas`` matches the alias (the first field)
    first; a VO configured under another alias is still found by its name.
    Raises :class:`VOMSConfigError` when neither matches.
    """
    pool = list(servers)
    chosen = [server for server in pool if server.alias == name]
    chosen = chosen or [server for server in pool if server.vo == name]
    if not chosen:
        where = "anywhere" if not pool else "among the configured servers"
        raise VOMSConfigError(
            f"no VOMS server is configured for {name!r} {where}; install the VO's vomses "
            "file in ~/.voms/vomses or /etc/vomses, or point X509_VOMSES at it"
        )
    return chosen


def ac_extension(acs: Sequence[bytes]) -> bytes:
    """The VOMS AC proxy extension (complete DER ``Extension``) holding ``acs``.

    :func:`xrdsec.proxies.voms_extension`; ready for
    :func:`~xrdsec.proxies.issue_proxy`'s ``extra_extensions``.
    :func:`~xrdsec.proxies.create_proxy` takes the ACs directly.
    """
    return voms_extension(acs)


def fetch_ac(
    servers: Sequence[VOMSServer],
    credential: ProxyCredential,
    *,
    fqans: Sequence[str] = (),
    lifetime: datetime.timedelta | float | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    ca_path: str | None = None,
    system_ca: bool = False,
    x509_strict: bool = True,
) -> bytes:
    """An attribute certificate (DER) from the first of ``servers`` that issues one.

    ``servers`` are one VO's (:func:`servers_for`), asked in order.
    ``credential`` authenticates the request - the user certificate and key
    as :func:`~xrdsec.proxies.load_credential` gives them, or an
    existing proxy; the AC is issued to the user behind it. ``fqans`` asks
    for groups and roles (``/atlas/Role=production``); none asks for the
    VO's defaults. ``lifetime`` asks for the AC's validity (the server may
    shorten it, and says so in a :class:`VOMSWarning`). ``ca_path`` is the
    CA directory that authenticates the server (default
    ``$X509_CERT_DIR``, else ``grid-security/certificates``) and also
    validates the AC; ``system_ca`` adds the operating system's store, for an
    IAM instance with a commercial certificate. ``x509_strict=False`` is
    :func:`xrdsec.tls.client_context`'s: Python 3.13's RFC 5280 strict
    checks off for the TLS connection to the server, so a tool that never
    applies them (ARC, gfal2) can reach the VOMS servers it reaches
    everything else with; on by default, as before. It does not touch the
    AC check, which is :mod:`xrdsec.voms`'s own.

    Raises :class:`VOMSRefusedError` for a server's refusal,
    :class:`VOMSUnavailableError` when every server failed (each failure in
    its message), :class:`VOMSConfigError` for an empty ``servers``, and
    :class:`ValueError` for a malformed FQAN.
    """
    if not servers:
        raise VOMSConfigError("there is no VOMS server to ask")
    query = _query(fqans, lifetime)
    context = _context(credential, ca_path, system_ca, x509_strict)
    failures: list[str] = []
    for server in servers:
        try:
            ac = _ask(server, query, context, timeout)
            _check(ac, credential, server, ca_path)
        except _Retry as exc:
            failures.append(f"{server.address}: {exc}")
            continue
        return ac
    raise VOMSUnavailableError(servers[0].vo, failures)


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------


def _query(fqans: Sequence[str], lifetime: datetime.timedelta | float | None) -> str:
    """``?fqans=...&lifetime=...`` for ``generate-ac``; ``""`` when nothing is asked.

    The FQANs are comma-joined, as the REST interface takes them; the
    lifetime is whole seconds, at least one.
    """
    for fqan in fqans:
        _check_fqan(fqan)
    params: list[tuple[str, str]] = []
    if fqans:
        params.append(("fqans", ",".join(fqans)))
    if lifetime is not None:
        seconds = (
            lifetime.total_seconds()
            if isinstance(lifetime, datetime.timedelta)
            else float(lifetime)
        )
        params.append(("lifetime", str(max(1, int(seconds)))))
    return f"?{urllib.parse.urlencode(params)}" if params else ""


def _check_fqan(fqan: str) -> None:
    """Refuse what cannot be sent as one FQAN: it is absolute, with no comma or blank.

    A comma would split it in the comma-joined parameter, and whitespace or
    a control character is never part of a VOMS group or role name.
    """
    if not fqan.startswith("/") or any(c == "," or c.isspace() or ord(c) < 32 for c in fqan):
        raise ValueError(f"not a VOMS FQAN: {fqan!r} (expected e.g. /vo/group/Role=role)")


def _context(
    credential: ProxyCredential, ca_path: str | None, system_ca: bool, strict: bool = True
) -> ssl.SSLContext:
    """A client TLS context that trusts the grid CAs and presents ``credential``.

    :func:`xrdsec.tls.client_context` - the one builder every connection
    in the package uses - with the credential handed over in memory
    (``credential_pem``): its key goes to OpenSSL through a pipe and is never
    written. The CA directory defaults to the grid's
    (:func:`xrdsec.credentials.grid_ca_path`) rather than the system store,
    because VOMS servers carry IGTF host certificates.
    """
    from .tls import client_context

    try:
        return client_context(
            credential_pem=credential.to_pem(),
            ca_path=ca_path or credentials.grid_ca_path(),
            system_ca=system_ca,
            x509_strict=strict,
        )
    except (ssl.SSLError, OSError) as exc:
        raise VOMSError(f"cannot present {credential.subject} to a VOMS server: {exc}") from exc


def _ask(server: VOMSServer, query: str, context: ssl.SSLContext, timeout: float) -> bytes:
    """One ``generate-ac`` request to ``server``; the AC's DER, or :class:`_Retry`.

    Any failure to connect, to complete TLS (an untrusted or misnamed server
    certificate included) or to read the answer is the server's, and the next
    one is asked.
    """
    connection = http.client.HTTPSConnection(
        server.host, server.port, context=context, timeout=timeout
    )
    try:
        connection.request(
            "GET",
            f"/generate-ac{query}",
            headers={"Accept": "application/xml", "User-Agent": f"xrdsec/{__version__}"},
        )
        response = connection.getresponse()
        status, body = response.status, response.read(_MAX_ANSWER + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise _Retry(_failure(exc)) from exc
    finally:
        connection.close()
    return _answer(server, status, body)


def _failure(exc: BaseException) -> str:
    """A short reason for a transport failure, naming the TLS verdict when there is one."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"its certificate is not trusted ({exc.verify_message})"
    return str(exc) or type(exc).__name__


def _answer(server: VOMSServer, status: int, body: bytes) -> bytes:
    """The AC in a ``<voms>`` answer, or the refusal / retry the answer amounts to.

    The REST answer is ``<voms><ac>BASE64</ac><warning>...</warning></voms>``
    on success and ``<voms><error><code>..</code><message>..</message>
    </error></voms>`` otherwise (HTTP 4xx/5xx). The server's warnings are
    passed on whatever else it said.
    """
    root = _document(status, body)
    for warning in root.iter("warning"):
        text = " ".join((warning.text or "").split())
        if text:
            warnings.warn(VOMSWarning(f"{server.address}: {text}"), stacklevel=4)
    error = root.find("error")
    if error is not None:
        _refusal(server, status, error)
    if status != 200:
        raise _Retry(f"HTTP {status}")
    return _decoded(root.findtext("ac") or "")


def _document(status: int, body: bytes) -> ET.Element:
    """The ``<voms>`` element of an answer; :class:`_Retry` for anything else.

    Anything that is not such a document - a proxy's HTML error page, a
    legacy server's binary reply, something enormous - is a failed server.
    The XML parser refuses document type declarations, so a hostile server
    cannot expand entities in this process.
    """
    if len(body) > _MAX_ANSWER:
        raise _Retry(f"the answer is larger than {_MAX_ANSWER} bytes")
    try:
        root = fromstring(body)
    except (UnsafeXML, SyntaxError):
        raise _Retry(f"HTTP {status} without a VOMS answer") from None
    if root.tag != "voms":
        raise _Retry(f"HTTP {status} without a VOMS answer")
    return root


def _decoded(text: str) -> bytes:
    """The DER of the base64 ``<ac>`` text (line breaks allowed); :class:`_Retry` if none."""
    encoded = "".join(text.split())
    if not encoded:
        raise _Retry("the answer holds no attribute certificate")
    try:
        return base64.b64decode(encoded, validate=True)
    except binascii.Error:
        raise _Retry("the attribute certificate is not valid base64") from None


def _refusal(server: VOMSServer, status: int, error: ET.Element) -> None:
    """Raise what an ``<error>`` means: :class:`_Retry` for the server's fault, else a refusal."""
    code = (error.findtext("code") or "").strip()
    reason = " ".join((error.findtext("message") or "").split())
    if code in _RETRYABLE or status >= 500:
        raise _Retry(": ".join(part for part in (code or f"HTTP {status}", reason) if part))
    raise VOMSRefusedError(server, code, reason)


# ---------------------------------------------------------------------------
# The answer, checked as the proxy carrying it will be
# ---------------------------------------------------------------------------


def _check(ac: bytes, credential: ProxyCredential, server: VOMSServer, ca_path: str | None) -> None:
    """Validate ``ac`` locally: :class:`_Retry` if it does not decode, a warning if untrusted.

    The AC is checked inside a throwaway proxy of ``credential`` - signed in
    memory, never shown to anyone - because that is exactly the shape
    :func:`~xrdsec.voms.validate_voms` judges: the holder binding
    walks the chain to the user certificate, so the AC is tested against the
    identity it will travel with. A credential that cannot issue a proxy (a
    limited one at path length zero) leaves the AC unchecked, with a warning.
    """
    try:
        extension = voms_extension([ac])
    except ValueError:
        raise _Retry("the attribute certificate does not decode") from None
    leaf = credential.chain[0]
    try:
        carrier = issue_proxy(
            credential,
            certificate_fields(leaf.der)["spki"],
            extra_extensions=[extension],
            lifetime=60,
        )
    except ProxyError as exc:
        _warn(f"the attribute certificate from {server.address} was not checked: {exc}")
        return
    result = _voms.validate_voms((carrier, *credential.chain), ca_path=ca_path)
    if not result.entries:
        raise _Retry("the attribute certificate does not decode")
    entry = result.entries[0]
    if not entry.verified:
        _warn(f"the attribute certificate from {server.address} does not verify: {entry.message}")
    if entry.vo != server.vo:
        _warn(
            f"{server.address} issued an attribute certificate for {entry.vo!r}, not {server.vo!r}"
        )


def _warn(message: str) -> None:
    """Emit a :class:`VOMSWarning` attributed to :func:`fetch_ac`'s caller."""
    warnings.warn(VOMSWarning(message), stacklevel=4)
