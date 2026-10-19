"""Local trust material: the CA directory and the ``vomsdir`` LSC/legacy files.

Two questions are answered here, both from files on disk and never from the
network. :func:`_trusted_chain` asks whether the AC's embedded signer chain
leads, by signature and validity, to a hash-named anchor in the CA directory
(``X509_CERT_DIR``). :func:`_lsc_matches` asks whether the VO's ``vomsdir``
(``X509_VOMS_DIR``) names that signer, either through a ``.lsc`` file of
subject/issuer DN pairs or through a legacy copy of the signer certificate.
:mod:`.policy` calls both, after the AC's intrinsic checks have passed;
unreadable, missing or damaged files become diagnostics via
:mod:`.diagnostics`.

Two names are deliberately looked up through the public
:mod:`xrdsec.voms` module at call time rather than imported here:
``load_certificates`` and ``_trust_files``. Callers and both projects' test
suites replace them on that module (``monkeypatch.setattr(voms, ...)``) to
simulate damaged files or prove that an invalid VO name never touches the
filesystem, and that only works if the lookup goes through the facade.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from ..der import DERError
from ..x509 import Name, verify_issued
from .diagnostics import _certificate_time_problem, _io_problem, _problem
from .model import _MAX_CHAIN_DEPTH, Certificate, VOMSDiagnostic


def _trusted_chain(
    embedded: Sequence[Certificate],
    ca_path: str,
    now: float,
    diagnostics: list[VOMSDiagnostic] | None = None,
) -> bool:
    """Whether the AC's signer chain leads to a valid trust anchor in ``ca_path``.

    ``embedded[0]`` is the signer; the rest of ``embedded`` and every anchor in
    the CA directory are candidate issuers. Each link must be in its validity
    window *now* and be signed by a candidate whose subject is its issuer
    (:func:`~xrdsec.x509.verify_issued` checks the signature), and the
    walk succeeds only on reaching a certificate that is byte-for-byte one of
    the local anchors - an embedded self-signed CA proves nothing, because the
    attacker chose it. The walk is bounded by ``_MAX_CHAIN_DEPTH`` so a loop of
    cross-signed certificates terminates. CA extension constraints and CRLs are
    not checked; the :mod:`xrdsec.voms` docstring states that limit.
    """
    origins: dict[bytes, str] = {}
    anchors = _load_anchors(ca_path, diagnostics, origins)
    if not anchors:
        return False
    candidates = [*embedded[1:], *anchors]
    current = embedded[0]
    for _ in range(_MAX_CHAIN_DEPTH):
        if not current.not_before <= now < current.not_after:
            _certificate_time_problem(diagnostics, current, now, ca_path, "signer_certificate")
            return False
        issuer = _trusted_issuer(current, candidates)
        if issuer is None:
            _problem(
                diagnostics,
                "ca_chain_incomplete",
                f"Cannot link VOMS signer '{current.subject}' to a trusted CA in '{ca_path}'. "
                "Check that the correct CA bundle and intermediate certificates are installed.",
                ca_path,
            )
            return False
        if _is_anchor(issuer, anchors):
            if issuer.not_before <= now < issuer.not_after:
                return True
            _certificate_time_problem(
                diagnostics, issuer, now, origins[issuer.der], "ca_certificate"
            )
            return False
        current = issuer
    _problem(
        diagnostics,
        "ca_chain_depth",
        "The VOMS signing certificate chain is too long or contains a loop. "
        "Check the intermediate certificates in the VO's configuration.",
        ca_path,
    )
    return False


def _trusted_issuer(
    certificate: Certificate, candidates: Sequence[Certificate]
) -> Certificate | None:
    """The first candidate whose subject is ``certificate``'s issuer and whose key signed it.

    Name match first, signature second: the name check is cheap and rules out
    almost every candidate in a large CA directory before any public-key work.
    """
    for issuer in candidates:
        if issuer.subject == certificate.issuer and verify_issued(certificate, issuer):
            return issuer
    return None


def _is_anchor(certificate: Certificate, anchors: Sequence[Certificate]) -> bool:
    """Whether ``certificate`` is, byte for byte, one of the local anchors."""
    return any(certificate.der == anchor.der for anchor in anchors)


def _load_anchors(
    directory: str,
    diagnostics: list[VOMSDiagnostic] | None = None,
    origins: dict[bytes, str] | None = None,
) -> list[Certificate]:
    """Every certificate in the hash-named files (``12345678.0``) of a CA directory.

    Only OpenSSL ``c_rehash``-style names are read, as the grid middleware does;
    ``.pem``, ``.signing_policy`` and ``.crl_r0`` files sit next to them in an
    IGTF bundle and are not anchors. ``origins`` (when given) records the file
    each certificate came from, first file wins, so an expired-CA diagnostic can
    name the file to replace. Names are sorted so the walk, and hence which
    file a diagnostic names, does not depend on directory order.
    """
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        _io_problem(diagnostics, "ca_directory", Path(directory), exc)
        return []
    found: list[Certificate] = []
    for name in names:
        if not _is_anchor_filename(name):
            continue
        path = Path(directory, name)
        certificates = _read_anchor_file(path, diagnostics)
        found.extend(certificates)
        if origins is not None:
            for certificate in certificates:
                origins.setdefault(certificate.der, str(path))
    if not found:
        _problem(
            diagnostics,
            "ca_store_empty",
            f"No usable CA certificates were found in '{directory}'. Install the trusted "
            "CA bundle there; this directory needs hash-named certificate files such as "
            "'12345678.0'.",
            directory,
        )
    return found


def _is_anchor_filename(name: str) -> bool:
    """Whether ``name`` has the ``<8-character hash>.<digits>`` subject-hash shape."""
    stem, dot, index = name.partition(".")
    return bool(dot and index.isdigit() and len(stem) == 8)


def _read_anchor_file(path: Path, diagnostics: list[VOMSDiagnostic] | None) -> list[Certificate]:
    """The certificates in one CA file, or ``[]`` with a diagnostic if it cannot be used.

    A damaged file is reported and skipped rather than failing the whole
    directory: one broken CA must not make every other VO untrusted.
    """
    from .. import voms  # through the facade, where callers patch it; see the module docstring

    try:
        data = path.read_bytes()
    except OSError as exc:
        _io_problem(diagnostics, "ca_file", path, exc)
        return []
    try:
        certificates: list[Certificate] = list(voms.load_certificates(data))
    except (DERError, IndexError, ValueError):
        certificates = []
    if not certificates:
        _problem(
            diagnostics,
            "ca_file_corrupt",
            f"CA certificate file '{path}' is empty, damaged or not a certificate. "
            "Reinstall it from your trusted CA bundle.",
            str(path),
        )
    return certificates


def _lsc_matches(
    directory: str,
    vo: str,
    chain: Sequence[Certificate],
    diagnostics: list[VOMSDiagnostic] | None = None,
) -> bool:
    """Whether ``directory/<vo>/`` vouches for this signer chain.

    Either a ``.lsc`` file lists the chain's DNs (the modern form, which
    survives a VOMS host certificate renewal), or a legacy copy of the signer's
    own certificate sits in the VO directory or at the ``vomsdir`` top level.
    The VO name comes from the AC itself, so it is checked with
    :func:`_safe_vo` *before* it is joined to a path: a VO called ``../..``
    must not be able to point trust at an arbitrary directory. Diagnostics are
    buffered and published only if nothing matched, so one stale ``.lsc`` next
    to a good one is not reported as a failure.
    """
    from .. import voms  # through the facade, where callers patch it; see the module docstring

    if not _safe_vo(vo) or not chain:
        _problem(diagnostics, "vo_name_invalid", "The VOMS VO name or signing chain is invalid.")
        return False
    pending: list[VOMSDiagnostic] = []
    vo_path = Path(directory, vo)
    files = voms._trust_files(vo_path, pending)
    lsc_files = [path for path in files if path.name.endswith(".lsc")]
    if _voms_files_match(Path(directory), files, lsc_files, chain, pending):
        return True
    if not lsc_files:
        _problem(
            pending,
            "lsc_missing",
            f"No .lsc trust file was found for VO '{vo}' in '{vo_path}'. "
            "Install the VO's official .lsc file or correct X509_VOMS_DIR.",
            str(vo_path),
        )
    if diagnostics is not None:
        diagnostics.extend(pending)
    return False


def _voms_files_match(
    root: Path,
    files: Sequence[Path],
    lsc_files: Sequence[Path],
    chain: Sequence[Certificate],
    diagnostics: list[VOMSDiagnostic],
) -> bool:
    """Whether any ``.lsc`` file, or failing that any legacy certificate file, matches."""
    return any(_lsc_file_matches(path, chain, diagnostics) for path in lsc_files) or (
        _legacy_matches(_legacy_files(root, files), chain[0], diagnostics)
    )


def _safe_vo(vo: str) -> bool:
    """Whether a VO name from an AC is safe to use as one directory component.

    VO names are DNS-like (``atlas``, ``vo.example.org``); anything with a path
    separator, or exactly ``.``/``..``, is refused before touching the disk.
    """
    return (
        bool(vo) and vo not in (".", "..") and all(char.isalnum() or char in "_.-" for char in vo)
    )


def _trust_files(
    directory: Path,
    diagnostics: list[VOMSDiagnostic] | None = None,
    role: str = "voms_directory",
) -> list[Path]:
    """The visible regular files in a trust directory, sorted; ``[]`` if unreadable.

    Dot-files are skipped because package managers and editors leave
    ``.rpmnew``-style and swap files there; sorting makes the match order, and
    so the diagnostics, reproducible.
    """
    try:
        return sorted(
            path for path in directory.iterdir() if path.is_file() and not path.name.startswith(".")
        )
    except OSError as exc:
        _io_problem(diagnostics, role, directory, exc)
        return []


def _legacy_files(root: Path, vo_files: Sequence[Path]) -> list[Path]:
    """Candidate legacy signer files: the VO's own directory first, then the ``vomsdir`` root.

    Before ``.lsc`` files existed, ``vomsdir`` held copies of the VOMS servers'
    host certificates, sometimes per VO and sometimes flat; both layouts are
    still found on long-lived installations.
    """
    from .. import voms  # through the facade, where callers patch it; see the module docstring

    found = [path for path in vo_files if not path.name.endswith(".lsc")]
    found.extend(path for path in voms._trust_files(root) if not path.name.endswith(".lsc"))
    return found


def _legacy_matches(
    paths: Sequence[Path],
    signer: Certificate,
    diagnostics: list[VOMSDiagnostic] | None = None,
) -> bool:
    """Whether any of ``paths`` contains a certificate identical to ``signer``.

    Byte equality, not name equality: a legacy file pins one exact certificate,
    which is why it breaks on every VOMS host certificate renewal and why
    ``.lsc`` files replaced it.
    """
    from .. import voms  # through the facade, where callers patch it; see the module docstring

    for path in paths:
        try:
            certificates = voms.load_certificates(path.read_bytes())
            if any(certificate.der == signer.der for certificate in certificates):
                return True
        except OSError as exc:
            _io_problem(diagnostics, "legacy_signer_file", path, exc)
            continue
        except (DERError, IndexError, ValueError):
            _problem(
                diagnostics,
                "legacy_signer_file_corrupt",
                f"Legacy VOMS signer file '{path}' is damaged or is not a certificate. "
                "Reinstall the VO's official trust configuration.",
                str(path),
            )
    return False


def _lsc_file_matches(
    path: Path,
    chain: Sequence[Certificate],
    diagnostics: list[VOMSDiagnostic] | None = None,
) -> bool:
    """Whether one ``.lsc`` file describes ``chain``, with a diagnostic when it does not.

    The format is alternating subject and issuer DN lines, starting at the
    VOMS server's certificate and going up towards the CA; an odd number of
    lines is a truncated file, not a partial match.
    """
    lines = _read_lsc_lines(path, diagnostics)
    if lines is None:
        return False
    pairs = len(lines) // 2
    if not pairs or len(lines) % 2:
        _problem(
            diagnostics,
            "lsc_corrupt",
            f"VOMS trust file '{path}' is empty or incomplete. Reinstall the VO's official "
            ".lsc file; it needs two lines per subject/issuer pair.",
            str(path),
        )
        return False
    matches = _lsc_lines_match(lines, chain)
    if not matches:
        _problem(
            diagnostics,
            "lsc_mismatch",
            f"VOMS trust file '{path}' does not match this proxy's VO signing server. "
            "Obtain the current .lsc file from the VO administrator.",
            str(path),
        )
    return matches


def _read_lsc_lines(path: Path, diagnostics: list[VOMSDiagnostic] | None) -> list[str] | None:
    """The meaningful lines of a ``.lsc`` file, or ``None`` if it cannot be read.

    Blank lines and ``#`` comments are dropped. The LSC format also allows
    alternative chains separated by a ``------ NEXT CHAIN ------`` line; this
    reader does not split on it, so such a file is reported as incomplete
    rather than partly matched.
    """
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError as exc:
        _io_problem(diagnostics, "lsc_file", path, exc)
        return None
    except UnicodeError:
        _problem(
            diagnostics,
            "lsc_corrupt",
            f"VOMS trust file '{path}' is not valid UTF-8 text. "
            "Reinstall the VO's official .lsc file.",
            str(path),
        )
        return None


def _lsc_lines_match(lines: Sequence[str], chain: Sequence[Certificate]) -> bool:
    """Whether each subject/issuer pair matches the chain certificate at the same position.

    A file may describe fewer certificates than the AC embeds (VOMS servers
    often include the root too), but never more.
    """
    pairs = len(lines) // 2
    return pairs <= len(chain) and all(
        _dn_matches(lines[2 * index], chain[index].subject)
        and _dn_matches(lines[2 * index + 1], chain[index].issuer)
        for index in range(pairs)
    )


def _dn_matches(value: str, name: Name) -> bool:
    """Whether an ``.lsc`` DN names ``name``, in OpenSSL slash form or RFC 2253 form.

    VOs publish both: ``/DC=ch/DC=cern/CN=voms.cern.ch`` is the historical
    OpenSSL one-line form, and newer tooling writes the comma-separated,
    most-specific-first RFC 2253 rendering.
    """
    return value == str(name) or value == _rfc2253(name)


def _rfc2253(name: Name) -> str:
    """``name`` in RFC 2253 order (most specific RDN first) with RFC 2253 escaping."""
    return ",".join(f"{key}={_escape_dn(value)}" for key, value in reversed(name.rdns))


def _escape_dn(value: str) -> str:
    """Escape one attribute value per RFC 2253 section 2.4.

    The special characters get a backslash anywhere; a leading space or ``#``
    and a trailing space are escaped only at those positions, because that is
    where they would otherwise be stripped or read as a hex-encoded value.
    """
    escaped = "".join("\\" + char if char in ',+"\\<>;=' else char for char in value)
    if escaped.startswith((" ", "#")):
        escaped = "\\" + escaped
    if escaped.endswith(" "):
        escaped = escaped[:-1] + "\\ "
    return escaped
