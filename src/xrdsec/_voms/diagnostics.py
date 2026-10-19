"""Actionable, non-secret messages for VOMS trust and configuration failures.

A failed trust check is reported twice: once as the entry's
:class:`~xrdsec.voms.VOMSStatus` (the first failed check, for
programs) and once as a list of :class:`~xrdsec.voms.VOMSDiagnostic`
records (a stable ``code`` plus a sentence telling a person what to fix). The
helpers here build those records. They are separate from the checks in
:mod:`.trust`, :mod:`.policy` and :mod:`.vomses` so that the wording - which
users read and xgfalclient shows - lives in one place, and so a check can stay
a short sequence of decisions rather than a page of message templates.

Every helper accepts ``diagnostics=None`` and then records nothing: the same
checks run on paths that only want the verdict.
"""

from __future__ import annotations

import time
from pathlib import Path

from .model import Certificate, VOMSDiagnostic


def _problem(
    diagnostics: list[VOMSDiagnostic] | None,
    code: str,
    message: str,
    path: str = "",
    error_number: int | None = None,
) -> None:
    """Append one diagnostic, or do nothing when the caller only wants a verdict."""
    if diagnostics is not None:
        diagnostics.append(VOMSDiagnostic(code, message, path, error_number))


def _io_problem(
    diagnostics: list[VOMSDiagnostic] | None, role: str, path: Path, exc: OSError
) -> None:
    """Turn an ``OSError`` on a trust or configuration path into a diagnostic.

    The code is ``<role>_<reason>`` (``ca_file_permissions``,
    ``lsc_file_missing``, ...), stable for programs and tests; the message names
    the path and the fix in plain words. ``errno`` is kept for callers that map
    failures to exit codes. The permissions advice warns against
    world-readable private keys because "make it readable" is the fix people
    otherwise reach for, and the same folders often hold ``hostkey.pem``.
    """
    label = {
        "ca_directory": "CA certificates folder",
        "ca_file": "CA certificate file",
        "voms_directory": "VO trust folder",
        "lsc_file": "VOMS .lsc trust file",
        "legacy_signer_file": "VOMS signing certificate file",
        "vomses_path": "VOMS endpoint configuration",
        "vomses_directory": "VOMS endpoint folder",
        "vomses_file": "VOMS endpoint file",
    }.get(role, "configuration path")
    if isinstance(exc, PermissionError):
        reason, fix = (
            "permissions",
            "Ask the owner or administrator to allow your account to read the file "
            "and access its parent directories. Do not make private keys world-readable.",
        )
        description = "Your account does not have permission to read"
    elif isinstance(exc, FileNotFoundError):
        reason, fix = (
            "missing",
            "Install the official trust/configuration files or correct the path.",
        )
        description = "Cannot find"
    elif isinstance(exc, (NotADirectoryError, IsADirectoryError)):
        reason, fix = (
            "wrong_type",
            "Check that the configured path names the right file or directory.",
        )
        description = "The configured path has the wrong file type:"
    else:
        reason, fix = "unreadable", "Check the path and filesystem, then try again."
        description = "Cannot read"
    _problem(
        diagnostics,
        f"{role}_{reason}",
        f"{description} {label} '{path}'. {fix}",
        str(path),
        exc.errno,
    )


def _certificate_time_problem(
    diagnostics: list[VOMSDiagnostic] | None,
    certificate: Certificate,
    now: float,
    path: str,
    role: str,
) -> None:
    """Report a CA or VOMS signer certificate that is expired or not yet valid.

    The boundary is printed in UTC with a hint to check the local clock,
    because a "not valid before" on a freshly issued certificate is far more
    often a skewed client clock than a bad certificate.
    """
    expired = now >= certificate.not_after
    boundary = certificate.not_after if expired else certificate.not_before
    stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(boundary))
    state = "expired at" if expired else "is not valid before"
    label = "CA certificate" if role == "ca_certificate" else "VO signing certificate"
    fix = (
        "Update the trusted CA bundle."
        if role == "ca_certificate"
        else "Ask the VO administrator to check the signing certificate and obtain a new proxy."
    )
    _problem(
        diagnostics,
        f"{role}_{'expired' if expired else 'not_yet_valid'}",
        f"{label} '{certificate.subject}' {state} {stamp} (trust path: '{path}'). {fix} "
        "If the date looks wrong, check your computer's clock.",
        path,
    )
