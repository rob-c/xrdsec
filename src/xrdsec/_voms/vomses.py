"""Syntax checks for ``vomses`` endpoint configuration files - the one parser.

A ``vomses`` file tells a proxy-*request* tool which VOMS servers to contact:
five quoted fields per line, ``"ALIAS" "HOST" "PORT" "SERVER DN" "VO"`` - the
alias (nickname) ``voms-proxy-init -voms`` matches first, then the VO name
that ends up in the attribute certificate (they are usually equal). It is not
trust material and is never needed to *use* an existing proxy, which is why it
is kept apart from :mod:`.trust`.

:func:`vomses_fields` is the single line parser: the facade's public
``check_vomses`` walks the configured file or directory with it (the per-file
and per-line checks are here), and :func:`xrdsec.voms_client.parse_vomses`
builds its :class:`~xrdsec.voms_client.VOMSServer` list from the same
fields, so a line the preflight accepts is exactly a line the client can use.
No network I/O happens: a clean result means the local configuration is
well-formed, not that an endpoint is reachable.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from .diagnostics import _io_problem, _problem
from .model import VOMSDiagnostic
from .trust import _safe_vo


def _check_vomses_file(path: Path, diagnostics: list[VOMSDiagnostic]) -> int:
    """Check every line of one ``vomses`` file; return how many endpoints it defines.

    Each malformed line gets its own diagnostic with its line number, and the
    remaining lines are still counted, so one typo does not hide the rest of
    a VO's configuration. An unreadable or non-UTF-8 file counts zero.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        _io_problem(diagnostics, "vomses_file", path, exc)
        return 0
    except UnicodeError:
        _problem(
            diagnostics,
            "vomses_corrupt",
            f"VOMS endpoint file '{path}' is not valid UTF-8 text. "
            "Reinstall the VO's official vomses configuration.",
            str(path),
        )
        return 0
    endpoints = 0
    for number, line in enumerate(lines, 1):
        try:
            endpoints += int(_vomses_line(line))
        except ValueError:
            _problem(
                diagnostics,
                "vomses_malformed",
                f"VOMS endpoint file '{path}', line {number}, is malformed. Expected "
                'five fields: "ALIAS" "HOST" "PORT" "SERVER DN" "VO", with a port from '
                "1 to 65535. Reinstall the VO's official vomses configuration.",
                str(path),
            )
    return endpoints


def _vomses_line(line: str) -> bool:
    """Whether ``line`` defines an endpoint: ``True`` for one, ``False`` for blank/comment.

    Raises ``ValueError`` for a malformed line; see :func:`vomses_fields`.
    """
    return vomses_fields(line) is not None


def vomses_fields(line: str) -> tuple[str, str, int, str, str] | None:
    """``(alias, host, port, server DN, VO)`` from one line; ``None`` for blank/comment.

    Fields are split with :func:`shlex.split` because the server DN is a quoted
    string containing spaces, and ``#`` starts a comment. A wrong field count,
    an empty or control-character field, an unsafe alias or VO name (either
    may become a ``vomsdir`` path component later) or a port outside 1-65535
    raises ``ValueError`` - including a non-numeric port, via ``int``, and an
    unterminated quote, via :func:`shlex.split`.
    """
    fields = shlex.split(line, comments=True)
    if not fields:
        return None
    if (
        len(fields) != 5
        or not all(_endpoint_text(field) for field in fields)
        or not (_safe_vo(fields[0]) and _safe_vo(fields[4]))
    ):
        raise ValueError("invalid fields")
    port = int(fields[2])
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return fields[0], fields[1], port, fields[3], fields[4]


def _endpoint_text(value: str) -> bool:
    """Whether a field is non-blank and free of ASCII control characters."""
    return bool(value.strip()) and not any(ord(char) < 32 or ord(char) == 127 for char in value)
