"""VOMS attribute certificates, using maintained ASN.1 and crypto backends.

VOMS puts RFC 5755 attribute certificates (ACs) in extension
``1.3.6.1.4.1.8005.100.100.5`` of an RFC 3820 proxy.  The proxy is already
sent byte-for-byte by GSI and mutual TLS; this module supplies the client-side
piece historically provided by ``libvomsapi``: inspect the VO/FQAN claims and,
when trust directories are supplied, decide whether they are trustworthy.

The parsing and crypto dependencies support macOS. The checks
are modelled on BriX: holder binding, validity, embedded signer, signature,
issuer, targets, CA signatures/dates, and ``vomsdir`` LSC binding. This is not
yet a full RFC 5280 path validator: CA extension constraints and CRLs are not
validated. Applications needing that policy must not treat this as a complete
replacement for an established certificate path validator.

How this module is organised: it is the public facade. The entry points -
:func:`inspect_voms`, :func:`validate_voms`, :func:`check_vomses` and the
default trust paths - are defined here; the machinery behind them lives in the
private :mod:`xrdsec._voms` package (the data model, DER decoding of
the ACs, the validation policy, CA/``vomsdir`` trust files, diagnostics
wording and ``vomses`` syntax). Every name those modules define, and the
helpers this module used to import, is re-exported below, so
``from xrdsec.voms import X`` keeps working for every ``X`` the
single-module layout had. A patch on this module reaches a caller only when
the caller looks the name up here: the entry points below do, and so does
``_voms.trust`` for ``load_certificates`` and ``_trust_files``; patch a
private helper in its own ``_voms`` module otherwise.
"""

from __future__ import annotations

# The stdlib names the single-module layout imported are kept as attributes
# too: tests patch through them (``voms.time``), and other code may.
import os as os
import shlex as shlex
import socket as socket
import stat
import time
from collections.abc import Iterable as Iterable
from collections.abc import Mapping as Mapping
from collections.abc import Sequence
from dataclasses import dataclass as dataclass
from dataclasses import field as field
from dataclasses import replace
from enum import Enum as Enum
from pathlib import Path
from typing import Protocol as Protocol

from ._voms.ac import _ac_extensions as _ac_extensions
from ._voms.ac import _ac_holder as _ac_holder
from ._voms.ac import _ac_parts as _ac_parts
from ._voms.ac import _ac_signature as _ac_signature
from ._voms.ac import _ac_validity as _ac_validity
from ._voms.ac import _attributes as _attributes
from ._voms.ac import _authority_key_id as _authority_key_id
from ._voms.ac import _certificate_extension as _certificate_extension
from ._voms.ac import _decode_ac as _decode_ac
from ._voms.ac import _decode_extension as _decode_extension
from ._voms.ac import _embedded_certificates as _embedded_certificates
from ._voms.ac import _encoded as _encoded
from ._voms.ac import _extension_fields as _extension_fields
from ._voms.ac import _extension_map as _extension_map
from ._voms.ac import _extension_value as _extension_value
from ._voms.ac import _first_directory_name as _first_directory_name
from ._voms.ac import _fqan_syntax as _fqan_syntax
from ._voms.ac import _general_name_text as _general_name_text
from ._voms.ac import _generic_attributes as _generic_attributes
from ._voms.ac import _has_unknown_critical as _has_unknown_critical
from ._voms.ac import _is_fqan_attribute as _is_fqan_attribute
from ._voms.ac import _one as _one
from ._voms.ac import _policy_authority as _policy_authority
from ._voms.ac import _targets as _targets
from ._voms.ac import _time as _time
from ._voms.ac import _valid_fqan as _valid_fqan
from ._voms.ac import _voms_extension as _voms_extension
from ._voms.diagnostics import _certificate_time_problem as _certificate_time_problem
from ._voms.diagnostics import _io_problem as _io_problem
from ._voms.diagnostics import _problem as _problem
from ._voms.model import _AKI_OID as _AKI_OID
from ._voms.model import _KNOWN_AC_EXTENSIONS as _KNOWN_AC_EXTENSIONS
from ._voms.model import _MAX_AC_ENTRIES as _MAX_AC_ENTRIES
from ._voms.model import _MAX_CHAIN_DEPTH as _MAX_CHAIN_DEPTH
from ._voms.model import _NO_REV_AVAIL_OID as _NO_REV_AVAIL_OID
from ._voms.model import _SKI_OID as _SKI_OID
from ._voms.model import _TARGETS_OID as _TARGETS_OID
from ._voms.model import VOMS_AC_OID as VOMS_AC_OID
from ._voms.model import VOMS_ATTRIBUTES_OID as VOMS_ATTRIBUTES_OID
from ._voms.model import VOMS_CERTS_OID as VOMS_CERTS_OID
from ._voms.model import VOMS_FQAN_OID as VOMS_FQAN_OID
from ._voms.model import Certificate as Certificate
from ._voms.model import VOMSAttribute as VOMSAttribute
from ._voms.model import VOMSDiagnostic as VOMSDiagnostic
from ._voms.model import VOMSEntry as VOMSEntry
from ._voms.model import VOMSResult as VOMSResult
from ._voms.model import VOMSStatus as VOMSStatus
from ._voms.model import _status_message as _status_message
from ._voms.model import _unique as _unique
from ._voms.policy import _aki_matches as _aki_matches
from ._voms.policy import _algorithm_identifier as _algorithm_identifier
from ._voms.policy import _Checks as _Checks
from ._voms.policy import _claims_status as _claims_status
from ._voms.policy import _external_trust_status as _external_trust_status
from ._voms.policy import _holder_matches as _holder_matches
from ._voms.policy import _intrinsic_status as _intrinsic_status
from ._voms.policy import _is_holder as _is_holder
from ._voms.policy import _proxy_parent as _proxy_parent
from ._voms.policy import _signature_algorithm as _signature_algorithm
from ._voms.policy import _signature_digest as _signature_digest
from ._voms.policy import _signature_shape_status as _signature_shape_status
from ._voms.policy import _signature_status as _signature_status
from ._voms.policy import _signer_chain as _signer_chain
from ._voms.policy import _target_status as _target_status
from ._voms.policy import _trust_status as _trust_status
from ._voms.policy import _validate_entry as _validate_entry
from ._voms.policy import _validity_status as _validity_status
from ._voms.trust import _dn_matches as _dn_matches
from ._voms.trust import _escape_dn as _escape_dn
from ._voms.trust import _is_anchor as _is_anchor
from ._voms.trust import _is_anchor_filename as _is_anchor_filename
from ._voms.trust import _legacy_files as _legacy_files
from ._voms.trust import _legacy_matches as _legacy_matches
from ._voms.trust import _load_anchors as _load_anchors
from ._voms.trust import _lsc_file_matches as _lsc_file_matches
from ._voms.trust import _lsc_lines_match as _lsc_lines_match
from ._voms.trust import _lsc_matches as _lsc_matches
from ._voms.trust import _read_anchor_file as _read_anchor_file
from ._voms.trust import _read_lsc_lines as _read_lsc_lines
from ._voms.trust import _rfc2253 as _rfc2253
from ._voms.trust import _safe_vo as _safe_vo
from ._voms.trust import _trust_files as _trust_files
from ._voms.trust import _trusted_chain as _trusted_chain
from ._voms.trust import _trusted_issuer as _trusted_issuer
from ._voms.trust import _voms_files_match as _voms_files_match
from ._voms.vomses import _check_vomses_file as _check_vomses_file
from ._voms.vomses import _endpoint_text as _endpoint_text
from ._voms.vomses import _vomses_line as _vomses_line

# Everything below is re-exported with a redundant ``as`` so mypy's strict
# no-implicit-reexport and ruff both treat it as this module's API. Two of the
# names matter beyond imports: ``_voms.trust`` calls ``load_certificates`` and
# ``_trust_files`` through this module at call time, so patching them here
# reaches the CA-directory and ``vomsdir`` readers.
from .credentials import grid_ca_path as grid_ca_path
from .credentials import grid_voms_dir as grid_voms_dir
from .der import TAG_BIT_STRING as TAG_BIT_STRING
from .der import TAG_BOOLEAN as TAG_BOOLEAN
from .der import TAG_GENERALIZED_TIME as TAG_GENERALIZED_TIME
from .der import TAG_INTEGER as TAG_INTEGER
from .der import TAG_OCTET_STRING as TAG_OCTET_STRING
from .der import TAG_OID as TAG_OID
from .der import TAG_SEQUENCE as TAG_SEQUENCE
from .der import TAG_UTF8_STRING as TAG_UTF8_STRING
from .der import DERError as DERError
from .der import Element as Element
from .der import encode as encode
from .der import oid_string as oid_string
from .der import parse as parse
from .der import read_integer as read_integer
from .rsa import RSAPublicKey as RSAPublicKey
from .signatures import signature_label as signature_label
from .signatures import verify_signature as verify_signature
from .x509 import Name as Name
from .x509 import certificate_fields as certificate_fields
from .x509 import decode_name as decode_name
from .x509 import extensions_of as extensions_of
from .x509 import load_certificates as load_certificates
from .x509 import parse_certificate as parse_certificate
from .x509 import verify_issued as verify_issued

__all__ = [
    "VOMS_AC_OID",
    "VOMS_FQAN_OID",
    "VOMSAttribute",
    "VOMSDiagnostic",
    "VOMSEntry",
    "VOMSResult",
    "VOMSStatus",
    "check_vomses",
    "default_ca_path",
    "default_voms_dir",
    "inspect_voms",
    "validate_voms",
]


def inspect_voms(chain: Sequence[Certificate]) -> VOMSResult:
    """Decode every VOMS AC in ``chain`` without making trust decisions.

    ``carrier`` is the certificate's index in ``chain``.  Delegated proxies
    commonly carry the AC on their parent rather than their leaf, so every
    certificate is searched.
    """
    entries: list[VOMSEntry] = []
    saw_extension = False
    failed = False
    for carrier, certificate in enumerate(chain):
        # A certificate whose extensions cannot be read, or whose VOMS
        # extension does not decode, is noted and skipped: an AC on another
        # link of the chain may still be perfectly good.
        try:
            data = _voms_extension(certificate)
        except (DERError, ValueError, IndexError):
            failed = True
            continue
        if data is None:
            continue
        saw_extension = True
        try:
            entries.extend(_decode_extension(data, carrier))
        except (DERError, ValueError, IndexError):
            failed = True
    # Anything decoded is UNCHECKED - claims, not facts. With nothing decoded,
    # a damaged extension (DECODE) is a different problem from no VOMS at all
    # (NO_EXTENSION): the first needs a new proxy, the second a VOMS-enabled one.
    status = (
        VOMSStatus.UNCHECKED
        if entries
        else (VOMSStatus.DECODE if saw_extension or failed else VOMSStatus.NO_EXTENSION)
    )
    return VOMSResult(tuple(entries), status)


def validate_voms(
    chain: Sequence[Certificate],
    *,
    ca_path: str | None = None,
    voms_dir: str | None = None,
    host: str | None = None,
    now: float | None = None,
    skew: int = 300,
) -> VOMSResult:
    """Decode and validate all VOMS ACs in a proxy chain.

    ``ca_path`` and ``voms_dir`` default through ``X509_CERT_DIR`` and
    ``X509_VOMS_DIR`` and then conventional Linux/Homebrew locations.  A
    missing directory is a failed trust check, never a silent downgrade.
    Individual ACs are independent: one good VO still verifies when another
    AC in the same proxy is bad.
    """
    decoded = inspect_voms(chain)
    if not decoded.entries:
        return decoded
    ca = ca_path or default_ca_path()
    vdir = voms_dir or default_voms_dir()
    moment = time.time() if now is None else now
    # One frozen set of inputs for every entry: all ACs in the proxy are judged
    # against the same clock reading and the same trust directories.
    checks = _Checks(ca_path=ca, voms_dir=vdir, host=host, now=moment, skew=skew)
    checked = tuple(_validate_entry(entry, chain, checks) for entry in decoded.entries)
    # One verified AC makes the proxy usable for that VO; with none, the first
    # entry's failure is the headline (each entry keeps its own status).
    good = any(entry.verified for entry in checked)
    status = VOMSStatus.OK if good else checked[0].status
    return VOMSResult(checked, status)


def default_ca_path() -> str | None:
    """Grid CA directory from the environment or Linux/Homebrew conventions."""
    return grid_ca_path()


def default_voms_dir() -> str | None:
    """VOMS LSC directory from the environment or Linux/Homebrew conventions."""
    return grid_voms_dir()


def check_vomses(path: str) -> tuple[VOMSDiagnostic, ...]:
    """Preflight endpoint configuration for obtaining a proxy, without network I/O.

    Accept a vomses file or directory of files. This is deliberately separate
    from existing-proxy validation: vomses is not CA or signer trust material,
    and is unnecessary when consuming a proxy that has already been issued.
    An empty result means the local configuration is readable and well-formed,
    not that a remote endpoint is reachable or trusted.
    """
    configured = Path(path)
    diagnostics: list[VOMSDiagnostic] = []
    # One stat decides the shape: a directory of per-VO files (the
    # ``/etc/vomses/`` layout) or a single combined file (``~/.voms/vomses``).
    try:
        mode = configured.stat().st_mode
    except OSError as exc:
        _io_problem(diagnostics, "vomses_path", configured, exc)
        if isinstance(exc, FileNotFoundError):
            issue = diagnostics[-1]
            diagnostics[-1] = replace(
                issue,
                message=issue.message + " This endpoint configuration is needed to "
                "obtain a proxy, not to use an existing one.",
            )
        return tuple(diagnostics)
    if stat.S_ISDIR(mode):
        files = _trust_files(configured, diagnostics, "vomses_directory")
    elif stat.S_ISREG(mode):
        files = [configured]
    else:
        _problem(
            diagnostics,
            "vomses_path_wrong_type",
            f"VOMS endpoint path '{path}' is not a regular file or directory. "
            "Use the VO's official vomses file or directory.",
            path,
        )
        return tuple(diagnostics)
    endpoints = sum(_check_vomses_file(file, diagnostics) for file in files)
    if not endpoints and not diagnostics:
        _problem(
            diagnostics,
            "vomses_empty",
            f"No VOMS endpoints are configured in '{path}'. Install the VO's official vomses "
            "configuration to obtain a proxy. Using an existing proxy does not require it.",
            path,
        )
    return tuple(diagnostics)
