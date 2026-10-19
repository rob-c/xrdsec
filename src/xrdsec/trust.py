"""Is this GSI server who it says it is? Asked before handing it a proxy.

A GSI login proves the *client* to the server. Delegation reverses the stakes:
the client is about to sign a credential for whoever is at the other end, so
it must first know who that is. This is the check the stock client makes:

* the server's certificate chains, signature by signature, to a CA in the
  certificate directory (``$X509_CERT_DIR``, then the conventional Linux or
  Homebrew grid-security location) - the anchors are the ones on disk, never
  ones that arrived over the wire;
* every certificate on the way is inside its validity period;
* every issuer on the way is a CA: ``basicConstraints`` with ``cA`` set,
  ``keyCertSign`` if it has a ``keyUsage`` at all, and a ``pathLenConstraint``
  no smaller than the number of intermediate CAs below it (:rfc:`5280`
  section 6.1.4) - which every IGTF authority satisfies, and without which
  any user certificate could sign a "server" certificate for any host;
* the certificate names the host the client dialled: its ``CN`` is the host
  or ``<service>/<host>``, or a ``subjectAltName`` DNS name (``*.`` matching
  one label) or IP address is.

Revocation lists are not consulted; a GSI server configured with ``-crl:0``
does not consult them either, and CRL freshness is its operator's policy.

RFC 3820 proxies are the one kind of certificate an end entity may sign, but
they never appear in the path built here: issuers come only from the
certificate directory, never from the wire, so a server presenting a proxy
fails at its first link ("no CA ... signed"). That is also why
``cryptography.x509.verification`` is not used for this path - it refuses
proxies outright and matches names byte for byte, while the anchors here are
the directory's and names compare the way OpenSSL compares them.
"""

from __future__ import annotations

import ipaddress
import os
import time

from cryptography import x509 as _x509
from cryptography.x509.oid import ExtensionOID

from .credentials import DEFAULT_CA_PATH, default_ca_path
from .der import parse
from .x509 import Certificate, extensions_of, load_certificates, verify_issued

__all__ = ["DEFAULT_CA_PATH", "TrustError", "anchors", "names_host", "verify_server"]

SUBJECT_ALT_NAME_OID = "2.5.29.17"
#: Longest CA path followed before giving up: grid PKIs are two or three deep.
MAX_DEPTH = 8

# GeneralName choices as context-specific primitive tags (RFC 5280 4.2.1.6).
_DNS_NAME = 0x82  # [2] dNSName
_IP_ADDRESS = 0x87  # [7] iPAddress


class TrustError(ValueError):
    """The server's certificate does not establish who the server is.

    ``code`` says which check failed, for a caller that reports or counts
    them rather than printing the sentence: ``ca_directory``,
    ``no_certificate``, ``wrong_host``, ``validity``, ``no_issuer``,
    ``issuer_not_ca``, ``issuer_key_usage``, ``path_length`` or
    ``path_too_long``.
    """

    def __init__(self, message: str, *, code: str = "untrusted") -> None:
        """Carry ``message`` for people and ``code`` (default ``untrusted``) for programs."""
        super().__init__(message)
        self.code = code


def anchors(ca_path: str | None) -> list[Certificate]:
    """Every CA certificate in the directory, from its ``<hash>.<n>`` files.

    The same files OpenSSL and XrdCrypto look CAs up by; signing policies,
    CRLs and namespaces files beside them are passed over.
    """
    directory = ca_path or default_ca_path()
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        raise TrustError(
            f"cannot read the CA directory {directory}: {exc}", code="ca_directory"
        ) from exc
    found: list[Certificate] = []
    for name in names:
        stem, dot, index = name.partition(".")
        if not (dot and index.isdigit() and len(stem) == 8):
            continue
        try:
            with open(os.path.join(directory, name), "rb") as handle:
                found.extend(load_certificates(handle.read()))
        except OSError:
            continue
    return found


def names_host(certificate: Certificate, host: str) -> bool:
    """Whether ``certificate`` is for ``host``, the way XrdSecgsi decides."""
    wanted = host.strip("[]").lower().rstrip(".")
    common = certificate.subject.cn.lower()
    if common == wanted or common.endswith("/" + wanted):
        return True
    return any(_alt_name_matches(kind, value, wanted) for kind, value in _alt_names(certificate))


def _alt_names(certificate: Certificate) -> list[tuple[int, bytes]]:
    """The ``subjectAltName`` entries of ``certificate`` as ``(tag, raw value)`` pairs.

    Raw tags and bytes are all :func:`_alt_name_matches` needs: an
    ``iPAddress`` value is the 4- or 16-byte address itself, and a
    ``dNSName`` is IA5 (ASCII) text.
    """
    for extension in extensions_of(certificate.der):
        if extension.oid == SUBJECT_ALT_NAME_OID:
            return [(name.tag, name.value) for name in parse(extension.value)[0].children()]
    return []


def _alt_name_matches(kind: int, value: bytes, wanted: str) -> bool:
    """Whether one ``subjectAltName`` entry names ``wanted``.

    An ``iPAddress`` is compared as an address, so ``::1`` matches
    ``0:0:0:0:0:0:0:1``. A ``dNSName`` wildcard covers exactly one leftmost
    label (RFC 6125 section 6.4.3): ``*.example.org`` matches
    ``a.example.org`` but neither ``example.org`` nor ``a.b.example.org``.
    Any other kind (URI, email) never names a host.
    """
    if kind == _IP_ADDRESS:
        try:
            return ipaddress.ip_address(value) == ipaddress.ip_address(wanted)
        except ValueError:
            return False
    if kind != _DNS_NAME:
        return False
    pattern = value.decode("ascii", "replace").lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, tail = wanted.partition(".")
        return bool(head) and tail == pattern[2:]
    return pattern == wanted


def _current(certificate: Certificate, moment: float) -> None:
    """Raise ``TrustError(code="validity")`` unless ``moment`` is inside the validity period."""
    if not certificate.not_before <= moment < certificate.not_after:
        raise TrustError(f"{certificate.subject} is outside its validity period", code="validity")


def _issuer_of(certificate: Certificate, trusted: list[Certificate]) -> Certificate:
    """The CA in ``trusted`` that issued ``certificate``: same name, and its key signed it.

    ``trusted`` holds only anchors from the certificate directory, so this is
    where a certificate chain that was merely *presented* by the server stops
    counting for anything.
    """
    for candidate in trusted:
        if candidate.subject == certificate.issuer and verify_issued(certificate, candidate):
            return candidate
    raise TrustError(
        f"no CA in the certificate directory signed {certificate.subject}", code="no_issuer"
    )


def _constraints(
    certificate: Certificate,
) -> tuple[_x509.BasicConstraints | None, _x509.KeyUsage | None]:
    """The ``basicConstraints`` and ``keyUsage`` of ``certificate``, each if present.

    A certificate ``cryptography`` will not parse, or whose extensions are
    malformed, has neither - and so is no CA.
    """
    try:
        extensions = _x509.load_der_x509_certificate(certificate.der).extensions
    except (ValueError, _x509.DuplicateExtension):
        return None, None
    found = {extension.oid: extension.value for extension in extensions}
    basic = found.get(ExtensionOID.BASIC_CONSTRAINTS)
    usage = found.get(ExtensionOID.KEY_USAGE)
    return (
        basic if isinstance(basic, _x509.BasicConstraints) else None,
        usage if isinstance(usage, _x509.KeyUsage) else None,
    )


def _may_issue(issuer: Certificate, below: int) -> None:
    """Refuse ``issuer`` unless it is a CA allowed ``below`` intermediate CAs under it.

    The three :rfc:`5280` checks OpenSSL makes of every issuer on a path:
    ``basicConstraints`` present with ``cA`` true, ``keyCertSign`` asserted
    when ``keyUsage`` is present, and ``pathLenConstraint`` (when given) at
    least the number of non-self-issued intermediate CAs between it and the
    end entity.
    """
    basic, usage = _constraints(issuer)
    if basic is None or not basic.ca:
        raise TrustError(
            f"{issuer.subject} is not a CA (its basicConstraints do not say cA)",
            code="issuer_not_ca",
        )
    if usage is not None and not usage.key_cert_sign:
        raise TrustError(
            f"{issuer.subject} may not sign certificates (its keyUsage lacks keyCertSign)",
            code="issuer_key_usage",
        )
    if basic.path_length is not None and below > basic.path_length:
        raise TrustError(
            f"{issuer.subject} allows {basic.path_length} intermediate CA(s) below it, "
            f"the path has {below}",
            code="path_length",
        )


def verify_server(
    chain_pem: bytes,
    host: str,
    ca_path: str | None = None,
    *,
    now: float | None = None,
) -> Certificate:
    """The server's certificate, once it is shown to be a CA-issued one for ``host``.

    Raises :class:`TrustError` saying - in words and as its ``code`` - which
    check failed.
    """
    moment = time.time() if now is None else now
    certificates = load_certificates(chain_pem)
    if not certificates:
        raise TrustError("the server sent no certificate", code="no_certificate")
    server = certificates[0]
    if not names_host(server, host):
        raise TrustError(
            f"the server certificate {server.subject} is not for {host}", code="wrong_host"
        )
    trusted = anchors(ca_path)
    link = server
    # ``below``: the non-self-issued intermediate CAs between the server and this issuer.
    for below in range(MAX_DEPTH):
        _current(link, moment)
        issuer = _issuer_of(link, trusted)
        _may_issue(issuer, below)
        if issuer.is_anchor:
            _current(issuer, moment)
            return server
        link = issuer
    raise TrustError(
        f"the CA path from {server.subject} is longer than {MAX_DEPTH}", code="path_too_long"
    )
