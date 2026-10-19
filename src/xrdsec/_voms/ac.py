"""Decoding RFC 5755 VOMS attribute certificates from DER, with no trust decisions.

This is the parser half of :mod:`xrdsec.voms`: it turns the bytes of
the proxy extension ``1.3.6.1.4.1.8005.100.100.5`` into
:class:`~xrdsec.voms.VOMSEntry` values (VO, FQANs, generic
attributes, holder, validity, embedded signer certificates, targets) and keeps
the raw pieces - the to-be-signed bytes, both algorithm identifiers, the
signature - that :mod:`.policy` later checks. Nothing here consults a clock, a
trust directory or a key; a malformed structure raises
:class:`~xrdsec.der.DERError` and the facade's ``inspect_voms`` turns
that into ``VOMSStatus.DECODE``.

Keeping decoding apart from validation means the strict-DER rules can be read
and tested on their own, and that "what does this proxy claim?" never depends
on "should I believe it?".
"""

from __future__ import annotations

import time
from collections.abc import Mapping

from ..der import (
    TAG_BIT_STRING,
    TAG_BOOLEAN,
    TAG_GENERALIZED_TIME,
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    TAG_UTF8_STRING,
    DERError,
    Element,
    encode,
    oid_string,
    parse,
    read_integer,
)
from ..x509 import Name, decode_name, extensions_of, parse_certificate
from .model import (
    _AKI_OID,
    _KNOWN_AC_EXTENSIONS,
    _MAX_AC_ENTRIES,
    _TARGETS_OID,
    VOMS_AC_OID,
    VOMS_ATTRIBUTES_OID,
    VOMS_CERTS_OID,
    VOMS_FQAN_OID,
    Certificate,
    VOMSAttribute,
    VOMSEntry,
)


def _first_directory_name(element: Element) -> Name:
    """The first ``directoryName [4]`` below a GeneralNames-shaped value."""
    if element.tag == 0xA4:
        children = element.children()
        if len(children) == 1:
            return decode_name(_encoded(children[0]))
    if element.constructed:
        for child in element.children():
            found = _first_directory_name(child)
            if found:
                return found
    return Name()


def _encoded(element: Element) -> bytes:
    """Re-encode a parsed element to its exact DER bytes, header included.

    DER has exactly one encoding per value, so this reproduces the bytes that
    were on the wire - which is what makes it safe to hash or verify the
    re-encoded ``tbs`` instead of slicing the original buffer.
    """
    return encode(element.tag, element.value)


def _one(data: bytes) -> Element:
    """Parse ``data`` as exactly one element; trailing bytes are a ``DERError``.

    Extension values are OCTET STRINGs wrapping one encoded structure. Accepting
    leftovers would let two parsers disagree about what a proxy says, so every
    nested decode in this module goes through here.
    """
    element, end = parse(data)
    if end != len(data):
        raise DERError(f"{len(data) - end} trailing bytes after the element")
    return element


def _time(element: Element) -> float:
    """An AC validity bound as seconds since the epoch.

    RFC 5755 requires ``GeneralizedTime`` in UTC (``YYYYMMDDHHMMSSZ``, no
    fractions) for attribute certificates - unlike X.509, where ``UTCTime`` is
    also allowed - so anything else is a decoding failure, not a guess.
    ``calendar.timegm`` is imported on first use only: decoding is rare and
    this keeps the import out of every proxy load.
    """
    if element.tag != TAG_GENERALIZED_TIME:
        raise DERError("VOMS validity is not GeneralizedTime")
    text = element.value.decode("ascii")
    if not text.endswith("Z"):
        raise DERError("VOMS validity is not UTC")
    try:
        return float(__import__("calendar").timegm(time.strptime(text, "%Y%m%d%H%M%SZ")))
    except ValueError as exc:
        raise DERError(f"malformed VOMS time {text!r}") from exc


def _extension_map(element: Element | None) -> dict[str, tuple[bool, bytes]]:
    """The AC's extensions as ``{oid: (critical, value)}``; no extensions is ``{}``.

    A repeated OID keeps its last occurrence. RFC 5280 forbids repeats, and
    the map is built from bytes the AC's signature covers, so a repeat is the
    issuing server's mistake rather than something an attacker can add later.
    """
    found: dict[str, tuple[bool, bytes]] = {}
    if element is None:
        return found
    for extension in element.children():
        key, critical, value = _extension_fields(extension)
        found[key] = (critical, value)
    return found


def _extension_fields(extension: Element) -> tuple[str, bool, bytes]:
    """One ``Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }``.

    The optional ``critical`` must be a BOOLEAN when present; any non-zero byte
    counts as TRUE, as BER readers do (strict DER would only allow ``0xFF``, but
    rejecting a sloppy TRUE could hide a critical extension rather than refuse it).
    """
    if extension.tag != TAG_SEQUENCE:
        raise DERError("malformed VOMS AC extension")
    parts = extension.children()
    if len(parts) not in (2, 3) or parts[0].tag != TAG_OID:
        raise DERError("malformed VOMS AC extension")
    if len(parts) == 3 and parts[1].tag != TAG_BOOLEAN:
        raise DERError("malformed VOMS AC extension")
    if parts[-1].tag != TAG_OCTET_STRING:
        raise DERError("VOMS AC extension has no OCTET STRING value")
    critical = len(parts) == 3 and parts[1].value != b"\x00"
    return oid_string(parts[0]), critical, parts[-1].value


def _attributes(element: Element) -> tuple[str, str, tuple[str, ...]]:
    """The VO, its server URI and the FQANs from the AC's ``attributes`` field.

    Only the VOMS FQAN attribute (``1.3.6.1.4.1.8005.100.100.4``) is read; other
    attribute types are skipped, as libvomsapi does. The VO normally comes from
    the policyAuthority ``vo://host:port``; an AC without one falls back to the
    first path component of the first FQAN (``/atlas/Role=NULL`` -> ``atlas``).
    """
    vo = uri = ""
    fqans: list[str] = []
    for attribute in element.children():
        parts = attribute.children()
        if not _is_fqan_attribute(parts):
            continue
        for syntax in parts[1].children():
            found_vo, found_uri, found_fqans = _fqan_syntax(syntax)
            if found_vo:
                vo, uri = found_vo, found_uri
            fqans.extend(found_fqans)
    if not vo and fqans:
        vo = fqans[0].split("/", 2)[1]
    return vo, uri, tuple(fqans)


def _is_fqan_attribute(parts: list[Element]) -> bool:
    return len(parts) >= 2 and parts[0].tag == TAG_OID and oid_string(parts[0]) == VOMS_FQAN_OID


def _fqan_syntax(syntax: Element) -> tuple[str, str, tuple[str, ...]]:
    """One ``IetfAttrSyntax``: ``policyAuthority`` first, the FQAN values last.

    FQANs that fail :func:`_valid_fqan` are dropped rather than failing the AC,
    so one garbled group does not hide the valid memberships next to it; an AC
    left with none is then refused as ``ATTRIBUTES`` by the policy.
    """
    fields = syntax.children()
    if not fields:
        return "", "", ()
    vo, uri = _policy_authority(fields[0])
    fqans = tuple(
        text
        for value in fields[-1].children()
        if value.tag in (TAG_OCTET_STRING, TAG_UTF8_STRING)
        if _valid_fqan(text := value.value.decode("utf-8", "replace"))
    )
    return vo, uri, fqans


def _policy_authority(element: Element) -> tuple[str, str]:
    """Split the ``[0] policyAuthority`` GeneralNames into ``(vo, "host:port")``.

    VOMS writes it as the URI-like string ``atlas://voms.example.org:15001``;
    anything without ``://`` (or not under tag ``[0]``) yields empty strings.
    """
    if element.tag != 0xA0:
        return "", ""
    policy = _general_name_text(element)
    if "://" not in policy:
        return "", ""
    vo, uri = policy.split("://", 1)
    return vo, uri


def _valid_fqan(value: str) -> bool:
    """Whether ``value`` has the shape of an FQAN: an absolute path of printable ASCII.

    Commas are refused because FQAN lists are comma-joined in logs, environment
    variables and gridmap-style policy files; whitespace and control characters
    are refused because they would let one value masquerade as two lines.
    """
    return (
        len(value) > 1
        and value.startswith("/")
        and "," not in value
        and all("!" <= char <= "~" for char in value)
    )


def _general_name_text(element: Element) -> str:
    """The first IA5 ``dNSName [2]`` or ``uniformResourceIdentifier [6]`` found below ``element``.

    The search is depth-first so that it does not depend on how many
    GeneralNames/explicit-tag wrappers surround the string.
    """
    if element.tag in (0x82, 0x86):
        return element.value.decode("ascii", "replace")
    if element.constructed:
        for child in element.children():
            found = _general_name_text(child)
            if found:
                return found
    return ""


def _generic_attributes(data: bytes | None) -> tuple[VOMSAttribute, ...]:
    """The VOMS generic attributes extension (``...100.100.11``) as name/value/qualifier triples.

    The structure is ``SEQUENCE { SEQUENCE OF provider }``, each provider a
    ``SEQUENCE { policyAuthority, ..., SEQUENCE OF SEQUENCE { name, qualifier,
    value } }`` (note the wire order puts the qualifier second). Triples whose
    fields are not all OCTET STRINGs are skipped, not fatal: these attributes
    are informational and never used for trust.
    """
    if data is None:
        return ()
    out: list[VOMSAttribute] = []
    outer = _one(data)
    providers = outer.children()[0].children() if outer.children() else []
    for provider in providers:
        fields = provider.children()
        if len(fields) < 2:
            continue
        for triple in fields[-1].children():
            values = triple.children()
            if len(values) == 3 and all(value.tag == TAG_OCTET_STRING for value in values):
                name, qualifier, value = (part.value.decode("utf-8", "replace") for part in values)
                out.append(VOMSAttribute(name, value, qualifier))
    return tuple(out)


def _embedded_certificates(data: bytes | None) -> tuple[Certificate, ...]:
    """The signer chain the VOMS server put in the ``...100.100.10`` extension.

    The value is a ``SEQUENCE { SEQUENCE OF Certificate }`` written as one
    concatenated run of certificates, so they are walked by DER length rather
    than by children. These certificates are attacker-supplied until
    :mod:`.policy` and :mod:`.trust` have checked them against the local CA
    and ``vomsdir`` material.
    """
    if data is None:
        return ()
    outer = _one(data).children()
    if len(outer) != 1:
        raise DERError("VOMS certs extension is not a one-element sequence")
    certs: list[Certificate] = []
    pos = 0
    body = outer[0].value
    while pos < len(body):
        _element, end = parse(body, pos)
        certs.append(parse_certificate(body[pos:end]))
        pos = end
    return tuple(certs)


def _targets(data: bytes | None) -> tuple[str, ...] | None:
    """The lowercased host names the AC is restricted to (RFC 5755 ``targetInformation``).

    ``None`` means the extension is absent - the AC is valid everywhere - which
    is different from an empty tuple. Only ``targetName [0]`` entries are
    read; trailing dots are stripped so ``host.`` and ``host`` compare equal.
    """
    if data is None:
        return None
    names: list[str] = []
    outer = _one(data)
    for group in outer.children():
        for target in group.children():
            if target.tag == 0xA0:
                text = _general_name_text(target)
                if text:
                    names.append(text.lower().rstrip("."))
    return tuple(names)


def _authority_key_id(data: bytes | None) -> bytes | None:
    """The ``keyIdentifier [0]`` of the AKI extension, or ``None`` if there is none.

    The issuer-name-and-serial alternative (``[1]``/``[2]``) is ignored: the
    signer is already chosen by subject name, and the key identifier is the
    only part that adds a key binding on top of it.
    """
    if data is None:
        return None
    for child in _one(data).children():
        if child.tag == 0x80:
            return child.value
    return None


def _decode_ac(element: Element, carrier: int) -> VOMSEntry:
    """Decode one ``AttributeCertificate`` into a :class:`VOMSEntry`.

    ``info`` is the ``AttributeCertificateInfo`` sequence in RFC 5755 field
    order: version, holder, issuer, signature algorithm, serial, validity,
    attributes, [issuerUniqueID], [extensions]. ``carrier`` is the index in the
    proxy chain of the certificate the AC was found on; the holder check walks
    from there. The raw ``tbs`` and both algorithm identifiers are kept so the
    policy can verify the signature and insist the inner and outer algorithm
    fields agree, as RFC 5755 requires.
    """
    top, info = _ac_parts(element)
    holder, holder_serial = _ac_holder(info[1])
    extensions = _extension_map(_ac_extensions(info))
    embedded = _embedded_certificates(_extension_value(extensions, VOMS_CERTS_OID))
    generic = _generic_attributes(_extension_value(extensions, VOMS_ATTRIBUTES_OID))
    validity = _ac_validity(info[5])
    vo, uri, fqans = _attributes(info[6])
    return VOMSEntry(
        vo=vo,
        uri=uri,
        fqans=fqans,
        attributes=generic,
        holder=holder,
        issuer=_first_directory_name(info[2]),
        not_before=_time(validity[0]),
        not_after=_time(validity[1]),
        carrier=carrier,
        _version=read_integer(info[0]),
        _holder_serial=holder_serial,
        _tbs=_encoded(top[0]),
        _inner_algorithm=_encoded(info[3]),
        _outer_algorithm=_encoded(top[1]),
        _signature=_ac_signature(top[2]),
        _embedded=embedded,
        _targets=_targets(_extension_value(extensions, _TARGETS_OID)),
        _aki=_authority_key_id(_extension_value(extensions, _AKI_OID)),
        _unknown_critical=_has_unknown_critical(extensions),
    )


def _ac_parts(element: Element) -> tuple[list[Element], list[Element]]:
    """Split an AC into ``(top, info)`` after checking the outer shape.

    ``top`` is ``[acinfo, signatureAlgorithm, signatureValue]``; a missing or
    empty BIT STRING signature is malformed rather than "unsigned", so it can
    never reach the signature check looking like something to skip.
    """
    top = element.children()
    if (
        element.tag != TAG_SEQUENCE
        or len(top) != 3
        or top[0].tag != TAG_SEQUENCE
        or top[1].tag != TAG_SEQUENCE
        or top[2].tag != TAG_BIT_STRING
        or not top[2].value
    ):
        raise DERError("malformed VOMS attribute certificate")
    info = top[0].children()
    if len(info) < 7:
        raise DERError("VOMS attribute certificate is missing required fields")
    return top, info


def _ac_holder(element: Element) -> tuple[Name, int | None]:
    """The holder's issuer name and serial from ``Holder.baseCertificateID [0]``.

    VOMS binds an AC to the proxy owner's end-entity certificate by
    ``IssuerSerial`` (RFC 5755 section 4.2.2). ``entityName`` and
    ``objectDigestInfo`` are not used by VOMS and are ignored; an AC carrying
    only those has no serial and fails the holder check in :mod:`.policy`.
    """
    holder_fields = element.children()
    base = next((item for item in holder_fields if item.tag == 0xA0), None)
    holder = Name()
    holder_serial: int | None = None
    if base is not None:
        base_fields = base.children()
        if base_fields:
            holder = _first_directory_name(base_fields[0])
        holder_serial = next(
            (read_integer(item) for item in base_fields if item.tag == TAG_INTEGER), None
        )
    return holder, holder_serial


def _ac_validity(element: Element) -> list[Element]:
    """The ``AttCertValidityPeriod`` as its two ``GeneralizedTime`` children."""
    validity = element.children()
    if len(validity) != 2:
        raise DERError("VOMS validity is not a pair")
    return validity


def _ac_extensions(info: list[Element]) -> Element | None:
    """The extensions element, if the AC has one.

    It sits at index 7, or at 8 when the optional ``issuerUniqueID`` BIT STRING
    precedes it; VOMS never sends that field, but skipping it costs one test.
    """
    if len(info) <= 7:
        return None
    return info[8] if len(info) > 8 and info[7].tag == TAG_BIT_STRING else info[7]


def _ac_signature(element: Element) -> bytes:
    """The signature bytes, or empty when the BIT STRING has unused bits.

    Signatures are whole octets, so a non-zero "unused bits" prefix byte means
    the value is not a signature at all; empty fails verification downstream.
    """
    return element.value[1:] if element.value[:1] == b"\x00" else b""


def _has_unknown_critical(extensions: dict[str, tuple[bool, bytes]]) -> bool:
    """Whether any extension is marked critical but not understood here.

    RFC 5280 requires refusing such a certificate rather than ignoring the
    extension; the policy reports it as ``VOMSStatus.EXTENSION``.
    """
    return any(
        critical and oid not in _KNOWN_AC_EXTENSIONS for oid, (critical, _) in extensions.items()
    )


def _extension_value(values: dict[str, tuple[bool, bytes]], oid: str) -> bytes | None:
    """The value of ``oid`` in an extension map, without its criticality flag."""
    found = values.get(oid)
    return found[1] if found is not None else None


def _decode_extension(data: bytes, carrier: int) -> tuple[VOMSEntry, ...]:
    """All ACs in one proxy's VOMS extension (``SEQUENCE { SEQUENCE OF AC }``).

    VOMS puts one AC per VO in the inner sequence. The count is capped at
    ``_MAX_AC_ENTRIES`` so a hostile proxy cannot make validation do unbounded
    signature and filesystem work.
    """
    root = _one(data)
    outer = root.children()
    if root.tag != TAG_SEQUENCE or len(outer) != 1 or outer[0].tag != TAG_SEQUENCE:
        raise DERError("VOMS AC sequence has the wrong shape")
    certificates = outer[0].children()
    if not certificates:
        raise DERError("VOMS AC sequence is empty")
    if len(certificates) > _MAX_AC_ENTRIES:
        raise DERError("VOMS AC sequence has too many entries")
    return tuple(_decode_ac(ac, carrier) for ac in certificates)


def _voms_extension(certificate: Certificate) -> bytes | None:
    """The raw VOMS AC extension value of ``certificate``, or ``None``."""
    return _certificate_extension(certificate, VOMS_AC_OID)


def _certificate_extension(certificate: Certificate, wanted: str) -> bytes | None:
    """The value of extension ``wanted`` from either client's certificate model.

    xgfalclient's certificate exposes extensions as a mapping; xrdclient's
    :class:`~xrdsec.x509.Certificate` exposes only OID names, so the
    DER is re-read through :func:`~xrdsec.x509.extensions_of`.
    """
    if isinstance(certificate.extensions, Mapping):
        found = certificate.extensions.get(wanted)
        return found[1] if found is not None else None
    for extension in extensions_of(certificate.der):
        if extension.oid == wanted:
            return extension.value
    return None
