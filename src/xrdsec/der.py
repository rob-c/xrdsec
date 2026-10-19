"""A small DER reader and writer for the structures X.509 libraries do not model.

Most certificate work goes through ``cryptography``; this module covers what
it does not expose: VOMS attribute certificates, PKCS#10 request attributes,
GSI's ``ProxyCertInfo`` variants, Kerberos-adjacent encodings and test
fixtures that must be byte-exact. TLV framing and primitive codecs (INTEGER,
OBJECT IDENTIFIER) are delegated to ``asn1crypto``; what is kept here is the
:class:`Element` API both clients were written against and the input policy
on top of it.

That policy is stricter than BER, deliberately: definite lengths only,
single-byte tags only, at most four length octets, and no trailing bytes where
one element is expected (:func:`parse_one`). Every input here may come from a
peer - a proxy chain, a server's delegation request - and a lenient parser
is how two implementations come to disagree about what a signed structure
says. A malformed input is always a :class:`DERError`, a ``ValueError``
subclass, so callers can catch decoding failures without catching bugs.

The writers return complete encodings (``bytes``) and compose by
concatenation: ``sequence(integer(1), oid("1.2.3"))``. ``Element.encoded``
and :func:`raw_children` reproduce input bytes exactly, which is what a
signature check or a copied extension needs.
"""

from __future__ import annotations

import calendar
import time
from dataclasses import dataclass

from asn1crypto import core, parser

__all__ = [
    "TAG_BIT_STRING",
    "TAG_BOOLEAN",
    "TAG_GENERALIZED_TIME",
    "TAG_IA5_STRING",
    "TAG_INTEGER",
    "TAG_NULL",
    "TAG_OCTET_STRING",
    "TAG_OID",
    "TAG_PRINTABLE_STRING",
    "TAG_SEQUENCE",
    "TAG_SET",
    "TAG_UTC_TIME",
    "TAG_UTF8_STRING",
    "DERError",
    "Element",
    "bit_string",
    "boolean",
    "decode_time",
    "encode",
    "encode_integer",
    "encode_oid",
    "encode_time",
    "explicit",
    "generalized_time",
    "integer",
    "null",
    "octet_string",
    "oid",
    "oid_string",
    "parse",
    "parse_all",
    "parse_one",
    "printable_string",
    "raw_children",
    "read_integer",
    "sequence",
    "set_of",
    "tlv",
    "utc_time",
    "utf8_string",
    "validity_time",
]

# Universal-class tag bytes as they appear on the wire: class bits 7-6 are
# 00, bit 5 is set for constructed types (hence SEQUENCE 0x30, not 0x10).
# Context-specific tags elsewhere are written literally (0xA0 = [0]
# constructed, 0x80 = [0] primitive).
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18


class DERError(ValueError):
    """The bytes given are not the DER structure they claim to be."""


@dataclass(frozen=True, slots=True)
class Element:
    """One tag-length-value triple; ``encoded`` re-emits it byte for byte."""

    tag: int
    value: bytes

    @property
    def constructed(self) -> bool:
        """Whether the identifier's constructed bit (``0x20``) is set: it has children."""
        return bool(self.tag & 0x20)

    @property
    def encoded(self) -> bytes:
        """The element re-encoded as DER, identical to the bytes it was parsed from."""
        return tlv(self.tag, self.value)

    def children(self) -> list[Element]:
        """Decode the contents of a constructed element into its child elements.

        Children are parsed on each call rather than cached: elements are small,
        frozen and usually walked once, and caching would make them stateful.
        """
        if not self.constructed:
            raise DERError(f"tag 0x{self.tag:02x} is primitive and has no children")
        return parse_all(self.value)

    def __getitem__(self, index: int) -> Element:
        """The ``index``-th child; ``IndexError`` if there are not that many."""
        return self.children()[index]

    def __repr__(self) -> str:
        """Tag and length only: element values can be key material."""
        return f"Element(tag=0x{self.tag:02x}, len={len(self.value)})"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _check_header(data: bytes, pos: int) -> None:
    """Enforce the input policy on an identifier and length before decoding.

    Refuses a missing tag or length octet, a high-tag-number form (low five
    bits all set), and the indefinite length ``0x80`` that BER allows and DER
    forbids.
    """
    if pos < 0 or pos >= len(data):
        raise DERError("truncated: no tag byte")
    if data[pos] & 0x1F == 0x1F:
        raise DERError("multi-byte tags are not supported")
    if pos + 1 >= len(data):
        raise DERError("truncated: no length byte")
    count = data[pos + 1]
    if count == 0x80:
        raise DERError("indefinite lengths are not valid DER")
    if count > 0x80:
        _check_long_length(data, pos, count & 0x7F)


def _check_long_length(data: bytes, pos: int, count: int) -> None:
    """Bound a long-form length to four octets that fit inside ``data``.

    Four octets is a 4 GiB element - far beyond anything here - so a larger
    count is treated as garbage rather than handed to a decoder.
    """
    if count > 4:
        raise DERError(f"length of length {count} is implausible")
    if pos + 2 + count > len(data):
        raise DERError("truncated: long-form length runs past the end")


def parse(data: bytes, pos: int = 0) -> tuple[Element, int]:
    """Read the element starting at ``data[pos]``; return it and the offset after it.

    The header is checked here first, because ``asn1crypto`` accepts
    indefinite lengths and multi-byte tags that this module refuses. The
    returned ``tag`` is the full identifier byte (class, constructed bit and
    number), which is how every caller compares tags.
    """
    _check_header(data, pos)
    try:
        # ``asn1crypto`` reports class, constructed bit and tag number apart;
        # they are packed back into the identifier byte for ``Element.tag``.
        class_, method, tag, header, content, _ = parser.parse(bytes(data[pos:]))
    except ValueError as exc:
        raise DERError(f"truncated DER element: {exc}") from exc
    return Element((class_ << 6) | (method << 5) | tag, content), pos + len(header) + len(content)


def parse_one(data: bytes) -> Element:
    """Parse ``data`` as exactly one element; trailing bytes are a ``DERError``."""
    element, end = parse(data)
    if end != len(data):
        raise DERError(f"{len(data) - end} trailing bytes after the element")
    return element


def parse_all(data: bytes) -> list[Element]:
    """Parse ``data`` as a run of consecutive elements, such as a SEQUENCE's contents."""
    out: list[Element] = []
    pos = 0
    while pos < len(data):
        element, pos = parse(data, pos)
        out.append(element)
    return out


def read_integer(element: Element) -> int:
    """The value of an INTEGER element, as a signed two's-complement number.

    An empty INTEGER is malformed. A non-minimal encoding (a redundant
    leading ``0x00``/``0xFF``) is not refused: its value is still unambiguous.
    """
    if element.tag != TAG_INTEGER:
        raise DERError(f"expected INTEGER, got tag 0x{element.tag:02x}")
    if not element.value:
        raise DERError("INTEGER with no content")
    return int.from_bytes(element.value, "big", signed=True)


def oid_string(element: Element) -> str:
    """The dotted form of an OBJECT IDENTIFIER element (``"1.2.840.113549"``).

    A final octet with its continuation bit set means the last arc was cut
    off; that is refused here explicitly rather than left to the library.
    """
    if element.tag != TAG_OID:
        raise DERError(f"expected OBJECT IDENTIFIER, got tag 0x{element.tag:02x}")
    if not element.value:
        raise DERError("OBJECT IDENTIFIER with no content")
    if element.value[-1] & 0x80:
        raise DERError("OBJECT IDENTIFIER ends mid-arc")
    return str(core.ObjectIdentifier.load(parser.emit(0, 0, TAG_OID, element.value)).dotted)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def tlv(tag: int, value: bytes) -> bytes:
    """Encode ``value`` under the one-byte identifier ``tag``, with a DER length."""
    return bytes(parser.emit(tag >> 6, (tag >> 5) & 1, tag & 0x1F, value))


def integer(value: int) -> bytes:
    """A DER INTEGER, minimally encoded in two's complement."""
    return bytes(core.Integer(value).dump())


def oid(dotted: str) -> bytes:
    """A DER OBJECT IDENTIFIER from its dotted form."""
    return bytes(core.ObjectIdentifier(dotted).dump())


def sequence(*parts: bytes) -> bytes:
    """A SEQUENCE of the already-encoded ``parts``, in the order given."""
    return tlv(TAG_SEQUENCE, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    """A SET OF, members sorted as DER requires."""
    return tlv(TAG_SET, b"".join(sorted(parts)))


def octet_string(data: bytes) -> bytes:
    """An OCTET STRING holding ``data``."""
    return tlv(TAG_OCTET_STRING, data)


def bit_string(data: bytes) -> bytes:
    """A BIT STRING of whole octets (the leading "unused bits" octet is zero)."""
    return tlv(TAG_BIT_STRING, b"\x00" + data)


def boolean(value: bool) -> bytes:
    """A DER BOOLEAN: TRUE must be ``0xFF``, the only encoding DER allows."""
    return tlv(TAG_BOOLEAN, b"\xff" if value else b"\x00")


def null() -> bytes:
    """The NULL value, as RSA ``AlgorithmIdentifier`` parameters use."""
    return tlv(TAG_NULL, b"")


def utf8_string(text: str) -> bytes:
    """A UTF8String, the default DirectoryString type of RFC 5280."""
    return tlv(TAG_UTF8_STRING, text.encode("utf-8"))


def printable_string(text: str) -> bytes:
    """A PrintableString; ``text`` must be ASCII (the character set is not checked)."""
    return tlv(TAG_PRINTABLE_STRING, text.encode("ascii"))


def utc_time(when: float) -> bytes:
    """A UTCTime (two-digit year) for ``when``, in UTC with seconds."""
    return tlv(TAG_UTC_TIME, time.strftime("%y%m%d%H%M%SZ", time.gmtime(when)).encode())


def generalized_time(when: float) -> bytes:
    """A GeneralizedTime (four-digit year) for ``when``, in UTC with seconds."""
    return tlv(TAG_GENERALIZED_TIME, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(when)).encode())


def validity_time(when: float) -> bytes:
    """RFC 5280: UTCTime through 2049, GeneralizedTime from 2050."""
    year = time.gmtime(when).tm_year
    return utc_time(when) if year < 2050 else generalized_time(when)


def explicit(number: int, inner: bytes) -> bytes:
    """A context-specific constructed tag ``[number] EXPLICIT``."""
    return tlv(0xA0 | number, inner)


def decode_time(element: Element) -> float:
    """``UTCTime``/``GeneralizedTime`` as a UNIX timestamp."""
    text = element.value.decode("ascii", "replace").strip()
    if text.endswith("Z"):
        text = text[:-1]
    if element.tag == TAG_UTC_TIME:
        if len(text) < 10:
            raise DERError(f"malformed UTCTime {text!r}")
        year = int(text[:2])
        text = f"{2000 + year if year < 50 else 1900 + year}{text[2:]}"
    elif element.tag != TAG_GENERALIZED_TIME:
        raise DERError(f"tag 0x{element.tag:02x} is not a certificate time")
    text = (text + "000000")[:14]
    try:
        parsed = time.strptime(text, "%Y%m%d%H%M%S")
    except ValueError as exc:
        raise DERError(f"malformed time {text!r}") from exc
    return float(calendar.timegm(parsed))


def raw_children(data: bytes) -> list[bytes]:
    """The children of the one constructed element in ``data``, byte for byte.

    :meth:`Element.children` decodes; this keeps each child exactly as it was
    written, which is what a signature covers and what a copied extension or
    name must reproduce.
    """
    outer, _ = parse(data)
    if not outer.constructed:
        raise DERError(f"tag 0x{outer.tag:02x} is primitive and has no children")
    out: list[bytes] = []
    pos = 0
    while pos < len(outer.value):
        _element, end = parse(outer.value, pos)
        out.append(outer.value[pos:end])
        pos = end
    return out


encode = tlv
encode_integer = integer


def encode_oid(dotted: str) -> bytes:
    """A DER OBJECT IDENTIFIER; a malformed dotted string is a ``DERError``.

    Unlike :func:`oid`, a bad dotted string (or one with fewer than two arcs)
    is reported as a :class:`DERError`, for OIDs that come from data rather
    than from a constant in the code.
    """
    if len(dotted.split(".")) < 2:
        raise DERError("OBJECT IDENTIFIER needs at least two arcs")
    try:
        return bytes(core.ObjectIdentifier(dotted).dump())
    except ValueError as exc:
        raise DERError(f"invalid OBJECT IDENTIFIER {dotted!r}: {exc}") from exc


def encode_time(when: float) -> bytes:
    """A certificate time: UTCTime through 2049, GeneralizedTime after (RFC 5280)."""
    import time

    moment = time.gmtime(int(when))
    if moment.tm_year < 2050:
        return encode(TAG_UTC_TIME, time.strftime("%y%m%d%H%M%SZ", moment).encode("ascii"))
    return encode(TAG_GENERALIZED_TIME, time.strftime("%Y%m%d%H%M%SZ", moment).encode("ascii"))
