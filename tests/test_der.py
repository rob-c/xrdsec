"""The DER reader. Strictness is the feature, so most of this is refusals."""

import pytest

from xrdsec import der as _der
from xrdsec.der import (
    TAG_INTEGER,
    TAG_OID,
    TAG_SEQUENCE,
    DERError,
    Element,
    decode_time,
    encode_oid,
    oid_string,
    parse,
    parse_all,
    read_integer,
)
from xrdsec.testing.rawpki import integer, oid, sequence, tlv


def test_parses_a_short_form_element():
    element, end = parse(bytes.fromhex("020103"))
    assert (element.tag, element.value, end) == (TAG_INTEGER, b"\x03", 3)


def test_parses_a_long_form_length():
    body = b"\x2a" * 300
    element, end = parse(tlv(0x04, body))
    assert element.value == body
    assert end == 304  # tag, 0x82, two length bytes, content


def test_sequence_exposes_children_and_indexing():
    element, _ = parse(sequence(integer(1), integer(65537)))
    assert element.tag == TAG_SEQUENCE
    assert element.constructed
    assert [read_integer(child) for child in element.children()] == [1, 65537]
    assert read_integer(element[1]) == 65537


def test_primitive_elements_have_no_children():
    element, _ = parse(integer(7))
    assert not element.constructed
    with pytest.raises(DERError, match="primitive"):
        element.children()


def test_parse_all_consumes_every_element():
    elements = parse_all(integer(1) + integer(2) + integer(3))
    assert [read_integer(e) for e in elements] == [1, 2, 3]


def test_integers_are_signed_and_arbitrary_width():
    big = (1 << 511) | 3
    assert read_integer(parse(integer(big))[0]) == big
    assert read_integer(Element(TAG_INTEGER, b"\xff")) == -1
    assert read_integer(Element(TAG_INTEGER, b"\x00\x80")) == 128


def test_object_identifiers_round_trip():
    for dotted in ("1.2.840.113549.1.1.1", "1.3.6.1.5.5.7.1.14", "0.9.2342.19200300.100.1.25"):
        assert oid_string(parse(oid(dotted))[0]) == dotted


def test_indefinite_length_is_refused():
    with pytest.raises(DERError, match="indefinite"):
        parse(b"\x30\x80\x02\x01\x01\x00\x00")


def test_multi_byte_tags_are_refused():
    with pytest.raises(DERError, match="multi-byte"):
        parse(b"\x1f\x81\x00\x01\x00")


@pytest.mark.parametrize(
    "data, message",
    [
        (b"", "no tag byte"),
        (b"\x02", "no length byte"),
        (b"\x02\x84\x00", "runs past the end"),
        (b"\x02\x05\x01", "truncated"),
        (b"\x02\x89" + b"\x00" * 9, "implausible"),
    ],
)
def test_malformed_encodings_raise(data, message):
    with pytest.raises(DERError, match=message):
        parse(data)


def test_type_confusion_is_caught():
    with pytest.raises(DERError, match="expected INTEGER"):
        read_integer(Element(TAG_OID, b"\x2a"))
    with pytest.raises(DERError, match="expected OBJECT IDENTIFIER"):
        oid_string(Element(TAG_INTEGER, b"\x01"))
    with pytest.raises(DERError, match="no content"):
        read_integer(Element(TAG_INTEGER, b""))
    with pytest.raises(DERError, match="no content"):
        oid_string(Element(TAG_OID, b""))


def test_an_oid_ending_mid_arc_is_refused():
    with pytest.raises(DERError, match="ends mid-arc"):
        oid_string(Element(TAG_OID, b"\x2a\x86"))


def test_der_error_is_a_value_error():
    """Callers catch ``ValueError``; the specific type is a convenience."""
    assert issubclass(DERError, ValueError)


def test_repr_says_tag_and_length():
    assert repr(Element(0x30, b"abc")) == "Element(tag=0x30, len=3)"


def test_a_time_that_is_not_a_date_is_refused():
    """Right length, wrong characters: ``strptime``'s refusal is reported as a DER error."""
    with pytest.raises(DERError, match="malformed time"):
        decode_time(Element(0x17, b"26ab31120000Z"))


@pytest.mark.parametrize("dotted", ["3.1", "1.40.1", "1.2.x", "1..2"])
def test_an_oid_from_data_that_asn1_cannot_encode_is_a_der_error(dotted):
    """``encode_oid`` is for OIDs read from data, so a bad one must not escape as ValueError."""
    with pytest.raises(DERError, match="invalid OBJECT IDENTIFIER"):
        encode_oid(dotted)


# Ported from xrdclient's shared-core contracts (tests/test_shared_crypto.py).


@pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, -1, -129, 2**70])
def test_der_integer_round_trips(value):
    assert _der.read_integer(_der.parse_one(_der.integer(value))) == value


@pytest.mark.parametrize(
    "dotted", ["1.2.840.113549.1.1.11", "2.5.4.3", "1.3.6.1.4.1.3536.1.1.1.9", "2.999.3"]
)
def test_der_oid_round_trips(dotted):
    assert _der.oid_string(_der.parse_one(_der.oid(dotted))) == dotted


def test_der_primitive_writers():
    long = _der.octet_string(b"x" * 300)
    assert _der.parse_one(long).value == b"x" * 300
    assert _der.parse_one(_der.boolean(True)).value == b"\xff"
    assert _der.parse_one(_der.boolean(False)).value == b"\x00"
    assert _der.null() == b"\x05\x00"
    assert _der.parse_one(_der.printable_string("ab")).tag == _der.TAG_PRINTABLE_STRING
    assert _der.parse_one(_der.utf8_string("é")).value == "é".encode()
    assert _der.parse_one(_der.bit_string(b"\x01")).value == b"\x00\x01"
    assert _der.set_of(b"\x02\x01\x02", b"\x02\x01\x01") == b"\x31\x06\x02\x01\x01\x02\x01\x02"
    assert _der.explicit(3, b"") == b"\xa3\x00"


def test_der_constructed_element_round_trip():
    element = _der.parse_one(_der.sequence(_der.integer(1), _der.integer(2)))
    assert element.constructed and len(element.children()) == 2
    assert _der.read_integer(element[1]) == 2
    assert element.encoded == _der.sequence(_der.integer(1), _der.integer(2))
    assert repr(element) == "Element(tag=0x30, len=6)"


def test_der_times() -> None:
    moment = 1_790_000_000.0
    assert _der.decode_time(_der.parse_one(_der.utc_time(moment))) == moment
    assert _der.decode_time(_der.parse_one(_der.generalized_time(moment))) == moment
    assert _der.parse_one(_der.validity_time(moment)).tag == _der.TAG_UTC_TIME
    far = 2_600_000_000.0  # 2052
    assert _der.parse_one(_der.validity_time(far)).tag == _der.TAG_GENERALIZED_TIME
    assert _der.decode_time(_der.Element(_der.TAG_UTC_TIME, b"991231235959Z")) == 946684799.0
    assert _der.decode_time(_der.Element(_der.TAG_GENERALIZED_TIME, b"20260101")) == 1767225600.0
    with pytest.raises(_der.DERError, match="malformed UTCTime"):
        _der.decode_time(_der.Element(_der.TAG_UTC_TIME, b"99"))
    with pytest.raises(_der.DERError, match="not a certificate time"):
        _der.decode_time(_der.Element(_der.TAG_INTEGER, b"1"))
    with pytest.raises(_der.DERError, match="malformed time"):
        _der.decode_time(_der.Element(_der.TAG_GENERALIZED_TIME, b"2026xx01000000"))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "no tag byte"),
        (b"\x30", "no length byte"),
        (b"\x30\x80", "indefinite"),
        (b"\x30\x85\x01\x01\x01\x01\x01", "implausible"),
        (b"\x30\x82\x01", "runs past the end"),
        (b"\x30\x05\x01", "5 bytes requested"),
        (b"\x1f\x01\x00", "multi-byte tags"),
    ],
)
def test_der_rejects_malformed(data: bytes, message: str) -> None:
    with pytest.raises(_der.DERError, match=message):
        _der.parse(data)


def test_der_strictness() -> None:
    with pytest.raises(_der.DERError, match="trailing"):
        _der.parse_one(_der.null() + b"\x00")
    with pytest.raises(_der.DERError, match="primitive"):
        _der.parse_one(_der.integer(1)).children()
    with pytest.raises(_der.DERError, match="expected INTEGER"):
        _der.read_integer(_der.parse_one(_der.null()))
    with pytest.raises(_der.DERError, match="no content"):
        _der.read_integer(_der.Element(_der.TAG_INTEGER, b""))
    with pytest.raises(_der.DERError, match="expected OBJECT IDENTIFIER"):
        _der.oid_string(_der.parse_one(_der.null()))
    with pytest.raises(_der.DERError, match="no content"):
        _der.oid_string(_der.Element(_der.TAG_OID, b""))
    with pytest.raises(_der.DERError, match="mid-arc"):
        _der.oid_string(_der.Element(_der.TAG_OID, b"\x2a\x86"))
    assert _der.parse_all(b"") == []
