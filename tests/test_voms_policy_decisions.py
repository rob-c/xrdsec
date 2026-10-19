"""Additional VOMS policy decisions, using offline fixtures only."""

from __future__ import annotations

import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from xrdsec import signatures, voms
from xrdsec.der import DERError, Element
from xrdsec.testing.rawpki import integer, name, oid, sequence, tlv
from xrdsec.voms import VOMS_FQAN_OID

from tests._vomspki import (
    ECDSA_SHA256,
    ED25519,
    NULL,
    RSA_PSS,
    _algorithm,
    _embedded_signer,
    _fixture,
    _general_names,
)


@pytest.fixture
def claims(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path)
    return proxy.chain, voms.inspect_voms(proxy.chain).entries[0]


def _parts(*parts: bytes) -> list[Element]:
    return voms._one(sequence(*parts)).children()


def test_remaining_uses_current_time_and_verified_vos_omit_empty_names(claims, monkeypatch):
    _, entry = claims
    monkeypatch.setattr(time, "time", lambda: 100.0)
    assert entry.remaining() == entry.not_after - 100.0
    verified = replace(entry, status=voms.VOMSStatus.OK, vo="")
    assert voms.VOMSResult((verified,), voms.VOMSStatus.OK).vos == ()


@pytest.mark.parametrize("parts", [(), (integer(1),), (oid("1.2.3"), NULL, NULL, NULL)])
def test_extension_field_count_is_checked_before_access(parts):
    with pytest.raises(DERError, match="malformed VOMS AC extension"):
        voms._extension_fields(voms._one(sequence(*parts)))


@pytest.mark.parametrize(
    "parts", [(), (integer(1),), (integer(1), sequence()), (oid(VOMS_FQAN_OID), sequence())]
)
def test_fqan_attribute_requires_both_fields_and_an_oid(parts):
    assert voms._is_fqan_attribute(_parts(*parts)) == (
        len(parts) == 2 and parts[0] == oid(VOMS_FQAN_OID)
    )


@pytest.mark.parametrize("text", ["", "/", "/atlas,bad"])
def test_short_or_comma_separated_fqans_are_not_permissions(text):
    assert not voms._valid_fqan(text)


def test_generic_attributes_ignore_a_wrongly_typed_triple():
    triple = sequence(tlv(0x04, b"name"), integer(1), tlv(0x04, b"value"))
    provider = sequence(sequence(), sequence(triple))
    assert voms._generic_attributes(sequence(sequence(provider))) == ()


@pytest.mark.parametrize(
    "parts",
    [
        (integer(1), sequence(), tlv(0x03, b"\0x")),
        (sequence(), integer(1), tlv(0x03, b"\0x")),
        (sequence(), sequence(), integer(1)),
        (sequence(), sequence(), tlv(0x03, b"")),
    ],
)
def test_ac_shape_checks_each_required_type(parts):
    with pytest.raises(DERError, match="malformed VOMS attribute certificate"):
        voms._ac_parts(voms._one(sequence(*parts)))


def test_holder_search_ignores_unrelated_optional_fields():
    encoded_name = name(("2.5.4.3", "Alice"))
    holder = sequence(integer(7), tlv(0xA0, _general_names(encoded_name) + integer(123)))
    found_name, serial = voms._ac_holder(voms._one(holder))
    assert found_name.cn == "Alice" and serial == 123


@pytest.mark.parametrize("optional", [tlv(0x03, b"\0"), sequence()])
def test_optional_ac_unique_id_does_not_hide_extensions(optional):
    fields = _parts(*(integer(0) for _ in range(7)), optional, sequence())
    selected = voms._ac_extensions(fields)
    assert selected is fields[8 if fields[7].tag == 3 else 7]


def test_ac_signature_with_unused_bits_cannot_verify():
    assert voms._ac_signature(voms._one(tlv(0x03, b"\x01x"))) == b""


def test_ac_list_requires_a_sequence_inside_its_wrapper():
    with pytest.raises(DERError, match="wrong shape"):
        voms._decode_extension(sequence(integer(1)), 0)


@pytest.mark.parametrize("algorithm", [ECDSA_SHA256, ED25519, RSA_PSS])
def test_non_rsa_algorithm_parameters_fail_closed(claims, algorithm):
    _, entry = claims
    changed = replace(entry, _outer_algorithm=_algorithm(algorithm, NULL))
    assert (
        voms._signature_status(changed, _embedded_signer(entry))[0]
        is voms.VOMSStatus.SIGNATURE_ALGORITHM
    )
    assert voms._signature_digest(changed) is None


def _ec_spki(curve: ec.EllipticCurve | None = None) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    from cryptography.hazmat.primitives import serialization

    key = ec.generate_private_key(curve or ec.SECP384R1())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, spki


def test_a_signer_key_of_the_wrong_type_is_a_bad_signature(claims):
    _, entry = claims
    _key, spki = _ec_spki()
    assert not signatures.verify_signature(spki, "1.2.840.113549.1.1.11", None, b"x", b"m")
    rsa_spki = voms.certificate_fields(_embedded_signer(entry).der)["spki"]
    for algorithm in (ECDSA_SHA256, ED25519):
        assert not signatures.verify_signature(rsa_spki, algorithm, None, b"x", b"m")


def test_ecdsa_is_verified_on_any_named_curve_and_hash():
    """Not just P-256 with SHA-256: an ECDSA VOMS server on P-384 verifies too."""
    from cryptography.hazmat.primitives import hashes

    key, spki = _ec_spki()
    signature = key.sign(b"message", ec.ECDSA(hashes.SHA384()))
    assert signatures.verify_signature(spki, "1.2.840.10045.4.3.3", None, signature, b"message")
    assert not signatures.verify_signature(spki, ECDSA_SHA256, None, signature, b"message")


@pytest.mark.parametrize("algorithm", [ECDSA_SHA256, ED25519, "1.3.101.113"])
def test_eddsa_and_ecdsa_parameters_must_be_absent(algorithm):
    with pytest.raises(signatures.SignatureAlgorithmError):
        signatures.verify_signature(b"", algorithm, NULL, b"", b"")


def test_malformed_signature_parameters_are_an_unsupported_algorithm():
    with pytest.raises(signatures.SignatureAlgorithmError, match="malformed"):
        signatures.verify_signature(b"", ED25519, NULL + NULL, b"", b"")


def test_claims_require_a_vo_even_when_fqans_are_present(claims):
    _, entry = claims
    assert voms._claims_status(replace(entry, vo="")) is voms.VOMSStatus.ATTRIBUTES


@pytest.mark.parametrize("targets", [(), ("service.example",)])
def test_unrestricted_or_matching_targets_are_accepted(claims, targets):
    _, entry = claims
    assert (
        voms._target_status(replace(entry, _targets=targets), "service.example")
        is voms.VOMSStatus.OK
    )


@pytest.mark.parametrize("changes", [{"_holder_serial": None}, {"carrier": 999}])
def test_missing_holder_serial_or_carrier_cannot_match(claims, changes):
    chain, entry = claims
    assert not voms._holder_matches(replace(entry, **changes), chain)


def test_algorithm_identifier_requires_an_oid():
    with pytest.raises(DERError, match="no OID"):
        voms._algorithm_identifier(voms._one(sequence(integer(1))))


def test_two_null_parameters_are_not_a_single_optional_null():
    assert not signatures.null_parameters(_parts(NULL, NULL))


def test_pss_known_digest_with_non_null_parameters_is_rejected():
    assert signatures.pss_hash({"algorithm": "sha256", "parameters": 1}) is None


@pytest.mark.parametrize("key_field", [integer(1), tlv(0x03, b"")])
def test_a_signer_key_that_is_not_a_bit_string_cannot_sign(claims, key_field):
    _, entry = claims
    header = tuple(integer(index) for index in range(5))
    spki = sequence(sequence(oid(ED25519)), key_field)
    signer = replace(_embedded_signer(entry), der=sequence(sequence(*header, spki)))
    assert voms._signature_status(entry, signer)[0] is voms.VOMSStatus.SIGNATURE


def test_matching_issuer_without_a_usable_key_cannot_authorize(claims):
    _, entry = claims
    signer = _embedded_signer(entry)
    issuer = SimpleNamespace(subject=signer.issuer, der=b"")
    assert voms._trusted_issuer(signer, (issuer,)) is None


def test_non_numeric_ca_hash_suffix_is_ignored():
    assert not voms._is_anchor_filename("12345678.invalid")


def test_lsc_requires_a_signing_chain(tmp_path):
    diagnostics: list[voms.VOMSDiagnostic] = []
    assert not voms._lsc_matches(str(tmp_path), "atlas", (), diagnostics)
    assert diagnostics[0].code == "vo_name_invalid"


def test_legacy_signer_discovery_never_treats_root_lsc_as_a_certificate(tmp_path):
    root_lsc = tmp_path / "root.lsc"
    root_cert = tmp_path / "root.pem"
    root_lsc.write_text("not a certificate")
    root_cert.write_text("test placeholder")
    assert voms._legacy_files(tmp_path, ()) == [root_cert]
