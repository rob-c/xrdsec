"""VOMS attribute certificate decoding and verification."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from xrdsec import credentials as _gridpaths
from xrdsec import ed25519, p256, signatures, voms
from xrdsec.der import DERError
from xrdsec.rsa import RSAPrivateKey, RSAPublicKey
from xrdsec.testing.rawpki import (
    PROXY_CERT_INFO_OID,
    bitstring,
    integer,
    make_certificate,
    name,
    oid,
    pem,
    public_key_info,
    sequence,
    setof,
    throwaway_key,
    tlv,
)
from xrdsec.voms import (
    VOMS_FQAN_OID,
    VOMSEntry,
    VOMSResult,
    VOMSStatus,
    default_ca_path,
    default_voms_dir,
    inspect_voms,
    validate_voms,
)
from xrdsec.x509 import Name, certificate_data, parse_certificate

from tests._vomspki import (
    DIGEST_SHA256,
    EC_PUBLIC_KEY,
    ECDSA_SHA256,
    ED25519,
    MGF1,
    NULL,
    P256,
    RSA_PSS,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    _ac,
    _algorithm,
    _embedded_signer,
    _extension,
    _fixture,
    _general_names,
    _gentime,
)


def _assert_verified_result(result: VOMSResult) -> VOMSEntry:
    assert result.status is VOMSStatus.OK
    assert result.vos == ("atlas",)
    assert result.fqans == ("/atlas/Role=production/Capability=NULL",)
    entry = result.verified[0]
    assert entry.verified
    assert entry.digest == "sha256"
    assert entry.carrier == 0
    assert entry.attributes[0].name == "nickname"
    assert entry.attributes[0].value == "alice"
    return entry


def _pss_parameters(digest: str = DIGEST_SHA256, salt_length: int = 32) -> bytes:
    digest_algorithm = sequence(oid(digest), NULL)
    return sequence(
        tlv(0xA0, digest_algorithm),
        tlv(0xA1, sequence(oid(MGF1), digest_algorithm)),
        tlv(0xA2, integer(salt_length)),
    )


def _pss_sign(key: RSAPrivateKey, message: bytes, salt: bytes = b"\x42" * 32) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    numbers = rsa.RSAPrivateNumbers(
        key.p,
        key.q,
        key.d,
        key.d % (key.p - 1),
        key.d % (key.q - 1),
        pow(key.q, -1, key.p),
        rsa.RSAPublicNumbers(key.e, key.n),
    )
    return numbers.private_key().sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=len(salt)),
        hashes.SHA256(),
    )


def _ec_spki(public: tuple[int, int]) -> bytes:
    return sequence(
        sequence(oid(EC_PUBLIC_KEY), oid(P256)),
        bitstring(p256.encode_point(public)),
    )


def _ed25519_spki(public: bytes) -> bytes:
    return sequence(sequence(oid(ED25519)), bitstring(public))


@pytest.mark.parametrize("kind", ["pss", "ecdsa", "ed25519"])
def test_modern_voms_signature_algorithms(tmp_path, kind):
    options: dict[str, object] = {}
    spki = None
    if kind == "pss":
        signer = throwaway_key(7)
        spki = public_key_info(signer.public)
        options = {
            "inner_algorithm": RSA_PSS,
            "outer_algorithm": RSA_PSS,
            "algorithm_parameters": _pss_parameters(),
            "signature_function": lambda message: _pss_sign(signer, message),
        }
        expected_digest = "rsassa-pss"
    elif kind == "ecdsa":
        secret = int.from_bytes(b"p256 VOMS signer".ljust(32, b"\0"), "big")
        spki = _ec_spki(p256.public_key(secret))
        options = {
            "inner_algorithm": ECDSA_SHA256,
            "outer_algorithm": ECDSA_SHA256,
            "algorithm_parameters": b"",
            "signature_function": lambda message: sequence(
                *map(integer, p256.sign(secret, message))
            ),
        }
        expected_digest = "sha256"
    else:
        seed = bytes(range(32))
        spki = _ed25519_spki(ed25519.public_key(seed))
        options = {
            "inner_algorithm": ED25519,
            "outer_algorithm": ED25519,
            "algorithm_parameters": b"",
            "signature_function": lambda message: ed25519.sign(seed, message),
        }
        expected_digest = "ed25519"
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path, ac_options=options, voms_spki=spki)
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert result.verified[0].digest == expected_digest


def test_signature_algorithm_rejection_edges(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path / "rsa")
    entry = inspect_voms(proxy.chain).entries[0]
    signer = _embedded_signer(entry)

    malformed = replace(entry, _outer_algorithm=sequence())
    assert voms._signature_status(malformed, signer) == (
        VOMSStatus.SIGNATURE_ALGORITHM,
        "",
    )
    bad_pss = replace(
        entry,
        _outer_algorithm=_algorithm(RSA_PSS, integer(1)),
        _signature=b"bad",
    )
    assert voms._signature_status(bad_pss, signer)[0] is VOMSStatus.SIGNATURE_ALGORITHM


def test_ecdsa_and_ed25519_signature_rejection_edges(tmp_path):
    proxy, _, _, facts = _fixture(tmp_path / "rsa")
    entry = inspect_voms(proxy.chain).entries[0]
    signer = _embedded_signer(entry)
    ecdsa = replace(
        entry,
        _outer_algorithm=_algorithm(ECDSA_SHA256, b""),
        _signature=sequence(integer(1)),
    )
    assert voms._signature_status(ecdsa, signer) == (VOMSStatus.SIGNATURE, "sha256")
    ec_secret = 42
    ec_der = make_certificate(
        facts["voms_name"],
        facts["ca_name"],
        throwaway_key(1).public,
        throwaway_key(1),
        subject_spki=_ec_spki(p256.public_key(ec_secret)),
    )
    ec_signer = parse_certificate(ec_der)
    assert voms._signature_status(ecdsa, ec_signer) == (VOMSStatus.SIGNATURE, "sha256")
    assert voms._signature_status(ecdsa, replace(ec_signer, der=sequence())) == (
        VOMSStatus.SIGNATURE,
        "sha256",
    )

    ed = replace(entry, _outer_algorithm=_algorithm(ED25519, b""), _signature=b"bad")
    assert voms._signature_status(ed, signer) == (VOMSStatus.SIGNATURE, "ed25519")
    assert voms._signature_status(ed, replace(signer, der=sequence())) == (
        VOMSStatus.SIGNATURE,
        "ed25519",
    )
    pss_without_rsa_key = replace(
        entry, _outer_algorithm=_algorithm(RSA_PSS, b""), _signature=b"bad"
    )
    assert voms._signature_status(pss_without_rsa_key, ec_signer) == (
        VOMSStatus.SIGNATURE,
        "rsassa-pss",
    )


def test_signature_digest_labels(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path)
    entry = inspect_voms(proxy.chain).entries[0]
    ecdsa = replace(entry, _outer_algorithm=_algorithm(ECDSA_SHA256, b""))
    ed = replace(entry, _outer_algorithm=_algorithm(ED25519, b""))
    assert voms._signature_digest(entry) == "sha256"
    assert voms._signature_digest(replace(entry, _outer_algorithm=_algorithm(RSA_PSS, b""))) == (
        "rsassa-pss"
    )
    assert voms._signature_digest(ecdsa) == "sha256"
    assert voms._signature_digest(ed) == "ed25519"
    assert voms._signature_digest(replace(entry, _outer_algorithm=_algorithm("1.2.3", b""))) is None


def test_pss_parameter_rejection_edges():
    parsed = voms._one(_pss_parameters())
    assert signatures.pss_parameters([]) == signatures.PSSParameters()
    assert signatures.pss_parameters([parsed, parsed]) is None
    assert signatures.pss_parameters([voms._one(integer(1))]) is None

    duplicate = sequence(tlv(0xA2, integer(1)), tlv(0xA2, integer(2)))
    assert signatures.pss_parameters([voms._one(duplicate)]) is None
    invalid_fields = [
        tlv(0xA4, integer(1)),
        tlv(0xA0, integer(1) + integer(2)),
        tlv(0xA0, sequence(oid("1.2.3"))),
        tlv(0xA1, sequence(oid("1.2.3"))),
        tlv(0xA1, sequence(oid(MGF1))),
        tlv(0xA1, sequence(oid(MGF1), sequence(oid(DIGEST_SHA256), NULL), NULL)),
        tlv(0xA1, sequence(oid(MGF1), sequence(oid("1.2.3")))),
        tlv(0xA0, sequence(oid(DIGEST_SHA256), integer(1))),
        tlv(0xA0, sequence(oid(DIGEST_SHA256), NULL, NULL)),
        tlv(0xA2, tlv(0x02, b"\xff")),
        tlv(0xA3, integer(2)),
        tlv(0xA3, sequence()),
    ]
    for field in invalid_fields:
        assert signatures.pss_parameters([voms._one(sequence(field))]) is None
    trailer = sequence(tlv(0xA3, integer(1)))
    assert signatures.pss_parameters([voms._one(trailer)]) == signatures.PSSParameters()


def test_strict_der_and_algorithm_shapes(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path)
    entry = inspect_voms(proxy.chain).entries[0]
    signer = _embedded_signer(entry)
    bad_parameters = replace(entry, _outer_algorithm=_algorithm(SHA256, integer(1)))
    assert voms._signature_status(bad_parameters, signer)[0] is VOMSStatus.SIGNATURE_ALGORITHM
    assert voms._signature_digest(bad_parameters) is None
    assert voms._signature_status(entry, replace(signer, der=sequence())) == (
        VOMSStatus.SIGNATURE,
        "sha256",
    )

    assert signatures.null_parameters([])
    assert not signatures.null_parameters([voms._one(integer(1))])
    assert not signatures.null_parameters([voms._one(tlv(0x05, b"x"))])
    with pytest.raises(DERError, match="no OID"):
        voms._algorithm_identifier(voms._one(integer(1)))
    with pytest.raises(DERError, match="no OID"):
        voms._algorithm_identifier(voms._one(sequence(oid(SHA256), NULL, NULL)))

    with pytest.raises(DERError, match="wrong shape"):
        voms._decode_extension(setof(sequence()), 0)
    too_many = sequence(sequence(*(sequence() for _ in range(33))))
    with pytest.raises(DERError, match="too many"):
        voms._decode_extension(too_many, 0)
    malformed_extension = sequence(oid("1.2.3"), integer(1), tlv(0x04, b"x"))
    with pytest.raises(DERError, match="malformed VOMS AC extension"):
        voms._extension_map(voms._one(sequence(malformed_extension)))
    with pytest.raises(DERError, match="malformed VOMS attribute certificate"):
        voms._decode_ac(voms._one(setof(sequence(), _algorithm(), bitstring(b"x"))), 0)
    assert signatures.pss_parameters([voms._one(setof())]) is None
    assert signatures.pss_parameters([voms._one(tlv(0x30, b"\x02"))]) is None
    with pytest.raises(DERError, match="malformed VOMS AC extension"):
        voms._extension_map(voms._one(sequence(integer(1))))


def test_pss_encoding_rejection_edges():
    key = throwaway_key(7)
    spki = public_key_info(key.public)
    params = _pss_parameters()
    valid = _pss_sign(key, b"message")

    def verify(signature: bytes, message: bytes = b"message", spki: bytes = spki) -> bool:
        return signatures.verify_signature(spki, RSA_PSS, params, signature, message)

    assert verify(valid)
    assert not verify(b"bad")
    assert not verify(b"\0" * len(valid))
    assert not verify(valid, b"other")
    assert not verify(key.n.to_bytes(len(valid), "big"))
    assert not verify(b"\x01\x00", spki=RSAPublicKey(257, 1).der())


def test_an_unusable_signer_key_is_a_bad_signature_not_an_error(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path)
    entry = inspect_voms(proxy.chain).entries[0]
    signer = _embedded_signer(entry)
    fields = b"".join(integer(index) for index in range(5))
    for der in (
        sequence(),
        sequence(sequence()),
        sequence(sequence(fields + sequence(integer(1)))),
        sequence(sequence(fields + sequence(sequence(oid(ED25519)), tlv(0x03, b"\x01x")))),
    ):
        status = voms._signature_status(entry, replace(signer, der=der))
        assert status == (VOMSStatus.SIGNATURE, "sha256")


def test_a_voms_proxy_is_decoded_and_fully_verified(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path, ac_options={"generic": True})
    inspected = inspect_voms(proxy.chain)
    assert inspected.status is VOMSStatus.UNCHECKED
    assert inspected.entries[0].status is VOMSStatus.UNCHECKED
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    entry = _assert_verified_result(result)
    assert entry.attributes[0].qualifier == "atlas"
    assert 0 < entry.remaining(now=time.time()) <= 3601


def test_a_delegated_proxy_finds_the_ac_on_its_parent(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path, parent_carrier=True)
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert result.entries[0].carrier == 1


def test_one_bad_ac_does_not_poison_another_vo_entry(tmp_path):
    _, _, _, facts = _fixture(tmp_path / "facts")
    arguments = (
        facts["user_name"],
        2,
        facts["voms_name"],
        facts["voms_der"],
        facts["voms_key"],
    )
    bad = _ac(*arguments, holder_serial=999)
    good = _ac(*arguments)
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path / "proxy", acs=(bad, good))
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert tuple(entry.status for entry in result.entries) == (VOMSStatus.HOLDER, VOMSStatus.OK)
    assert result.verified == (result.entries[1],)


@pytest.mark.parametrize(
    ("options", "status"),
    [
        ({"version": 2}, VOMSStatus.VERSION),
        ({"holder_serial": 999}, VOMSStatus.HOLDER),
        ({"not_before": time.time() + 1000}, VOMSStatus.NOT_YET_VALID),
        ({"not_after": time.time() - 1000}, VOMSStatus.EXPIRED),
        ({"embedded": ()}, VOMSStatus.NO_SIGNER),
        ({"inner_algorithm": SHA1}, VOMSStatus.SIGNATURE_ALGORITHM),
        ({"fqan": None}, VOMSStatus.ATTRIBUTES),
    ],
)
def test_intrinsic_failures_are_typed(tmp_path, options, status):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path, ac_options=options)
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is status
    assert not result.verified and not result.entries[0].verified


def test_signature_issuer_target_and_extension_failures_are_typed(tmp_path):
    _, _, _, facts = _fixture(tmp_path / "base")
    unknown = _extension("1.2.3.4.5", tlv(0x05, b""), critical=True)
    targets = _extension("2.5.29.55", sequence(sequence(tlv(0xA0, tlv(0x82, b"elsewhere")))))
    cases: list[tuple[dict[str, object], VOMSStatus]] = [
        ({"signature_key": throwaway_key(2)}, VOMSStatus.SIGNATURE),
        ({"issuer_name": facts["user_name"]}, VOMSStatus.ISSUER),
        ({"extra_extensions": (targets,)}, VOMSStatus.TARGET),
        ({"extra_extensions": (unknown,)}, VOMSStatus.EXTENSION),
        ({"outer_algorithm": "1.2.840.113549.1.1.4"}, VOMSStatus.SIGNATURE_ALGORITHM),
    ]
    for index, (options, expected) in enumerate(cases):
        proxy, ca_dir, voms_dir, _ = _fixture(tmp_path / str(index), ac_options=options)
        result = validate_voms(
            proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir), host="this-host"
        )
        assert result.status is expected


def test_external_trust_failures_are_not_silently_downgraded(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path)
    untrusted = validate_voms(proxy.chain, ca_path=str(tmp_path / "none"), voms_dir=str(voms_dir))
    no_lsc = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(tmp_path / "none"))
    assert untrusted.status is VOMSStatus.UNTRUSTED
    assert no_lsc.status is VOMSStatus.LSC


def test_legacy_voms_certificate_and_rfc2253_lsc_are_accepted(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(tmp_path)
    entry = inspect_voms(proxy.chain).entries[0]
    assert entry._embedded
    lsc = next(Path(voms_dir, "atlas").glob("*.lsc"))
    lsc.unlink()
    Path(voms_dir, "atlas", "server.pem").write_bytes(_embedded_signer(entry).pem())
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    Path(voms_dir, "atlas", "server.pem").unlink()
    lsc.write_text("CN=voms.example,DC=org\nCN=Grid CA,DC=org\n")
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK


def test_missing_and_malformed_extensions_have_distinct_results(tmp_path):
    proxy, _, _, _ = _fixture(tmp_path)
    assert inspect_voms(proxy.chain[1:]).status is VOMSStatus.NO_EXTENSION
    malformed = replace(proxy.chain[0], der=b"\x30")
    assert inspect_voms((malformed,)).status is VOMSStatus.DECODE


def test_default_directories_honour_environment_and_homebrew(monkeypatch, tmp_path):
    certs, voms = tmp_path / "certs", tmp_path / "voms"
    certs.mkdir()
    voms.mkdir()
    monkeypatch.setenv("X509_CERT_DIR", str(certs))
    monkeypatch.setenv("X509_VOMS_DIR", str(voms))
    assert default_ca_path() == str(certs)
    assert default_voms_dir() == str(voms)
    monkeypatch.delenv("X509_CERT_DIR")
    monkeypatch.delenv("X509_VOMS_DIR")
    monkeypatch.setattr("xrdsec.credentials.GRID_SECURITY_DIRS", None)  # the platform's own
    monkeypatch.setattr(os.path, "isdir", lambda path: path.startswith("/opt/homebrew"))
    monkeypatch.setattr("xrdsec.credentials.sys.platform", "darwin")
    assert default_ca_path() == "/opt/homebrew/etc/grid-security/certificates"
    assert default_voms_dir() == "/opt/homebrew/etc/grid-security/vomsdir"


def test_der_name_and_time_helpers_reject_malformed_values():
    empty = voms._one(sequence())
    assert not voms._first_directory_name(empty)
    nested = voms._one(sequence(sequence(), tlv(0xA4, name(("2.5.4.3", "server")))))
    assert voms._first_directory_name(nested).cn == "server"
    assert not voms._first_directory_name(
        voms._one(tlv(0xA4, name(("2.5.4.3", "one")) + name(("2.5.4.3", "two"))))
    )

    with pytest.raises(DERError, match="trailing"):
        voms._one(sequence() + b"\x00")
    with pytest.raises(DERError, match="GeneralizedTime"):
        voms._time(voms._one(integer(1)))
    with pytest.raises(DERError, match="UTC"):
        voms._time(voms._one(tlv(0x18, b"20260101000000")))
    with pytest.raises(DERError, match="malformed VOMS time"):
        voms._time(voms._one(tlv(0x18, b"not-a-timeZ")))


def test_der_attribute_helpers_reject_malformed_values():
    assert voms._extension_map(None) == {}
    with pytest.raises(DERError, match="malformed VOMS AC extension"):
        voms._extension_map(voms._one(sequence(sequence(integer(1), tlv(0x04, b"x")))))
    with pytest.raises(DERError, match="no OCTET STRING"):
        voms._extension_map(voms._one(sequence(sequence(oid("1.2.3"), integer(1)))))

    syntax = sequence(
        integer(1),
        sequence(integer(1), tlv(0x04, b"bad,fqan"), tlv(0x04, b"/atlas/good")),
    )
    plain_policy = sequence(tlv(0xA0, tlv(0x86, b"not-a-uri")), sequence())
    empty_syntax = sequence()
    attributes = voms._one(
        sequence(
            sequence(oid("1.2.3"), setof()),
            sequence(oid(VOMS_FQAN_OID), setof(empty_syntax, plain_policy, syntax)),
        )
    )
    vo, uri, fqans = voms._attributes(attributes)
    assert (vo, uri, fqans) == ("atlas", "", ("/atlas/good",))
    assert not voms._general_name_text(voms._one(sequence(integer(1))))


def test_der_nested_attribute_helpers_reject_malformed_values():
    assert voms._generic_attributes(None) == ()
    assert voms._generic_attributes(sequence()) == ()
    short_provider = sequence(sequence(sequence(integer(1))))
    assert voms._generic_attributes(short_provider) == ()
    bad_triple = sequence(
        sequence(
            sequence(_general_names(name(("2.5.4.3", "server"))), sequence(sequence(integer(1))))
        )
    )
    assert voms._generic_attributes(bad_triple) == ()

    assert voms._embedded_certificates(None) == ()
    with pytest.raises(DERError, match="one-element"):
        voms._embedded_certificates(sequence(sequence(), sequence()))
    assert voms._targets(None) is None
    targets = sequence(sequence(integer(1), tlv(0xA0, sequence())))
    assert voms._targets(targets) == ()
    assert voms._authority_key_id(None) is None
    assert voms._authority_key_id(sequence(integer(1))) is None


def test_der_ac_helpers_reject_malformed_values(tmp_path, monkeypatch):
    with pytest.raises(DERError, match="malformed VOMS attribute certificate"):
        voms._decode_ac(voms._one(sequence()), 0)
    with pytest.raises(DERError, match="missing required fields"):
        voms._decode_ac(voms._one(sequence(sequence(), _algorithm(), bitstring(b"x"))), 0)
    short_validity = sequence(
        integer(1),
        sequence(),
        sequence(),
        _algorithm(),
        integer(1),
        sequence(_gentime(time.time())),
        sequence(),
    )
    with pytest.raises(DERError, match="validity is not a pair"):
        voms._decode_ac(voms._one(sequence(short_validity, _algorithm(), bitstring(b"x"))), 0)
    empty_base_holder = sequence(
        integer(1),
        sequence(tlv(0xA0, b"")),
        sequence(),
        _algorithm(),
        integer(1),
        sequence(_gentime(time.time() - 10), _gentime(time.time() + 10)),
        sequence(),
    )
    assert not voms._decode_ac(
        voms._one(sequence(empty_base_holder, _algorithm(), bitstring(b"x"))), 0
    ).holder
    with pytest.raises(DERError, match="wrong shape"):
        voms._decode_extension(sequence(sequence(), sequence()), 0)
    with pytest.raises(DERError, match="empty"):
        voms._decode_extension(sequence(sequence()), 0)

    proxy, _, _, _ = _fixture(tmp_path)
    entry = inspect_voms(proxy.chain).entries[0]
    assert voms._signature_digest(replace(entry, _outer_algorithm=sequence())) is None
    assert voms._certificate_extension(_embedded_signer(entry), "1.2.3") is None
    assert validate_voms(()).status is VOMSStatus.NO_EXTENSION

    monkeypatch.setattr(voms, "_voms_extension", lambda _certificate: b"\x30")
    assert inspect_voms(proxy.chain).status is VOMSStatus.DECODE

    def broken_extension(_certificate):
        raise DERError("x")

    monkeypatch.setattr(voms, "_voms_extension", broken_extension)
    assert inspect_voms(proxy.chain).status is VOMSStatus.DECODE


@dataclass(frozen=True)
class _MappedCertificate:
    """xgfalclient's certificate model: extensions as ``{oid: (critical, value)}``."""

    subject: Name
    issuer: Name
    serial: int
    not_before: float
    not_after: float
    public_key: RSAPublicKey | None
    extensions: Mapping[str, tuple[bool, bytes]]
    der: bytes
    is_proxy: bool


def test_a_chain_in_xgfalclients_certificate_model_yields_the_same_acs(tmp_path):
    """xgfalclient's certificates expose ``{oid: (critical, value)}``, not OID names.

    One validator serves both clients, so the AC must be found - and decode
    identically - whichever model the chain arrives in.
    """
    proxy, _, _, _ = _fixture(tmp_path)
    mapped = [
        _MappedCertificate(
            subject=link.subject,
            issuer=link.issuer,
            serial=link.serial,
            not_before=link.not_before,
            not_after=link.not_after,
            public_key=link.public_key,
            extensions=certificate_data(link.der).extension_values,
            der=link.der,
            is_proxy=link.is_proxy,
        )
        for link in proxy.chain
    ]
    assert all(isinstance(link.extensions, dict) for link in mapped)
    expected = inspect_voms(proxy.chain)
    found = inspect_voms(mapped)
    assert found.status is expected.status
    assert found.entries == expected.entries and found.entries[0].fqans
    assert voms._certificate_extension(mapped[0], "1.2.3") is None


@pytest.mark.parametrize(
    ("ski", "aki", "status"),
    [
        (tlv(0x04, b"key-id"), b"key-id", VOMSStatus.OK),
        (tlv(0x04, b"key-id"), b"other", VOMSStatus.ISSUER),
        (b"\x30", b"key-id", VOMSStatus.ISSUER),
        (None, b"key-id", VOMSStatus.OK),
    ],
)
def test_authority_key_identifier_binding(tmp_path, ski, aki, status):
    aki_extension = _extension("2.5.29.35", sequence(tlv(0x80, aki)))
    proxy, ca_dir, voms_dir, _ = _fixture(
        tmp_path,
        voms_ski=ski,
        ac_options={"extra_extensions": (aki_extension,)},
    )
    assert validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir)).status is status


def test_matching_unknown_signature_algorithm_is_rejected(tmp_path):
    proxy, ca_dir, voms_dir, _ = _fixture(
        tmp_path,
        ac_options={
            "inner_algorithm": "1.2.840.113549.1.1.4",
            "outer_algorithm": "1.2.840.113549.1.1.4",
        },
    )
    assert (
        validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir)).status
        is VOMSStatus.SIGNATURE_ALGORITHM
    )


@pytest.mark.parametrize(
    ("algorithm", "digest"),
    [(SHA1, "sha1"), (SHA256, "sha256"), (SHA384, "sha384"), (SHA512, "sha512")],
)
def test_supported_rsa_signature_algorithms(tmp_path, algorithm, digest):
    proxy, ca_dir, voms_dir, _ = _fixture(
        tmp_path,
        ac_options={
            "inner_algorithm": algorithm,
            "outer_algorithm": algorithm,
            "signature_digest": digest,
        },
    )
    result = validate_voms(proxy.chain, ca_path=str(ca_dir), voms_dir=str(voms_dir))
    assert result.status is VOMSStatus.OK
    assert result.verified[0].digest == digest


def test_the_lazy_package_hands_out_the_voms_module():
    import xrdsec

    assert xrdsec.voms.validate_voms is validate_voms
    assert xrdsec.voms.inspect_voms is inspect_voms
    assert xrdsec.voms.VOMSStatus is VOMSStatus


def test_trust_chain_failure_edges(tmp_path):
    proxy, ca_dir, _, facts = _fixture(tmp_path / "fixture")
    entry = inspect_voms(proxy.chain).entries[0]
    signer = _embedded_signer(entry)
    now = time.time()

    assert not voms._trusted_chain((replace(signer, not_after=0),), str(ca_dir), now)
    assert not voms._trusted_chain(
        (replace(signer, issuer=Name((("CN", "nobody"),))),), str(ca_dir), now
    )
    bad_der = make_certificate(
        facts["voms_name"],
        facts["ca_name"],
        facts["voms_key"].public,
        facts["user_key"],
        serial=9,
    )
    assert not voms._trusted_chain((parse_certificate(bad_der),), str(ca_dir), now)

    middle_key = throwaway_key(6)
    middle_name = name(("2.5.4.3", "Intermediate"))
    middle_der = make_certificate(
        middle_name, facts["ca_name"], middle_key.public, facts["ca_key"], serial=10
    )
    leaf_der = make_certificate(
        facts["voms_name"], middle_name, facts["voms_key"].public, middle_key, serial=11
    )
    assert voms._trusted_chain(
        (parse_certificate(leaf_der), parse_certificate(middle_der)), str(ca_dir), now
    )

    key_a, key_b = throwaway_key(7), throwaway_key(5)
    name_a, name_b = name(("2.5.4.3", "A")), name(("2.5.4.3", "B"))
    cert_a = parse_certificate(make_certificate(name_a, name_b, key_a.public, key_b, serial=12))
    cert_b = parse_certificate(make_certificate(name_b, name_a, key_b.public, key_a, serial=13))
    assert not voms._trusted_chain((cert_a, cert_b, cert_a), str(ca_dir), now)

    anchors = tmp_path / "anchors"
    anchors.mkdir()
    (anchors / "README").write_text("ignored")
    (anchors / "12345678.0").mkdir()
    assert voms._load_anchors(str(anchors)) == []


def test_lsc_failure_edges(tmp_path, monkeypatch):
    proxy, _, voms_dir, facts = _fixture(tmp_path / "fixture")
    signer = _embedded_signer(inspect_voms(proxy.chain).entries[0])

    assert not voms._lsc_matches(str(voms_dir), "../atlas", (signer,))
    legacy = Path(voms_dir, "atlas", "wrong.pem")
    legacy.write_bytes(pem("CERTIFICATE", facts["ca_der"]))
    next(Path(voms_dir, "atlas").glob("*.lsc")).unlink()
    assert not voms._lsc_matches(str(voms_dir), "atlas", (signer,))

    lsc = tmp_path / "test.lsc"
    lsc.write_text("\n# only comments\n")
    assert not voms._lsc_file_matches(lsc, (signer,))
    lsc.write_text("a\nb\nc\nd\n")
    assert not voms._lsc_file_matches(lsc, (signer,))
    lsc.write_text(f"CN=wrong\n{signer.issuer}\n")
    assert not voms._lsc_file_matches(lsc, (signer,))
    lsc.write_text(f"{signer.subject}\nCN=wrong\n")
    assert not voms._lsc_file_matches(lsc, (signer,))

    original_read_text = Path.read_text

    def fail_read_text(path, *args, **kwargs):
        if path == lsc:
            raise OSError("unreadable")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_read_text)
    assert not voms._lsc_file_matches(lsc, (signer,))

    def fail_certificates(_data):
        raise OSError

    monkeypatch.setattr(voms, "load_certificates", fail_certificates)
    assert not voms._lsc_matches(str(voms_dir), "atlas", (signer,))


def test_voms_name_path_and_holder_edges(tmp_path, monkeypatch):
    proxy, _, _, _ = _fixture(tmp_path / "fixture")
    entry = inspect_voms(proxy.chain).entries[0]

    assert voms._escape_dn(" #comma, ") == r"\ #comma\,\ "
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("xrdsec.credentials.GRID_SECURITY_DIRS", None)  # the platform's own
    assert _gridpaths._candidates("vomsdir") == ("/etc/grid-security/vomsdir",)
    monkeypatch.delenv("X509_CERT_DIR", raising=False)
    monkeypatch.setattr(os.path, "isdir", lambda _path: False)
    assert default_ca_path() is None

    assert not voms._holder_matches(replace(entry, holder=Name()), proxy.chain)
    orphan = replace(proxy.chain[0], issuer=Name((("CN", "missing"),)))
    assert not voms._holder_matches(entry, (orphan,))
    first = replace(proxy.chain[0], serial=999)
    second = replace(
        proxy.chain[1],
        serial=998,
        subject=first.issuer,
        issuer=first.subject,
        extensions=(PROXY_CERT_INFO_OID,),
    )
    assert not voms._holder_matches(entry, (first, second))
