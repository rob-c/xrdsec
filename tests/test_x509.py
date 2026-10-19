"""X.509 and RFC 3820 proxies. The chains are minted in process by :mod:`xrdsec.testing.rawpki`."""

import time
from pathlib import Path

import pytest

from xrdsec.der import DERError, Element
from xrdsec.der import decode_time as _decode_time
from xrdsec.rsa import RSAPrivateKey
from xrdsec.testing.rawpki import (
    PROXY_CERT_INFO,
    PROXY_CERT_INFO_OID,
    bitstring,
    integer,
    make_certificate,
    name,
    oid,
    pem,
    private_key_pem,
    proxy_chain,
    public_key_info,
    sequence,
    setof,
    throwaway_key,
    tlv,
    utctime,
    utf8,
)
from xrdsec.x509 import (
    LEGACY_PROXY_OID,
    Certificate,
    Name,
    ProxyCredential,
    certificate_data,
    default_proxy_path,
    load_certificates,
    load_proxy,
    parse_certificate,
)

CN = "2.5.4.3"
DC = "0.9.2342.19200300.100.1.25"


@pytest.fixture(scope="module")
def key():
    return throwaway_key(0)


@pytest.fixture
def proxy_file(tmp_path, key):
    path = tmp_path / "x509up_u1000"
    path.write_bytes(proxy_chain(key))
    return path


def test_a_proxy_file_loads_as_a_chain(proxy_file, key):
    proxy = load_proxy(str(proxy_file))
    assert len(proxy.chain) == 3
    assert proxy.key == key
    assert proxy.path == str(proxy_file)
    assert proxy.certificate is proxy.chain[0]


def test_the_anchor_in_a_proxy_file_is_not_put_on_the_wire(proxy_file):
    """A server refuses a chain carrying the CA it is meant to verify against.

    ``proxy_chain`` writes the CA into the file, as some proxy tools do. It is
    loaded - the chain is what the file holds - but what GSI sends is the
    proxy and the certificate that signed it, because the far end looks its
    own anchors up rather than believing one that arrives.
    """
    proxy = load_proxy(str(proxy_file))
    assert [link.is_anchor for link in proxy.chain] == [False, False, True]
    assert proxy.pem() == proxy.chain[0].pem() + proxy.chain[1].pem()
    assert proxy.pem().count(b"BEGIN CERTIFICATE") == 2


def test_a_file_of_nothing_but_an_anchor_is_sent_as_it_is(tmp_path, key):
    """Sending nothing at all would make the server's refusal a mystery."""
    ca_name = name(("2.5.4.3", "Only A CA"))
    only = pem("CERTIFICATE", make_certificate(ca_name, ca_name, key.public, key))
    path = tmp_path / "anchor-only"
    path.write_bytes(only + private_key_pem(key))
    proxy = load_proxy(str(path))
    assert [link.is_anchor for link in proxy.chain] == [True]
    assert proxy.pem() == proxy.chain[0].pem()


def test_the_subject_reads_like_openssl(proxy_file):
    proxy = load_proxy(str(proxy_file))
    assert str(proxy.subject) == "/DC=org/DC=example/CN=Jane Doe/CN=1234567890"
    assert proxy.subject.cn == "1234567890"
    assert proxy.subject.get("DC") == ["org", "example"]


def test_the_identity_strips_the_proxy_common_names(proxy_file):
    """What a job's log should print: the human, not the delegation."""
    assert load_proxy(str(proxy_file)).identity == "/DC=org/DC=example/CN=Jane Doe"


@pytest.mark.parametrize("cn", ["proxy", "12345", "1"])
def test_every_proxy_naming_convention_is_stripped(tmp_path, key, cn):
    path = tmp_path / "p.pem"
    path.write_bytes(proxy_chain(key, proxy_cn=cn))
    assert load_proxy(str(path)).identity == "/DC=org/DC=example/CN=Jane Doe"


def test_the_proxy_certificate_is_recognised(proxy_file):
    chain = load_proxy(str(proxy_file)).chain
    assert chain[0].is_proxy
    assert PROXY_CERT_INFO_OID in chain[0].extensions
    assert not chain[2].is_proxy  # the self-signed CA


def test_a_legacy_globus_proxy_is_recognised(key):
    """Pre-RFC proxies carry a different OID and are still in the wild."""
    subject = name((DC, "org"), (CN, "Jane"))
    der = make_certificate(
        subject, subject, key.public, key, extensions=((LEGACY_PROXY_OID, PROXY_CERT_INFO),)
    )
    assert load_certificates(pem("CERTIFICATE", der))[0].is_proxy


def test_a_proxy_without_the_extension_is_caught_by_its_name(key):
    """Some issuers omit proxyCertInfo; the appended CN still gives it away."""
    issuer = name((DC, "org"), (CN, "Jane"))
    subject = name((DC, "org"), (CN, "Jane"), (CN, "proxy"))
    der = make_certificate(subject, issuer, key.public, key)
    certificate = load_certificates(pem("CERTIFICATE", der))[0]
    assert certificate.is_proxy and not certificate.extensions


def test_a_ca_issued_certificate_is_not_a_proxy(key):
    der = make_certificate(name((CN, "Jane")), name((CN, "Example CA")), key.public, key)
    assert not load_certificates(pem("CERTIFICATE", der))[0].is_proxy


def test_validity_is_read_and_expiry_is_reported(tmp_path, key):
    fresh = load_proxy(str(_write(tmp_path / "a.pem", proxy_chain(key))))
    assert not fresh.expired
    assert 0 < fresh.remaining() <= 43200

    stale = _write(tmp_path / "b.pem", proxy_chain(key, not_after=time.time() - 7200))
    expired = load_proxy(str(stale))
    assert expired.expired
    assert expired.remaining() < 0
    assert expired.certificate.expired


def test_the_chain_expiry_is_the_earliest_member(tmp_path, key):
    """A proxy is only as good as the shortest-lived certificate above it."""
    soon = time.time() + 600
    proxy = load_proxy(str(_write(tmp_path / "c.pem", proxy_chain(key, not_after=soon))))
    assert proxy.certificate.not_after < min(c.not_after for c in proxy.chain[1:])
    assert proxy.remaining() == pytest.approx(soon - time.time(), abs=2)
    assert not proxy.expired


def test_the_public_key_comes_back(proxy_file, key):
    assert load_proxy(str(proxy_file)).certificate.public_key == key.public


def test_a_certificate_round_trips_through_pem(proxy_file):
    certificate = load_proxy(str(proxy_file)).certificate
    again = load_certificates(certificate.pem())[0]
    assert again == certificate


def test_the_chain_pem_is_what_goes_on_the_wire(proxy_file):
    """GSI echoes the chain verbatim, so concatenation order must hold.

    Everything the file holds except the anchor, which the test above is
    about, and in the order the file holds it.
    """
    proxy = load_proxy(str(proxy_file))
    sent = [link for link in proxy.chain if not link.is_anchor]
    assert proxy.pem() == b"".join(c.pem() for c in sent)
    assert load_certificates(proxy.pem()) == sent


def test_serials_and_issuers_are_decoded(proxy_file):
    chain = load_proxy(str(proxy_file)).chain
    assert [c.serial for c in chain] == [3, 2, 1]
    assert str(chain[0].issuer) == str(chain[1].subject)
    assert str(chain[2].issuer) == str(chain[2].subject)  # the CA is self-signed


def test_an_unparseable_member_does_not_lose_the_chain(tmp_path, key):
    """A proxy file routinely carries material this reader has no view on."""
    junk = pem("CERTIFICATE", b"\x30\x03\x02\x01\x01")
    path = _write(tmp_path / "d.pem", junk + proxy_chain(key))
    assert len(load_proxy(str(path)).chain) == 3


def test_a_file_with_no_certificate_is_refused(tmp_path, key):
    path = _write(tmp_path / "e.pem", private_key_pem(key))
    with pytest.raises(DERError, match="no certificate"):
        load_proxy(str(path))


def test_a_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        load_proxy(str(tmp_path / "absent.pem"))


def test_non_certificate_blocks_are_ignored(key):
    assert load_certificates(private_key_pem(key)) == []
    assert load_certificates("") == []


def test_the_proxy_path_follows_the_grid_convention(monkeypatch, tmp_path):
    import os

    from xrdsec import credentials

    monkeypatch.delenv("X509_USER_PROXY", raising=False)
    monkeypatch.setattr(credentials, "TMP_DIR", "/tmp")
    assert default_proxy_path() == f"/tmp/x509up_u{os.geteuid()}"
    monkeypatch.setenv("X509_USER_PROXY", str(tmp_path / "mine.pem"))
    assert default_proxy_path() == str(tmp_path / "mine.pem")


def test_an_explicit_environment_beats_the_process_one(monkeypatch, tmp_path):
    monkeypatch.setenv("X509_USER_PROXY", "/tmp/from-env")
    named = {"X509_USER_PROXY": str(tmp_path / "cfg.pem")}
    assert default_proxy_path(named) == str(tmp_path / "cfg.pem")
    assert default_proxy_path({}, uid=7).endswith("x509up_u7")


@pytest.mark.parametrize(
    "tag, text, expected",
    [
        (0x17, "260731120000Z", "2026-07-31 12:00:00"),
        (0x17, "4901011200Z", "2049-01-01 12:00:00"),  # the 50-year pivot, below
        (0x17, "500101120000Z", "1950-01-01 12:00:00"),  # and above
        (0x18, "20260731120000Z", "2026-07-31 12:00:00"),
        (0x18, "20260731120000", "2026-07-31 12:00:00"),  # the Z is conventional, not required
    ],
)
def test_both_time_encodings_are_understood(tag, text, expected):
    when = _decode_time(Element(tag, text.encode()))
    assert time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(when)) == expected


@pytest.mark.parametrize("tag, text", [(0x17, "26Z"), (0x02, "20260731120000Z")])
def test_malformed_times_are_refused(tag, text):
    with pytest.raises(DERError):
        _decode_time(Element(tag, text.encode()))


def test_bmp_strings_in_a_subject_are_decoded():
    """A DirectoryString may be UTF-16BE; a mojibake CN is a support ticket."""
    from xrdsec.der import parse
    from xrdsec.testing.rawpki import oid, sequence, setof, tlv
    from xrdsec.x509 import name_from_element

    encoded = sequence(setof(sequence(oid(CN), tlv(0x1E, "Jané".encode("utf-16-be")))))
    assert name_from_element(parse(encoded)[0]).cn == "Jané"


def test_an_unknown_attribute_type_falls_back_to_its_oid(key):
    der = make_certificate(name(("1.2.3.4", "x")), name((CN, "CA")), key.public, key)
    assert str(load_certificates(pem("CERTIFICATE", der))[0].subject) == "/1.2.3.4=x"


def test_an_empty_name_is_falsy():
    assert not Name()
    assert Name().cn == ""
    assert str(Name()) == ""
    assert Name((("CN", "a"),))


def test_reprs_do_not_leak_the_key(proxy_file):
    proxy = load_proxy(str(proxy_file))
    text = repr(proxy)
    assert text == (
        "ProxyCredential(subject='/DC=org/DC=example/CN=Jane Doe/CN=1234567890', key=<redacted>)"
    )
    assert isinstance(proxy.key, RSAPrivateKey)
    assert str(proxy.key.d) not in text
    assert "der" not in repr(proxy.certificate)  # 2 kB of DER is not a repr


def test_certificate_str_is_its_subject(proxy_file):
    certificate = load_proxy(str(proxy_file)).certificate
    assert str(certificate) == str(certificate.subject)


def test_the_dataclasses_are_hashable_and_frozen(proxy_file):
    proxy = load_proxy(str(proxy_file))
    assert isinstance(proxy, ProxyCredential)
    assert isinstance(proxy.certificate, Certificate)
    with pytest.raises(AttributeError):
        # Assigning to a frozen field is the point: mypy rightly calls it an error.
        proxy.certificate.serial = 9  # type: ignore[misc]


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Certificates that are not what they should be
# ---------------------------------------------------------------------------


def _hand_built(*fields: bytes) -> bytes:
    """A certificate whose body is exactly ``fields``, signature and all."""
    algorithm = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    return sequence(sequence(*fields), algorithm, bitstring(b"\x00"))


def test_a_body_too_short_to_be_a_certificate_is_refused():
    with pytest.raises(DERError, match="missing required fields"):
        parse_certificate(_hand_built(tlv(0xA0, integer(2)), integer(1)))


def test_validity_that_is_not_a_pair_of_times_is_refused(key):
    algorithm = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    subject = name((CN, "broken"))
    with pytest.raises(DERError, match="validity is not a pair"):
        parse_certificate(
            _hand_built(
                tlv(0xA0, integer(2)),
                integer(1),
                algorithm,
                subject,
                sequence(utctime(time.time())),  # one time, not two
                subject,
                public_key_info(key.public),
            )
        )


def test_a_certificate_whose_key_is_not_rsa_is_still_readable(key):
    """An EC certificate is a name, a validity and a key we cannot use."""
    algorithm = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    subject = name((CN, "elliptic"))
    ec_key = sequence(sequence(oid("1.2.840.10045.2.1")), bitstring(b"\x04" + b"\x11" * 64))
    der = _hand_built(
        tlv(0xA0, integer(2)),
        integer(7),
        algorithm,
        subject,
        sequence(utctime(time.time() - 60), utctime(time.time() + 60)),
        subject,
        ec_key,
    )
    certificate = parse_certificate(der)
    assert certificate.public_key is None
    assert certificate.subject.cn == "elliptic"
    assert certificate.serial == 7


@pytest.mark.parametrize(
    "spki",
    [
        # P-256 named, but the point is not on the curve: ``ValueError``.
        sequence(
            sequence(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")),
            bitstring(b"\x04" + b"\x11" * 64),
        ),
        # An algorithm ``cryptography`` has never heard of: ``UnsupportedAlgorithm``.
        sequence(sequence(oid("1.2.3.4.5")), bitstring(b"\x00" * 8)),
    ],
    ids=["point-off-curve", "unknown-algorithm"],
)
def test_a_key_the_library_cannot_load_still_leaves_a_readable_certificate(key, spki):
    """The certificate parses strictly, but its key does not: the bounded decoder takes over.

    ``cryptography`` loads the certificate lazily, so the key only fails when
    asked for; inspection (``describe_proxy``, VOMS) must still see the names.
    """
    subject = name((CN, "keyless"))
    data = certificate_data(make_certificate(subject, subject, key.public, key, subject_spki=spki))
    assert data.public_key is None
    assert data.subject.cn == "keyless"


def test_an_attribute_that_is_not_a_pair_is_skipped(key):
    """A malformed RDN costs that attribute, not the whole certificate."""
    lopsided = sequence(setof(sequence(oid(CN))), setof(sequence(oid(CN), utf8("real"))))
    der = make_certificate(lopsided, lopsided, key.public, key)
    assert parse_certificate(der).subject.cn == "real"


def test_a_public_key_field_of_the_wrong_shape_leaves_the_key_out(key):
    """SubjectPublicKeyInfo must be algorithm-then-bits; anything else is not a key."""
    algorithm = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    subject = name((CN, "shapeless"))
    der = _hand_built(
        tlv(0xA0, integer(2)),
        integer(3),
        algorithm,
        subject,
        sequence(utctime(time.time() - 60), utctime(time.time() + 60)),
        subject,
        sequence(sequence(oid("1.2.840.10045.2.1"))),  # no BIT STRING beside it
    )
    assert parse_certificate(der).public_key is None


def test_trailing_fields_that_are_not_extensions_are_passed_over(key):
    """``issuerUniqueID`` is ``[1]``; only ``[3]`` holds extensions."""
    algorithm = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    subject = name((CN, "unique"))
    der = _hand_built(
        tlv(0xA0, integer(2)),
        integer(4),
        algorithm,
        subject,
        sequence(utctime(time.time() - 60), utctime(time.time() + 60)),
        subject,
        public_key_info(key.public),
        tlv(0xA1, b"\x00\x01"),  # [1] issuerUniqueID
        tlv(0xA3, sequence(sequence())),  # [3] with one empty extension
    )
    certificate = parse_certificate(der)
    assert certificate.extensions == ()
    assert certificate.public_key == key.public


def test_an_ec_proxy_loads_with_its_library_key(tmp_path):
    """GSI needs RSA, but an EC proxy is still a proxy: it loads, and says what its key is."""
    import datetime

    from cryptography import x509 as library
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from xrdsec.x509 import load_proxy

    key = ec.generate_private_key(ec.SECP256R1())
    subject = library.Name([library.NameAttribute(NameOID.COMMON_NAME, "EC user")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        library.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "x509up"
    path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    proxy = load_proxy(str(path))
    assert isinstance(proxy.key, ec.EllipticCurvePrivateKey)
    assert proxy.certificate.public_key is None


# -- what xgfalclient's certificate view is built from ------------------------


def test_the_proxy_policy_is_read_from_either_proxy_extension():
    from xrdsec.x509 import INHERIT_ALL_OID, proxy_policy

    assert proxy_policy({}) is None
    assert proxy_policy({PROXY_CERT_INFO_OID: (True, PROXY_CERT_INFO)}) == INHERIT_ALL_OID
    assert proxy_policy({LEGACY_PROXY_OID: (True, PROXY_CERT_INFO)}) == INHERIT_ALL_OID
    # Too garbled to name a policy: still a proxy, of no readable kind.
    assert proxy_policy({PROXY_CERT_INFO_OID: (True, b"\x05")}) == ""
    assert proxy_policy({PROXY_CERT_INFO_OID: (True, sequence())}) == ""


def test_a_gt2_proxy_is_known_by_its_exact_name():
    from xrdsec.x509 import legacy_proxy_kind

    issuer = Name((("DC", "org"), ("CN", "Jane")))
    assert legacy_proxy_kind(Name((*issuer.rdns, ("CN", "proxy"))), issuer) == "proxy"
    limited = Name((*issuer.rdns, ("CN", "limited proxy")))
    assert legacy_proxy_kind(limited, issuer) == "limited proxy"
    # XrdCl's reading would take these; Globus' does not.
    assert legacy_proxy_kind(Name((*issuer.rdns, ("CN", "12345"))), issuer) is None
    assert legacy_proxy_kind(Name((*issuer.rdns, ("OU", "proxy"))), issuer) is None
    assert legacy_proxy_kind(Name((("CN", "Other"), ("CN", "proxy"))), issuer) is None
    assert legacy_proxy_kind(Name(), issuer) is None


def test_a_decoded_signature_is_checked_with_any_key_form(key):
    from xrdsec.x509 import certificate_data, signed_by

    data = certificate_data(make_certificate(name((CN, "x")), name((CN, "x")), key.public, key))
    assert signed_by(data.tbs, data.signature_oid, data.signature, key.public)
    assert signed_by(data.tbs, data.signature_oid, data.signature, key.public.der())
    assert not signed_by(data.tbs, data.signature_oid, data.signature, throwaway_key(1).public)
    assert not signed_by(data.tbs, "1.2.3", data.signature, key.public)  # unknown algorithm


def test_certificates_are_read_into_whatever_view_the_caller_builds(proxy_file):
    from xrdsec.x509 import certificates_in

    subjects = certificates_in(proxy_file.read_bytes(), lambda der: parse_certificate(der).subject)
    assert subjects == [link.subject for link in load_proxy(str(proxy_file)).chain]


def test_a_key_in_a_file_of_its_own_is_read_from_there(tmp_path, key):
    from xrdsec.rsa import pem_blocks
    from xrdsec.x509 import credential_key, read_credential_files

    blocks = pem_blocks(proxy_chain(key))
    certificates = b"".join(pem(label, der) for label, der in blocks if label == "CERTIFICATE")
    cert_path = _write(tmp_path / "usercert.pem", certificates)
    key_path = _write(tmp_path / "userkey.pem", private_key_pem(key))
    assert read_credential_files(str(cert_path), str(key_path)) == (
        certificates,
        private_key_pem(key),
    )
    assert read_credential_files(str(cert_path), str(cert_path)) == (certificates, certificates)
    assert load_proxy(str(cert_path), str(key_path)).key == key
    with pytest.raises(DERError):
        credential_key(certificates)  # no key in there


def test_a_non_rsa_key_is_handed_back_as_the_library_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from xrdsec.x509 import credential_key

    ec_key = ec.generate_private_key(ec.SECP256R1())
    blob = ec_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    loaded = credential_key(blob)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)
    assert loaded.private_numbers() == ec_key.private_numbers()


def test_pem_encoding_wraps_at_64_columns():
    from xrdsec.x509 import pem_encode

    block = pem_encode("THING", bytes(100))
    lines = block.decode().splitlines()
    assert lines[0] == "-----BEGIN THING-----" and lines[-1] == "-----END THING-----"
    assert [len(line) for line in lines[1:-1]] == [64, 64, 8]


# -- CA-directory names ---------------------------------------------------------
#
# Each vector was checked against ``openssl x509 -subject_hash
# -subject_hash_old``; GSI names the client's CA by them, and a server looks
# the CA up in its certificate directory under exactly these file names.


@pytest.mark.parametrize(
    ("der_hex", "new", "old"),
    [
        # DC=org, CN=example ca - UTF8String, already canonical
        (
            "302a31133011060a0992268993f22c6401190c036f72673113301106035504030c0a"
            "6578616d706c65206361",
            "33027a7e",
            "b67780a4",
        ),
        # DC=ORG (IA5String), CN="  Example \t  CA  " (PrintableString): the same
        # name once canonical - lower case, trimmed, inner space runs folded -
        # so the same new hash, while the old one hashes the DER as written
        (
            "303131133011060a0992268993f22c64011916034f5247311a301806035504031311"
            "20204578616d706c652009202043412020",
            "33027a7e",
            "3a47d1e6",
        ),
        # a multi-valued RDN, whose entries are re-sorted as DER sorts a SET
        (
            "301c311a300a06035504030c035a6564300c060355040a0c05416c706861",
            "ea43f420",
            "12bce3ca",
        ),
        # a NumericString serial is not a type OpenSSL folds: hashed as written
        (
            "3028310e300c0603550405120531322033343116301406035504030c0d53657269616c20486f6c646572",
            "71ca461e",
            "e517d4ed",
        ),
        # bytes above 0x7F are left alone; only the double space is folded
        (
            "301a3118301606035504030c0fc3856e67737472c3b66d20204c6162",
            "f46cadc2",
            "0ecc1048",
        ),
    ],
)
def test_name_hashes_are_the_ones_openssl_gives(der_hex, new, old):
    from xrdsec.x509 import name_hashes

    assert name_hashes(bytes.fromhex(der_hex)) == (new, old)


def test_the_issuer_hashes_of_a_certificate_name_its_ca():
    from xrdsec.testing.rawpki import proxy_chain, throwaway_key
    from xrdsec.x509 import issuer_hashes, load_certificates

    _proxy, user, ca = load_certificates(proxy_chain(throwaway_key(0)))
    assert issuer_hashes(user) == ("33027a7e", "b5f5da31")
    assert issuer_hashes(ca) == issuer_hashes(user)  # a CA signs itself


def test_name_encoding_preserves_the_original_der():
    """Ported from xrdclient's shared-core contracts: a decoded name re-encodes byte for byte."""
    from xrdsec import x509

    rdns = (
        ("C", "GB"),
        ("DC", "example"),
        ("emailAddress", "user@example.org"),
        ("CN", "A unicode physicist: é"),
        ("1.2.3", ""),
    )
    encoded = x509.encode_name(rdns)
    decoded = x509.decode_name(encoded)
    assert decoded.rdns == rdns
    assert decoded.encoded() == encoded
    assert x509.Name(rdns).encoded() == encoded
    assert decoded == x509.Name(rdns)
    assert hash(decoded) == hash(x509.Name(rdns))


# ---------------------------------------------------------------------------
# Building blocks and the fallback decoder's helpers (moved from xgfalclient,
# whose tests/test_crypto.py pinned these cases before 0.4.0)
# ---------------------------------------------------------------------------


def test_names_round_trip_through_the_fallback_reader():
    """Every attribute type and string kind comes back as written, original DER included."""
    from xrdsec import der
    from xrdsec.x509 import encode_name, name_from_element

    rdns = (
        ("DC", "org"),
        ("emailAddress", "a@b"),
        ("CN", "Ünïcode"),
        ("O", "Plain Org"),
        ("2.5.4.99", ""),
    )
    encoded = encode_name(rdns)
    decoded = name_from_element(der.parse_one(encoded))
    assert decoded.rdns == rdns
    assert decoded.encoded() == encoded
    assert Name(decoded.rdns).encoded() == encoded
    odd = der.sequence(
        der.set_of(der.sequence(der.oid("2.5.4.3"))),  # malformed attribute: skipped
        der.set_of(der.sequence(der.oid("2.5.4.3"), der.tlv(0x1E, "bmp".encode("utf-16-be")))),
    )
    assert name_from_element(der.parse_one(odd)).rdns == (("CN", "bmp"),)


def test_the_certificate_building_blocks_encode_as_der_requires():
    """keyUsage drops trailing zero bits; a critical flag is written only when true."""
    from xrdsec import der
    from xrdsec.delegation import proxy_cert_info_extension
    from xrdsec.x509 import (
        INHERIT_ALL_OID,
        extension,
        key_usage,
        parse_extension,
        policy_language,
        signature_algorithm,
    )

    assert der.parse_one(key_usage(0, 2)).value == b"\x05\xa0"
    assert der.parse_one(key_usage(5, 6)).value == b"\x01\x06"
    with pytest.raises(ValueError, match="between 0 and 7"):
        key_usage()
    with pytest.raises(ValueError, match="between 0 and 7"):
        key_usage(8)
    critical = der.parse_one(extension("2.5.29.15", b"\x03\x01\x00", critical=True)).children()
    assert critical[1].tag == der.TAG_BOOLEAN
    assert len(der.parse_one(extension("2.5.29.15", b"\x03\x01\x00")).children()) == 2
    value = parse_extension(proxy_cert_info_extension(INHERIT_ALL_OID, None)).value
    assert policy_language(value) == INHERIT_ALL_OID
    assert der.parse_one(signature_algorithm("sha384")).children()[0] == der.parse_one(
        der.oid("1.2.840.113549.1.1.12")
    )


def test_tbs_extensions_skip_what_is_not_an_extension():
    """Only ``[3]`` holds extensions; a value that is not an OCTET STRING is no extension."""
    from xrdsec import der
    from xrdsec.x509 import tbs_extensions

    oddities = [
        der.Element(0xA1, b""),  # not [3]
        der.parse_one(
            der.explicit(
                3,
                der.sequence(
                    der.sequence(der.oid("1.2.3"), der.integer(1)),  # value is not an OCTET STRING
                    der.sequence(der.oid("1.2.4"), der.boolean(False), der.octet_string(b"v")),
                    # three parts, but the middle one is no BOOLEAN: not critical
                    der.sequence(der.oid("1.2.5"), der.integer(1), der.octet_string(b"w")),
                ),
            )
        ),
    ]
    assert tbs_extensions(oddities) == {"1.2.4": (False, b"v"), "1.2.5": (False, b"w")}
