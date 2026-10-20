"""X.509 delegation: the request a GSI server sends, and the proxy signed for it.

Also the pieces delegation added underneath: a DER writer, RSA's block-wise
"encrypt with the private key" that signed Diffie-Hellman uses, the raw
certificate structure a signer copies from, and the check that a server is
who it says it is before anything is signed for it.

Where ``openssl`` is installed, the proxies made here are also handed to
``openssl verify -allow_proxy_certs``, which knows nothing of this code.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from xrdsec import der, rsa, x509
from xrdsec.delegation import (
    DelegationError,
    ProxyRequest,
    load_proxy_request,
    proxy_path_length,
    sign_proxy_request,
)
from xrdsec.testing.rawpki import (
    CA_CONSTRAINTS,
    PROXY_CERT_INFO,
    PROXY_CERT_INFO_OID,
    bitstring,
    extension,
    integer,
    make_certificate_with,
    make_request,
    name,
    oid,
    pem,
    public_key_info,
    sequence,
    setof,
    throwaway_key,
    tlv,
    utctime,
)
from xrdsec.trust import (
    DEFAULT_CA_PATH,
    MAX_DEPTH,
    TrustError,
    anchors,
    names_host,
    verify_server,
)
from xrdsec.x509 import Extension, load_certificates

DC = "0.9.2342.19200300.100.1.25"
CN = "2.5.4.3"
ORG = "2.5.4.10"
KEY_USAGE = extension("2.5.29.15", bytes.fromhex("030205a0"), critical=True)
BASIC = extension("2.5.29.19", sequence(), critical=True)
SKI = extension("2.5.29.14", tlv(0x04, b"\x01" * 20))
AKI = extension("2.5.29.35", sequence(tlv(0x80, b"\x02" * 20)))
PCI = extension(PROXY_CERT_INFO_OID, PROXY_CERT_INFO, critical=True)

USER = ((ORG, "example"), (CN, "Jane Doe"))
CA = ((ORG, "example"), (CN, "Example CA"))

#: A distinguished name as ``(OID, value)`` pairs, in order.
Names = tuple[tuple[str, str], ...]
#: The proxy key, the CA key and the user key.
Keys = tuple[rsa.RSAPrivateKey, rsa.RSAPrivateKey, rsa.RSAPrivateKey]


@pytest.fixture(scope="module")
def keys() -> Keys:
    return throwaway_key(0), throwaway_key(1), throwaway_key(2)


def _cert(der_bytes: bytes) -> x509.Certificate:
    return load_certificates(pem("CERTIFICATE", der_bytes))[0]


def signer_proxy(
    keys: Keys, *extensions: bytes, not_after: float | None = None
) -> x509.Certificate:
    """The client's proxy: ``Jane Doe/CN=proxy``, signed by her user key."""
    proxy_key, _ca, user_key = keys
    chosen = extensions or (BASIC, KEY_USAGE, SKI, AKI, PCI)
    return _cert(
        make_certificate_with(
            name(*USER, (CN, "proxy")),
            name(*USER),
            proxy_key.public,
            user_key,
            chosen,
            serial=4,
            not_after=not_after,
        )
    )


def request_for(keys, cn: str = "12345", **kwargs) -> bytes:
    _proxy, request_key, _user = keys
    kwargs.setdefault("extensions", (PCI,))
    return make_request(name(*USER, (CN, "proxy"), (CN, cn)), request_key, **kwargs)


# -- the DER writer -----------------------------------------------------------


@pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, -1, -129, 1 << 2048])
def test_integers_round_trip_through_the_writer(value):
    element, _ = der.parse(der.encode_integer(value))
    assert der.read_integer(element) == value
    assert der.encode_integer(value) == integer(value)


def test_oids_round_trip_and_match_the_test_encoder():
    for dotted in ("1.2.840.113549.1.1.11", "2.5.29.15", "1.3.6.1.5.5.7.1.14", "2.5.4.3"):
        assert der.encode_oid(dotted) == oid(dotted)
        assert der.oid_string(der.parse(der.encode_oid(dotted))[0]) == dotted


def test_an_oid_needs_two_arcs():
    with pytest.raises(der.DERError, match="two arcs"):
        der.encode_oid("1")


def test_long_lengths_are_minimal():
    assert der.encode(0x04, b"x" * 300)[:4] == b"\x04\x82\x01\x2c"
    assert der.sequence(b"\x05\x00") == b"\x30\x02\x05\x00"


def test_times_switch_to_generalized_in_2050():
    assert der.encode_time(1790704254) == utctime(1790704254)
    late = der.parse(der.encode_time(2556144000))[0]  # 2051-01-01
    assert (late.tag, late.value) == (der.TAG_GENERALIZED_TIME, b"20510101000000Z")


def test_raw_children_keep_each_child_as_written():
    body = sequence(integer(1), sequence(integer(2)))
    assert der.raw_children(body) == [integer(1), sequence(integer(2))]
    with pytest.raises(der.DERError, match="primitive"):
        der.raw_children(integer(1))


# -- RSA block operations --------------------------------------------------------


def test_private_encryption_is_undone_by_the_public_key(keys):
    key = keys[0]
    message = os.urandom(3 * (key.size - 11) + 5)  # four blocks, the last short
    sealed = key.encrypt_private(message)
    assert len(sealed) == 4 * key.size
    assert key.public.decrypt_public(sealed) == message


def test_recover_refuses_what_is_not_a_signature(keys):
    key = keys[0]
    with pytest.raises(ValueError, match="not PKCS#1"):
        keys[1].public.recover(key.encrypt_private(b"tag"))
    with pytest.raises(ValueError, match="bytes, key is"):
        key.public.recover(b"\x00" * 10)
    with pytest.raises(ValueError, match="whole number"):
        key.public.decrypt_public(b"\x00" * (key.size + 1))
    with pytest.raises(ValueError, match="whole number"):
        key.public.decrypt_public(b"")
    with pytest.raises(ValueError, match="nothing"):
        key.encrypt_private(b"")


def test_the_public_key_exports_as_openssl_writes_it(keys, tmp_path):
    public = keys[0].public
    assert public.der() == public_key_info(public)
    assert rsa.load_public_key(public.pem()) == public
    text = public.pem().decode()
    assert text.startswith("-----BEGIN PUBLIC KEY-----\n") and text.endswith(
        "-----END PUBLIC KEY-----\n"
    )
    assert all(len(line) <= 64 for line in text.splitlines())
    if shutil.which("openssl") is None:
        return
    source = tmp_path / "key.pem"
    source.write_bytes(public.pem())
    written = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(source), "-pubout"],
        capture_output=True,
        check=True,
    ).stdout
    assert written == public.pem()


# -- the raw certificate ----------------------------------------------------------


def test_certificate_fields_are_the_bytes_as_written(keys):
    signer = signer_proxy(keys)
    fields = x509.certificate_fields(signer.der)
    assert fields["subject"] == name(*USER, (CN, "proxy"))
    assert fields["issuer"] == name(*USER)
    assert fields["spki"] == public_key_info(keys[0].public)
    assert x509.decode_name(fields["subject"]) == signer.subject


def test_a_version_one_certificate_has_no_version_field_and_no_extensions(keys):
    algorithm = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    tbs = sequence(
        integer(9),
        algorithm,
        name(*CA),
        sequence(utctime(time.time() - 60), utctime(time.time() + 60)),
        name(*CA),
        public_key_info(keys[1].public),
    )
    certificate = sequence(tbs, algorithm, bitstring(keys[1].sign(tbs, digest="sha256")))
    assert "extensions" not in x509.certificate_fields(certificate)
    assert x509.extensions_of(certificate) == []
    assert x509.verify_signed(certificate, keys[1].public)


def test_a_certificate_body_that_stops_short_is_refused():
    with pytest.raises(der.DERError, match="missing"):
        x509.certificate_fields(sequence(sequence(integer(1)), sequence(), bitstring(b"")))


def test_extensions_are_read_with_their_criticality(keys):
    found = x509.extensions_of(signer_proxy(keys).der)
    assert [e.oid for e in found] == [
        "2.5.29.19",
        "2.5.29.15",
        "2.5.29.14",
        "2.5.29.35",
        PROXY_CERT_INFO_OID,
    ]
    assert [e.critical for e in found] == [True, True, False, False, True]
    assert found[1] == Extension("2.5.29.15", True, bytes.fromhex("030205a0"), KEY_USAGE)


@pytest.mark.parametrize(
    "raw",
    [
        sequence(oid("2.5.29.15")),
        sequence(integer(1), tlv(0x04, b"")),
        sequence(oid("1.2"), integer(1)),
    ],
)
def test_a_malformed_extension_is_refused(raw):
    with pytest.raises(der.DERError, match="malformed"):
        x509.parse_extension(raw)


def test_signatures_are_checked_over_the_body_as_written(keys):
    signer = signer_proxy(keys)
    assert x509.verify_signed(signer.der, keys[2].public)
    assert not x509.verify_signed(signer.der, keys[1].public)
    assert not x509.verify_signed(b"\x30\x00", keys[2].public)
    tampered = signer.der[:-1] + bytes([signer.der[-1] ^ 1])
    assert not x509.verify_signed(tampered, keys[2].public)


def test_an_unknown_algorithm_or_a_padded_bit_string_is_not_a_valid_signature(keys):
    body = sequence(integer(1))
    md5 = sequence(oid("1.2.840.113549.1.1.4"), tlv(0x05, b""))
    good = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    signature = keys[0].sign(body, digest="sha256")
    assert not x509.verify_signed(sequence(body, md5, bitstring(signature)), keys[0].public)
    assert not x509.verify_signed(
        sequence(body, good, tlv(0x03, b"\x01" + signature)), keys[0].public
    )
    assert not x509.verify_signed(sequence(body, good, tlv(0x04, signature)), keys[0].public)
    with pytest.raises(der.DERError, match="unsupported"):
        x509.signature_digest("1.2.840.113549.1.1.4")
    assert x509.signature_digest("1.2.840.113549.1.1.5") == "sha1"


# -- the proxy request --------------------------------------------------------------


def test_a_request_is_read_from_pem_or_der(keys):
    raw = request_for(keys)
    for form in (raw, pem("CERTIFICATE REQUEST", raw), pem("CERTIFICATE REQUEST", raw).decode()):
        request = load_proxy_request(form)
        assert str(request.subject) == "/O=example/CN=Jane Doe/CN=proxy/CN=12345"
        assert request.serial == 12345
        assert request.public_key == keys[1].public
        assert [e.oid for e in request.extensions] == [PROXY_CERT_INFO_OID]
        assert request.verify()


def test_a_negative_cn_is_the_unsigned_serial_xrdcrypto_meant(keys):
    """The server prints an unsigned serial with ``%d``; it can come out negative."""
    assert load_proxy_request(request_for(keys, "-2")).serial == (1 << 32) - 2


@pytest.mark.parametrize("cn", ["proxy", "12a", ""])
def test_a_request_not_ending_in_a_serial_is_refused(keys, cn):
    with pytest.raises(DelegationError, match="CN=<serial>"):
        _ = load_proxy_request(request_for(keys, cn)).serial


def test_a_request_whose_last_rdn_is_not_a_cn_is_refused(keys):
    raw = make_request(name(*USER, (ORG, "123")), keys[1])
    with pytest.raises(DelegationError, match="CN=<serial>"):
        _ = load_proxy_request(raw).serial
    with pytest.raises(DelegationError, match="CN=<serial>"):
        _ = load_proxy_request(make_request(name(), keys[1])).serial


def test_requests_without_extensions_or_with_other_attributes_read_as_none(keys):
    assert load_proxy_request(request_for(keys, extensions=())).extensions == ()
    challenge = sequence(oid("1.2.840.113549.1.9.7"), setof(tlv(0x0C, b"pw")))
    odd = load_proxy_request(request_for(keys, attributes=challenge))
    assert odd.extensions == ()


#: dCache's ``extensionRequest``: one bare ``Extension`` in the ``SET`` (no
#: ``SEQUENCE OF``), its value a bare ``SEQUENCE`` (no OCTET STRING), and a
#: limited-proxy policy - the shape a production door sent on 2026-10-20.
DCACHE_POLICY = sequence(sequence(oid("1.3.6.1.4.1.3536.1.1.1.9")))
DCACHE_PCI = sequence(oid(PROXY_CERT_INFO_OID), tlv(0x01, b"\xff"), DCACHE_POLICY)


def _dcache_request(keys, extension_der: bytes = DCACHE_PCI) -> bytes:
    requested = sequence(oid("1.2.840.113549.1.9.14"), setof(extension_der))
    return request_for(keys, attributes=requested)


def test_a_dcache_request_is_read_as_the_rfc_one_means(keys):
    request = load_proxy_request(_dcache_request(keys))
    [found] = request.extensions
    assert (found.oid, found.critical) == (PROXY_CERT_INFO_OID, True)
    assert found.value == DCACHE_POLICY  # what the OCTET STRING would have held
    assert found.der == DCACHE_PCI
    assert request.verify()


def test_a_dcache_request_is_signed_like_any_other(keys):
    issued = sign_proxy_request(
        load_proxy_request(_dcache_request(keys)), signer_proxy(keys), keys[0]
    )
    found = x509.extensions_of(issued.der)
    assert [e.oid for e in found] == ["2.5.29.19", "2.5.29.15", PROXY_CERT_INFO_OID]
    body = der.parse(found[2].value)[0].children()
    assert der.oid_string(body[0].children()[0]) == "1.3.6.1.5.5.7.21.1"  # inheritAll


def test_a_bare_extension_in_the_set_may_still_wrap_its_value(keys):
    """Only the missing ``SEQUENCE OF`` is dCache's quirk here: the value is proper."""
    request = load_proxy_request(_dcache_request(keys, PCI))
    assert [e.oid for e in request.extensions] == [PROXY_CERT_INFO_OID]


@pytest.mark.parametrize(
    "extension_der",
    [
        sequence(oid(PROXY_CERT_INFO_OID), integer(1)),
        sequence(oid(PROXY_CERT_INFO_OID), tlv(0x01, b"\xff"), integer(1), DCACHE_POLICY),
    ],
)
def test_a_bare_extension_that_is_still_malformed_is_refused(keys, extension_der):
    with pytest.raises(DelegationError, match="unreadable"):
        load_proxy_request(_dcache_request(keys, extension_der))


def test_a_forged_request_does_not_verify(keys):
    assert not load_proxy_request(request_for(keys, signer=keys[0])).verify()


@pytest.mark.parametrize(
    "raw",
    [
        b"garbage",
        sequence(sequence(integer(0)), sequence(), bitstring(b"")),
        sequence(sequence(tlv(0x0C, b"v"), sequence(), sequence()), sequence(), bitstring(b"")),
        sequence(
            sequence(integer(0), sequence(), sequence(sequence(), integer(1))),
            sequence(),
            bitstring(b""),
        ),
    ],
)
def test_an_unreadable_request_is_refused(raw):
    with pytest.raises(DelegationError, match="unreadable"):
        load_proxy_request(raw)


def test_path_lengths_are_read_from_both_layouts():
    def ext(body: bytes) -> Extension:
        return Extension(PROXY_CERT_INFO_OID, True, body)

    policy = sequence(oid("1.3.6.1.5.5.7.21.1"))
    assert proxy_path_length(ext(sequence(policy))) is None
    assert proxy_path_length(ext(sequence(integer(3), policy))) == 3
    assert proxy_path_length(ext(sequence(policy, tlv(0xA1, integer(2))))) == 2


# -- signing it -------------------------------------------------------------------


def test_the_delegated_proxy_follows_the_xrdcrypto_profile(keys):
    signer = signer_proxy(keys)
    moment = time.time()
    issued = sign_proxy_request(load_proxy_request(request_for(keys)), signer, keys[0], now=moment)

    assert issued.serial == 12345
    assert issued.subject.rdns == (*signer.subject.rdns, ("CN", "12345"))
    assert issued.issuer == signer.subject
    assert issued.public_key == keys[1].public
    assert issued.not_before == float(int(moment))
    assert issued.not_after == signer.not_after  # capped by the signer, never beyond
    assert issued.is_proxy
    assert x509.verify_signed(issued.der, keys[0].public)


def test_the_delegated_proxy_carries_the_signers_extensions_and_its_own(keys):
    issued = sign_proxy_request(load_proxy_request(request_for(keys)), signer_proxy(keys), keys[0])
    found = x509.extensions_of(issued.der)
    assert [(e.oid, e.critical) for e in found] == [
        ("2.5.29.19", True),
        ("2.5.29.15", True),
        (PROXY_CERT_INFO_OID, True),
    ]
    assert found[0].der == BASIC and found[1].der == KEY_USAGE  # copied as written
    assert proxy_path_length(found[2]) is None
    body = der.parse(found[2].value)[0].children()
    assert der.oid_string(body[0].children()[0]) == "1.3.6.1.5.5.7.21.1"  # inheritAll
    algorithm = der.parse(der.raw_children(issued.der)[1])[0].children()[0]
    assert der.oid_string(algorithm) == "1.2.840.113549.1.1.11"


def test_a_path_length_constraint_is_carried_one_step_down(keys):
    constrained = extension(
        PROXY_CERT_INFO_OID,
        sequence(integer(3), sequence(oid("1.3.6.1.5.5.7.21.1"))),
        critical=True,
    )
    signer = signer_proxy(keys, KEY_USAGE, constrained)
    issued = sign_proxy_request(load_proxy_request(request_for(keys)), signer, keys[0])
    assert proxy_path_length(x509.extensions_of(issued.der)[-1]) == 2

    legacy = extension(
        "1.3.6.1.4.1.3536.1.222",
        sequence(sequence(oid("1.3.6.1.5.5.7.21.1")), tlv(0xA1, integer(0))),
        critical=True,
    )
    with pytest.raises(DelegationError, match="path length"):
        sign_proxy_request(
            load_proxy_request(request_for(keys)), signer_proxy(keys, KEY_USAGE, legacy), keys[0]
        )


@pytest.mark.parametrize(
    ("extensions", "message"),
    [
        ((KEY_USAGE, extension("2.5.29.17", sequence(tlv(0x82, b"h")))), "subjectAltName"),
        ((BASIC, PCI), "keyUsage"),
    ],
)
def test_a_signer_xrdcrypto_would_not_use_is_refused(keys, extensions, message):
    with pytest.raises(DelegationError, match=message):
        sign_proxy_request(
            load_proxy_request(request_for(keys)), signer_proxy(keys, *extensions), keys[0]
        )


def test_requests_that_must_not_be_signed_are_refused(keys):
    signer = signer_proxy(keys)
    wrong_subject = make_request(name(*USER, (CN, "12345")), keys[1], extensions=(PCI,))
    cases = [
        (request_for(keys), signer_proxy(keys, not_after=time.time() - 1), keys[0], "expired"),
        (request_for(keys), signer, keys[1], "does not belong"),
        (wrong_subject, signer, keys[0], "not /O=example"),
        (request_for(keys, signer=keys[0]), signer, keys[0], "not signed by the key"),
        (request_for(keys, extensions=()), signer, keys[0], "no extensions"),
    ]
    for raw, who, key, message in cases:
        with pytest.raises(DelegationError, match=message):
            sign_proxy_request(load_proxy_request(raw), who, key)


def _openssl_verifies_proxies() -> bool:
    if shutil.which("openssl") is None:
        return False
    # macOS ships LibreSSL as ``openssl``, whose ``verify`` has no -allow_proxy_certs.
    done = subprocess.run(
        ["openssl", "verify", "-help"], capture_output=True, text=True, check=False
    )
    return "-allow_proxy_certs" in done.stdout + done.stderr


@pytest.mark.skipif(
    not _openssl_verifies_proxies(),
    reason="no OpenSSL with -allow_proxy_certs on PATH (absent, or LibreSSL)",
)
def test_openssl_accepts_the_delegated_chain(keys, tmp_path):
    """The whole chain - CA, user, proxy, delegated proxy - by OpenSSL's rules."""
    proxy_key, ca_key, user_key = keys
    ca = make_certificate_with(
        name(*CA),
        name(*CA),
        ca_key.public,
        ca_key,
        (extension("2.5.29.19", sequence(tlv(0x01, b"\xff")), critical=True),),
    )
    user = make_certificate_with(name(*USER), name(*CA), user_key.public, ca_key, (KEY_USAGE,))
    signer = signer_proxy(keys)
    issued = sign_proxy_request(load_proxy_request(request_for(keys)), signer, proxy_key)
    (tmp_path / "ca.pem").write_bytes(pem("CERTIFICATE", ca))
    (tmp_path / "chain.pem").write_bytes(signer.pem() + pem("CERTIFICATE", user))
    (tmp_path / "leaf.pem").write_bytes(issued.pem())
    done = subprocess.run(
        [
            "openssl",
            "verify",
            "-allow_proxy_certs",
            "-CAfile",
            str(tmp_path / "ca.pem"),
            "-untrusted",
            str(tmp_path / "chain.pem"),
            str(tmp_path / "leaf.pem"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr


# -- is the server who it says it is ------------------------------------------------


def server_certificate(
    keys: Keys,
    subject: Names,
    *extensions: bytes,
    issuer: Names = CA,
    signer: rsa.RSAPrivateKey | None = None,
    not_after: float | None = None,
) -> bytes:
    return make_certificate_with(
        name(*subject),
        name(*issuer),
        keys[0].public,
        signer or keys[1],
        extensions,
        not_after=not_after,
    )


@pytest.fixture
def ca_dir(tmp_path, keys):
    directory = tmp_path / "certificates"
    directory.mkdir()
    ca = make_certificate_with(name(*CA), name(*CA), keys[1].public, keys[1], (CA_CONSTRAINTS,))
    (directory / "0a1b2c3d.0").write_bytes(pem("CERTIFICATE", ca))
    (directory / "0a1b2c3d.signing_policy").write_text("not a certificate")
    (directory / "README").write_text("nor this")
    (directory / "deadbeef.1").mkdir()  # a name that fits, but will not open
    return directory


def test_a_ca_issued_certificate_for_the_host_is_trusted(keys, ca_dir):
    chain = pem(
        "CERTIFICATE", server_certificate(keys, ((ORG, "example"), (CN, "srv.example.org")))
    )
    assert str(verify_server(chain, "srv.example.org", str(ca_dir)).subject).endswith(
        "srv.example.org"
    )
    assert len(anchors(str(ca_dir))) == 1


def test_an_intermediate_ca_in_the_directory_is_followed(keys, ca_dir):
    middle = ((ORG, "example"), (CN, "Middle CA"))
    intermediate = make_certificate_with(
        name(*middle), name(*CA), keys[2].public, keys[1], (CA_CONSTRAINTS,)
    )
    (ca_dir / "11223344.0").write_bytes(pem("CERTIFICATE", intermediate))
    leaf = server_certificate(keys, ((CN, "host/srv"),), issuer=middle, signer=keys[2])
    verify_server(pem("CERTIFICATE", leaf), "srv", str(ca_dir))


def test_a_certificate_for_another_host_or_from_nowhere_is_not(keys, ca_dir, tmp_path):
    chain = pem("CERTIFICATE", server_certificate(keys, ((CN, "srv"),)))
    with pytest.raises(TrustError, match="not for other"):
        verify_server(chain, "other", str(ca_dir))
    with pytest.raises(TrustError, match="no certificate"):
        verify_server(b"", "srv", str(ca_dir))
    stranger = server_certificate(keys, ((CN, "srv"),), signer=keys[2])
    with pytest.raises(TrustError, match="no CA in the certificate directory"):
        verify_server(pem("CERTIFICATE", stranger), "srv", str(ca_dir))
    with pytest.raises(TrustError, match="cannot read the CA directory"):
        verify_server(chain, "srv", str(tmp_path / "absent"))


def test_expired_links_are_not_trusted(keys, ca_dir, tmp_path):
    old = server_certificate(keys, ((CN, "srv"),), not_after=time.time() - 10)
    with pytest.raises(TrustError, match="validity"):
        verify_server(pem("CERTIFICATE", old), "srv", str(ca_dir))
    stale = tmp_path / "stale"
    stale.mkdir()
    ca = make_certificate_with(
        name(*CA), name(*CA), keys[1].public, keys[1], (CA_CONSTRAINTS,), not_after=time.time() - 10
    )
    (stale / "0a1b2c3d.0").write_bytes(pem("CERTIFICATE", ca))
    fresh = pem("CERTIFICATE", server_certificate(keys, ((CN, "srv"),)))
    with pytest.raises(TrustError, match="Example CA is outside"):
        verify_server(fresh, "srv", str(stale))


def test_a_path_that_never_reaches_an_anchor_gives_up(keys, tmp_path):
    first, second = ((CN, "CA one"),), ((CN, "CA two"),)
    loop = tmp_path / "loop"
    loop.mkdir()
    (loop / "00000001.0").write_bytes(
        pem(
            "CERTIFICATE",
            make_certificate_with(
                name(*first), name(*second), keys[1].public, keys[2], (CA_CONSTRAINTS,)
            ),
        )
    )
    (loop / "00000002.0").write_bytes(
        pem(
            "CERTIFICATE",
            make_certificate_with(
                name(*second), name(*first), keys[2].public, keys[1], (CA_CONSTRAINTS,)
            ),
        )
    )
    leaf = server_certificate(keys, ((CN, "srv"),), issuer=first, signer=keys[1])
    with pytest.raises(TrustError, match=f"longer than {MAX_DEPTH}"):
        verify_server(pem("CERTIFICATE", leaf), "srv", str(loop))


def test_the_ca_directory_falls_back_to_the_environment_then_the_grid_default(monkeypatch, ca_dir):
    monkeypatch.setenv("X509_CERT_DIR", str(ca_dir))
    assert len(anchors(None)) == 1
    monkeypatch.delenv("X509_CERT_DIR")
    monkeypatch.setattr("xrdsec.credentials.sys.platform", "linux")
    monkeypatch.setattr(os.path, "isdir", lambda _path: False)
    monkeypatch.setattr(os, "listdir", _refuse)
    with pytest.raises(TrustError, match=DEFAULT_CA_PATH):
        anchors(None)


def test_the_ca_directory_discovers_homebrew(monkeypatch):
    monkeypatch.delenv("X509_CERT_DIR", raising=False)
    monkeypatch.setattr("xrdsec.credentials.GRID_SECURITY_DIRS", None)  # the platform's own
    monkeypatch.setattr("xrdsec.credentials.sys.platform", "darwin")
    monkeypatch.setattr(os.path, "isdir", lambda path: path.startswith("/opt/homebrew"))
    monkeypatch.setattr(os, "listdir", _refuse)
    with pytest.raises(TrustError, match="/opt/homebrew/etc/grid-security/certificates"):
        anchors(None)


def _refuse(path):
    raise FileNotFoundError(path)


@pytest.mark.parametrize(
    ("names", "host", "expected"),
    [
        ((), "srv.example.org", False),
        ((tlv(0x82, b"srv.example.org"),), "SRV.example.org.", True),
        ((tlv(0x82, b"*.example.org"),), "srv.example.org", True),
        ((tlv(0x82, b"*.example.org"),), "a.srv.example.org", False),
        ((tlv(0x82, b"*.example.org"),), ".example.org", False),
        ((tlv(0x87, bytes([127, 0, 0, 1])),), "127.0.0.1", True),
        ((tlv(0x87, bytes(16)),), "[::]", True),
        ((tlv(0x87, bytes([127, 0, 0, 1])),), "localhost", False),
        ((tlv(0x81, b"srv@example.org"),), "srv.example.org", False),
    ],
)
def test_host_names_are_matched_the_way_xrdsecgsi_matches_them(keys, names, host, expected):
    extensions = (extension("2.5.29.17", sequence(*names)),) if names else (KEY_USAGE,)
    certificate = _cert(server_certificate(keys, ((CN, "Some Service"),), *extensions))
    assert names_host(certificate, host) is expected


def test_fields_past_the_expected_ones_are_passed_over(keys):
    """A request's stray trailing field; a certificate's ``issuerUniqueID``."""
    info = sequence(
        integer(0), name(*USER, (CN, "7")), public_key_info(keys[1].public), tlv(0x81, b"\x00")
    )
    algorithm = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    raw = sequence(info, algorithm, bitstring(keys[1].sign(info, digest="sha256")))
    assert load_proxy_request(raw).extensions == ()

    tbs = sequence(
        tlv(0xA0, integer(2)),
        integer(1),
        algorithm,
        name(*CA),
        sequence(utctime(time.time() - 60), utctime(time.time() + 60)),
        name(*CA),
        public_key_info(keys[1].public),
        tlv(0x81, b"\x00"),
        tlv(0xA3, sequence(KEY_USAGE)),
    )
    certificate = sequence(tbs, algorithm, bitstring(keys[1].sign(tbs, digest="sha256")))
    assert [e.oid for e in x509.extensions_of(certificate)] == ["2.5.29.15"]


# -- the certificate builder against the hand-assembled DER it replaced -------------


def _reference_proxy(
    request: ProxyRequest, signer: x509.Certificate, key: rsa.RSAPrivateKey, moment: float
) -> bytes:
    """``sign_proxy_request`` as it was before ``CertificateBuilder``: TBS by hand.

    Kept verbatim so the library-built certificate can be compared byte for
    byte with what the client used to put on the wire.
    """
    from xrdsec import delegation

    copied, depth = delegation._inherited(signer)
    algorithm = der.sequence(der.encode_oid("1.2.840.113549.1.1.11"), der.encode(0x05, b""))
    extensions = der.sequence(*copied, delegation._proxy_cert_info(depth))
    tbs = der.sequence(
        der.encode(0xA0, der.encode_integer(2)),
        der.encode_integer(request.serial),
        algorithm,
        x509.certificate_fields(signer.der)["subject"],
        der.sequence(der.encode_time(moment), der.encode_time(signer.not_after)),
        request.subject_der,
        request.spki,
        der.encode(0xA3, extensions),
    )
    signature = key.sign(tbs, digest="sha256")
    return der.sequence(tbs, algorithm, der.encode(0x03, b"\x00" + signature))


LEGACY_GT3 = extension(
    "1.3.6.1.4.1.3536.1.222",
    sequence(sequence(oid("1.3.6.1.5.5.7.21.1")), tlv(0xA1, integer(4))),
    critical=True,
)
PCI_LIMITED_DEPTH = extension(
    PROXY_CERT_INFO_OID,
    sequence(integer(5), sequence(oid("1.3.6.1.5.5.7.21.1"))),
    critical=True,
)


@pytest.mark.parametrize(
    "extensions",
    [
        (BASIC, KEY_USAGE, SKI, AKI, PCI),  # RFC 3820, unlimited
        (KEY_USAGE, PCI_LIMITED_DEPTH),  # RFC 3820 with a path length
        (KEY_USAGE, LEGACY_GT3),  # pre-RFC Globus (GT3/GT4) extension
        (KEY_USAGE,),  # GT2 legacy: a proxy by name alone
    ],
    ids=["rfc3820", "rfc3820-depth", "gt3", "gt2"],
)
def test_the_built_proxy_is_byte_identical_to_the_hand_assembled_one(keys, extensions):
    signer = signer_proxy(keys, *extensions)
    request = load_proxy_request(request_for(keys))
    moment = float(int(time.time()))
    issued = sign_proxy_request(request, signer, keys[0], now=moment)
    assert issued.der == _reference_proxy(request, signer, keys[0], moment)


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _spki(key: ec.EllipticCurvePrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _ec_signer_proxy(keys: Keys, ec_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    from xrdsec.testing.rawpki import make_certificate

    return _cert(
        make_certificate(
            name(*USER, (CN, "proxy")),
            name(*USER),
            keys[0].public,
            keys[2],
            serial=5,
            extensions=(("2.5.29.15", bytes.fromhex("030205a0")),),
            subject_spki=_spki(ec_key),
        )
    )


def test_an_ec_proxy_delegates_with_ecdsa(keys):
    ec_key = _ec_key()
    signer = _ec_signer_proxy(keys, ec_key)
    assert signer.public_key is None  # not RSA: only the SPKI says what it is
    issued = sign_proxy_request(load_proxy_request(request_for(keys)), signer, ec_key)
    algorithm = der.parse(der.raw_children(issued.der)[1])[0].children()[0]
    assert der.oid_string(algorithm) == "1.2.840.10045.4.3.2"  # ecdsa-with-SHA256
    assert x509.verify_issued(issued, signer)
    assert x509.verify_signed(issued.der, _spki(ec_key))
    assert not x509.verify_signed(issued.der, keys[0].public)
    with pytest.raises(DelegationError, match="does not belong"):
        sign_proxy_request(load_proxy_request(request_for(keys)), signer, _ec_key())


def test_an_ec_key_request_is_certified(keys):
    from cryptography import x509 as library
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    requested = _ec_key()
    subject = library.Name(
        [
            library.NameAttribute(NameOID.ORGANIZATION_NAME, "example"),
            library.NameAttribute(NameOID.COMMON_NAME, "Jane Doe"),
            library.NameAttribute(NameOID.COMMON_NAME, "proxy"),
            library.NameAttribute(NameOID.COMMON_NAME, "777"),
        ]
    )
    csr = (
        library.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            library.UnrecognizedExtension(ObjectIdentifier(PROXY_CERT_INFO_OID), PROXY_CERT_INFO),
            critical=True,
        )
        .sign(requested, hashes.SHA256())
    )
    request = load_proxy_request(csr.public_bytes(serialization.Encoding.PEM))
    assert request.public_key is None and request.verify()
    issued = sign_proxy_request(request, signer_proxy(keys), keys[0])
    assert issued.serial == 777
    assert x509.certificate_fields(issued.der)["spki"] == _spki(requested)


def test_a_request_for_a_key_of_unknown_type_is_unreadable(keys):
    odd = sequence(sequence(oid("1.2.3.4")), bitstring(b"\x01\x02"))
    info = sequence(integer(0), name(*USER, (CN, "proxy"), (CN, "1")), odd, tlv(0xA0, b""))
    algorithm = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
    raw = sequence(info, algorithm, bitstring(keys[1].sign(info, digest="sha256")))
    with pytest.raises(DelegationError, match="unreadable proxy request"):
        load_proxy_request(raw)


def test_a_serial_of_zero_cannot_be_issued(keys):
    with pytest.raises(DelegationError, match="cannot issue the proxy"):
        sign_proxy_request(load_proxy_request(request_for(keys, "0")), signer_proxy(keys), keys[0])


def test_only_rsa_and_ec_keys_sign(keys):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    with pytest.raises(DelegationError, match="Ed25519PrivateKey"):
        sign_proxy_request(
            load_proxy_request(request_for(keys)),
            signer_proxy(keys),
            # The wrong type on purpose: the refusal of an unsupported key is under test.
            ed25519.Ed25519PrivateKey.generate(),  # type: ignore[arg-type]
        )
    library_rsa = keys[0].to_cryptography()
    issued = sign_proxy_request(
        load_proxy_request(request_for(keys)), signer_proxy(keys), library_rsa
    )
    assert x509.verify_signed(issued.der, keys[0].public)


def test_a_signer_whose_key_cannot_be_read_does_not_hold_the_key(keys):
    from dataclasses import replace

    signer = replace(signer_proxy(keys), der=sequence())
    with pytest.raises(DelegationError, match="does not belong"):
        sign_proxy_request(load_proxy_request(request_for(keys)), signer, keys[0])


def test_issue_certificate_is_the_shared_builder(keys):
    from xrdsec.delegation import issue_certificate

    common = {
        "subject": name(*USER, (CN, "proxy")),
        "issuer": name(*USER),
        "public_key": public_key_info(keys[1].public),
        "signer": keys[2],
        "not_before": time.time() - 60.5,
        "not_after": time.time() + 3600,
    }
    issued = _cert(issue_certificate(**common, extensions=[KEY_USAGE], digest="SHA-384"))
    assert issued.serial & 1 and issued.serial < 1 << 63  # random, positive, odd
    assert issued.not_before == float(int(common["not_before"]))
    algorithm = der.parse(der.raw_children(issued.der)[1])[0].children()[0]
    assert der.oid_string(algorithm) == "1.2.840.113549.1.1.12"
    with pytest.raises(ValueError, match="unsupported digest"):
        issue_certificate(**common, digest="sha1")
    odd = sequence(sequence(oid("1.2.3.4")), bitstring(b"\x01"))
    with pytest.raises(der.DERError, match="cannot certify"):
        issue_certificate(**{**common, "public_key": odd})


def test_names_keep_their_string_types(keys):
    """A PrintableString stays one: issuer and subject must match byte for byte."""
    from xrdsec.delegation import issue_certificate

    printable = sequence(
        setof(sequence(oid(ORG), tlv(0x13, b"example"))),
        setof(sequence(oid(CN), tlv(0x1E, "Jäne".encode("utf-16-be")))),
        setof(sequence(oid(CN), tlv(0x1C, "x".encode("utf-32-be")))),
    )
    raw = issue_certificate(
        subject=printable,
        issuer=printable,
        public_key=public_key_info(keys[1].public),
        signer=keys[1],
        not_before=time.time(),
        not_after=time.time() + 60,
    )
    fields = x509.certificate_fields(raw)
    assert fields["subject"] == fields["issuer"] == printable


# -- what an issuer must be -----------------------------------------------------------


def _ca_with(
    keys: Keys,
    *extensions: bytes,
    subject: Names = CA,
    issuer: Names = CA,
    signer: rsa.RSAPrivateKey | None = None,
    key: rsa.RSAPrivateKey | None = None,
) -> bytes:
    return make_certificate_with(
        name(*subject), name(*issuer), (key or keys[1]).public, signer or keys[1], extensions
    )


def _directory(tmp_path: Path, *certificates: bytes) -> str:
    directory = tmp_path / "ca"
    directory.mkdir(parents=True)
    for index, certificate in enumerate(certificates):
        (directory / f"{index:08x}.0").write_bytes(pem("CERTIFICATE", certificate))
    return str(directory)


def _code(chain_der: bytes, directory: str) -> str:
    with pytest.raises(TrustError) as caught:
        verify_server(pem("CERTIFICATE", chain_der), "srv", directory)
    return caught.value.code


def test_an_issuer_that_is_not_a_ca_is_refused(keys, tmp_path):
    leaf = server_certificate(keys, ((CN, "srv"),))
    assert _code(leaf, _directory(tmp_path, _ca_with(keys, KEY_USAGE))) == "issuer_not_ca"


def test_an_issuer_saying_ca_false_is_refused(keys, tmp_path):
    not_ca = extension("2.5.29.19", sequence(), critical=True)
    leaf = server_certificate(keys, ((CN, "srv"),))
    assert _code(leaf, _directory(tmp_path, _ca_with(keys, not_ca))) == "issuer_not_ca"


def test_an_issuer_whose_extensions_will_not_parse_is_no_ca(keys, tmp_path):
    twice = _ca_with(keys, CA_CONSTRAINTS, CA_CONSTRAINTS)  # a duplicate extension
    leaf = server_certificate(keys, ((CN, "srv"),))
    assert _code(leaf, _directory(tmp_path, twice)) == "issuer_not_ca"


def test_an_issuer_without_keycertsign_is_refused(keys, tmp_path):
    leaf = server_certificate(keys, ((CN, "srv"),))
    anchor = _ca_with(keys, CA_CONSTRAINTS, KEY_USAGE)  # digitalSignature, keyEncipherment
    assert _code(leaf, _directory(tmp_path, anchor)) == "issuer_key_usage"
    signing = extension(
        "2.5.29.15", bytes.fromhex("03020106"), critical=True
    )  # keyCertSign, cRLSign
    trusted = _directory(tmp_path / "ok", _ca_with(keys, CA_CONSTRAINTS, signing))
    assert verify_server(pem("CERTIFICATE", leaf), "srv", trusted).subject.cn == "srv"


def _path_length(depth: int) -> bytes:
    return extension("2.5.29.19", sequence(tlv(0x01, b"\xff"), integer(depth)), critical=True)


@pytest.mark.parametrize(("depth", "trusted"), [(0, False), (1, True)])
def test_a_path_length_constraint_is_respected(keys, tmp_path, depth, trusted):
    middle = ((ORG, "example"), (CN, "Middle CA"))
    root = _ca_with(keys, _path_length(depth))
    intermediate = _ca_with(keys, CA_CONSTRAINTS, subject=middle, key=keys[2])
    leaf = server_certificate(keys, ((CN, "srv"),), issuer=middle, signer=keys[2])
    directory = _directory(tmp_path, root, intermediate)
    if trusted:
        assert verify_server(pem("CERTIFICATE", leaf), "srv", directory).subject.cn == "srv"
    else:
        assert _code(leaf, directory) == "path_length"


def test_a_server_presenting_a_proxy_is_not_trusted(keys, ca_dir):
    """Proxies are signed by end entities, which are never in the CA directory."""
    user = server_certificate(keys, ((CN, "Bob"),))  # any CA-issued user
    proxy = make_certificate_with(
        name((CN, "Bob"), (CN, "srv")), name((CN, "Bob")), keys[2].public, keys[0], (PCI,)
    )
    assert _cert(proxy).is_proxy
    with pytest.raises(TrustError, match="no CA") as caught:
        verify_server(pem("CERTIFICATE", proxy) + pem("CERTIFICATE", user), "srv", str(ca_dir))
    assert caught.value.code == "no_issuer"


def test_an_ec_ca_chain_is_trusted(tmp_path):
    """Signatures are checked for any key type the CA has, not only RSA."""
    import datetime

    from cryptography import x509 as library
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    ca_key, server_key = _ec_key(), _ec_key()
    now = datetime.datetime.now(datetime.UTC)
    ca_name = library.Name([library.NameAttribute(NameOID.COMMON_NAME, "EC CA")])

    def issue(subject: library.Name, key: ec.EllipticCurvePrivateKey, *, ca: bool) -> bytes:
        builder = (
            library.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(library.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(library.BasicConstraints(ca=ca, path_length=None), critical=True)
        )
        built = builder.sign(ca_key, hashes.SHA384())
        return built.public_bytes(serialization.Encoding.DER)

    root = issue(ca_name, ca_key, ca=True)
    host = library.Name([library.NameAttribute(NameOID.COMMON_NAME, "srv")])
    leaf = issue(host, server_key, ca=False)
    trusted = verify_server(pem("CERTIFICATE", leaf), "srv", _directory(tmp_path, root))
    assert trusted.public_key is None and trusted.subject.cn == "srv"


def test_a_signature_algorithm_with_extra_fields_does_not_verify(keys):
    body = sequence(integer(1))
    padded = sequence(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""), tlv(0x05, b""))
    signature = keys[0].sign(body, digest="sha256")
    assert not x509.verify_signed(sequence(body, padded, bitstring(signature)), keys[0].public)


def test_an_issuer_without_a_readable_key_did_not_sign(keys):
    from dataclasses import replace

    signer = signer_proxy(keys)
    assert not x509.verify_issued(signer, replace(signer, der=b"\x30\x00"))


def test_the_shared_request_parser_says_what_is_wrong(keys):
    """xgfalclient reads GridFTP, SRM and gridsite requests with this parser."""
    from xrdsec.delegation import parse_proxy_request

    parsed = parse_proxy_request(request_for(keys))
    assert parsed.verify() and parsed.public_key == keys[1].public
    with pytest.raises(der.DERError, match="not a PKCS#10"):
        parse_proxy_request(sequence(integer(0)))
    with pytest.raises(der.DERError, match="not a PKCS#10"):
        parse_proxy_request(sequence(sequence(), sequence(), integer(0)))
    # A key cryptography cannot load: its ValueError, as a DERError.
    bad_key = sequence(sequence(oid(rsa.RSA_OID), tlv(0x05, b"")), bitstring(b"x"))
    info = sequence(integer(0), sequence(), bad_key)
    with pytest.raises(der.DERError, match="not a PKCS#10 certificate request: "):
        parse_proxy_request(sequence(info, sequence(), bitstring(b"")))
