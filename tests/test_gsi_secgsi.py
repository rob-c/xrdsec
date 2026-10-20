"""XrdSecgsi: bucket framing, Diffie-Hellman, and whole simulated logins.

Ported from xrdclient's ``tests/test_gsi.py`` with the code it tests
(``auth/gsi.py`` became :mod:`xrdsec.gsi.secgsi` in 0.4.0; xrdclient keeps
the tests of its own adapter). The interesting tests play the far end with
:class:`xrdsec.testing.gsi.SecgsiServer` - for the unsigned exchange, and for
the signed one and delegation - so the session key, the proof of possession,
the chain and the delegated proxy are all checked the way ``XrdSecgsi``
would check them. xrdclient's interop suite gives a real server the last word.
"""

from __future__ import annotations

import dataclasses
import socket
import struct
import time
from pathlib import Path
from typing import Any, TypeVar

import pytest

from xrdcore.errors import CredentialError
from xrdsec.aes import cbc_decrypt
from xrdsec.gsi import secgsi
from xrdsec.gsi.secgsi import (
    BUCKET_CIPHER,
    BUCKET_CIPHER_ALG,
    BUCKET_CLNT_OPTS,
    BUCKET_CRYPTOMOD,
    BUCKET_ISSUER_HASH,
    BUCKET_MAIN,
    BUCKET_MD_ALG,
    BUCKET_MESSAGE,
    BUCKET_NONE,
    BUCKET_PUK,
    BUCKET_RTAG,
    BUCKET_SIGNED_RTAG,
    BUCKET_VERSION,
    BUCKET_X509,
    CLIENT_DIGESTS,
    CLIENT_OPTS_DEFAULT,
    REFUSAL,
    STEP_CLIENT_CERT,
    STEP_CLIENT_CERTREQ,
    STEP_SERVER_CERT,
    STEP_SERVER_PXYREQ,
    VERSION_SIGNED_DH,
    VERSION_UNSIGNED_DH,
    Bucket,
    Delegation,
    SecgsiClient,
    ServerCheck,
    Session,
    answer_certificate,
    answer_proxy_request,
    build_cert_response,
    build_certreq,
    choose_digest,
    client_ca_hashes,
    decode_message,
    encode_message,
    encode_public_blob,
    find_bucket,
    parse_dh_parameters,
    parse_peer_blob,
    read_proxy,
    seal,
    session_key,
    unseal,
)
from xrdsec.rsa import RSAPrivateKey
from xrdsec.testing.gsi import SecgsiLogin, SecgsiServer
from xrdsec.testing.rawpki import (
    DH_GENERATOR,
    DH_PRIME,
    dh_parameters_pem,
    pem,
    proxy_chain,
    throwaway_key,
)
from xrdsec.x509 import ProxyCredential, load_certificates, load_proxy

_T = TypeVar("_T")


def _present(value: _T | None) -> _T:
    """``value``, which the test expects to be there."""
    assert value is not None
    return value


def _bucket(message: bytes | None, kind: int) -> bytes:
    """Bucket ``kind`` of ``message``, both of which the test expects to exist."""
    return _present(find_bucket(_present(message), kind))


def write_private(path: Path, data: bytes) -> Path:
    """A credential file as ``voms-proxy-init`` leaves one: mode 0600."""
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _rsa(proxy: ProxyCredential) -> RSAPrivateKey:
    """The proxy's key, which every proxy these tests make has as RSA."""
    assert isinstance(proxy.key, RSAPrivateKey)
    return proxy.key


@pytest.fixture(scope="module")
def key():
    return throwaway_key(0)


@pytest.fixture
def proxy(tmp_path_factory, key):
    path = tmp_path_factory.mktemp("gsi") / "x509up_u1000"
    write_private(path, proxy_chain(key))
    return load_proxy(str(path))


# -- framing ----------------------------------------------------------------


def test_a_message_round_trips_through_the_bucket_encoding():
    buckets = [Bucket(BUCKET_CRYPTOMOD, b"ssl"), Bucket(BUCKET_RTAG, b"\x01" * 8)]
    encoded = encode_message(STEP_CLIENT_CERTREQ, buckets)
    assert encoded.startswith(b"gsi\x00")
    step, decoded = decode_message(encoded)
    assert step == STEP_CLIENT_CERTREQ
    assert decoded == buckets


def test_the_encoding_is_the_wire_format_byte_for_byte():
    """Pinned against XrdSut: name, step, then type/length/value, then zero."""
    encoded = encode_message(1000, [Bucket(3000, b"ssl")])
    assert encoded == b"gsi\x00" + struct.pack(">III", 1000, 3000, 3) + b"ssl" + struct.pack(
        ">I", BUCKET_NONE
    )


def test_an_empty_message_is_a_name_a_step_and_a_terminator():
    assert decode_message(encode_message(2000, [])) == (2000, [])


def test_find_bucket_picks_out_one_type():
    encoded = encode_message(1, [Bucket(7, b"a"), Bucket(9, b"b")])
    assert find_bucket(encoded, 9) == b"b"
    assert find_bucket(encoded, 11) is None
    assert find_bucket(b"not a gsi message at all", 7) is None


def test_buckets_after_the_terminator_are_ignored():
    """The zero type ends the list; XrdSut pads after it."""
    encoded = encode_message(1, [Bucket(7, b"a")]) + struct.pack(">II", 9, 1) + b"b"
    assert decode_message(encoded)[1] == [Bucket(7, b"a")]


def test_a_message_that_simply_stops_is_read_to_its_end():
    """XrdSut always writes the terminator; a truncated one still decodes."""
    encoded = encode_message(1, [Bucket(7, b"a")])[: -struct.calcsize(">I")]
    assert decode_message(encoded) == (1, [Bucket(7, b"a")])


@pytest.mark.parametrize(
    "data, message",
    [
        (b"gsi", "no protocol name"),
        (b"gsi\x00\x00\x00", "too short for a step code"),
        (b"gsi\x00" + struct.pack(">II", 1, 3000) + b"\x00\x00", "truncated length"),
        (b"gsi\x00" + struct.pack(">III", 1, 3000, 99) + b"ab", "99 bytes, 2 available"),
    ],
)
def test_malformed_messages_are_refused(data, message):
    with pytest.raises(CredentialError, match=message):
        decode_message(data)


def test_bucket_repr_does_not_dump_its_payload():
    assert repr(Bucket(3022, b"x" * 4096)) == "Bucket(type=3022, len=4096)"


# -- Diffie-Hellman ---------------------------------------------------------


def test_dh_parameters_are_read_from_pem():
    assert parse_dh_parameters(dh_parameters_pem()) == (DH_PRIME, DH_GENERATOR)


def test_unreadable_dh_parameters_are_refused():
    with pytest.raises(CredentialError, match="no PEM block"):
        parse_dh_parameters(b"nothing here")
    with pytest.raises(CredentialError, match="unreadable DH parameters"):
        parse_dh_parameters(pem("DH PARAMETERS", b"\x30\x03\x02\x01\x05"))


def test_a_public_blob_round_trips():
    public = pow(DH_GENERATOR, 12345, DH_PRIME)
    peer = parse_peer_blob(encode_public_blob(dh_parameters_pem(), public))
    assert (peer.p, peer.g, peer.public) == (DH_PRIME, DH_GENERATOR, public)
    assert peer.params_pem == dh_parameters_pem()


def test_the_closing_delimiter_is_matched_on_nine_bytes():
    """The reference encoder drops the last dash; parsing must tolerate both."""
    blob = dh_parameters_pem() + b"---BPUB---" + b"02" + b"---EPUB--"
    assert parse_peer_blob(blob).public == 2


@pytest.mark.parametrize(
    "blob, message",
    [
        (b"no delimiters", "malformed"),
        (b"---BPUB------EPUB---", "malformed"),
        (dh_parameters_pem() + b"---BPUB---zz---EPUB---", "not hexadecimal"),
    ],
)
def test_a_malformed_public_blob_is_refused(blob, message):
    with pytest.raises(CredentialError, match=message):
        parse_peer_blob(blob)


def test_both_sides_agree_on_the_session_key():
    """The whole point of the exchange; asymmetry here is silent failure."""
    ours, theirs = 0x1234567, 0x89ABCDEF
    params = dh_parameters_pem()
    mine = parse_peer_blob(encode_public_blob(params, pow(DH_GENERATOR, theirs, DH_PRIME)))
    yours = parse_peer_blob(encode_public_blob(params, pow(DH_GENERATOR, ours, DH_PRIME)))
    assert session_key(mine, ours) == session_key(yours, theirs)
    assert len(session_key(mine, ours)) == 16


def test_a_too_small_shared_secret_is_refused():
    """2**100 is a perfectly valid secret in a proper group - and 13 bytes long."""
    small = parse_peer_blob(encode_public_blob(dh_parameters_pem(), 2))
    with pytest.raises(CredentialError, match="need 16"):
        session_key(small, 100)


def _group(prime: int, generator: int = 5) -> bytes:
    from xrdsec.testing.rawpki import integer, sequence

    return pem("DH PARAMETERS", sequence(integer(prime), integer(generator)))


def _peer(public: int, prime: int = DH_PRIME, generator: int = DH_GENERATOR) -> secgsi.PeerPublic:
    return secgsi.PeerPublic(_group(prime, generator), prime, generator, public)


def test_a_toy_group_is_refused_before_any_arithmetic():
    """A prime under 512 bits is not used at all."""
    with pytest.raises(CredentialError, match="is 5 bits; fewer than 512"):
        session_key(_peer(2, 23, 5), 3)
    with pytest.raises(CredentialError, match="511 bits"):
        session_key(_peer(2, (1 << 510) | 1), 3)


@pytest.mark.parametrize("public", [0, 1, DH_PRIME - 1, DH_PRIME, DH_PRIME + 1, 1 << 800])
def test_a_public_value_outside_the_group_is_refused(public):
    """y = 1 and y = p-1 pin the secret to 1 or +-1; y >= p is not an element."""
    with pytest.raises(CredentialError, match="strictly between 1 and p-1"):
        session_key(_peer(public), 12345)


def test_the_boundaries_themselves_are_fine():
    assert len(session_key(_peer(2), 1 << 200)) == 16
    assert len(session_key(_peer(DH_PRIME - 2), 1 << 200 | 1)) == 16


@pytest.mark.parametrize(
    ("prime", "generator"),
    [(DH_PRIME + 1, 2), (DH_PRIME, 1), (DH_PRIME, DH_PRIME - 1), (DH_PRIME, 0)],
)
def test_a_malformed_group_is_refused(prime, generator):
    with pytest.raises(CredentialError, match="group is malformed"):
        session_key(_peer(2, prime, generator), 3)


def test_a_value_of_small_order_in_a_group_that_is_not_prime_is_refused():
    """With p = 3q, y = 1 (mod q) and -1 (mod 3) squares to 1: a secret anyone knows."""
    modulus = DH_PRIME * 3
    public = (3 * pow(3, -1, DH_PRIME) + 2 * DH_PRIME * pow(DH_PRIME, -1, 3)) % modulus
    assert pow(public, 2, modulus) == 1 and 1 < public < modulus - 1
    with pytest.raises(CredentialError, match="degenerate secret"):
        session_key(_peer(public, modulus, 2), 2)


def test_a_weak_group_is_used_and_warned_about_once(caplog, monkeypatch):
    monkeypatch.setattr(secgsi, "_WARNED_BITS", set())
    with caplog.at_level("WARNING"):
        session_key(_peer(2), 1 << 200)
        session_key(_peer(3), 1 << 200)
    assert caplog.text.count("only 768 bits") == 1


def test_a_strong_group_says_nothing(caplog):
    prime = (1 << 2047) + 1  # odd and 2048 bits: all the check looks at
    with caplog.at_level("WARNING"):
        session_key(_peer(2**100 + 5, prime, 2), 1 << 300)
    assert "bits" not in caplog.text


def test_a_padded_secret_keeps_its_leading_zeros():
    theirs = (1 << 200) | 5
    peer = parse_peer_blob(
        encode_public_blob(dh_parameters_pem(), pow(DH_GENERATOR, theirs, DH_PRIME))
    )
    mine = next(
        candidate
        for candidate in range(3, 100000)
        if pow(peer.public, candidate, DH_PRIME).bit_length() <= DH_PRIME.bit_length() - 8
    )
    padded = session_key(peer, mine, padded=True)
    assert padded[0] == 0
    assert padded != session_key(peer, mine)
    assert padded[1:] == session_key(peer, mine)[:15]


def test_the_client_never_sends_an_unchecked_reply_to_a_bad_group(proxy):
    bad = encode_message(
        STEP_SERVER_CERT,
        [Bucket(BUCKET_PUK, encode_public_blob(dh_parameters_pem(), 1))],
    )
    with pytest.raises(CredentialError, match="out of range"):
        answer_certificate(bad, proxy.pem(), _rsa(proxy))


# -- the first client message ----------------------------------------------


def test_the_certreq_carries_what_the_server_reads():
    message = build_certreq(cryptomod="ssl", issuer_hash="1a2b3c4d.0", rtag=b"\x07" * 8)
    step, buckets = decode_message(message)
    by_type = {bucket.type: bucket.data for bucket in buckets}
    assert step == STEP_CLIENT_CERTREQ
    assert by_type[BUCKET_CRYPTOMOD] == b"ssl"
    assert by_type[BUCKET_VERSION] == struct.pack(">I", VERSION_UNSIGNED_DH)
    assert by_type[BUCKET_ISSUER_HASH] == b"1a2b3c4d.0"
    assert by_type[BUCKET_CLNT_OPTS] == struct.pack(">I", CLIENT_OPTS_DEFAULT)
    assert find_bucket(by_type[BUCKET_MAIN], BUCKET_RTAG) == b"\x07" * 8


def test_the_advertised_version_selects_unsigned_dh():
    """At or above 10400 the server would choose signed DH."""
    assert VERSION_UNSIGNED_DH < 10400 <= VERSION_SIGNED_DH


def test_an_empty_cryptomod_falls_back_to_ssl():
    message = build_certreq(cryptomod="", rtag=b"\x00" * 8)
    assert find_bucket(message, BUCKET_CRYPTOMOD) == b"ssl"


# -- the unsigned handshake ----------------------------------------------------


def _test_server(private: int = (1 << 250) | 99, **options: Any) -> SecgsiServer:
    """A server over the test suite's small Oakley group, with a pinned exponent."""
    return SecgsiServer(prime=DH_PRIME, generator=DH_GENERATOR, private=private, **options)


def server_challenge(
    private: int = (1 << 250) | 99, *, tag: bytes = b"\xa5" * 8, bucket: int = BUCKET_PUK
) -> bytes:
    """What ``kXGS_cert`` looks like coming back from a pre-10400 XrdSecgsi."""
    blob = _test_server(private).public_blob()
    inner = encode_message(STEP_SERVER_CERT, [Bucket(BUCKET_RTAG, tag)])
    return encode_message(
        STEP_SERVER_CERT,
        [Bucket(bucket, blob), Bucket(BUCKET_MAIN, inner), Bucket(BUCKET_X509, b"server chain")],
    )


def test_a_server_can_complete_the_handshake(proxy, key):
    """Play the far end: agree the key, decrypt, and verify the signature."""
    tag = b"\xa5" * 8
    server = _test_server(certificate_pem=b"server chain")
    response = build_cert_response(server.challenge(tag=tag, signed=False), proxy.pem(), key)
    step, buckets = decode_message(response)
    by_type = {bucket.type: bucket.data for bucket in buckets}
    assert step == STEP_CLIENT_CERT
    assert by_type[BUCKET_CIPHER_ALG] == b"aes-128-cbc"
    assert by_type[BUCKET_MD_ALG] == b"sha256"
    assert parse_peer_blob(by_type[BUCKET_PUK]).p == DH_PRIME  # the server's group, echoed

    login = server.read_certificate(response, tag=tag)
    assert not login.use_iv
    assert login.plain == cbc_decrypt(login.key, by_type[BUCKET_MAIN])
    assert login.chain_pem == proxy.pem()
    assert len(login.client_tag) == 8
    signature = _bucket(login.plain, BUCKET_SIGNED_RTAG)
    public = _present(proxy.certificate.public_key)
    assert public.verify(tag, signature) and not public.verify(b"\x00" * 8, signature)


def test_the_response_is_deterministic_when_its_randomness_is_given(proxy, key):
    """Injectable ``private``/``rtag`` are what makes the encoding pinnable."""
    challenge = server_challenge()
    private, rtag = (1 << 251) | 7, b"\x01" * 8
    first = build_cert_response(challenge, proxy.pem(), key, private=private, rtag=rtag)
    second = build_cert_response(challenge, proxy.pem(), key, private=private, rtag=rtag)
    assert first == second
    other = build_cert_response(challenge, proxy.pem(), key, private=private + 1, rtag=rtag)
    assert other != first


def test_a_server_without_a_proof_request_gets_no_signature(proxy, key):
    """No ``kXRS_rtag`` means nothing to prove; sending a signature anyway is noise."""
    theirs = (1 << 255) | 0x1234567
    challenge = encode_message(
        STEP_SERVER_CERT, [Bucket(BUCKET_PUK, _test_server(theirs).public_blob())]
    )
    response = build_cert_response(challenge, proxy.pem(), key, private=(1 << 254) | 7)
    secret = session_key(parse_peer_blob(_bucket(response, BUCKET_PUK)), theirs)
    plain = cbc_decrypt(secret, _bucket(response, BUCKET_MAIN))
    assert find_bucket(plain, BUCKET_SIGNED_RTAG) is None
    assert find_bucket(plain, BUCKET_X509) == proxy.pem()


def test_signed_dh_needs_the_servers_certificate(proxy, key):
    """``kXRS_cipher`` instead of ``kXRS_puk`` means the signed path."""
    challenge = server_challenge(bucket=BUCKET_CIPHER)
    with pytest.raises(CredentialError, match="sent no RSA certificate"):
        build_cert_response(challenge, proxy.pem(), key)


def test_a_challenge_with_no_public_key_is_refused(proxy, key):
    with pytest.raises(CredentialError, match="no DH public key"):
        build_cert_response(encode_message(STEP_SERVER_CERT, []), proxy.pem(), key)


# -- the client's state machine ---------------------------------------------------


def test_the_client_drives_both_rounds(proxy):
    client = SecgsiClient(proxy, issuer_hash="1a2b3c4d.0")
    first = client.initial()
    assert find_bucket(first, BUCKET_ISSUER_HASH) == b"1a2b3c4d.0"
    second = _present(client.step(server_challenge()))
    assert decode_message(second)[0] == STEP_CLIENT_CERT


def test_the_identity_is_the_human_behind_the_proxy(proxy):
    assert SecgsiClient(proxy).identity == "/DC=org/DC=example/CN=Jane Doe"


def test_a_proxy_request_before_the_key_exchange_is_a_protocol_error(proxy):
    with pytest.raises(CredentialError, match="before the key exchange"):
        SecgsiClient(proxy).step(encode_message(STEP_SERVER_PXYREQ, []))


def test_an_unexpected_step_is_named_not_guessed(proxy):
    with pytest.raises(CredentialError, match="unexpected GSI step 2999"):
        SecgsiClient(proxy).step(encode_message(2999, []))


def test_an_expired_proxy_is_reported_before_the_round_trip(tmp_path, key):
    path = tmp_path / "old.pem"
    path.write_bytes(proxy_chain(key, not_after=time.time() - 7200))
    with pytest.raises(CredentialError, match="expired"):
        SecgsiClient(load_proxy(str(path))).initial()


def test_a_proxy_whose_key_is_not_rsa_is_refused_at_the_second_round(proxy):
    """``load_proxy`` types the key loosely, so ``step`` checks it itself."""
    borrowed = dataclasses.replace(proxy, key=object())
    with pytest.raises(CredentialError, match="not RSA"):
        SecgsiClient(borrowed).step(encode_message(STEP_SERVER_CERT, []))


@pytest.mark.parametrize(
    ("offered", "version", "sent", "padded"),
    [
        ("sslnopad", 10400, b"sslnopad", False),
        ("sslnopad", 10300, b"ssl", False),
        ("ssl|gcrypt", 10400, b"ssl", True),
        ("", 10400, b"ssl", True),
        ("|x", 10400, b"ssl", True),
    ],
)
def test_the_crypto_module_says_whether_the_dh_secret_is_padded(
    proxy, offered, version, sent, padded
):
    client = SecgsiClient(proxy, cryptomod=offered, server_version=version)
    assert client.padded is padded
    assert find_bucket(client.initial(), BUCKET_CRYPTOMOD) == sent


# -- signed Diffie-Hellman and delegation ------------------------------------


SERVER_NAME = (("2.5.4.10", "example"), ("2.5.4.3", "srv.example.org"))
CA_NAME = (("2.5.4.10", "example"), ("2.5.4.3", "Example CA"))


@dataclasses.dataclass(frozen=True)
class _Pki:
    """A CA directory and a server certificate (with its key) that CA issued."""

    ca_path: str
    server_pem: bytes
    key: RSAPrivateKey


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A CA directory, and a server certificate it issued: key 2, signed by key 1."""
    from xrdsec.testing.rawpki import CA_CONSTRAINTS, make_certificate_with, name

    ca_key, server_key = throwaway_key(1), throwaway_key(2)
    directory = tmp_path_factory.mktemp("certificates")
    ca = make_certificate_with(
        name(*CA_NAME), name(*CA_NAME), ca_key.public, ca_key, (CA_CONSTRAINTS,)
    )
    (directory / "0a1b2c3d.0").write_bytes(pem("CERTIFICATE", ca))
    server = make_certificate_with(
        name(*SERVER_NAME), name(*CA_NAME), server_key.public, ca_key, ()
    )
    return _Pki(str(directory), pem("CERTIFICATE", server), server_key)


@pytest.fixture
def delegating_proxy(tmp_path, key):
    path = tmp_path / "x509up_dlg"
    path.write_bytes(proxy_chain(key, key_usage=True))
    return load_proxy(str(path))


def signed_server(
    pki: _Pki, private: int = (1 << 250) | 99, *, certificate: bytes | None = None
) -> SecgsiServer:
    """A server at 10400 or later: it signs its DH blob with the key of its certificate."""
    chain = pki.server_pem if certificate is None else certificate
    return _test_server(private, certificate_pem=chain, key=pki.key)


def signed_challenge(pki: _Pki, *, certificate: bytes | None = None) -> bytes:
    """``kXGS_cert`` from a server at 10400 or later, with the tag ``abcdEFGH``."""
    return signed_server(pki, certificate=certificate).challenge(tag=b"abcdEFGH")


def server_reads_certificate(
    server: SecgsiServer, response: bytes | None, proxy: ProxyCredential
) -> SecgsiLogin:
    """What ``ServerDoCert`` does with a signed ``kXGC_cert``, plus the framing it expects."""
    by_type = {bucket.type: bucket.data for bucket in decode_message(_present(response))[1]}
    assert by_type[BUCKET_PUK] == _present(proxy.certificate.public_key).pem()
    assert by_type[BUCKET_CIPHER_ALG] == b"aes-128-cbc#16"
    login = server.read_certificate(_present(response), tag=b"abcdEFGH")
    assert login.use_iv
    return login


def _session(secret: bytes, proxy: ProxyCredential, *, use_iv: bool = True) -> SecgsiLogin:
    """A login state for a delegation round started without a certificate round."""
    return SecgsiLogin(secret, use_iv, b"", proxy.pem(), b"")


def the_request(proxy: ProxyCredential, cn: str = "4242", **kwargs: Any) -> bytes:
    from xrdsec.testing.rawpki import make_request, name

    subject = name(*[(_OIDS[k], v) for k, v in proxy.subject.rdns], ("2.5.4.3", cn))
    return make_request(subject, throwaway_key(2), extensions=(_PCI,), **kwargs)


_OIDS = {"DC": "0.9.2342.19200300.100.1.25", "CN": "2.5.4.3"}


def _pci() -> bytes:
    from xrdsec.testing.rawpki import PROXY_CERT_INFO, PROXY_CERT_INFO_OID, extension

    return extension(PROXY_CERT_INFO_OID, PROXY_CERT_INFO, critical=True)


_PCI = _pci()


def test_a_signed_exchange_ends_in_a_delegated_proxy(pki, delegating_proxy):
    """Both rounds, played from the server's side, as ``XrdSecgsi`` checks them."""
    client = SecgsiClient(
        delegating_proxy,
        cryptomod="ssl",
        server_version=10600,
        delegation=Delegation(True, "srv.example.org", pki.ca_path),
    )
    first = client.initial()
    assert struct.unpack(">I", _bucket(first, BUCKET_VERSION))[0] == VERSION_SIGNED_DH
    assert struct.unpack(">I", _bucket(first, BUCKET_CLNT_OPTS))[0] == 0x85

    server = signed_server(pki, (1 << 250) | 12345)
    login = server_reads_certificate(
        server, client.step(server.challenge(tag=b"abcdEFGH")), delegating_proxy
    )
    assert login.chain_pem == delegating_proxy.pem()

    answer = _present(client.step(server.proxy_request(login, the_request(delegating_proxy))))
    plain = server.read_signed_proxy(login, answer)
    (issued,) = load_certificates(_bucket(plain, BUCKET_X509))
    assert issued.issuer == delegating_proxy.subject
    assert issued.subject.rdns == (*delegating_proxy.subject.rdns, ("CN", "4242"))
    assert issued.public_key == throwaway_key(2).public
    assert find_bucket(plain, BUCKET_MESSAGE) is None


def test_an_untrusted_server_is_answered_but_not_given_a_proxy(pki, delegating_proxy, caplog):
    """The stock client's answer: log in, and tell the server no in words."""
    client = SecgsiClient(
        delegating_proxy,
        server_version=10400,
        delegation=Delegation(True, "impostor.example.org", pki.ca_path),
    )
    client.initial()
    server = signed_server(pki, (1 << 250) | 7)
    login = server_reads_certificate(
        server, client.step(server.challenge(tag=b"abcdEFGH")), delegating_proxy
    )
    assert "not for impostor.example.org" in caplog.text
    reply = _present(client.step(server.proxy_request(login, the_request(delegating_proxy))))
    plain = server.read_signed_proxy(login, reply)
    assert find_bucket(plain, BUCKET_X509) is None
    assert find_bucket(plain, BUCKET_MESSAGE) == REFUSAL.encode()


def test_without_the_option_nothing_is_offered_and_nothing_signed(pki, delegating_proxy):
    client = SecgsiClient(delegating_proxy, server_version=10400)
    first = client.initial()
    assert struct.unpack(">I", _bucket(first, BUCKET_CLNT_OPTS))[0] == CLIENT_OPTS_DEFAULT
    server = signed_server(pki, (1 << 250) | 7)
    login = server_reads_certificate(
        server, client.step(server.challenge(tag=b"abcdEFGH")), delegating_proxy
    )
    reply = _present(client.step(server.proxy_request(login, the_request(delegating_proxy))))
    assert find_bucket(server.read_signed_proxy(login, reply), BUCKET_MESSAGE) == REFUSAL.encode()


def test_an_old_server_gets_the_unsigned_exchange_and_no_offer(proxy, caplog):
    client = SecgsiClient(proxy, server_version=10300, delegation=Delegation(True, "srv", None))
    first = client.initial()
    assert struct.unpack(">I", _bucket(first, BUCKET_VERSION))[0] == VERSION_UNSIGNED_DH
    assert struct.unpack(">I", _bucket(first, BUCKET_CLNT_OPTS))[0] == CLIENT_OPTS_DEFAULT
    assert "predates the signed exchange" in caplog.text
    assert decode_message(_present(client.step(server_challenge())))[0] == STEP_CLIENT_CERT


def test_a_nopad_server_gets_an_unpadded_secret(pki, proxy):
    private = (1 << 250) | 3
    message, session = answer_certificate(
        signed_server(pki, private).challenge(), proxy.pem(), _rsa(proxy), padded=False
    )
    public = _present(proxy.certificate.public_key)
    client = parse_peer_blob(public.decrypt_public(_bucket(message, BUCKET_CIPHER)))
    assert session.key == session_key(client, private)
    assert session.use_iv and session.server_pem == pki.server_pem


def test_signed_dh_parameters_must_verify_under_the_servers_key(pki, proxy):
    stranger = pem("CERTIFICATE", _self_signed(throwaway_key(0)))
    with pytest.raises(CredentialError, match="not signed by its certificate"):
        answer_certificate(signed_challenge(pki, certificate=stranger), proxy.pem(), _rsa(proxy))
    with pytest.raises(CredentialError, match="sent no RSA certificate"):
        answer_certificate(signed_challenge(pki, certificate=b"junk"), proxy.pem(), _rsa(proxy))


def _self_signed(signer: RSAPrivateKey) -> bytes:
    from xrdsec.testing.rawpki import make_certificate_with, name

    subject = name(("2.5.4.3", "someone"))
    return make_certificate_with(subject, subject, signer.public, signer, ())


def test_proxy_requests_that_cannot_be_signed_get_a_reason(pki, proxy):
    """A proxy with no keyUsage, a request missing or garbled: words, not a failed login."""
    session = Session(b"k" * 16, True)
    login = _session(session.key, proxy)
    server = _test_server()
    cases = [
        (the_request(proxy), b"problems signing the request: the signing proxy has no keyUsage"),
        (None, b"bucket with proxy request missing"),
    ]
    for request, reason in cases:
        reply = answer_proxy_request(
            server.proxy_request(login, request), session, proxy, _rsa(proxy), allowed=True
        )
        plain = server.read_signed_proxy(login, reply)
        assert _bucket(plain, BUCKET_MESSAGE).startswith(reason)


def test_an_unsigned_session_seals_without_an_iv(delegating_proxy):
    session = Session(b"k" * 16, False)
    login = _session(session.key, delegating_proxy, use_iv=False)
    server = _test_server()
    message = server.proxy_request(login, the_request(delegating_proxy))
    reply = answer_proxy_request(
        message,
        session,
        delegating_proxy,
        _rsa(delegating_proxy),
        allowed=True,
        iv=b"\x00" * 16,
    )
    assert load_certificates(_bucket(server.read_signed_proxy(login, reply), BUCKET_X509))


def test_a_proxy_request_that_does_not_decrypt_or_has_no_body_is_refused(delegating_proxy):
    session = Session(b"k" * 16, True)
    key = _rsa(delegating_proxy)
    with pytest.raises(CredentialError, match="no main buffer"):
        answer_proxy_request(
            encode_message(STEP_SERVER_PXYREQ, []), session, delegating_proxy, key, allowed=True
        )
    garbled = encode_message(STEP_SERVER_PXYREQ, [Bucket(BUCKET_MAIN, b"\x00" * 40)])
    with pytest.raises(CredentialError, match="cannot decrypt"):
        answer_proxy_request(garbled, session, delegating_proxy, key, allowed=True)


def test_sealing_puts_the_iv_first():
    key = b"q" * 16
    sealed = seal(key, b"hello", use_iv=True, iv=b"\x07" * 16)
    assert sealed[:16] == b"\x07" * 16
    assert unseal(key, sealed, use_iv=True) == b"hello"
    assert len(seal(key, b"hello", use_iv=True)) == 32
    assert unseal(key, seal(key, b"hello", use_iv=False), use_iv=False) == b"hello"


# -- which CA, and which digest ------------------------------------------------
#
# Both were once constants: the CA hash echoed the server's own ``ca:`` and the
# digest was always ``sha256``. That worked against EOS only because its host
# certificate and a CERN user's come from the same CA, and it failed against
# every dCache door (``sha1:md5`` only) and every xrootd whose host CA differs
# from the user's ("chain is inconsistent: kXGC_cert").


def test_the_ca_hashes_skip_the_proxies_and_the_anchor(proxy):
    """The issuer of the end-entity certificate: not a proxy's, not the CA's own."""
    assert [c.is_proxy for c in proxy.chain] == [True, False, False]
    assert client_ca_hashes(proxy) == "33027a7e.0|b5f5da31.0"
    deeper = dataclasses.replace(proxy, chain=(proxy.chain[0], *proxy.chain))
    assert client_ca_hashes(deeper) == "33027a7e.0|b5f5da31.0"


def test_a_chain_with_nothing_to_hash_has_no_ca_hashes(proxy):
    assert client_ca_hashes(dataclasses.replace(proxy, chain=(proxy.chain[-1],))) == ""


def test_an_unhashable_end_entity_certificate_has_no_ca_hashes(proxy):
    broken = dataclasses.replace(proxy.chain[1], der=b"\x30\x00")
    assert client_ca_hashes(dataclasses.replace(proxy, chain=(proxy.chain[0], broken))) == ""


@pytest.mark.parametrize(
    ("offered", "chosen"),
    [
        (None, b"sha256"),  # a server that predates the list
        (b"", b"sha256"),
        (b"sha256", b"sha256"),  # current xrootd (EOS, CNAF)
        (b"sha1:md5", b"sha1"),  # dCache, and RAL's xrootd
        (b"sha1:sha256", b"sha256"),  # our preference, not the server's order
        (b"SHA1 : md5", b"sha1"),
    ],
)
def test_the_digest_is_ours_that_the_server_lists_first(offered, chosen):
    assert CLIENT_DIGESTS == ("sha256", "sha1")
    assert choose_digest(offered) == chosen


def test_a_server_that_lists_no_digest_we_have_is_told_so():
    with pytest.raises(CredentialError, match="only the digests md5"):
        choose_digest(b"md5")


def test_the_reply_carries_the_digest_the_server_offered(proxy, key):
    """dCache answers anything else with "all sender digests are unsupported"."""
    step, buckets = decode_message(server_challenge())
    offered = encode_message(step, [*buckets, Bucket(BUCKET_MD_ALG, b"sha1:md5")])
    assert find_bucket(build_cert_response(offered, proxy.pem(), key), BUCKET_MD_ALG) == b"sha1"


# -- the server proves who it is on every login --------------------------------


def _checking(
    proxy: ProxyCredential,
    pki: _Pki,
    host: str = "srv.example.org",
    names: tuple[str, ...] = (),
    bypass: str = "",
) -> SecgsiClient:
    return SecgsiClient(
        proxy, server_version=10400, server_check=ServerCheck(host, pki.ca_path, names, bypass)
    )


def test_a_verified_server_is_logged_in_to(pki, proxy):
    client = _checking(proxy, pki)
    client.initial()
    assert decode_message(_present(client.step(signed_challenge(pki))))[0] == STEP_CLIENT_CERT


def test_a_server_for_another_host_is_refused_before_anything_is_sent(pki, proxy, monkeypatch):
    monkeypatch.setattr(secgsi, "answer_certificate", lambda *a, **k: pytest.fail("answered"))
    client = _checking(proxy, pki, host="impostor.example.org", bypass="XRD_GSI_VERIFY_SERVER=0")
    client.initial()
    with pytest.raises(CredentialError) as refused:
        client.step(signed_challenge(pki))
    message = str(refused.value)
    assert "impostor.example.org did not prove its identity" in message
    assert "is not for impostor.example.org" in message
    assert "XrdSecGSISRVNAMES" in message
    assert message.endswith("on a test setup only, XRD_GSI_VERIFY_SERVER=0 skips the check")


def test_without_a_bypass_the_refusal_names_none(pki, proxy):
    client = _checking(proxy, pki, host="impostor.example.org")
    client.initial()
    with pytest.raises(CredentialError) as refused:
        client.step(signed_challenge(pki))
    assert str(refused.value).endswith("list that name in $XrdSecGSISRVNAMES")


def test_a_server_whose_ca_is_not_trusted_is_refused(pki, proxy, tmp_path):
    client = SecgsiClient(
        proxy, server_version=10400, server_check=ServerCheck("srv.example.org", str(tmp_path))
    )
    client.initial()
    with pytest.raises(CredentialError, match="no CA in the certificate directory"):
        client.step(signed_challenge(pki))


def test_a_challenge_without_a_certificate_is_refused(pki, proxy):
    client = _checking(proxy, pki)
    client.initial()
    with pytest.raises(CredentialError, match="sent no certificate"):
        client.step(server_challenge())


@pytest.mark.parametrize("patterns", [("srv.example.org",), ("*.example.org",), ("nope", "srv*")])
def test_an_alias_the_srvnames_allow_is_accepted(pki, proxy, patterns):
    client = _checking(proxy, pki, host="alias.example.net", names=patterns)
    client.initial()
    assert decode_message(_present(client.step(signed_challenge(pki))))[0] == STEP_CLIENT_CERT


def test_srvnames_widen_only_the_name_not_the_chain(pki, proxy, tmp_path):
    client = SecgsiClient(
        proxy,
        server_version=10400,
        server_check=ServerCheck("alias.example.net", str(tmp_path), ("*.example.org",)),
    )
    client.initial()
    with pytest.raises(CredentialError, match="no CA in the certificate directory"):
        client.step(signed_challenge(pki))
    unmatched = _checking(proxy, pki, host="alias.example.net", names=("*.example.com",))
    unmatched.initial()
    with pytest.raises(CredentialError, match=r"is not for alias\.example\.net"):
        unmatched.step(signed_challenge(pki))


def test_srvnames_come_from_the_stock_variable(monkeypatch):
    monkeypatch.setenv("XrdSecGSISRVNAMES", " a.example.org, *.CERN.ch ,,")
    assert secgsi.server_names() == ("a.example.org", "*.cern.ch")
    monkeypatch.delenv("XrdSecGSISRVNAMES")
    assert secgsi.server_names() == ()


def _resolving(
    proxy: ProxyCredential, pki: _Pki, names: tuple[str, ...], *, host: str = "alias.example.net"
) -> SecgsiClient:
    check = ServerCheck(host, pki.ca_path, resolve=lambda: names)
    return SecgsiClient(proxy, server_version=10400, server_check=check)


def test_a_name_dns_gives_the_host_is_accepted(pki, proxy, caplog):
    """A round-robin alias whose node holds a certificate in its own name (CNAF)."""
    client = _resolving(proxy, pki, ("other.example.org", "srv.example.org"))
    client.initial()
    with caplog.at_level("DEBUG", "xrdsec"):
        reply = client.step(signed_challenge(pki))
    assert decode_message(_present(reply))[0] == STEP_CLIENT_CERT
    assert "alias.example.net proved to be srv.example.org, its name in DNS" in caplog.text


def test_a_server_only_dns_names_is_logged_in_to_but_not_delegated_to(
    pki, delegating_proxy, caplog
):
    """Stock XrdSecgsi: "proxy delegation forbidden when trusting DNS"."""
    check = ServerCheck("alias.example.net", pki.ca_path, resolve=lambda: ("srv.example.org",))
    client = SecgsiClient(
        delegating_proxy,
        server_version=10400,
        delegation=Delegation(True, "alias.example.net", pki.ca_path),
        server_check=check,
    )
    client.initial()
    with caplog.at_level("WARNING", "xrdsec"):
        client.step(signed_challenge(pki))
    assert not client._may_delegate
    assert "only DNS names it in its certificate" in caplog.text


def test_a_server_that_names_itself_is_still_delegated_to(pki, delegating_proxy):
    check = ServerCheck("srv.example.org", pki.ca_path, resolve=lambda: pytest.fail("asked"))
    client = SecgsiClient(
        delegating_proxy,
        server_version=10400,
        delegation=Delegation(True, "srv.example.org", pki.ca_path),
        server_check=check,
    )
    client.initial()
    client.step(signed_challenge(pki))
    assert client._may_delegate


def test_dns_names_that_the_certificate_does_not_carry_are_refused(pki, proxy):
    client = _resolving(proxy, pki, ("other.example.org",))
    client.initial()
    with pytest.raises(CredentialError) as refused:
        client.step(signed_challenge(pki))
    assert "alias.example.net did not prove its identity" in str(refused.value)
    assert "(nor for other.example.org, its name in DNS)" in str(refused.value)


def test_dns_is_asked_only_when_the_name_does_not_match(pki, proxy):
    check = ServerCheck("srv.example.org", pki.ca_path, resolve=lambda: pytest.fail("asked"))
    client = SecgsiClient(proxy, server_version=10400, server_check=check)
    client.initial()
    assert decode_message(_present(client.step(signed_challenge(pki))))[0] == STEP_CLIENT_CERT


def test_dns_widens_only_the_name_not_the_chain(pki, proxy, tmp_path):
    check = ServerCheck("alias.example.net", str(tmp_path), resolve=lambda: ("srv.example.org",))
    client = SecgsiClient(proxy, server_version=10400, server_check=check)
    client.initial()
    with pytest.raises(CredentialError, match=r"nor for srv\.example\.org, its name in DNS"):
        client.step(signed_challenge(pki))


@pytest.mark.parametrize(
    ("value", "trusted"), [(None, True), ("1", True), ("yes", True), ("0", False), (" 0 ", False)]
)
def test_trustdns_is_the_stock_variable_and_on_by_default(monkeypatch, value, trusted):
    if value is None:
        monkeypatch.delenv("XrdSecGSITRUSTDNS", raising=False)
    else:
        monkeypatch.setenv("XrdSecGSITRUSTDNS", value)
    assert secgsi.trust_dns() is trusted


def _fake_dns(
    monkeypatch: pytest.MonkeyPatch, forward: dict[str, list[str]], reverse: dict[str, str]
) -> None:
    def getaddrinfo(host: str, port: object, *args: object, **kwargs: object) -> list[Any]:
        if host not in forward:
            raise socket.gaierror(socket.EAI_NONAME, "no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in forward[host]]

    def gethostbyaddr(address: str) -> tuple[str, list[str], list[str]]:
        if address not in reverse:
            raise socket.herror(1, "no PTR")
        return (reverse[address], [], [address])

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyaddr", gethostbyaddr)


def test_dns_names_are_the_confirmed_ptr_names_of_every_address(monkeypatch):
    forward = {
        "alias.example.org": ["192.0.2.2", "192.0.2.1", "192.0.2.3", "192.0.2.4"],
        "node1.example.org": ["192.0.2.1"],
        "node2.example.org": ["192.0.2.2"],
        "liar.example.com": ["198.51.100.9"],
        "twin.example.org": ["192.0.2.4"],
    }
    reverse = {
        "192.0.2.1": "Node1.Example.org.",
        "192.0.2.2": "node2.example.org",
        "192.0.2.3": "liar.example.com",  # does not resolve back: refused
        "192.0.2.4": "node1.example.org",  # does not resolve back to .4 either
    }
    _fake_dns(monkeypatch, forward, reverse)
    assert secgsi.dns_names("alias.example.org") == ("node1.example.org", "node2.example.org")


def test_dns_names_of_an_unknown_host_or_address_are_none(monkeypatch):
    _fake_dns(monkeypatch, {"bare.example.org": ["192.0.2.7"]}, {})
    assert secgsi.dns_names("nowhere.example.org") == ()
    assert secgsi.dns_names("bare.example.org") == ()
    _fake_dns(monkeypatch, {"a.example.org": ["192.0.2.8"]}, {"192.0.2.8": "gone.example.org"})
    assert secgsi.dns_names("a.example.org") == ()


def test_a_server_verified_at_login_is_trusted_with_a_proxy(pki, delegating_proxy, monkeypatch):
    """The login check is the delegation check, so it is not made twice."""
    monkeypatch.setattr(SecgsiClient, "_trusted", lambda *a: pytest.fail("checked twice"))
    client = SecgsiClient(
        delegating_proxy,
        server_version=10400,
        delegation=Delegation(True, "srv.example.org", pki.ca_path),
        server_check=ServerCheck("srv.example.org", pki.ca_path),
    )
    client.initial()
    client.step(signed_challenge(pki))
    assert client._may_delegate


# -- the proxy file is this user's alone ---------------------------------------


def test_a_proxy_is_read_only_when_it_is_private(tmp_path, key):
    path = write_private(tmp_path / "x509up", proxy_chain(key))
    assert read_proxy(str(path)).path == str(path)
    path.chmod(0o640)
    with pytest.raises(PermissionError, match="chmod 600"):
        read_proxy(str(path))


def test_a_link_is_followed_only_when_named(tmp_path, key):
    real = write_private(tmp_path / "real", proxy_chain(key))
    link = tmp_path / "x509up_link"
    link.symlink_to(real)
    assert read_proxy(str(link)).path == str(link)
    with pytest.raises(PermissionError, match="symbolic link"):
        read_proxy(str(link), named=False)


def test_a_file_that_is_not_a_proxy_is_refused(tmp_path):
    path = write_private(tmp_path / "empty", b"")
    with pytest.raises(ValueError, match="no certificate"):
        read_proxy(str(path))
