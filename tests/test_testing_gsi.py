"""The acceptor-side GSI helpers fake servers are built on, and the gsi package's lazy table."""

from __future__ import annotations

import ssl

import pytest

import xrdsec.gsi
from xrdcore.errors import CredentialError
from xrdsec import rsa
from xrdsec.gsi.gss import GSIError, SecurityContext
from xrdsec.gsi.secgsi import (
    BUCKET_CIPHER_ALG,
    BUCKET_PUK,
    BUCKET_X509,
    STEP_CLIENT_CERT,
    SecgsiClient,
    decode_message,
    encode_message,
    find_bucket,
    parse_dh_parameters,
    parse_peer_blob,
)
from xrdsec.testing.gsi import (
    MODP_2048_GENERATOR,
    MODP_2048_PRIME,
    SecgsiLogin,
    SecgsiServer,
    accept_tokens,
    acceptor,
    dh_parameters_pem,
    exchange_tokens,
    proxy_owner,
)
from xrdsec.testing.pki import PKI, test_key


def client_tls(pki: PKI) -> ssl.SSLContext:
    """A client context presenting the PKI's proxy, ``ssl``'s host check off."""
    context = ssl.create_default_context(cafile=str(pki.ca_file))
    context.check_hostname = False
    context.load_cert_chain(str(pki.proxy_path))
    return context


# -- the gsi package ----------------------------------------------------------------


def test_the_gsi_package_loads_its_modules_on_demand() -> None:
    assert dir(xrdsec.gsi) == ["gss", "httpg", "secgsi"]
    assert xrdsec.gsi.httpg.HTTPGConnection.__name__ == "HTTPGConnection"
    with pytest.raises(AttributeError, match="no attribute 'nothing'"):
        _ = xrdsec.gsi.nothing


# -- GSS -------------------------------------------------------------------------


def test_the_token_loop_completes_a_delegation(pki: PKI) -> None:
    """The acceptor loop against a client driven the other way round, token by token."""
    key = rsa.RSAPrivateKey.from_cryptography(test_key(4))
    server = acceptor(pki.server_context(), delegation_key=key)
    client = SecurityContext(client_tls(pki), delegate=pki.credential())
    outbox = [client.step()]

    def receive() -> bytes:
        return outbox.pop(0)

    def send(token: bytes) -> None:
        outbox.append(client.step(token))

    assert accept_tokens(server, receive, send)
    assert server.delegated is not None
    assert server.delegated.chain[0].public_key == key.public
    peer = server.peer_certificate()
    assert peer is not None
    assert proxy_owner(str(peer.subject)) == "/DC=org/DC=xrdsec/OU=People/CN=Test User"


def test_the_token_loop_stops_when_the_client_gives_up(pki: PKI) -> None:
    server = acceptor(pki.server_context(), turn=False)
    assert not accept_tokens(server, lambda: None, lambda token: None)
    assert not server.complete and not server.turn


def test_both_ends_in_process_converge_and_return_the_responders_tokens(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki))
    server = acceptor(pki.server_context())
    sent = exchange_tokens(client, server)
    assert client.complete and server.complete
    assert sent and sent[0]  # the server's first answer is its TLS flight
    assert server.unwrap(client.wrap(b"ping")) == b"ping"


def test_an_exchange_that_does_not_converge_is_a_gsi_error(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki))
    server = acceptor(pki.server_context())
    with pytest.raises(GSIError, match="did not converge in 1 rounds"):
        exchange_tokens(client, server, rounds=1)


@pytest.mark.parametrize(
    ("subject", "owner"),
    [
        ("/DC=org/CN=Jane/CN=123456", "/DC=org/CN=Jane"),
        ("/DC=org/CN=Jane/CN=proxy/CN=limited proxy", "/DC=org/CN=Jane"),
        ("/DC=org/CN=Jane/CN=12/CN=34", "/DC=org/CN=Jane"),
        ("/CN=123", "/CN=123"),  # at least one RDN survives
        ("/DC=org/CN=Jane/CN=proxyish", "/DC=org/CN=Jane/CN=proxyish"),
    ],
)
def test_the_proxy_owner_drops_every_proxy_cn(subject: str, owner: str) -> None:
    assert proxy_owner(subject) == owner


# -- XrdSecgsi ------------------------------------------------------------------------


def test_the_default_group_is_rfc_3526_group_14() -> None:
    assert MODP_2048_PRIME.bit_length() == 2048 and MODP_2048_GENERATOR == 2
    assert parse_dh_parameters(dh_parameters_pem()) == (MODP_2048_PRIME, 2)


def test_a_whole_login_over_the_default_group(pki: PKI, caplog: pytest.LogCaptureFixture) -> None:
    """A random exponent, the full-size group: no weak-group warning, a working session."""
    host_pem = pki.host_cert_path.read_bytes()
    host_key = rsa.load_private_key(pki.host_key_path.read_bytes())
    server = SecgsiServer(host_pem, host_key)
    assert 2 <= server.private <= MODP_2048_PRIME - 2
    client = SecgsiClient(pki.credential(), server_version=10400)
    client.initial()
    with caplog.at_level("WARNING"):
        login = server.read_certificate(client.step(server.challenge()) or b"", tag=b"abcdEFGH")
    assert "bits" not in caplog.text
    assert login.use_iv and login.chain_pem == pki.credential().pem()


def test_the_unsigned_challenge_needs_no_key() -> None:
    challenge = SecgsiServer(private=5).challenge(signed=False)
    blob = find_bucket(challenge, BUCKET_PUK)
    assert blob is not None and parse_peer_blob(blob).public == pow(2, 5, MODP_2048_PRIME)


def test_the_signed_challenge_needs_the_servers_key() -> None:
    with pytest.raises(CredentialError, match="needs the server's private key"):
        SecgsiServer(private=5).challenge()


def test_a_reply_from_the_wrong_round_is_refused() -> None:
    server = SecgsiServer(private=5)
    with pytest.raises(CredentialError, match="expected kXGC_cert, got step 1002"):
        server.read_certificate(encode_message(1002, []))
    login = SecgsiLogin(b"k" * 16, True, b"", b"", b"")
    with pytest.raises(CredentialError, match="expected kXGC_sigpxy, got step 1001"):
        server.read_signed_proxy(login, encode_message(STEP_CLIENT_CERT, []))


def test_an_unsigned_tag_or_a_chain_without_a_certificate_is_refused(pki: PKI) -> None:
    server = SecgsiServer(private=(1 << 250) | 3)
    client = SecgsiClient(pki.credential(), server_version=10300)
    client.initial()
    reply = client.step(server.challenge(signed=False, tag=b"12345678")) or b""
    assert find_bucket(reply, BUCKET_CIPHER_ALG) == b"aes-128-cbc"
    with pytest.raises(CredentialError, match="did not sign the server's random tag"):
        server.read_certificate(reply, tag=b"otherTAG")
    assert decode_message(reply)[0] == STEP_CLIENT_CERT
    login = server.read_certificate(reply)
    no_chain = SecgsiLogin(login.key, login.use_iv, login.plain, b"", login.client_tag)
    with pytest.raises(CredentialError, match="sent no RSA certificate"):
        no_chain.client_key()
    assert find_bucket(login.plain, BUCKET_X509) == login.chain_pem
