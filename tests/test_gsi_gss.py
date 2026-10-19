"""The Globus GSI GSS mechanism: token-driven TLS, the delegation byte, name checks.

Ported from xgfalclient's ``tests/test_gsi.py`` with the code it tests
(``crypto/gsi.py`` became :mod:`xrdsec.gsi.gss` in 0.4.0).
"""

from __future__ import annotations

import dataclasses
import ssl
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from xrdsec import der, rsa
from xrdsec.delegation import make_proxy_request, sign_globus_request
from xrdsec.gsi import gss
from xrdsec.gsi.gss import DelegatedCredential, GSIError, SecurityContext
from xrdsec.testing.gsi import exchange_tokens
from xrdsec.testing.pki import PKI, create_pki, test_key
from xrdsec.x509 import (
    LIMITED_PROXY_OID,
    SUBJECT_ALT_NAME_OID,
    CertificateData,
    Name,
    certificate_data,
    proxy_policy,
)


def key(slot: int) -> rsa.RSAPrivateKey:
    """Frozen key ``slot`` as xrdsec's RSA view, which a delegation acceptor holds."""
    return rsa.RSAPrivateKey.from_cryptography(test_key(slot))


def data(certificate: object) -> CertificateData:
    """A ``cryptography`` certificate from the test PKI as xrdsec's decoded view."""
    assert hasattr(certificate, "public_bytes")
    return certificate_data(certificate.public_bytes(serialization.Encoding.DER))


def client_tls(pki: PKI, *, ca: Path | None = None) -> ssl.SSLContext:
    """A client context presenting the PKI's proxy, with ``ssl``'s host check off (GSI's own)."""
    context = ssl.create_default_context(cafile=str(ca or pki.ca_file))
    context.check_hostname = False
    context.load_cert_chain(str(pki.proxy_path))
    return context


def test_handshake_without_delegation(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki), server_hostname="localhost")
    server = SecurityContext(pki.server_context(), server_side=True)
    exchange_tokens(client, server)
    assert server.delegated is None and client.delegated is None
    assert server.unwrap(client.wrap(b"MIC stuff")) == b"MIC stuff"
    assert client.unwrap(server.wrap(b"reply")) == b"reply"
    client.check_host("localhost")
    peer = server.peer_certificate()
    assert peer is not None and peer.is_proxy


def test_handshake_with_delegation(pki: PKI) -> None:
    credential = pki.credential()
    client = SecurityContext(client_tls(pki), delegate=credential, lifetime=600)
    server = SecurityContext(pki.server_context(), server_side=True, delegation_key=key(4))
    exchange_tokens(client, server)
    delegated = server.delegated
    assert isinstance(delegated, DelegatedCredential)
    assert delegated.chain[0].public_key == key(4).public
    assert delegated.chain[0].issuer.rdns == credential.certificate.subject.rdns
    assert delegated.chain[0].not_after <= delegated.chain[0].not_before + 600 + 300
    assert delegated.credential().identity == str(data(pki.user).subject)
    proxy_file = pki.directory / "delegated.pem"
    proxy_file.write_bytes(delegated.pem())
    proxy_file.chmod(0o600)
    ssl.create_default_context().load_cert_chain(str(proxy_file))  # usable as a client credential


def test_limited_delegation(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki), delegate=pki.credential(), limited=True)
    server = SecurityContext(pki.server_context(), server_side=True, delegation_key=key(4))
    exchange_tokens(client, server)
    assert server.delegated is not None
    assert proxy_policy(server.delegated.chain[0].extension_values) == LIMITED_PROXY_OID


def test_server_generates_its_key(pki: PKI, monkeypatch: pytest.MonkeyPatch) -> None:
    generated = key(7)

    def generate(cls: type[rsa.RSAPrivateKey], bits: int = 2048) -> rsa.RSAPrivateKey:
        return generated

    monkeypatch.setattr(rsa.RSAPrivateKey, "generate", classmethod(generate))
    client = SecurityContext(client_tls(pki), delegate=pki.credential())
    server = SecurityContext(pki.server_context(), server_side=True)
    exchange_tokens(client, server)
    assert server.delegation_key is generated


def test_handshake_failure(pki: PKI, tmp_path: Path) -> None:
    other = create_pki(tmp_path / "other", key_slots=(5, 6, 7))
    client = SecurityContext(client_tls(pki, ca=other.ca_file))
    server = SecurityContext(pki.server_context(), server_side=True)
    with pytest.raises(GSIError, match="TLS handshake failed"):
        exchange_tokens(client, server)


class BadFlag(SecurityContext):
    """A client that answers the handshake with a flag no GSI peer sends."""

    def _handshake(self) -> None:
        try:
            self.tls.do_handshake()
        except ssl.SSLWantReadError:
            return
        self.tls.write(b"X")
        self._state, self.complete = "done", True


def test_unexpected_flag(pki: PKI) -> None:
    client = BadFlag(client_tls(pki))
    server = SecurityContext(pki.server_context(), server_side=True)
    with pytest.raises(GSIError, match="unexpected GSI delegation flag"):
        exchange_tokens(client, server)


def _handshaken(pki: PKI, *, delegate: bool) -> tuple[SecurityContext, SecurityContext]:
    """A pair whose handshake is done but whose delegation has not started."""
    client = SecurityContext(client_tls(pki), delegate=pki.credential() if delegate else None)
    server = SecurityContext(pki.server_context(), server_side=True, delegation_key=key(4))
    token = client.step()
    while client._state in ("handshake", "turn"):
        token = client.step(server.step(token))
    server.step(token)  # the flag
    return client, server


def _signed(slot: int, pki: PKI) -> bytes:
    """A Globus proxy for key ``slot``, signed by the PKI's default proxy."""
    credential = pki.credential()
    return sign_globus_request(
        make_proxy_request(key(slot)), [link.der for link in credential.chain], credential.key
    )


def test_partial_request_and_chain_wait(pki: PKI) -> None:
    client, _ = _handshaken(pki, delegate=True)
    client._pending = make_proxy_request(key(4))[:10]
    client._answer_request()
    assert not client.complete and client._state == "request"
    _, server = _handshaken(pki, delegate=True)
    server._state = "chain"
    server._pending = b"\x30\x82\x05\x00partial"
    server._accept_chain()
    assert not server.complete


def test_chain_for_the_wrong_key(pki: PKI) -> None:
    _, server = _handshaken(pki, delegate=True)
    server._state = "chain"
    server._pending = _signed(5, pki)
    with pytest.raises(GSIError, match="does not certify the requested key"):
        server._accept_chain()


def test_full_chain_from_an_older_peer(pki: PKI) -> None:
    """A delegator that sends its whole chain is accepted as sent."""
    _, server = _handshaken(pki, delegate=True)
    server._state = "chain"
    chain = pki.credential().chain
    server._pending = _signed(4, pki) + b"".join(link.der for link in chain if not link.is_anchor)
    server._accept_chain()
    assert server.delegated is not None and len(server.delegated.chain) == 3


def test_ssl_compatible_is_plain_tls(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki), ssl_compatible=True)
    server = SecurityContext(pki.server_context(), server_side=True, ssl_compatible=True)
    exchange_tokens(client, server)
    assert server.unwrap(client.wrap(b"data")) == b"data"


def test_tls12_has_no_turn(pki: PKI) -> None:
    tls = client_tls(pki)
    tls.maximum_version = ssl.TLSVersion.TLSv1_2
    client = SecurityContext(tls, delegate=pki.credential())
    server = SecurityContext(pki.server_context(), server_side=True, delegation_key=key(4))
    exchange_tokens(client, server)
    assert client.tls.version() == "TLSv1.2" and server.delegated is not None


def test_unsignable_request(pki: PKI) -> None:
    client, _ = _handshaken(pki, delegate=True)
    client._pending = der.sequence(der.integer(1))
    with pytest.raises(GSIError, match="cannot sign the delegation request"):
        client._answer_request()


def test_garbage_and_close_notify(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki))
    server = SecurityContext(pki.server_context(), server_side=True)
    exchange_tokens(client, server)
    with pytest.raises(GSIError, match="cannot decrypt"):
        server.unwrap(b"\x17\x03\x03\x00\x05hello")
    client = SecurityContext(client_tls(pki))
    server = SecurityContext(pki.server_context(), server_side=True)
    exchange_tokens(client, server)
    with pytest.raises(ssl.SSLWantReadError):
        server.tls.unwrap()  # sends close_notify, then waits for the peer's
    assert client.unwrap(server._out.read()) == b""


def test_peer_without_certificate(pki: PKI) -> None:
    client = SecurityContext(client_tls(pki))
    server = SecurityContext(pki.server_context(require_client=False), server_side=True)
    exchange_tokens(client, server)
    assert server.peer_certificate() is None
    with pytest.raises(GSIError, match="no certificate"):
        server.check_host("localhost")


def test_host_names(pki: PKI) -> None:
    host, ca = data(pki.host), data(pki.ca)
    gss.check_host(host, "LOCALHOST.")
    with pytest.raises(GSIError, match="does not match host"):
        gss.check_host(host, "other.example")
    assert gss.dns_names(host) == ["localhost"]
    assert gss.dns_names(ca) == []
    broken = dataclasses.replace(host, extension_values={SUBJECT_ALT_NAME_OID: (False, b"\x05")})
    assert gss.dns_names(broken) == []
    gss.check_host(
        dataclasses.replace(ca, subject=Name((("CN", "ftp/se.example.org"),))), "se.example.org"
    )
    gss.check_host(
        dataclasses.replace(ca, subject=Name((("CN", "se.example.org"),))), "se.example.org"
    )
    assert gss._matches("*.example.org", "a.example.org")
    assert not gss._matches("*.example.org", "example.org")
    assert not gss._matches("*.example.org", ".example.org")
    assert not gss._matches("*.example.org", "a.b.example.org")


def test_custom_host_names(tmp_path: Path) -> None:
    other = create_pki(tmp_path, hosts=("se.example.org", "10.0.0.1"), host_cn="se.example.org")
    assert gss.dns_names(data(other.host)) == ["se.example.org"]


@pytest.mark.skipif(not ssl.HAS_TLSv1_3, reason="this Python's ssl module has no TLS 1.3")
def test_dcache_style_peers_take_no_turn(pki: PKI) -> None:
    """dCache's GSI engine neither sends nor waits for the TLS 1.3 turn."""
    client = SecurityContext(client_tls(pki), delegate=pki.credential(), turn=False)
    server = SecurityContext(
        pki.server_context(), server_side=True, delegation_key=key(4), turn=False
    )
    exchange_tokens(client, server)
    assert client.tls.version() == "TLSv1.3" and server.delegated is not None
    assert server.unwrap(client.wrap(b"hello")) == b"hello"


# -- peer_chain_der, the 3.11/3.12 bridge (moved from xgfalclient's _compat) --------


class _Certificate:
    """What ``_sslobj.get_unverified_chain`` returns before 3.13: encodes on request."""

    def __init__(self, der: bytes) -> None:
        self.der = der

    def public_bytes(self, encoding: int) -> bytes:
        assert encoding == 2  # DER
        return self.der


class _NewTls:
    """An ``SSLObject`` from 3.13 on: the public method, returning DER bytes."""

    def get_unverified_chain(self) -> list[bytes]:
        return [b"leaf", b"ca"]


class _SslObj:
    """The private ``_sslobj`` of 3.11 and 3.12."""

    def __init__(self, chain: list[_Certificate] | None) -> None:
        self.chain = chain

    def get_unverified_chain(self) -> list[_Certificate] | None:
        return self.chain


class _OldTls:
    """An ``SSLObject`` before 3.13: only the private object has the method."""

    def __init__(self, chain: list[_Certificate] | None) -> None:
        self._sslobj = _SslObj(chain)


def test_peer_chain_der_public_method() -> None:
    assert gss.peer_chain_der(_NewTls()) == [b"leaf", b"ca"]


def test_peer_chain_der_private_method_before_3_13() -> None:
    chain = [_Certificate(b"leaf"), _Certificate(b"ca")]
    assert gss.peer_chain_der(_OldTls(chain)) == [b"leaf", b"ca"]


def test_peer_chain_der_private_method_without_a_peer_chain() -> None:
    assert gss.peer_chain_der(_OldTls(None)) == []


def _bio_handshake(initiator: ssl.SSLContext, acceptor: ssl.SSLContext) -> set[str]:
    """Drive both ends of a TLS handshake over memory BIOs; the sides that finished."""
    incoming, outgoing, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = initiator.wrap_bio(incoming, outgoing)
    server = acceptor.wrap_bio(s_in, s_out, server_side=True)
    done: set[str] = set()
    for _ in range(10):
        for label, side, out, peer_in in (
            ("initiator", client, outgoing, s_in),
            ("acceptor", server, s_out, incoming),
        ):
            try:
                side.do_handshake()
                done.add(label)
            except (ssl.SSLWantReadError, ssl.SSLError):
                pass
            peer_in.write(out.read())
    return done


def test_data_contexts_are_cached_and_accept_proxies(pki: PKI) -> None:
    """The pair a DCAU data channel uses: cached, proxies allowed, no host name, no tickets."""
    path = str(pki.proxy_path)
    initiator, acceptor = gss.data_contexts(path, path, str(pki.ca_dir))
    assert gss.data_contexts(path, path, str(pki.ca_dir)) == (initiator, acceptor)
    for context in (initiator, acceptor):
        assert context.verify_mode == ssl.CERT_REQUIRED and not context.check_hostname
        assert context.verify_flags & ssl.VERIFY_ALLOW_PROXY_CERTS
        assert not context.verify_flags & ssl.VERIFY_X509_STRICT
    assert acceptor.num_tickets == 0
    # Both ends present the user's proxy and accept the other's.
    assert _bio_handshake(initiator, acceptor) == {"initiator", "acceptor"}


def test_data_contexts_without_a_ca_directory_trust_nobody(pki: PKI) -> None:
    path = str(pki.proxy_path)
    initiator, acceptor = gss.data_contexts(path, path, None)
    assert initiator.verify_mode == ssl.CERT_REQUIRED
    assert _bio_handshake(initiator, acceptor) != {"initiator", "acceptor"}
