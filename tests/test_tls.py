"""``xrdsec.tls.client_context``: the grid's TLS rules for any client's HTTPS.

Ported from xrdclient's ``tests/test_tls.py``. Each test hands the context to
the standard library's own :class:`http.client.HTTPSConnection` - as a tool
outside this package would - and completes a real handshake with
:class:`~xrdsec.testing.https.FakeHTTPSServer`, so what is checked is what a
server sees: which certificate, if any, the client presented, and which CAs
and CRLs decided whether the server was believed.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from xrdcore.errors import CredentialError, InsecureCredentialError
from xrdsec import credentials, tls
from xrdsec.testing.https import FakeHTTPSServer, Response
from xrdsec.testing.pki import PKI, create_pki

USER = "/DC=org/DC=xrdsec/OU=People/CN=Test User"


@pytest.fixture(scope="module")
def pki(tmp_path_factory) -> PKI:
    return create_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    """No trust settings from the developer's shell."""
    for name in (tls.SYSTEM_CA_ENV, tls.CRL_ENV, "SSL_CERT_DIR", "SSL_CERT_FILE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def mtls(pki):
    """A server that asks for - but does not require - a client certificate."""
    context = pki.server_context()
    context.verify_mode = ssl.CERT_OPTIONAL
    with FakeHTTPSServer(tls=context) as srv:
        srv.route("GET", r"/d/f", lambda request: Response(200, b"over tls"))
        yield srv


def _get(context: ssl.SSLContext, server: FakeHTTPSServer) -> bytes:
    """``GET /d/f`` over ``context`` with nothing of this package's but the context."""
    conn = http.client.HTTPSConnection("localhost", server.port, context=context, timeout=10)
    try:
        conn.request("GET", "/d/f")
        return conn.getresponse().read()
    finally:
        conn.close()


def _presented(server: FakeHTTPSServer) -> str | None:
    """The end-entity identity of the certificate the last client presented, or ``None``."""
    peer = server.requests[-1].peer
    return None if peer is None else peer.identity


def _pair(tmp_path, pki: PKI, *, mode=0o600, encryption=None) -> tuple[str, str]:
    """A copy of the user's ``usercert.pem`` and ``userkey.pem``, the key as asked."""
    cert = tmp_path / "usercert.pem"
    cert.write_bytes(pki.user.public_bytes(serialization.Encoding.PEM))
    key = tmp_path / "userkey.pem"
    key.write_bytes(
        pki.user_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption or serialization.NoEncryption(),
        )
    )
    key.chmod(mode)
    return str(cert), str(key)


# ---------------------------------------------------------------------------
# Who the client is
# ---------------------------------------------------------------------------


def test_nothing_is_presented_unless_asked(pki, mtls, tmp_path, monkeypatch):
    """A token-only client must not leak the proxy it would find in ``/tmp``."""
    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp_path))
    pki.proxy(path=tmp_path / f"x509up_u{os.geteuid()}")
    assert _get(tls.client_context(ca_path=pki.ca_dir), mtls) == b"over tls"
    assert _presented(mtls) is None
    _get(tls.client_context(ca_path=pki.ca_dir, present_default=True), mtls)
    assert _presented(mtls) == USER  # the default proxy itself


def test_an_unusable_default_proxy_is_passed_over(pki, mtls, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(credentials, "TMP_DIR", str(tmp_path))
    (tmp_path / f"x509up_u{os.geteuid()}").write_bytes(b"not a proxy")
    context = tls.client_context(ca_path=pki.ca_dir, present_default=True)
    assert _get(context, mtls) == b"over tls"
    assert _presented(mtls) is None
    assert "not presenting the X.509 proxy" in caplog.text


def test_a_proxy_is_presented_as_the_client_chain(pki, mtls):
    _get(tls.client_context(cert=pki.proxy_path, ca_path=pki.ca_dir), mtls)
    assert _presented(mtls) == USER
    assert mtls.requests[-1].peer.subject.startswith(USER + "/CN=")


def test_a_named_proxy_that_will_not_load_says_which(tmp_path):
    broken = tmp_path / "proxy.pem"
    broken.write_bytes(b"junk")
    with pytest.raises(OSError, match=rf"cannot use the X\.509 proxy {broken}"):
        tls.client_context(cert=broken)


def test_a_certificate_and_separate_key_are_presented_without_a_file(pki, mtls, tmp_path):
    cert, key = _pair(tmp_path, pki)
    before = set(os.listdir(tmp_path))
    _get(tls.client_context(cert=cert, key=key, ca_path=pki.ca_dir), mtls)
    assert _presented(mtls) == USER
    assert set(os.listdir(tmp_path)) == before  # no key spliced to disk


def test_a_credential_held_in_memory_is_presented(pki, mtls):
    pem = pki.credential().to_pem()
    _get(tls.client_context(credential_pem=pem, ca_path=pki.ca_dir), mtls)
    assert _presented(mtls) == USER
    assert tls.client_context(credential_pem=pem) is tls.client_context(credential_pem=pem)


def test_a_file_and_a_memory_credential_are_one_too_many(pki):
    with pytest.raises(ValueError, match="not both"):
        tls.client_context(cert=pki.proxy_path, credential_pem=b"x")


@pytest.mark.parametrize(
    "password",
    ["sesame", b"sesame", lambda: "sesame", lambda: b"sesame"],
    ids=["text", "bytes", "callable-text", "callable-bytes"],
)
def test_an_encrypted_key_is_unlocked_by_the_pass_phrase_given(pki, tmp_path, password):
    locked = serialization.BestAvailableEncryption(b"sesame")
    cert, key = _pair(tmp_path, pki, encryption=locked)
    assert isinstance(tls.client_context(cert=cert, key=key, key_password=password), ssl.SSLContext)


def test_an_encrypted_key_without_a_usable_pass_phrase_is_refused(pki, tmp_path):
    locked = serialization.BestAvailableEncryption(b"sesame")
    cert, key = _pair(tmp_path, pki, encryption=locked)
    with pytest.raises(CredentialError, match="encrypted and no pass phrase"):
        tls.client_context(cert=cert, key=key)
    with pytest.raises(CredentialError, match="pass phrase is empty"):
        tls.client_context(cert=cert, key=key, key_password=lambda: "")
    with pytest.raises(CredentialError, match=r"cannot use the X\.509 certificate"):
        tls.client_context(cert=cert, key=key, key_password="wrong")


def test_a_key_others_can_read_is_refused(pki, tmp_path):
    cert, key = _pair(tmp_path, pki, mode=0o644)
    with pytest.raises(InsecureCredentialError, match="chmod 600"):
        tls.client_context(cert=cert, key=key)


def test_a_key_without_its_certificate_is_a_mistake(tmp_path):
    with pytest.raises(ValueError, match="without the certificate"):
        tls.client_context(key=str(tmp_path / "userkey.pem"))


# ---------------------------------------------------------------------------
# Trust and revocation
# ---------------------------------------------------------------------------


def test_the_grid_directory_vouches_for_the_server(pki, mtls, tmp_path):
    assert _get(tls.client_context(ca_path=pki.ca_dir), mtls) == b"over tls"
    assert _get(tls.client_context(ca_file=pki.ca_file), mtls) == b"over tls"
    other = create_pki(tmp_path / "other", key_slots=(5, 6, 7))
    with pytest.raises(ssl.SSLCertVerificationError):
        _get(tls.client_context(ca_path=other.ca_dir), mtls)


def test_a_blank_ca_path_means_the_system_store(pki, mtls, monkeypatch):
    """The xrdarc bug: ``X509_CERT_DIR=`` became a ``capath`` of ``""``."""
    monkeypatch.setenv("SSL_CERT_FILE", str(pki.ca_file))
    assert tls.client_context(ca_path="  ") is tls.client_context()
    assert _get(tls.client_context(ca_path=""), mtls) == b"over tls"


def test_the_system_store_can_join_a_grid_directory(pki, mtls, tmp_path, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(pki.ca_file))
    unrelated = create_pki(tmp_path / "unrelated", key_slots=(5, 6, 7)).ca_dir
    with pytest.raises(ssl.SSLCertVerificationError):
        _get(tls.client_context(ca_path=unrelated), mtls)
    assert _get(tls.client_context(ca_path=unrelated, system_ca=True), mtls) == b"over tls"


@pytest.mark.parametrize(
    ("check", "refused"),
    [(None, False), (False, False), ("0", False), (True, True), ("leaf", True), ("chain", True)],
)
def test_crls_are_checked_when_asked(tmp_path, check, refused):
    pki = create_pki(tmp_path / "pki")
    pki.install_crl(revoked=[pki.host.serial_number])
    context = pki.server_context()
    context.verify_mode = ssl.CERT_OPTIONAL
    with FakeHTTPSServer(tls=context) as srv:
        srv.route("GET", r"/d/f", lambda request: Response(200, b"over tls"))
        client = tls.client_context(ca_path=pki.ca_dir, check_crl=check)
        if refused:
            with pytest.raises(ssl.SSLCertVerificationError, match="revoked"):
                _get(client, srv)
        else:
            assert _get(client, srv) == b"over tls"


def test_crls_need_verification_and_a_directory(tmp_path):
    assert not tls.client_context(check_crl=True).verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    unverified = tls.client_context(ca_path=tmp_path, check_crl=True, verify=False)
    assert not unverified.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    assert (unverified.verify_mode, unverified.check_hostname) == (ssl.CERT_NONE, False)
    chain = tls.client_context(ca_path=tmp_path, check_crl="chain").verify_flags
    assert chain & ssl.VERIFY_CRL_CHECK_CHAIN


@pytest.mark.parametrize(
    ("word", "mode"),
    [
        ("", ""),
        ("0", ""),
        (" No ", ""),
        ("off", ""),
        ("false", ""),
        ("1", "leaf"),
        ("yes", "leaf"),
        ("leaf", "leaf"),
        ("CHAIN", "chain"),
    ],
)
def test_crl_vocabulary(word, mode):
    assert tls.crl_mode(word) == mode


def test_x509_strict_can_be_turned_off_for_gfal2_and_arc(tmp_path):
    lenient = tls.client_context(ca_path=tmp_path, x509_strict=False)
    assert not lenient.verify_flags & ssl.VERIFY_X509_STRICT
    assert lenient is not tls.client_context(ca_path=tmp_path)


def test_gsi_contexts_leave_the_name_check_to_the_caller(pki, tmp_path):
    """``check_hostname=False`` (GSI's own DN check) still verifies the chain; ALPN is offered."""
    named = tls.client_context(ca_path=tmp_path)
    gsi = tls.client_context(ca_path=tmp_path, check_hostname=False, alpn=["http/1.1"])
    assert named.check_hostname and named.verify_mode == ssl.CERT_REQUIRED
    assert not gsi.check_hostname and gsi.verify_mode == ssl.CERT_REQUIRED
    unnamed = tls.client_context(ca_path=tmp_path, check_hostname=False)
    assert gsi is not named and gsi is not unnamed
    common = {"cert": str(pki.proxy_path), "ca_path": pki.ca_dir}
    with FakeHTTPSServer(tls=pki.server_context()) as srv:
        # A name the server's certificate does not carry: only a context that
        # leaves the name alone completes the handshake - against our CA.
        for check, works in ((False, True), (True, False)):
            context = tls.client_context(**common, check_hostname=check, alpn=("http/1.1",))
            with socket.create_connection(("127.0.0.1", srv.port)) as raw:
                if works:
                    context.wrap_socket(raw, server_hostname="elsewhere.example").close()
                    continue
                with pytest.raises(ssl.SSLCertVerificationError, match="Hostname mismatch"):
                    context.wrap_socket(raw, server_hostname="elsewhere.example")


# ---------------------------------------------------------------------------
# One builder, one cache
# ---------------------------------------------------------------------------


def test_one_setup_is_one_shared_context_until_its_files_change(pki, tmp_path):
    proxy = pki.proxy(path=tmp_path / "proxy.pem")
    first = tls.client_context(cert=proxy, ca_path=tmp_path)
    assert tls.client_context(cert=proxy, ca_path=tmp_path) is first
    pki.proxy(path=tmp_path / "proxy.pem")  # renewed in place
    os.utime(proxy, ns=(5, 5))
    renewed = tls.client_context(cert=proxy, ca_path=tmp_path)
    assert renewed is not first
    tls.clear_cache()
    assert tls.client_context(cert=proxy, ca_path=tmp_path) is not renewed


def test_the_cache_is_bounded(tmp_path):
    contexts = [tls.client_context(ca_path=tmp_path / str(n)) for n in range(tls._CACHE_SIZE + 2)]
    assert len(tls._cache) == tls._CACHE_SIZE
    assert tls.client_context(ca_path=tmp_path / "0") is not contexts[0]


def test_the_presented_subject_is_the_proxys(pki):
    """The default proxy and the user certificate are distinct certificates."""
    leaf = x509.load_pem_x509_certificate(pki.proxy_path.read_bytes())
    assert leaf.subject != pki.user.subject
