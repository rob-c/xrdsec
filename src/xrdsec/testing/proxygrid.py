"""A small grid for proxy and VOMS-client tests: CA, user, VOMS server, host, ACs.

Everything is minted in process with ``cryptography`` (certificates) and the
:mod:`xrdsec.testing.rawpki` DER writers (attribute certificates, which
``cryptography`` does not model), so every test gets material valid *today*.
Keys are made once per process: RSA key generation dominates the cost
otherwise. It was a private helper of xrdsec's and xrdclient's suites, one
near-identical copy each; both import it from here since 0.4.0.

:class:`Grid` is the material on disk the way a grid node lays it out - a
hashed CA directory, a ``vomsdir`` with an LSC file, ``usercert.pem`` and a
``0600`` ``userkey.pem`` - and :class:`FakeVOMS` is a VOMS REST endpoint
(``GET /generate-ac``) over mutual TLS that answers as told. Nothing here is
imported by the library; public test API, versioned with the package.
"""

from __future__ import annotations

import base64
import datetime
import functools
import ipaddress
import os
import secrets
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
    PrivateKeyTypes,
)
from cryptography.x509.oid import NameOID

from xrdsec.testing.rawpki import bitstring, integer, oid, sequence, setof, tlv
from xrdsec.voms import VOMS_FQAN_OID
from xrdsec.voms_client import VOMSServer
from xrdsec.x509 import (
    ProxyCredential,
    load_certificates,
    name_hashes,
    parse_certificate,
)

VOMS_CERTS_OID = "1.3.6.1.4.1.8005.100.100.10"
NO_REV_AVAIL_OID = "2.5.29.56"
SHA256_RSA_OID = "1.2.840.113549.1.1.11"
DAY = datetime.timedelta(days=1)


@functools.cache
def key(slot: int) -> rsa.RSAPrivateKey:
    """An RSA key per ``slot``, generated once per process."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(*rdns: tuple[x509.ObjectIdentifier, str]) -> x509.Name:
    """A ``cryptography`` name from ``(oid, value)`` pairs, one RDN each."""
    return x509.Name([x509.RelativeDistinguishedName([x509.NameAttribute(k, v)]) for k, v in rdns])


DC = NameOID.DOMAIN_COMPONENT
CN = NameOID.COMMON_NAME
CA_NAME = _name((DC, "org"), (DC, "example"), (CN, "Test CA"))
USER_NAME = _name(
    (DC, "org"), (DC, "example"), (NameOID.ORGANIZATIONAL_UNIT_NAME, "People"), (CN, "Jane Doe")
)
VOMS_NAME = _name((DC, "org"), (DC, "example"), (CN, "voms.example.org"))
HOST_NAME = _name((DC, "org"), (DC, "example"), (CN, "localhost"))


def certificate(
    subject: x509.Name,
    issuer: x509.Name,
    public: CertificatePublicKeyTypes,
    signer: CertificateIssuerPrivateKeyTypes,
    *,
    serial: int,
    extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
) -> x509.Certificate:
    """A certificate signed SHA-256 by ``signer``, valid a day either side of now by default."""
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public)
        .serial_number(serial)
        .not_valid_before(not_before or now - DAY)
        .not_valid_after(not_after or now + 30 * DAY)
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    if subject != issuer:
        # Python 3.13's default context verifies X509-strictly, which wants
        # every CA-issued certificate to name its issuer's key.
        authority = x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key())
        builder = builder.add_extension(authority, critical=False)
    return builder.sign(signer, hashes.SHA256())


def usage(*, sign: bool = False, ca: bool = False) -> x509.KeyUsage:
    """A ``keyUsage``: an end entity's (digitalSignature...) or a CA's (keyCertSign...)."""
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=sign,
        key_encipherment=not ca,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def pem(cert: x509.Certificate) -> bytes:
    """``cert`` as PEM."""
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(private: PrivateKeyTypes, password: bytes | None = None) -> bytes:
    """A private key as PEM; encrypted (PKCS#8) when ``password`` is given."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


def der(cert: x509.Certificate) -> bytes:
    """``cert`` as DER."""
    return cert.public_bytes(serialization.Encoding.DER)


def _gentime(when: float) -> bytes:
    return tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(when)).encode())


def _extension(dotted: str, value: bytes) -> bytes:
    return sequence(oid(dotted), tlv(0x04, value))


def _general_names(name_der: bytes) -> bytes:
    return sequence(tlv(0xA4, name_der))


@dataclass
class Grid:
    """CA, user, VOMS server and host credentials, laid out under ``root``."""

    root: Path
    ca: x509.Certificate
    user: x509.Certificate
    voms: x509.Certificate
    host: x509.Certificate
    ca_dir: Path = field(init=False)
    voms_dir: Path = field(init=False)
    usercert: Path = field(init=False)
    userkey: Path = field(init=False)

    def __post_init__(self) -> None:
        """Write the CA directory, ``vomsdir`` LSC, user files and server files."""
        self.ca_dir = self.root / "certificates"
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        hashed = name_hashes(self.ca.subject.public_bytes())[0]
        (self.ca_dir / f"{hashed}.0").write_bytes(pem(self.ca))
        self.voms_dir = self.root / "vomsdir"
        (self.voms_dir / "atlas").mkdir(parents=True, exist_ok=True)
        parsed = parse_certificate(der(self.voms))
        (self.voms_dir / "atlas" / "voms.example.org.lsc").write_text(
            f"{parsed.subject}\n{parsed.issuer}\n"
        )
        self.usercert = self.root / "usercert.pem"
        self.usercert.write_bytes(pem(self.user))
        self.userkey = self.write_key(self.root / "userkey.pem", key(2))
        (self.root / "host.pem").write_bytes(pem(self.host) + key_pem(key(4)))

    @staticmethod
    def write_key(path: Path, private: PrivateKeyTypes, password: bytes | None = None) -> Path:
        """Write a private key ``0600``, as a user's key must be."""
        path.write_bytes(key_pem(private, password))
        os.chmod(path, 0o600)
        return path

    def credential(self) -> ProxyCredential:
        """The user certificate and key, as :func:`load_credential` would give them."""
        from xrdsec.rsa import RSAPrivateKey

        chain = tuple(load_certificates(pem(self.user) + pem(self.ca)))
        return ProxyCredential(chain=chain, key=RSAPrivateKey.from_cryptography(key(2)))

    def make_ac(
        self,
        fqans: tuple[str, ...] = ("/atlas/Role=NULL/Capability=NULL",),
        *,
        vo: str = "atlas",
        lifetime: float = 3600.0,
        signer: rsa.RSAPrivateKey | None = None,
    ) -> bytes:
        """A VOMS AC for the user, holder named as VOMS servers name it.

        The holder's ``baseCertificateID`` carries the user's *subject* (VOMS
        wrote the issuer of the proxy it was contacted with, which is the
        user) and the user certificate's serial; ``arcproxy -I`` refuses an
        AC whose holder is the CA's name, so the fixture matches the servers.
        """
        now = time.time()
        values = sequence(*(tlv(0x04, fqan.encode()) for fqan in fqans))
        uri = f"{vo}://voms.example.org:15000".encode()
        attributes = sequence(
            sequence(oid(VOMS_FQAN_OID), setof(sequence(tlv(0xA0, tlv(0x86, uri)), values)))
        )
        # ARC insists on both noRevAvail and authorityKeyIdentifier, as VOMS
        # servers write them.
        authority = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            (signer or key(3)).public_key()
        )
        extensions = sequence(
            _extension(VOMS_CERTS_OID, sequence(sequence(der(self.voms)))),
            _extension(NO_REV_AVAIL_OID, tlv(0x05, b"")),
            _extension("2.5.29.35", authority.public_bytes()),
        )
        algorithm = sequence(oid(SHA256_RSA_OID), tlv(0x05, b""))
        tbs = sequence(
            integer(1),
            sequence(
                tlv(
                    0xA0,
                    _general_names(self.user.subject.public_bytes())
                    + integer(self.user.serial_number),
                )
            ),
            tlv(0xA0, _general_names(self.voms.subject.public_bytes())),
            algorithm,
            integer(secrets.randbits(32) | 1),
            sequence(_gentime(now - 300), _gentime(now + lifetime)),
            attributes,
            extensions,
        )
        signature = (signer or key(3)).sign(tbs, padding.PKCS1v15(), hashes.SHA256())
        return sequence(tbs, algorithm, bitstring(signature))


@functools.cache
def _material() -> tuple[x509.Certificate, x509.Certificate, x509.Certificate, x509.Certificate]:
    """CA, user, VOMS and host certificates, minted once per process."""
    ca = certificate(
        CA_NAME,
        CA_NAME,
        key(1).public_key(),
        key(1),
        serial=1,
        extensions=(
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (usage(ca=True), True),
            (x509.SubjectKeyIdentifier.from_public_key(key(1).public_key()), False),
        ),
    )
    user = certificate(
        USER_NAME,
        CA_NAME,
        key(2).public_key(),
        key(1),
        serial=0x1234,
        extensions=(
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (usage(sign=True), True),
            (x509.SubjectAlternativeName([x509.RFC822Name("jane@example.org")]), False),
            (x509.SubjectKeyIdentifier.from_public_key(key(2).public_key()), False),
        ),
    )
    voms = certificate(
        VOMS_NAME,
        CA_NAME,
        key(3).public_key(),
        key(1),
        serial=3,
        extensions=((x509.SubjectKeyIdentifier.from_public_key(key(3).public_key()), False),),
    )
    host = certificate(
        HOST_NAME,
        CA_NAME,
        key(4).public_key(),
        key(1),
        serial=4,
        extensions=(
            (
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                False,
            ),
        ),
    )
    return ca, user, voms, host


def build_grid(root: Path) -> Grid:
    """The test grid, written under ``root``."""
    ca, user, voms, host = _material()
    return Grid(root, ca, user, voms, host)


# ---------------------------------------------------------------------------
# A VOMS REST endpoint
# ---------------------------------------------------------------------------

#: What a :class:`FakeVOMS` sends: ``(status, body)`` from the parsed query.
Answer = Callable[[dict[str, list[str]]], tuple[int, bytes]]


def ac_answer(ac: bytes, *warnings: str) -> tuple[int, bytes]:
    """A successful ``generate-ac`` answer carrying ``ac`` (and any warnings)."""
    extra = "".join(f"<warning>{text}</warning>" for text in warnings)
    encoded = base64.encodebytes(ac).decode()
    return 200, f'<?xml version="1.0"?><voms><ac>{encoded}</ac>{extra}</voms>'.encode()


def error_answer(status: int, code: str, message: str) -> tuple[int, bytes]:
    """A refusal, as VOMS and IAM send one."""
    body = f"<voms><error><code>{code}</code><message>{message}</message></error></voms>"
    return status, body.encode()


class FakeVOMS:
    """A ``generate-ac`` endpoint over mutual TLS (proxies accepted), on 127.0.0.1.

    ``answer`` decides each response; :attr:`requests` records each query and
    the client certificate's subject, so a test can check what was asked and
    who asked. Use as a context manager.
    """

    def __init__(self, grid: Grid, answer: Answer) -> None:
        """Bind, wrap in TLS that requires a client certificate, and start serving."""
        self.grid, self.answer = grid, answer
        self.requests: list[tuple[str, dict[str, list[str]], dict[str, Any]]] = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(grid.root / "host.pem"))
        context.load_verify_locations(cadata=pem(grid.ca).decode())
        context.verify_mode = ssl.CERT_REQUIRED
        context.verify_flags |= ssl.VERIFY_ALLOW_PROXY_CERTS
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # the stdlib's name
                parts = urlsplit(self.path)
                query = parse_qs(parts.query)
                connection = self.connection
                assert isinstance(connection, ssl.SSLSocket)
                # Mutual TLS: the handshake has already required a certificate.
                peer = connection.getpeercert() or {}
                fake.requests.append((parts.path, query, peer))
                status, body = fake.answer(query)
                self.send_response(status)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        class Server(ThreadingHTTPServer):
            def handle_error(self, request: object, client_address: object) -> None:
                pass  # a client that hung up mid-answer is what some tests do

        self.httpd = Server(("127.0.0.1", 0), Handler)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def server(self, alias: str = "atlas", vo: str = "atlas") -> VOMSServer:
        """This endpoint as a ``vomses`` entry."""
        return VOMSServer(alias, "127.0.0.1", self.port, "/DC=org/DC=example/CN=voms", vo)

    def __enter__(self) -> FakeVOMS:
        """The running server."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Stop serving and close the socket."""
        self.httpd.shutdown()
        self.httpd.server_close()
