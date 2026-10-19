"""VOMS test fixtures: attribute certificates, ``vomsdir`` trust files, and a fake VOMS server.

A VOMS attribute certificate (AC) is an RFC 5755 ``AttributeCertificate``
whose ``attributes`` carry the user's FQANs under a ``policyAuthority`` of
``<vo>://<host>:<port>``, with VOMS's own extensions: the signing server's
certificate chain (``...8005.100.100.10``), optional "generic attributes"
(``...100.100.11``), ``noRevAvail``, and optionally ``targetInformation``.
It travels inside a proxy certificate as the ``...100.100.5`` extension.
This module mints all of that for tests, and serves it the way a VOMS
server's REST endpoint does::

    >>> pki = create_pki(tmp_path)
    >>> voms = pki.host_signer                         # any certificate + key will do
    >>> ac = make_ac(pki.user_signer.der, voms.der, voms.key, ACSpec(fqans=("/atlas",)))
    >>> write_lsc(tmp_path / "vomsdir", "atlas", "voms.example", voms.chain)
    >>> proxy = voms_proxy(pki, [ac])                  # a proxy file carrying the AC

Where to start: :class:`ACSpec` lists every knob of :func:`make_ac`; the
defaults make an AC that :func:`xrdsec.voms.validate_voms` accepts,
and each field exists because some test needs to break exactly that part
(a wrong holder serial, a foreign issuer name, an unknown critical
extension, a signature algorithm that does not match the key...). The
builders are deliberately DER-level - ``cryptography`` has no attribute
certificate support, and a well-formed-only builder could not make the
malformed ACs the decoder's tests need.

:class:`FakeVOMSServer` (on :class:`~xrdsec.testing.https.FakeHTTPSServer`)
answers ``GET /generate-ac?fqans=<fqan>,<fqan>&lifetime=<seconds>`` with
``<voms><ac>base64</ac></voms>`` or ``<voms><error><code>..</code>
<message>..</message></error></voms>``, minting a real AC for the client
certificate that called; it is standalone, for the VOMS client code to be
tested against.

Stability: public test API, versioned with the package.
This consolidates the AC builders that xrdclient's, xgfalclient's and
xrdarc's suites each used to carry.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from ..der import (
    bit_string,
    generalized_time,
    integer,
    null,
    octet_string,
    oid,
    sequence,
    set_of,
    tlv,
)
from ..voms import VOMS_AC_OID, VOMS_FQAN_OID
from ..x509 import certificate_data, pem_encode
from .https import FakeHTTPSServer, Fault, Request, Response
from .pki import BasePKI, Signer, key_pem, proxy_certificate, test_key

__all__ = [
    "VOMS_ATTRIBUTES_OID",
    "VOMS_CERTS_OID",
    "ACSpec",
    "Attribute",
    "FakeVOMSServer",
    "SigningKey",
    "ac_extension",
    "ac_sequence",
    "lsc_text",
    "make_ac",
    "signature_algorithm",
    "voms_error",
    "voms_proxy",
    "voms_reply",
    "vomses_line",
    "write_lsc",
]

#: The AC extension embedding the VOMS server's signing certificate chain.
VOMS_CERTS_OID = "1.3.6.1.4.1.8005.100.100.10"
#: The AC extension carrying VOMS "generic attributes".
VOMS_ATTRIBUTES_OID = "1.3.6.1.4.1.8005.100.100.11"
_NO_REV_AVAIL_OID = "2.5.29.56"  # RFC 5755 section 4.3.6
_TARGETS_OID = "2.5.29.55"  # targetInformation, RFC 5755 section 4.3.2

#: What can sign an AC here: the algorithms VOMS servers (and BriX) use.
SigningKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey

# ``AlgorithmIdentifier`` OIDs by (key family, digest).
_RSA_OIDS = {
    "sha1": "1.2.840.113549.1.1.5",
    "sha256": "1.2.840.113549.1.1.11",
    "sha384": "1.2.840.113549.1.1.12",
    "sha512": "1.2.840.113549.1.1.13",
}
_ECDSA_OIDS = {
    "sha256": "1.2.840.10045.4.3.2",
    "sha384": "1.2.840.10045.4.3.3",
    "sha512": "1.2.840.10045.4.3.4",
}
_ED25519_OID = "1.3.101.112"
_PSS_OID = "1.2.840.113549.1.1.10"
_MGF1_OID = "1.2.840.113549.1.1.8"
_DIGEST_OIDS = {
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}
_HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


@dataclass(frozen=True, slots=True)
class Attribute:
    """One VOMS generic attribute: ``name = value``, scoped by ``qualifier`` (usually the VO)."""

    name: str
    value: str
    qualifier: str = ""


@dataclass(frozen=True, slots=True)
class ACSpec:
    """Everything about an AC that :func:`make_ac` can vary. The defaults make a valid one.

    ``fqans=None`` leaves the AC with no attributes at all (an empty
    ``SEQUENCE``), which is malformed; ``()`` writes the FQAN attribute
    with no values. Absolute ``not_before``/``not_after`` win over the
    default window (five minutes ago to ``lifetime`` from now). Every
    override field defaulting to ``None`` means "derive it": ``holder_serial``
    and ``holder_issuer`` from the holder certificate, ``issuer_name`` from
    the VOMS certificate, ``embedded`` (the chain in the VOMS-certs
    extension) as just the VOMS certificate, the two ``AlgorithmIdentifier``
    s from the key and ``digest`` (or ``pss``), and the signature from the
    key - ``sign`` replaces it with any function of the TBS bytes.
    ``extensions`` are extra DER ``Extension`` s, appended in order.
    """

    vo: str = "atlas"
    #: ``host:port`` of the VOMS server, the policy authority's second half.
    uri: str = "voms.example:15000"
    fqans: tuple[str, ...] | None = ("/atlas/Role=production/Capability=NULL",)
    attributes: tuple[Attribute, ...] = ()
    #: Host names the AC is restricted to (RFC 5755 ``targetInformation``, critical).
    targets: tuple[str, ...] = ()
    lifetime: float = 3600.0
    not_before: float | None = None
    not_after: float | None = None
    version: int = 1
    serial: int = 55
    holder_serial: int | None = None
    holder_issuer: bytes | None = None
    issuer_name: bytes | None = None
    embedded: tuple[bytes, ...] | None = None
    extensions: tuple[bytes, ...] = ()
    digest: str = "sha256"
    #: Sign RSA with RSASSA-PSS (MGF1, salt = digest length) instead of PKCS#1 v1.5.
    pss: bool = False
    algorithm: bytes | None = None
    outer_algorithm: bytes | None = None
    sign: Callable[[bytes], bytes] | None = None


#: A holder: a certificate (object or DER), or its issuer's DER name and serial directly.
Holder = x509.Certificate | bytes | tuple[bytes, int]


def _der(certificate: x509.Certificate | bytes) -> bytes:
    """``certificate`` as DER."""
    if isinstance(certificate, bytes):
        return certificate
    return certificate.public_bytes(serialization.Encoding.DER)


def _holder(holder: Holder, spec: ACSpec) -> bytes:
    """The ``Holder`` field: ``baseCertificateID [0] { issuer GeneralNames, serial }``.

    VOMS names the holder by its certificate's *issuer* and serial (RFC
    5755 section 4.2.2), which is why a proxy carries the AC of the user
    certificate it was made from, not of itself.
    """
    if isinstance(holder, tuple):
        issuer, serial = holder
    else:
        data = certificate_data(_der(holder))
        issuer, serial = data.issuer.encoded(), data.serial
    issuer = spec.holder_issuer if spec.holder_issuer is not None else issuer
    serial = spec.holder_serial if spec.holder_serial is not None else serial
    return sequence(tlv(0xA0, _general_names(issuer) + integer(serial)))


def _general_names(name_der: bytes) -> bytes:
    """``GeneralNames`` holding one ``directoryName [4]``."""
    return sequence(tlv(0xA4, name_der))


def _extension(extension_oid: str, value: bytes, *, critical: bool = False) -> bytes:
    """One DER ``Extension``; the criticality flag only when set."""
    flag = tlv(0x01, b"\xff") if critical else b""
    return sequence(oid(extension_oid), flag, octet_string(value))


def signature_algorithm(key: SigningKey, digest: str = "sha256", *, pss: bool = False) -> bytes:
    """The ``AlgorithmIdentifier`` an AC signed by ``key`` over ``digest`` carries.

    RSA: ``sha*WithRSAEncryption`` with a ``NULL`` parameter (RFC 4055), or
    RSASSA-PSS with explicit parameters; EC: ``ecdsa-with-SHA*`` with no
    parameters (RFC 5758); Ed25519: ``id-Ed25519``, no parameters, no digest
    (RFC 8410).
    """
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return sequence(oid(_ED25519_OID))
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return sequence(oid(_ECDSA_OIDS[digest]))
    if pss:
        hashed = sequence(oid(_DIGEST_OIDS[digest]), null())
        size = _HASHES[digest]().digest_size
        parameters = sequence(
            tlv(0xA0, hashed), tlv(0xA1, sequence(oid(_MGF1_OID), hashed)), tlv(0xA2, integer(size))
        )
        return sequence(oid(_PSS_OID), parameters)
    return sequence(oid(_RSA_OIDS[digest]), null())


def _signature(key: SigningKey, tbs: bytes, spec: ACSpec) -> bytes:
    """``key``'s signature over ``tbs`` in the algorithm :func:`signature_algorithm` names."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(tbs)
    algorithm = _HASHES[spec.digest]()
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(tbs, ec.ECDSA(algorithm))
    if spec.pss:
        scheme = padding.PSS(padding.MGF1(algorithm), algorithm.digest_size)
        return key.sign(tbs, scheme, algorithm)
    return key.sign(tbs, padding.PKCS1v15(), algorithm)


def _fqan_attributes(spec: ACSpec) -> bytes:
    """The ``attributes`` field: the FQAN attribute (``...100.100.4``), or nothing at all.

    ``IetfAttrSyntax { policyAuthority [0] GeneralNames, values SEQUENCE OF
    OCTET STRING }`` (RFC 5755 section 4.4.5), the authority being the
    ``uniformResourceIdentifier [6]`` ``<vo>://<uri>``.
    """
    if spec.fqans is None:
        return sequence()
    values = sequence(*(octet_string(fqan.encode()) for fqan in spec.fqans))
    authority = tlv(0xA0, tlv(0x86, f"{spec.vo}://{spec.uri}".encode()))
    return sequence(sequence(oid(VOMS_FQAN_OID), set_of(sequence(authority, values))))


def _extensions(voms_der: bytes, issuer: bytes, spec: ACSpec) -> bytes:
    """The AC's extensions: VOMS certs, ``noRevAvail``, then attributes, targets and extras.

    Generic attributes are VOMS's ``ACFullAttributes``: ``SEQUENCE { SEQUENCE
    OF SEQUENCE { grantor GeneralNames, SEQUENCE OF SEQUENCE { name,
    qualifier, value } } }`` - the wire order puts the qualifier second,
    unlike the name/value/qualifier the tools print.
    """
    chain = spec.embedded if spec.embedded is not None else (voms_der,)
    found = [
        _extension(VOMS_CERTS_OID, sequence(sequence(*chain))),
        _extension(_NO_REV_AVAIL_OID, null()),
    ]
    if spec.attributes:
        triples = (
            sequence(*(octet_string(part.encode()) for part in (a.name, a.qualifier, a.value)))
            for a in spec.attributes
        )
        provider = sequence(_general_names(issuer), sequence(*triples))
        # ``ACFullAttributes { providers SEQUENCE OF AttributeHolder }``: two layers.
        found.append(_extension(VOMS_ATTRIBUTES_OID, sequence(sequence(provider))))
    if spec.targets:
        names = (tlv(0xA0, tlv(0x82, host.encode("ascii"))) for host in spec.targets)
        found.append(_extension(_TARGETS_OID, sequence(sequence(*names)), critical=True))
    return sequence(*found, *spec.extensions)


def make_ac(
    holder: Holder,
    voms_cert: x509.Certificate | bytes,
    voms_key: SigningKey,
    spec: ACSpec | None = None,
) -> bytes:
    """A DER VOMS attribute certificate for ``holder``, issued and signed by the VOMS server.

    ``holder`` is the user's certificate (a ``cryptography`` object or DER)
    or ``(issuer name DER, serial)``; ``voms_cert``/``voms_key`` are the VOMS
    server's credential. ``spec`` (default: :class:`ACSpec` ``()``) says
    what goes in. The result is what ``voms-proxy-init`` embeds: pass a list
    of them to :func:`ac_extension` or :func:`voms_proxy`.
    """
    spec = spec or ACSpec()
    voms_der = _der(voms_cert)
    issuer = spec.issuer_name or certificate_data(voms_der).subject.encoded()
    now = time.time()
    start = spec.not_before if spec.not_before is not None else now - 300
    end = spec.not_after if spec.not_after is not None else now + spec.lifetime
    algorithm = spec.algorithm or signature_algorithm(voms_key, spec.digest, pss=spec.pss)
    tbs = sequence(
        integer(spec.version),
        _holder(holder, spec),
        tlv(0xA0, _general_names(issuer)),  # v2Form [0] { issuerName }
        algorithm,
        integer(spec.serial),
        sequence(generalized_time(start), generalized_time(end)),
        _fqan_attributes(spec),
        _extensions(voms_der, issuer, spec),
    )
    signature = spec.sign(tbs) if spec.sign is not None else _signature(voms_key, tbs, spec)
    return sequence(tbs, spec.outer_algorithm or algorithm, bit_string(signature))


def ac_sequence(acs: Sequence[bytes]) -> bytes:
    """``SEQUENCE { SEQUENCE OF AttributeCertificate }``: the proxy extension's value."""
    return sequence(sequence(*acs))


def ac_extension(acs: Sequence[bytes]) -> bytes:
    """The non-critical ``...8005.100.100.5`` proxy extension carrying ``acs``."""
    return _extension(VOMS_AC_OID, ac_sequence(acs))


def voms_proxy(
    pki: BasePKI[Any, Any, Any],
    acs: Sequence[bytes],
    *,
    path: Path | None = None,
    lifetime: float = 12 * 3600,
) -> Path:
    """Write a proxy of ``pki``'s user carrying ``acs``, as ``voms-proxy-init`` would.

    An RFC 3820 proxy (key slot 3) with the AC extension, followed by the
    user certificate; ``path`` defaults to ``x509up_voms`` beside the PKI.
    """
    key, user = test_key(3), pki.user_signer
    der = proxy_certificate(key, user, lifetime=lifetime, extensions=(ac_extension(acs),))
    target = path or pki.directory / "x509up_voms"
    target.write_bytes(
        pem_encode("CERTIFICATE", der) + key_pem(key) + pem_encode("CERTIFICATE", user.der)
    )
    target.chmod(0o600)
    return target


# ---------------------------------------------------------------------------
# vomsdir and vomses
# ---------------------------------------------------------------------------


def lsc_text(chain: Sequence[bytes]) -> str:
    """The ``.lsc`` file naming a VOMS server by ``chain`` (DER, server certificate first).

    One line per certificate - the server's subject, then each issuer's -
    in OpenSSL's slash form, as ``voms-proxy-init`` and BriX read it: the
    server certificate's subject, then its issuer, then the issuer's
    issuer for every intermediate given.
    """
    names = [str(certificate_data(chain[0]).subject)]
    names.extend(str(certificate_data(link).issuer) for link in chain[: max(len(chain) - 1, 1)])
    return "\n".join(names) + "\n"


def write_lsc(vomsdir: Path, vo: str, host: str, chain: Sequence[bytes]) -> Path:
    """Write ``<vomsdir>/<vo>/<host>.lsc`` for ``chain`` (see :func:`lsc_text`); its path."""
    directory = Path(vomsdir) / vo
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{host}.lsc"
    target.write_text(lsc_text(chain))
    return target


def vomses_line(vo: str, host: str, port: int, dn: str, alias: str | None = None) -> str:
    """One ``vomses`` line: ``"alias" "host" "port" "dn" "vo"``, newline-terminated."""
    return f'"{alias or vo}" "{host}" "{port}" "{dn}" "{vo}"\n'


# ---------------------------------------------------------------------------
# The VOMS REST server
# ---------------------------------------------------------------------------


def voms_reply(ac: bytes, warning: str = "") -> bytes:
    """A successful ``/generate-ac`` body: the AC base64-encoded in ``<voms><ac>``."""
    encoded = base64.encodebytes(ac).decode("ascii")
    extra = f"<warning>{escape(warning)}</warning>" if warning else ""
    return f"<voms><ac>\n{encoded}</ac>{extra}</voms>".encode()


def voms_error(code: str, message: str = "") -> bytes:
    """A refusal body: ``<voms><error><code>..</code><message>..</message></error></voms>``."""
    text = f"<message>{escape(message)}</message>" if message else ""
    return f"<voms><error><code>{escape(code)}</code>{text}</error></voms>".encode()


def _refusal(status: int, code: str, message: str) -> Response:
    """A VOMS error answer, as XML with the given HTTP status."""
    return Response(status, voms_error(code, message), {"Content-Type": "application/xml"})


class FakeVOMSServer(FakeHTTPSServer):
    """A VOMS server's REST interface: ``GET /generate-ac``, minting real ACs.

    ``voms`` is the server's credential (certificate chain and key; a PKI's
    ``host_signer`` will do), ``tls`` its server context - which must ask for
    a client certificate, since the client's certificate *is* the request.
    ``members`` maps a user's identity (end-entity subject, slash form) to
    the FQANs they hold; ``None`` makes everyone a member holding whatever
    they ask for. An answer, as VOMS gives it:

    * no client certificate, or not a member: ``403 NoSuchUser``;
    * an FQAN the member does not hold: ``403 NoSuchAttribute``;
    * a ``lifetime`` that is not a number: ``400 BadRequest``;
    * otherwise ``200`` with the AC - FQANs in the order asked (all of the
      member's when none are asked), the lifetime capped at
      :attr:`max_lifetime` with a ``<warning>`` saying so.

    The holder is :attr:`holder` if set, else the first non-proxy
    certificate of the client's chain - on Python before 3.13, which shows
    a server only the leaf, that is the proxy itself, so set :attr:`holder`
    when the AC must name the user certificate. Every AC minted is in
    :attr:`issued`. Canned refusals go through :meth:`refuse` (or any
    :class:`~xrdsec.testing.https.Fault`).
    """

    def __init__(
        self,
        voms: Signer,
        tls: Any = None,
        *,
        vo: str = "atlas",
        members: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        """Bind the port and install the ``/generate-ac`` route; :meth:`start` serves."""
        super().__init__(tls=tls, name="xrdsec-fake-voms")
        self.voms = voms
        self.vo = vo
        self.members = None if members is None else {k: tuple(v) for k, v in members.items()}
        #: The longest AC this server issues, in seconds (VOMS's default cap is 24 hours).
        self.max_lifetime = 86400
        #: The lifetime given when the request names none (VOMS's default, 12 hours).
        self.default_lifetime = 43200
        #: The certificate to name as holder; ``None``: the client's end-entity certificate.
        self.holder: Holder | None = None
        #: Every AC issued, in order, as DER.
        self.issued: list[bytes] = []
        self.route("GET", r"/generate-ac", self._generate)

    @property
    def uri(self) -> str:
        """``host:port``: the policy authority the ACs name after ``<vo>://``."""
        host, port = self.address
        return f"{host}:{port}"

    def refuse(self, code: str, message: str = "", status: int = 403) -> Fault:
        """Answer the next ``/generate-ac`` with this VOMS error instead of an AC."""
        xml = {"Content-Type": "application/xml"}
        body = voms_error(code, message)
        return self.add_fault(Fault("GET", r"^/generate-ac", status, body=body, headers=xml))

    def _generate(self, request: Request) -> Response:
        """``GET /generate-ac``: check who is asking for what, then mint."""
        identity = request.peer.identity if request.peer is not None else ""
        wanted = tuple(f for f in ",".join(request.query.get("fqans", [])).split(",") if f)
        granted = self._authorise(identity, wanted)
        if isinstance(granted, Response):
            return granted
        try:
            asked = int(request.param("lifetime") or self.default_lifetime)
        except ValueError:
            return _refusal(400, "BadRequest", "lifetime must be a number of seconds")
        lifetime = min(asked, self.max_lifetime)
        ac = self._mint(request, granted, lifetime)
        warning = f"lifetime shortened to {lifetime} seconds" if lifetime < asked else ""
        return Response(200, voms_reply(ac, warning), {"Content-Type": "application/xml"})

    def _authorise(self, identity: str, wanted: tuple[str, ...]) -> tuple[str, ...] | Response:
        """The FQANs to issue to ``identity`` for the request ``wanted``, or the refusal.

        A member list of ``None`` grants whatever is asked (``/<vo>`` when
        nothing is); otherwise only members, and only FQANs they hold.
        """
        held = self._held(identity)
        if held is None:
            who = identity or "anonymous"
            return _refusal(403, "NoSuchUser", f"{who} is not a member of {self.vo}")
        missing = [fqan for fqan in wanted if self.members is not None and fqan not in held]
        if missing:
            return _refusal(403, "NoSuchAttribute", f"{identity} does not hold {missing[0]}")
        return wanted or held or (f"/{self.vo}",)

    def _held(self, identity: str) -> tuple[str, ...] | None:
        """What ``identity`` holds: ``None`` if not a member, ``()`` with no member list."""
        if not identity:
            return None
        return () if self.members is None else self.members.get(identity)

    def _mint(self, request: Request, fqans: tuple[str, ...], lifetime: int) -> bytes:
        """Issue the AC for the caller and remember it."""
        holder = self.holder if self.holder is not None else self._end_entity(request)
        spec = ACSpec(vo=self.vo, uri=self.uri, fqans=fqans, lifetime=float(lifetime))
        ac = make_ac(holder, self.voms.der, self.voms.key, spec)
        with self._lock:
            self.issued.append(ac)
        return ac

    @staticmethod
    def _end_entity(request: Request) -> bytes:
        """The first non-proxy certificate of the caller's chain (else its leaf)."""
        assert request.peer is not None  # _authorise refused anonymous callers
        for link in request.peer.chain:
            if not certificate_data(link).is_proxy:
                return link
        return request.peer.certificate
