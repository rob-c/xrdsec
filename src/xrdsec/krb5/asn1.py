"""The RFC 4120 messages this client sends and reads, in DER.

Kerberos is specified in ASN.1 with explicit context tags on every field, so
each message is a SEQUENCE of ``[n]`` wrappers around universal types, and
the top-level messages are additionally wrapped in an ``[APPLICATION n]``
tag. The writer below is a handful of functions that compose; the reader
leans on :mod:`xrdsec.der` and a :class:`Fields` view that turns a
SEQUENCE into "field number to value" and refuses anything out of order.

Only the messages an AP-REQ login needs are here: Ticket (carried opaquely
except for its outer fields), Authenticator, AP-REQ, the TGS-REQ with its
PA-TGS-REQ, the KDC reply and its encrypted part, KRB-ERROR, and KRB-CRED
for ticket forwarding. The comments give each structure's ASN.1 so the code
can be checked against RFC 4120 section 5 line by line.

Where to start reading: :func:`fields` is the whole writing idea (an
explicitly tagged SEQUENCE with OPTIONAL members simply left out), and
:class:`Fields` is the whole reading idea. Everything else is one RFC
structure each, named after it.

What a maintainer must not break:

* **Byte-for-byte DER.** The KDC verifies a keyed checksum over the
  KDC-REQ-BODY *as sent*, and MIT-captured messages in
  ``tests/test_krb5_mit.py`` are re-encoded here and compared for
  equality. Minimal-length INTEGERs, definite lengths, ascending field
  numbers and the never-trimmed 32-bit flags are all DER rules those tests
  pin.
* **Strict reading.** A reply is attacker-supplied until its encrypted part
  has been opened and checked (:mod:`.tgs`). The reader refuses trailing
  bytes, out-of-order fields and wrong universal tags rather than guessing,
  so a malformed message fails as :class:`~xrdsec.der.DERError`
  and never as an ``IndexError`` deep in the caller.
* **Key material stays out of reprs** (:class:`Key`).

Only short-form tags exist in Kerberos (every context and application
number used is below 31), which is why a tag is one byte throughout.
"""

from __future__ import annotations

import calendar
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from ..der import (
    TAG_GENERALIZED_TIME,
    TAG_OCTET_STRING,
    TAG_SEQUENCE,
    DERError,
    Element,
    parse,
    read_integer,
)
from .model import Principal, Ticket

__all__ = [
    "EncKdcReplyPart",
    "EncryptedData",
    "Fields",
    "KdcReply",
    "Key",
    "KrbError",
    "TicketInfo",
    "decode_enc_kdc_rep_part",
    "decode_kdc_rep",
    "decode_krb_error",
    "decode_ticket",
    "encode_ap_req",
    "encode_authenticator",
    "encode_cred_info",
    "encode_enc_krb_cred_part",
    "encode_krb_cred",
    "encode_req_body",
    "encode_tgs_req",
    "principal_name",
    "read_principal_name",
]

#: Universal tags :mod:`xrdsec.der` does not already name.
#: KerberosString is a GeneralString (27) by RFC 4120 section 5.2.1, even
#: though in practice it carries UTF-8 - IA5 would be the "right" type.
TAG_BIT_STRING = 0x03
TAG_INTEGER = 0x02
TAG_GENERAL_STRING = 0x1B

#: The application tags (RFC 4120 section 5.10), as their constructed tag byte:
#: class APPLICATION (0x40) | constructed (0x20) | the tag number, so for
#: example Ticket is ``[APPLICATION 1]`` = 0x61 and KRB-ERROR ``[30]`` = 0x7E.
APP_TICKET = 0x61
APP_AUTHENTICATOR = 0x62
APP_AS_REP = 0x6B
APP_TGS_REQ = 0x6C
APP_TGS_REP = 0x6D
APP_AP_REQ = 0x6E
APP_KRB_CRED = 0x76
APP_ENC_AS_REP_PART = 0x79
APP_ENC_TGS_REP_PART = 0x7A
APP_ENC_KRB_CRED_PART = 0x7D
APP_KRB_ERROR = 0x7E

#: Message types (``msg-type``), which repeat the application tag number.
#: The KDC checks the field against the tag, so the two must agree.
KRB_TGS_REQ = 12
KRB_TGS_REP = 13
KRB_AP_REQ = 14
KRB_CRED = 22

#: Protocol version: ``pvno``, ``tkt-vno`` and ``authenticator-vno`` are all 5.
PVNO = 5


# -- writing -----------------------------------------------------------------


def _length(size: int) -> bytes:
    """A DER definite length (X.690 section 8.1.3).

    Short form - one byte - below 128; above it, ``0x80 | n`` followed by
    the ``n`` big-endian bytes of the length, with no leading zero byte,
    because DER allows exactly one encoding of each length.
    """
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    """One DER element: tag, definite length, content."""
    return bytes([tag]) + _length(len(content)) + content


def integer(value: int) -> bytes:
    """A DER INTEGER, in the fewest two's-complement bytes.

    The ``value < 0`` term makes -128 one byte (``0x80``) rather than two;
    for non-negative values the ``+ 1`` leaves room for the sign bit, so
    128 is ``00 80`` as DER requires. Nonces, enctypes and microseconds all
    pass through here, and the KDC rejects a non-minimal encoding.
    """
    size = (value + (value < 0)).bit_length() // 8 + 1
    return tlv(TAG_INTEGER, value.to_bytes(size, "big", signed=True))


def general_string(text: str) -> bytes:
    """A KerberosString: GeneralString restricted, in practice, to UTF-8."""
    return tlv(TAG_GENERAL_STRING, text.encode("utf-8"))


def octets(data: bytes) -> bytes:
    """An OCTET STRING: ciphertext, key values and checksums travel as these."""
    return tlv(TAG_OCTET_STRING, data)


def kerberos_time(epoch: float) -> bytes:
    """KerberosTime: GeneralizedTime, whole seconds, always UTC (``Z``).

    RFC 4120 section 5.2.3 forbids fractional seconds - the microseconds an
    authenticator needs travel separately as ``cusec`` - so the epoch is
    truncated, matching what :func:`read_time` gives back.
    """
    text = time.strftime("%Y%m%d%H%M%SZ", time.gmtime(int(epoch)))
    return tlv(TAG_GENERALIZED_TIME, text.encode("ascii"))


def kerberos_flags(value: int) -> bytes:
    """KerberosFlags: a 32-bit BIT STRING, never trimmed (RFC 4120 section 5.2.8).

    DER would normally drop trailing zero bits, but RFC 4120 requires all 32
    to be sent, so the content is always the "0 unused bits" byte followed
    by four bytes. Bit 0 (the MSB of ``value``) is the first flag.
    """
    return tlv(TAG_BIT_STRING, b"\x00" + value.to_bytes(4, "big"))


def sequence(*parts: bytes) -> bytes:
    """A SEQUENCE of already-encoded members, in the order given."""
    return tlv(TAG_SEQUENCE, b"".join(parts))


def sequence_of(items: Iterable[bytes]) -> bytes:
    """A SEQUENCE OF: the same wire form as :func:`sequence`, fed an iterable."""
    return tlv(TAG_SEQUENCE, b"".join(items))


def fields(*pairs: tuple[int, bytes | None]) -> bytes:
    """A SEQUENCE of explicitly tagged fields; ``None`` leaves an OPTIONAL out.

    Each ``(n, value)`` becomes ``[n] EXPLICIT`` - context class,
    constructed, so ``0xA0 | n`` - wrapped around the already-encoded value.
    Callers list fields in ascending ``n``, which is what DER (and the
    reader's :class:`Fields`) demand.
    """
    return sequence(*(tlv(0xA0 | number, value) for number, value in pairs if value is not None))


def principal_name(principal: Principal) -> bytes:
    """PrincipalName ::= SEQUENCE { name-type [0] Int32,
    name-string [1] SEQUENCE OF KerberosString }"""
    names = sequence_of(general_string(part) for part in principal.components)
    return fields((0, integer(principal.name_type)), (1, names))


@dataclass(frozen=True, slots=True)
class Key:
    """EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }

    The value is key material: it is left out of ``repr`` so that a debug
    print of anything holding one cannot leak it.
    """

    enctype: int
    value: bytes = field(repr=False)

    def encode(self) -> bytes:
        """The EncryptionKey's DER, as KrbCredInfo carries it to the server."""
        return fields((0, integer(self.enctype)), (1, octets(self.value)))


@dataclass(frozen=True, slots=True)
class EncryptedData:
    """EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL,
    cipher [2] OCTET STRING }

    ``cipher`` is already sealed by :mod:`.rfc3961` (the
    confounder, ciphertext and HMAC all inside it). ``kvno`` is only
    meaningful for tickets sealed under a long-term key; authenticators and
    KRB-CRED parts sealed under session keys leave it out.
    """

    etype: int
    cipher: bytes
    kvno: int | None = None

    def encode(self) -> bytes:
        """The EncryptedData's DER, with ``kvno`` omitted when it is ``None``."""
        kvno = None if self.kvno is None else integer(self.kvno)
        return fields((0, integer(self.etype)), (1, kvno), (2, octets(self.cipher)))


def encode_authenticator(
    client: Principal,
    ctime: int,
    cusec: int,
    *,
    checksum: tuple[int, bytes] | None = None,
    subkey: Key | None = None,
) -> bytes:
    """Authenticator ::= [APPLICATION 2] SEQUENCE { ... }

    ``authenticator-vno [0]``, ``crealm [1]``, ``cname [2]``, ``cksum [3]``
    OPTIONAL, ``cusec [4]``, ``ctime [5]``, ``subkey [6]`` OPTIONAL,
    ``seq-number [7]`` OPTIONAL; authorization-data [8] is never sent.

    ``ctime``/``cusec`` are the client's clock *already shifted* to the
    KDC's (see :attr:`~.model.Ticket.kdc_offset`): the receiver's replay
    cache and skew check key on them. ``checksum`` is ``(cksumtype, value)``
    and is only present in the TGS-REQ's authenticator, where it binds the
    request body. ``subkey`` exists for re-encoding MIT's own authenticators
    in the tests; this client never negotiates one. ``seq-number`` is not
    offered at all: it only matters to KRB-SAFE/KRB-PRIV sessions, which an
    xrootd login never opens, and leaving it out is what MIT does for the
    TGS-REQ and for ``XrdSecProtocolkrb5``'s AP-REQ alike.
    """
    cksum = None
    if checksum is not None:
        # Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }
        cksum = fields((0, integer(checksum[0])), (1, octets(checksum[1])))
    body = fields(
        (0, integer(PVNO)),
        (1, general_string(client.realm)),
        (2, principal_name(client)),
        (3, cksum),
        (4, integer(cusec)),
        (5, kerberos_time(ctime)),
        (6, None if subkey is None else subkey.encode()),
    )
    return tlv(APP_AUTHENTICATOR, body)


def encode_ap_req(ticket: bytes, authenticator: EncryptedData, options: int = 0) -> bytes:
    """AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno [0], msg-type [1], ap-options [2],
    ticket [3], authenticator [4] }

    ``ticket`` is the Ticket's DER exactly as the KDC issued it: it is
    sealed under the service's key, so it is spliced in verbatim rather than
    re-encoded - one changed byte and the service cannot open it.
    ``options`` is the ap-options flag word (``use-session-key`` for xrootd,
    zero inside a PA-TGS-REQ).
    """
    body = fields(
        (0, integer(PVNO)),
        (1, integer(KRB_AP_REQ)),
        (2, kerberos_flags(options)),
        (3, ticket),
        (4, authenticator.encode()),
    )
    return tlv(APP_AP_REQ, body)


def encode_req_body(
    *,
    options: int,
    server: Principal,
    till: int,
    nonce: int,
    etypes: Sequence[int],
) -> bytes:
    """KDC-REQ-BODY ::= SEQUENCE { kdc-options [0], cname [1] OPT, realm [2], sname [3] OPT, ... }

    For a TGS-REQ the client's name is in the ticket, so ``cname`` is left
    out; ``from``, ``rtime``, addresses, authorization data and additional
    tickets are never needed here either. ``realm [2]`` is, by RFC 4120
    section 5.4.1, "the realm part of the server's principal identifier",
    so it is taken from ``server`` rather than passed separately - for the
    same-realm requests :func:`~.tgs.request_ticket` allows it is also the
    TGT's realm.

    ``till [5]`` is the end time asked for (the TGT's own, so the KDC caps
    nothing it would not cap anyway), ``nonce [7]`` is what ties the reply
    to this request, and ``etype [8]`` lists the session-key enctypes we can
    use, most preferred first. These bytes are what the PA-TGS-REQ checksum
    covers, so they must be encoded exactly once and sent as encoded.
    """
    return fields(
        (0, kerberos_flags(options)),
        (2, general_string(server.realm)),
        (3, principal_name(server)),
        (5, kerberos_time(till)),
        (7, integer(nonce)),
        (8, sequence_of(integer(etype) for etype in etypes)),
    )


def encode_tgs_req(padata: Sequence[tuple[int, bytes]], body: bytes) -> bytes:
    """TGS-REQ ::= [APPLICATION 12] KDC-REQ

    ``KDC-REQ ::= SEQUENCE { pvno [1], msg-type [2], padata [3] SEQUENCE OF PA-DATA OPT,
    req-body [4] }``
    and ``PA-DATA ::= SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING }``.

    The field numbers start at 1, not 0, in KDC-REQ - a quirk of RFC 4120
    kept from RFC 1510. ``padata`` is ``(type, value)`` pairs; in practice the
    single PA-TGS-REQ holding the AP-REQ. ``body`` is the exact bytes the
    checksum inside that AP-REQ was computed over.
    """
    pas = sequence_of(fields((1, integer(kind)), (2, octets(value))) for kind, value in padata)
    return tlv(
        APP_TGS_REQ, fields((1, integer(PVNO)), (2, integer(KRB_TGS_REQ)), (3, pas), (4, body))
    )


def encode_cred_info(ticket: Ticket) -> bytes:
    """KrbCredInfo ::= SEQUENCE { key [0], prealm [1], pname [2], flags [3], authtime [4], ... }

    Every optional field MIT fills in is filled in: the session key, who the
    ticket is for and until when, so the receiver can write a usable cache.
    """
    return fields(
        (0, Key(ticket.enctype, ticket.key).encode()),
        (1, general_string(ticket.client.realm)),
        (2, principal_name(ticket.client)),
        (3, kerberos_flags(ticket.flags)),
        (4, kerberos_time(ticket.auth_time)),
        (5, kerberos_time(ticket.start_time)),
        (6, kerberos_time(ticket.end_time)),
        (7, kerberos_time(ticket.renew_till) if ticket.renew_till else None),
        (8, general_string(ticket.server.realm)),
        (9, principal_name(ticket.server)),
    )


def encode_enc_krb_cred_part(infos: Sequence[bytes], timestamp: int, usec: int) -> bytes:
    """EncKrbCredPart ::= [APPLICATION 29] SEQUENCE { ticket-info [0], nonce [1] OPT,
    timestamp [2] OPT, usec [3] OPT, ... }

    No addresses: tickets are forwarded addressless, as MIT does by default.
    No nonce either: RFC 4120 section 5.8.1 makes it a value the *recipient*
    chose beforehand, and the xrootd server never sends one.
    ``timestamp``/``usec`` let the server's replay cache recognise a resent
    message instead.
    """
    body = fields((0, sequence_of(infos)), (2, kerberos_time(timestamp)), (3, integer(usec)))
    return tlv(APP_ENC_KRB_CRED_PART, body)


def encode_krb_cred(tickets: Sequence[bytes], enc_part: EncryptedData) -> bytes:
    """KRB-CRED ::= [APPLICATION 22] SEQUENCE { pvno [0], msg-type [1],
    tickets [2] SEQUENCE OF Ticket, enc-part [3] }"""
    body = fields(
        (0, integer(PVNO)),
        (1, integer(KRB_CRED)),
        (2, sequence_of(tickets)),
        (3, enc_part.encode()),
    )
    return tlv(APP_KRB_CRED, body)


# -- reading -----------------------------------------------------------------


def _one(data: bytes, tag: int, what: str) -> Element:
    """Exactly one element with ``tag`` and nothing after it.

    Trailing bytes are refused, not ignored: a KDC reply is read before it
    has been authenticated, and accepting junk after a valid prefix is how
    parsers end up disagreeing about what a message said.
    """
    element, end = parse(data)
    if element.tag != tag:
        raise DERError(f"expected {what} (tag 0x{tag:02x}), got tag 0x{element.tag:02x}")
    if end != len(data):
        raise DERError(f"{len(data) - end} bytes of trailing data after {what}")
    return element


class Fields:
    """A SEQUENCE of ``[n]``-tagged fields, looked up by ``n``.

    Tags must be context-specific, constructed and strictly increasing, as
    DER requires; each field's single inner element is what lookups return.

    The view is built once, eagerly, so a malformed SEQUENCE fails at
    construction with ``what`` in the message ("KRB-ERROR has a field out of
    order") rather than at whichever lookup happens to touch the bad field.
    Lookups by number keep each decoder a readable transcription of its
    ASN.1 module: ``view.integer(6)`` is ``error-code [6]``.
    """

    __slots__ = ("_fields", "_what")

    def __init__(self, element: Element, what: str) -> None:
        """Index the ``[n]`` fields of ``element``; ``what`` names it in errors.

        Raises :class:`~xrdsec.der.DERError` if ``element`` is not
        a SEQUENCE, a member is not ``[n]`` constructed, the numbers do not
        strictly increase, or an ``[n]`` holds more than one element.
        """
        if element.tag != TAG_SEQUENCE:
            raise DERError(f"{what} is not a SEQUENCE (tag 0x{element.tag:02x})")
        self._what = what
        self._fields: dict[int, Element] = {}
        last = -1
        for child in element.children():
            # Low five bits are the tag number; the top three must be
            # context-specific (0x80) | constructed (0x20) for EXPLICIT [n].
            number = child.tag & 0x1F
            if child.tag & 0xE0 != 0xA0 or number <= last:
                raise DERError(f"{what} has a field out of order (tag 0x{child.tag:02x})")
            inner, end = parse(child.value)
            if end != len(child.value):
                raise DERError(f"{what} field [{number}] holds more than one value")
            self._fields[number] = inner
            last = number

    def get(self, number: int) -> Element:
        """The element in required field ``[number]``; absent is a DERError."""
        found = self._fields.get(number)
        if found is None:
            raise DERError(f"{self._what} lacks its required field [{number}]")
        return found

    def optional(self, number: int) -> Element | None:
        """The element in OPTIONAL field ``[number]``, or ``None``."""
        return self._fields.get(number)

    def integer(self, number: int) -> int:
        """Required field ``[number]`` as an INTEGER."""
        return read_integer(self.get(number))

    def string(self, number: int) -> str:
        """Required field ``[number]`` as a KerberosString."""
        return read_string(self.get(number))

    def octets(self, number: int) -> bytes:
        """Required field ``[number]`` as an OCTET STRING's bytes."""
        return read_octets(self.get(number))

    def time(self, number: int, default: int = 0) -> int:
        """Field ``[number]`` as epoch seconds, ``default`` when it is absent.

        Optional times (starttime, renew-till) default to 0 - the value MIT's
        ccache uses for "not set" - or to a caller-chosen fallback, as
        starttime falls back to authtime.
        """
        found = self.optional(number)
        return default if found is None else read_time(found)


def read_string(element: Element) -> str:
    """A KerberosString's text.

    Undecodable bytes are replaced rather than fatal: these strings are
    names and error texts shown to people, and a KDC with a Latin-1 realm
    description should still produce a readable error, not a crash.
    """
    if element.tag != TAG_GENERAL_STRING:
        raise DERError(f"expected GeneralString, got tag 0x{element.tag:02x}")
    return element.value.decode("utf-8", "replace")


def read_octets(element: Element) -> bytes:
    """An OCTET STRING's content, refusing any other universal type."""
    if element.tag != TAG_OCTET_STRING:
        raise DERError(f"expected OCTET STRING, got tag 0x{element.tag:02x}")
    return element.value


def read_time(element: Element) -> int:
    """KerberosTime as seconds since the epoch.

    Only the exact ``YYYYMMDDHHMMSSZ`` form RFC 4120 section 5.2.3 allows
    is accepted - no fractions, no offsets - and it is converted with
    :func:`calendar.timegm` because it is UTC (``time.mktime`` would apply
    the local zone).
    """
    text = element.value.decode("ascii", "replace")
    if element.tag != TAG_GENERALIZED_TIME or len(text) != 15 or not text.endswith("Z"):
        raise DERError(f"malformed KerberosTime {text!r}")
    try:
        return calendar.timegm(time.strptime(text, "%Y%m%d%H%M%SZ"))
    except ValueError as exc:
        raise DERError(f"malformed KerberosTime {text!r}") from exc


def read_flags(element: Element) -> int:
    """KerberosFlags as the 32-bit integer MIT stores (bit 0 is the MSB).

    Lenient on length where the writer is strict: a peer that trimmed
    trailing zero bits (as plain DER would) is padded back out, and bits
    past 32 are ignored. The first content byte is the unused-bit count,
    which is skipped.
    """
    if element.tag != TAG_BIT_STRING or len(element.value) < 1:
        raise DERError("malformed KerberosFlags")
    bits = element.value[1:5].ljust(4, b"\x00")
    return int.from_bytes(bits, "big")


def read_principal_name(element: Element, realm: str) -> Principal:
    """A PrincipalName, joined with ``realm``.

    The realm is a sibling field in every message (``crealm``, ``srealm``,
    ``realm``), not part of PrincipalName itself, so the caller supplies it.
    """
    view = Fields(element, "PrincipalName")
    names = view.get(1)
    if names.tag != TAG_SEQUENCE:
        raise DERError("PrincipalName name-string is not a SEQUENCE")
    return Principal(tuple(read_string(part) for part in names.children()), realm, view.integer(0))


def read_encrypted_data(element: Element) -> EncryptedData:
    """An EncryptedData, still sealed; :mod:`.tgs` decides which key opens it."""
    view = Fields(element, "EncryptedData")
    kvno = view.optional(1)
    return EncryptedData(
        view.integer(0), view.octets(2), None if kvno is None else read_integer(kvno)
    )


def read_key(element: Element) -> Key:
    """An EncryptionKey: the new session key out of an opened EncKDCRepPart."""
    view = Fields(element, "EncryptionKey")
    return Key(view.integer(0), view.octets(1))


@dataclass(frozen=True, slots=True)
class TicketInfo:
    """The cleartext outer fields of a Ticket; the rest is for the service.

    Only the service can open ``enc_part``; the client reads ``server`` to
    check the KDC issued the ticket it was asked for.
    """

    server: Principal
    enc_part: EncryptedData


def decode_ticket(der: bytes) -> TicketInfo:
    """Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2], enc-part [3] }"""
    outer = _one(der, APP_TICKET, "Ticket")
    view = Fields(_one(outer.value, TAG_SEQUENCE, "Ticket body"), "Ticket")
    if view.integer(0) != PVNO:
        raise DERError(f"Ticket version {view.integer(0)} is not 5")
    server = read_principal_name(view.get(2), view.string(1))
    return TicketInfo(server, read_encrypted_data(view.get(3)))


@dataclass(frozen=True, slots=True)
class KdcReply:
    """KDC-REP: the new ticket in the clear, and the part only the client can open.

    ``ticket`` is re-emitted DER of the Ticket element, byte-identical to
    what the KDC sent, because it will be spliced into AP-REQs and caches.
    Nothing here is trustworthy until :mod:`.tgs` has opened ``enc_part``.
    """

    msg_type: int
    client: Principal
    ticket: bytes
    enc_part: EncryptedData


def decode_kdc_rep(der: bytes) -> KdcReply:
    """TGS-REP ::= [APPLICATION 13] KDC-REP

    ``KDC-REP ::= SEQUENCE { pvno [0], msg-type [1], padata [2] OPT, crealm [3], cname [4],
    ticket [5], enc-part [6] }``
    """
    outer = _one(der, APP_TGS_REP, "TGS-REP")
    view = Fields(_one(outer.value, TAG_SEQUENCE, "TGS-REP body"), "TGS-REP")
    # padata [2] is ignored: a TGS-REP carries none that a same-realm
    # request without FAST would need.
    ticket = view.get(5)
    return KdcReply(
        msg_type=view.integer(1),
        client=read_principal_name(view.get(4), view.string(3)),
        ticket=tlv(ticket.tag, ticket.value),
        enc_part=read_encrypted_data(view.get(6)),
    )


@dataclass(frozen=True, slots=True)
class EncKdcReplyPart:
    """EncKDCRepPart: the session key and the terms the KDC granted.

    Times are epoch seconds in the KDC's clock; 0 means "absent" for
    ``renew_till``. ``server`` is checked against the ticket asked for,
    because this - not the cleartext Ticket - is the KDC's authenticated
    statement of whom the session key is for.
    """

    key: Key
    nonce: int
    flags: int
    auth_time: int
    start_time: int
    end_time: int
    renew_till: int
    server: Principal


def decode_enc_kdc_rep_part(der: bytes) -> EncKdcReplyPart:
    """EncTGSRepPart ::= [APPLICATION 26] EncKDCRepPart

    ``key [0], last-req [1], nonce [2], key-expiration [3] OPT, flags [4],
    authtime [5], starttime [6] OPT, endtime [7], renew-till [8] OPT,
    srealm [9], sname [10], caddr [11] OPT, encrypted-pa-data [12] OPT``.
    RFC 4120 section 5.4.2 asks clients to accept the AS tag (25) here too,
    because some KDCs have sent it.
    """
    outer, end = parse(der)
    if outer.tag not in (APP_ENC_TGS_REP_PART, APP_ENC_AS_REP_PART) or end != len(der):
        raise DERError(f"expected EncTGSRepPart, got tag 0x{outer.tag:02x}")
    view = Fields(_one(outer.value, TAG_SEQUENCE, "EncKDCRepPart body"), "EncKDCRepPart")
    # last-req [1] and key-expiration [3] are AS-exchange concerns (password
    # expiry warnings) and are not read; caddr [11] is unused since tickets
    # are addressless.
    auth_time = view.time(5)
    return EncKdcReplyPart(
        key=read_key(view.get(0)),
        nonce=view.integer(2),
        flags=read_flags(view.get(4)),
        auth_time=auth_time,
        start_time=view.time(6, auth_time),
        end_time=view.time(7),
        renew_till=view.time(8),
        server=read_principal_name(view.get(10), view.string(9)),
    )


@dataclass(frozen=True, slots=True)
class KrbError:
    """The fields of a KRB-ERROR worth telling a person about.

    ``server_time`` (``stime [4]``) is kept because a clock-skew error is
    only actionable with it; the KRB-ERROR is unauthenticated, so none of
    this is used for anything but the message.
    """

    code: int
    realm: str
    server: Principal
    text: str
    server_time: int


def decode_krb_error(der: bytes) -> KrbError:
    """KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... error-code [6], realm [9],
    sname [10], e-text [11] OPT ... }

    e-data [12] (pre-auth hints, mostly for the AS exchange) is not read.
    """
    outer = _one(der, APP_KRB_ERROR, "KRB-ERROR")
    view = Fields(_one(outer.value, TAG_SEQUENCE, "KRB-ERROR body"), "KRB-ERROR")
    text = view.optional(11)
    realm = view.string(9)
    return KrbError(
        code=view.integer(6),
        realm=realm,
        server=read_principal_name(view.get(10), realm),
        text="" if text is None else read_string(text),
        server_time=view.time(4),
    )
