"""The exchanges: a TGS request for a service ticket, and the AP-REQ that uses it.

A TGS-REQ (RFC 4120 section 3.3) proves possession of the ticket-granting
ticket with an AP-REQ of its own, carried as ``PA-TGS-REQ`` pre-auth data:
an authenticator sealed under the TGT session key (key usage 7) with a
keyed checksum of the request body inside it (key usage 6), so the body
cannot be altered in flight. The reply's encrypted part is sealed under the
same session key (key usage 8) and carries the new ticket's session key.
Before that key is used the reply is checked: the nonce must be the one sent
(it is what ties the reply to this request) and the ticket must be for the
principal asked for, both inside the encrypted part and outside it.

The AP-REQ for xrootd is what MIT's ``krb5_mk_req_extended`` produces for
``XrdSecProtocolkrb5``: ``use-session-key`` set in the AP options, and an
authenticator (key usage 11) holding only the client's name and the time -
no checksum, no subkey, no sequence number, because the server's
``krb5_rd_req`` asks for none of them. KRB-CRED (key usage 14) is how a
forwarded TGT reaches a server that runs with ``-exptkn``.

Every time sent is the local clock plus the cache's ``kdc_offset`` (MIT's
``kdc_timesync``), so a host whose clock drifted still lands inside the
KDC's and the server's five-minute skew window. Every failure surfaces as a
:class:`~xrdcore.errors.CredentialError` with a sentence a person can
act on (:func:`kdc_error_message`); decoding and integrity errors from the
lower layers never escape raw.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from xrdcore.errors import CredentialError
from xrdcore.log import get_logger

from ..der import DERError
from .asn1 import (
    APP_KRB_ERROR,
    EncryptedData,
    KrbError,
    decode_enc_kdc_rep_part,
    decode_kdc_rep,
    decode_krb_error,
    decode_ticket,
    encode_ap_req,
    encode_authenticator,
    encode_cred_info,
    encode_enc_krb_cred_part,
    encode_krb_cred,
    encode_req_body,
    encode_tgs_req,
)
from .kdc import exchange
from .model import Principal, Ticket
from .profile import Profile
from .rfc3961 import Enctype, IntegrityError, UnsupportedEnctypeError, get_enctype

__all__ = [
    "AP_OPTS_USE_SESSION_KEY",
    "KDC_OPT_FORWARDABLE",
    "KDC_OPT_FORWARDED",
    "TgsHooks",
    "TgsRequest",
    "build_ap_req",
    "build_krb_cred",
    "kdc_error_message",
    "request_ticket",
    "tgs_exchange",
]

_log = get_logger(__name__)

#: RFC 4120 section 7.5.1 key usage numbers.
USAGE_TGS_REQ_CKSUM = 6
USAGE_TGS_REQ_AUTH = 7
USAGE_TGS_REP_SESSION = 8
USAGE_AP_REQ_AUTH = 11
USAGE_KRB_CRED = 14

#: padata-type of the AP-REQ inside a TGS-REQ (RFC 4120 section 7.5.2).
PA_TGS_REQ = 1

#: AP options and KDC options, as 32-bit flag words (bit 0 is the MSB).
#: ``use-session-key`` is AP option bit 1; ``forwardable`` and ``forwarded``
#: are KDC option bits 1 and 2, the same positions as the ticket flags.
AP_OPTS_USE_SESSION_KEY = 0x40000000
KDC_OPT_FORWARDABLE = 0x40000000
KDC_OPT_FORWARDED = 0x20000000

#: What a person can do about the KDC errors a login actually meets, keyed by
#: RFC 4120 section 7.5.9 error code (6 C_PRINCIPAL_UNKNOWN, 7
#: S_PRINCIPAL_UNKNOWN, 32 TKT_EXPIRED, 37 SKEW, ...). Codes not listed get
#: a generic sentence; the KDC's own e-text is always appended.
_KDC_ERRORS = {
    6: "the KDC does not know the client {client}",
    7: "the KDC has no principal {server} - is the service principal in the server's "
    "configuration spelled the way it is registered?",
    9: "the KDC's database entry for {server} has no usable key",
    12: "the KDC's policy refused the request for {server}",
    14: "the KDC and this client share no encryption type for {server} "
    "(this client does aes256/aes128 with SHA-1 or SHA-2)",
    18: "the credentials for {client} have been revoked; run kinit again",
    20: "your ticket-granting ticket has been revoked; run kinit again",
    31: "the KDC could not verify the request (integrity check failed)",
    32: "your ticket-granting ticket has expired; run kinit",
    37: "the clock here and the KDC's differ by more than the allowed skew",
    41: "the KDC says the request was modified in flight",
}


def kdc_error_message(error: KrbError, client: Principal, server: Principal) -> str:
    """A KRB-ERROR as a sentence, with the KDC's own text appended.

    The KRB-ERROR is unauthenticated, so it only ever becomes a message:
    nothing about the login is decided from it.
    """
    template = _KDC_ERRORS.get(error.code, "the KDC refused the request for {server}")
    message = template.format(client=client, server=server)
    detail = f": {error.text}" if error.text else ""
    return f"{message} (KDC error {error.code}{detail})"


def _split_time(now: float) -> tuple[int, int]:
    """Whole seconds and microseconds, as ctime and cusec want them."""
    # Rounded, not truncated: a float time is rarely exact in its last microsecond.
    seconds, micro = divmod(round(now * 1_000_000), 1_000_000)
    return int(seconds), int(micro)


def _session(ticket: Ticket, what: str) -> Enctype:
    """The enctype of ``ticket``'s session key, if this client can use that key at all."""
    try:
        enctype = get_enctype(ticket.enctype)
    except UnsupportedEnctypeError as exc:
        raise CredentialError(f"{what} cannot be used: {exc}") from exc
    if len(ticket.key) != enctype.key_size:
        raise CredentialError(
            f"{what} cannot be used: its {enctype.name} session key is "
            f"{len(ticket.key)} bytes, not {enctype.key_size}"
        )
    return enctype


@dataclass(frozen=True, slots=True)
class TgsHooks:
    """The parts of a TGS exchange a test replaces: transport, clock and nonce.

    ``send(profile, realm, request)`` returns the KDC's reply (by default
    :func:`.kdc.exchange`), ``clock`` is the local time before the KDC
    offset is added, and ``nonce`` fixes the request nonce so a captured
    reply - which echoes the nonce it was issued for - replays. Production
    code passes none of this: the defaults are the real network, the real
    clock, and a freshly drawn nonce, and a fixed nonce outside a test
    would let an old reply be replayed.
    """

    send: Callable[[Profile, str, bytes], bytes] = exchange
    clock: Callable[[], float] = time.time
    nonce: int | None = None


#: The production hooks, shared because the dataclass is immutable.
_REAL = TgsHooks()


@dataclass(frozen=True, slots=True)
class TgsRequest:
    """What one TGS-REQ asks the KDC for.

    ``server`` is the service principal wanted (or ``krbtgt/REALM`` itself
    when a TGT is being fetched to forward); ``etypes`` are the session-key
    enctypes acceptable, most preferred first (``krb5.conf``'s
    ``default_tgs_enctypes``); ``options`` are KDC options such as
    :data:`KDC_OPT_FORWARDED`. A tuple, so the request is hashable and
    cannot change between being encoded and being checksummed.
    """

    server: Principal
    etypes: tuple[int, ...]
    options: int = 0


def request_ticket(
    tgt: Ticket,
    server: Principal,
    profile: Profile,
    *,
    etypes: Sequence[int],
    options: int = 0,
) -> Ticket:
    """Ask the KDC for a ticket to ``server``, using ``tgt``; check the answer.

    The production entry point, over the real network and clock - what
    :mod:`.client` calls (and what its tests stand a fake in for).
    :func:`tgs_exchange` is the same exchange with its seams exposed.
    """
    return tgs_exchange(tgt, TgsRequest(server, tuple(etypes), options), profile)


def tgs_exchange(tgt: Ticket, ask: TgsRequest, profile: Profile, hooks: TgsHooks = _REAL) -> Ticket:
    """The TGS exchange: build and send the request ``ask`` describes, check the reply.

    ``profile`` says where the realm's KDCs are; ``hooks`` replaces the
    network, clock and nonce in tests (:class:`TgsHooks`), so a captured
    KDC reply can be replayed byte for byte.

    Only same-realm requests are made: a server in another realm is refused
    before anything is sent, with a message saying so, because following
    cross-realm referrals would mean trusting TGTs for realms the user's
    ``krb5.conf`` may know nothing about. The reply is checked as the module
    docstring describes before its session key is believed.
    """
    server = ask.server
    # Only the home realm's own TGT (krbtgt/REALM@REALM) is ever used here.
    realm = tgt.server.realm
    if server.realm != realm:
        raise CredentialError(
            f"{server} is in realm {server.realm} but your ticket-granting ticket is for "
            f"{realm}; cross-realm authentication is not supported by this client"
        )
    session = _session(tgt, "your ticket-granting ticket")
    # 31 bits, as MIT draws it: some KDCs have read the UInt32 as signed.
    nonce = secrets.randbits(31) if hooks.nonce is None else hooks.nonce
    body = encode_req_body(
        options=ask.options, server=server, till=tgt.end_time, nonce=nonce, etypes=ask.etypes
    )
    ctime, cusec = _split_time(hooks.clock() + tgt.kdc_offset)
    # The checksum binds the body to the authenticator: a man in the middle
    # who changes the requested service or enctypes breaks it (usage 6).
    checksum = (session.checksum_type, session.checksum(tgt.key, USAGE_TGS_REQ_CKSUM, body))
    authenticator = encode_authenticator(tgt.client, ctime, cusec, checksum=checksum)
    sealed = EncryptedData(tgt.enctype, session.encrypt(tgt.key, USAGE_TGS_REQ_AUTH, authenticator))
    request = encode_tgs_req([(PA_TGS_REQ, encode_ap_req(tgt.der, sealed))], body)
    _log.debug("TGS-REQ for %s to realm %s (%d bytes)", server, realm, len(request))
    reply = hooks.send(profile, realm, request)
    return _read_reply(reply, tgt, server, nonce)


def _read_reply(reply: bytes, tgt: Ticket, server: Principal, nonce: int) -> Ticket:
    """Decode, decrypt and check a TGS reply; any doubt is a CredentialError.

    A KRB-ERROR is recognised by its first byte (``[APPLICATION 30]``)
    before anything else is decoded, so the person sees the KDC's reason
    rather than "expected TGS-REP".
    """
    try:
        if reply.startswith(bytes([APP_KRB_ERROR])):
            error = decode_krb_error(reply)
            raise CredentialError(kdc_error_message(error, tgt.client, server))
        return _open_reply(reply, tgt, server, nonce)
    except (DERError, IntegrityError, UnsupportedEnctypeError) as exc:
        raise CredentialError(f"the KDC's reply for {server} is unusable: {exc}") from exc


def _open_reply(reply: bytes, tgt: Ticket, server: Principal, nonce: int) -> Ticket:
    """Open the TGS-REP under the TGT session key and turn it into a :class:`Ticket`.

    Checks, in order, each an :class:`IntegrityError` that the caller turns
    into a CredentialError: the reply is sealed with the TGT's enctype; it
    decrypts and its HMAC verifies (usage 8); the nonce is ours; the ticket
    is for ``server`` both in the authenticated part and in the cleartext
    Ticket; it is for our client; and its session key has the size its
    enctype requires. The new ticket inherits the TGT's ``kdc_offset``,
    since it is the same KDC's clock.
    """
    rep = decode_kdc_rep(reply)
    if rep.enc_part.etype != tgt.enctype:
        raise IntegrityError(f"reply sealed with enctype {rep.enc_part.etype}, not {tgt.enctype}")
    plain = get_enctype(tgt.enctype).decrypt(tgt.key, USAGE_TGS_REP_SESSION, rep.enc_part.cipher)
    part = decode_enc_kdc_rep_part(plain)
    if part.nonce != nonce:
        raise IntegrityError("the nonce does not match the request's (a replayed reply?)")
    issued = decode_ticket(rep.ticket).server
    if not (part.server.same_name(server) and issued.same_name(server)):
        raise IntegrityError(f"asked for {server}, got a ticket for {part.server}")
    if not rep.client.same_name(tgt.client):
        raise IntegrityError(f"the ticket is for {rep.client}, not {tgt.client}")
    # A session key this client cannot use is no use.
    if len(part.key.value) != get_enctype(part.key.enctype).key_size:
        raise IntegrityError(f"the session key for {server} is {len(part.key.value)} bytes")
    return Ticket(
        client=tgt.client,
        server=part.server,
        enctype=part.key.enctype,
        auth_time=part.auth_time,
        start_time=part.start_time,
        end_time=part.end_time,
        renew_till=part.renew_till,
        flags=part.flags,
        der=rep.ticket,
        key=part.key.value,
        kdc_offset=tgt.kdc_offset,
    )


def build_ap_req(
    ticket: Ticket,
    *,
    options: int = AP_OPTS_USE_SESSION_KEY,
    clock: Callable[[], float] = time.time,
) -> bytes:
    """The AP-REQ XRootD's ``krb5`` plugin expects, for ``ticket``'s service.

    ``options`` defaults to ``use-session-key``, the flag word the stock
    client's ``krb5_mk_req_extended`` call sends (see the module
    docstring). The authenticator is sealed under the ticket's session key
    with key usage 11, its time shifted by the ticket's ``kdc_offset``.
    """
    enctype = _session(ticket, f"the ticket for {ticket.server}")
    ctime, cusec = _split_time(clock() + ticket.kdc_offset)
    authenticator = encode_authenticator(ticket.client, ctime, cusec)
    sealed = EncryptedData(
        ticket.enctype, enctype.encrypt(ticket.key, USAGE_AP_REQ_AUTH, authenticator)
    )
    return encode_ap_req(ticket.der, sealed, options)


def build_krb_cred(
    forwarded: Ticket, session: Ticket, *, clock: Callable[[], float] = time.time
) -> bytes:
    """KRB-CRED carrying ``forwarded``, sealed under ``session``'s key.

    ``session`` is the service ticket the AP-REQ just used: the server's
    ``krb5_rd_cred`` opens the message with that ticket's session key.
    """
    enctype = _session(session, f"the ticket for {session.server}")
    ctime, cusec = _split_time(clock() + session.kdc_offset)
    part = encode_enc_krb_cred_part([encode_cred_info(forwarded)], ctime, cusec)
    sealed = EncryptedData(session.enctype, enctype.encrypt(session.key, USAGE_KRB_CRED, part))
    return encode_krb_cred([forwarded.der], sealed)
