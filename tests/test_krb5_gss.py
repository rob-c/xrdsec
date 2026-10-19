"""Kerberos through GSS-API: status mapping, binding selection, contexts and the raw AP-REQ.

Everything here runs against :func:`xrdsec.testing.krb5.fake_gssapi_module`,
installed as ``sys.modules["gssapi"]``: a toy mechanism whose tokens are
readable and whose every call can be made to fail with a chosen status, so
the translation of library failures into :class:`~xrdsec.krb5.gss.KerberosError`
and the contexts' own policy (mutual authentication, confidentiality,
locking, ownership) are pinned without a KDC. What a real KDC and a real
library do is the clients' interoperability suites' business.
"""

from __future__ import annotations

import errno
import pickle
import sys
import threading
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from xrdcore.errors import AuthenticationError
from xrdsec import der
from xrdsec.krb5 import _status, gss
from xrdsec.testing.krb5 import FAKE_USER, FakeGssapi, fake_gssapi_module


@pytest.fixture(autouse=True)
def _fresh_backends() -> Iterator[None]:
    """No binding found by one test is reused by the next."""
    gss.reset()
    yield
    gss.reset()


@pytest.fixture
def gssapi(monkeypatch: pytest.MonkeyPatch) -> FakeGssapi:
    """The fake python-gssapi, as ``import gssapi`` will find it."""
    module = fake_gssapi_module()
    monkeypatch.setitem(sys.modules, "gssapi", module)
    return module


def no_gssapi(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``import gssapi`` raise ``ImportError``, as on a host without the extra."""
    monkeypatch.setitem(sys.modules, "gssapi", None)


def _established(gssapi: FakeGssapi) -> tuple[gss.ClientContext, gss.AcceptorContext]:
    """A client and a server context that completed the mutual handshake."""
    client = gss.ClientContext("host", "door")
    server = gss.AcceptorContext()
    client.step(server.step(client.step()))
    return client, server


# -- status codes ------------------------------------------------------------------------


def test_signed_and_is_error() -> None:
    assert _status.signed(_status.KDC_UNREACH & 0xFFFFFFFF) == _status.KDC_UNREACH
    assert _status.signed(5) == 5
    assert _status.is_error(7 << 16) and _status.is_error(1 << 24)
    assert not _status.is_error(_status.CONTINUE_NEEDED)


def test_routine_text() -> None:
    assert "argument" in _status.routine_text(1 << 24)
    assert "credentials" in _status.routine_text(_status.NO_CRED << 16)
    assert _status.routine_text(99 << 16) == f"GSS major status 0x{99 << 16:08x}"
    assert "duplicate" in _status.routine_text(2)


@pytest.mark.parametrize(
    ("major", "minor", "protection", "code"),
    [
        (_status.FAILURE << 16, _status.KDC_UNREACH & 0xFFFFFFFF, False, errno.ETIMEDOUT),
        (_status.FAILURE << 16, errno.ETIMEDOUT, False, errno.ETIMEDOUT),
        (_status.FAILURE << 16, errno.ECONNREFUSED, False, errno.ECONNREFUSED),
        (1 << 24, 0, False, errno.EINVAL),
        (2, 0, True, errno.EPROTO),
        (2, 0, False, errno.EPROTO),
        (_status.BAD_MIC << 16, 0, True, errno.EPROTO),
        (_status.BAD_MIC << 16, 0, False, errno.EACCES),
        (_status.NO_CRED << 16, 0, False, errno.EACCES),
        (_status.NO_CRED << 16, 0, True, errno.EACCES),
        (_status.BAD_MECH << 16, 0, False, errno.EPROTONOSUPPORT),
        (_status.UNAVAILABLE << 16, 0, False, errno.EOPNOTSUPP),
        (_status.FAILURE << 16, 0, False, errno.EACCES),
    ],
)
def test_errno_for(major: int, minor: int, protection: bool, code: int) -> None:
    assert _status.errno_for(major, minor, protection=protection) == code


def test_hints() -> None:
    failure = _status.FAILURE << 16
    assert "kinit" in _status.hint_for(_status.NO_CRED << 16, 0)
    assert "kinit" in _status.hint_for(failure, _status.KG_EMPTY_CCACHE)
    assert "service principal" in _status.hint_for(
        failure, _status.KDC_ERR_S_PRINCIPAL_UNKNOWN & 0xFFFFFFFF
    )
    assert "clocks" in _status.hint_for(failure, _status.AP_ERR_SKEW)
    assert "no KDC" in _status.hint_for(failure, _status.KDC_UNREACH)
    assert _status.hint_for(failure, 0) == ""


def test_supplementary_status_does_not_display_success_as_a_failure() -> None:
    error = _status.describe("checking token", 2, 1, (["duplicate"], ["Success"]))
    assert "duplicate" in error.message
    assert "Success" not in error.message


def test_describe_falls_back_to_rfc_words_and_the_minor_number() -> None:
    error = _status.describe("doing it", _status.NO_CRED << 16, 7, ([], []))
    assert error.message.startswith("doing it failed: No credentials were supplied")
    assert "minor code 7" in error.message
    assert (error.major, error.minor, error.code) == (_status.NO_CRED << 16, 7, errno.EACCES)


def test_kerberos_error_is_an_authentication_error_that_pickles_whole() -> None:
    error = gss.KerberosError("nope", errno.EACCES, 1, 2, b"tok")
    assert isinstance(error, AuthenticationError)
    assert str(error) == "nope"
    assert error.args == ("nope", errno.EACCES)
    copy = pickle.loads(pickle.dumps(error))
    assert type(copy) is gss.KerberosError
    assert (copy.message, copy.code, copy.major, copy.minor, copy.token) == (
        "nope",
        errno.EACCES,
        1,
        2,
        b"tok",
    )


# -- the binding -------------------------------------------------------------------------


def test_gssapi_is_the_binding_and_is_cached(gssapi: FakeGssapi) -> None:
    assert gss.backend() == "gssapi"
    assert gss.available() is None
    assert gss.load_backend() is gss.load_backend()
    assert gss.load_backend("gssapi").gssapi is gssapi


def test_no_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    no_gssapi(monkeypatch)
    reason = gss.available()
    assert reason is not None
    assert "gssapi" in reason and gss.INSTALL_HINT in reason
    assert str(gss.available(hint="install the client's extra")).endswith("the client's extra")
    assert gss.backend() is None
    with pytest.raises(gss.KerberosError) as info:
        gss.ClientContext("host", "door")
    assert info.value.code == errno.EPROTONOSUPPORT


def test_a_failure_is_not_cached_but_a_success_is_until_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    no_gssapi(monkeypatch)
    assert gss.backend("gssapi") is None
    monkeypatch.setitem(sys.modules, "gssapi", fake_gssapi_module())
    assert gss.backend("gssapi") == "gssapi"
    no_gssapi(monkeypatch)
    assert gss.backend("gssapi") == "gssapi"  # remembered
    gss.reset()
    assert gss.backend("gssapi") is None


def test_an_unknown_binding_is_refused(gssapi: FakeGssapi) -> None:
    with pytest.raises(gss.KerberosError, match="unknown Kerberos backend") as info:
        gss.load_backend("heimdal")
    assert info.value.code == errno.EINVAL
    assert "unknown" in str(gss.available("ctypes"))  # a client's alias is the client's


# -- contexts ----------------------------------------------------------------------------


def test_context_lifecycle_and_protection_policy(gssapi: FakeGssapi) -> None:
    with gss.ClientContext("host", "door") as client, gss.AcceptorContext() as server:
        with pytest.raises(gss.KerberosError, match="not yet established"):
            client.wrap(b"not ready")
        with pytest.raises(gss.KerberosError, match="needs the client's token") as info:
            server.step(b"")
        assert info.value.code == errno.EINVAL
        client.step(server.step(client.step()))
        with pytest.raises(gss.KerberosError, match="already established"):
            client.step(b"again")
        token = client.wrap(b"message", confidential=False)
        with pytest.raises(gss.KerberosError, match="unencrypted"):
            server.unwrap(token, require_confidential=True)
    with pytest.raises(gss.KerberosError, match="closed") as info:
        client.step(b"again")
    assert info.value.code == errno.EBADF
    with pytest.raises(gss.KerberosError, match="closed"):
        client.get_mic(b"message")
    client.close()  # idempotent


def test_handshake_and_protection(gssapi: FakeGssapi) -> None:
    client = gss.ClientContext("host", "door.example", delegate=True)
    server = gss.AcceptorContext()
    assert client.backend == server.backend == "gssapi"
    reply = server.step(client.step())
    assert server.complete and not client.complete
    assert client.step(reply) == b""
    assert client.complete
    assert client.initiator_name == server.initiator_name == FAKE_USER
    assert client.target_name == "host/door.example@XGFAL.TEST"
    assert client.flags & gss.MUTUAL_FLAG and client.flags & gss.DELEG_FLAG
    assert server.unwrap(client.wrap(b"hi"), require_confidential=True) == b"hi"
    assert client.unwrap(server.wrap(b"yo", confidential=False)) == b"yo"
    server.verify_mic(b"m", client.get_mic(b"m"))
    with pytest.raises(gss.KerberosError) as info:
        server.verify_mic(b"m", b"bad")
    assert info.value.code == errno.EPROTO
    assert "Message Integrity Check" in info.value.message  # the RFC's words stand in
    with pytest.raises(gss.KerberosError, match="invalid Message Integrity") as info:
        server.unwrap(b"junk")
    assert info.value.code == errno.EPROTO
    gssapi.no_conf = True
    with pytest.raises(gss.KerberosError, match="confidentiality"):
        client.wrap(b"x")
    client.close()
    server.close()


def test_one_step_and_names(gssapi: FakeGssapi) -> None:
    client = gss.ClientContext("", "", principal="xrootd/h@XGFAL.TEST", mutual=False)
    token = client.step()
    assert client.complete and client.target_name == "xrootd/h@XGFAL.TEST"
    assert client.target == gss.Target("xrootd/h@XGFAL.TEST", gss.PRINCIPAL)
    server = gss.AcceptorContext(principal="xrootd/h@XGFAL.TEST", keytab="/tmp/kt")
    assert gssapi.last_credentials["store"] == {"keytab": "/tmp/kt"}
    assert gssapi.last_credentials["name"].text == "xrootd/h@XGFAL.TEST"
    assert server.step(token) == b""
    gss.AcceptorContext(keytab="/tmp/kt")
    assert gssapi.last_credentials["name"] is None
    gss.AcceptorContext("host", "door")
    assert gssapi.last_credentials["store"] is None
    gss.ClientContext("host", "door", ccache="FILE:/tmp/cc")
    assert gssapi.last_credentials["store"] == {"ccache": "FILE:/tmp/cc"}


def test_unestablished_names_and_optional_requested_flags(gssapi: FakeGssapi) -> None:
    with gss.ClientContext(
        "host",
        "",
        mutual=False,
        replay=False,
        sequence=False,
        confidentiality=False,
        integrity=False,
    ) as client:
        assert client.initiator_name is None
        assert client.target_name is None
        assert client.flags == 0 and client.requested == 0
        assert client.target.name == "host"
    assert gss.ClientContext("host", "door").requested == (
        gss.MUTUAL_FLAG | gss.REPLAY_FLAG | gss.SEQUENCE_FLAG | gss.CONF_FLAG | gss.INTEG_FLAG
    )
    with gss.AcceptorContext("host", ""):
        assert gssapi.last_credentials["name"].text == "host/localhost@XGFAL.TEST"


def test_library_errors_are_translated(gssapi: FakeGssapi) -> None:
    errors: Any = gssapi.exceptions
    gssapi.fail["SecurityContext"] = errors.GSSError(7 << 16, 0x96C73A8D, "No credentials")
    with pytest.raises(gss.KerberosError, match="preparing Kerberos") as info:
        gss.ClientContext("host", "door")
    assert info.value.code == errno.EACCES and "run kinit" in info.value.message
    assert f"No credentials: minor text {0x96C73A8D}" in info.value.message

    gssapi.fail["SecurityContext"] = errors.GSSError(13 << 16, 1, "Unspecified GSS failure")
    with pytest.raises(gss.KerberosError) as info:
        gss.ClientContext("host", "door")
    assert info.value.message.endswith("Unspecified GSS failure: minor code 1")

    gssapi.fail["SecurityContext"] = errors.GSSError(13 << 16, 5, "Unspecified GSS failure")
    with pytest.raises(gss.KerberosError) as info:
        gss.ClientContext("host", "door")
    assert info.value.message.endswith("failed: minor text 5")  # MIT's filler is dropped

    gssapi.fail["Credentials"] = NotImplementedError("no credential store extension")
    with pytest.raises(gss.KerberosError, match="store extension") as info:
        gss.ClientContext("host", "door", ccache="FILE:/x")
    assert info.value.code == errno.EOPNOTSUPP

    gssapi.fail["Credentials"] = errors.GeneralError("bad keytab")
    with pytest.raises(gss.KerberosError, match="preparing a Kerberos acceptor") as info:
        gss.AcceptorContext(keytab="/x")
    assert info.value.code == errno.EACCES


def test_establishment_errors_keep_the_error_token(gssapi: FakeGssapi) -> None:
    errors: Any = gssapi.exceptions
    client = gss.ClientContext("host", "door")
    gssapi.fail["step"] = errors.GSSError(13 << 16, _status.KDC_UNREACH & 0xFFFFFFFF)
    with pytest.raises(gss.KerberosError) as info:
        client.step()
    assert info.value.code == errno.ETIMEDOUT
    assert info.value.token == b""
    client.step()
    with pytest.raises(gss.KerberosError, match="Invalid token"):
        client.step(b"bad")
    server = gss.AcceptorContext()
    with pytest.raises(gss.KerberosError) as info:
        server.step(b"bad")
    assert info.value.token == b"KRB-ERROR"

    client = gss.ClientContext("host", "door")
    token = client.step()
    gssapi.fail["actual_flags"] = errors.GSSError(8 << 16, 0, "")
    with pytest.raises(gss.KerberosError, match="gss_inquire_context"):
        client.step(gss.AcceptorContext().step(token))


@pytest.mark.parametrize("name", ["wrap", "unwrap", "get_signature", "verify_signature"])
def test_message_protection_errors_are_eproto(gssapi: FakeGssapi, name: str) -> None:
    client, server = _established(gssapi)
    calls: dict[str, Callable[[], object]] = {
        "wrap": lambda: client.wrap(b"x"),
        "unwrap": lambda: server.unwrap(b"WC:x"),
        "get_signature": lambda: client.get_mic(b"x"),
        "verify_signature": lambda: server.verify_mic(b"x", b"MIC:x"),
    }
    gssapi.fail[name] = gssapi.exceptions.GSSError(2, 0, "The token was a duplicate")
    with pytest.raises(gss.KerberosError, match="duplicate") as info:
        calls[name]()
    assert info.value.code == errno.EPROTO


def test_mutual_authentication_is_enforced(gssapi: FakeGssapi) -> None:
    client = gss.ClientContext("host", "door")
    reply = gss.AcceptorContext().step(client.step())
    gssapi.flags_override = 0
    with pytest.raises(gss.KerberosError, match="mutual") as info:
        client.step(reply)
    assert info.value.code == errno.EACCES
    assert not client.complete


def test_contexts_are_locked(gssapi: FakeGssapi) -> None:
    """Wrapping from many threads at once goes through one context safely."""
    client, server = _established(gssapi)
    results: list[bytes] = []

    def worker(index: int) -> None:
        for _ in range(50):
            results.append(server.unwrap(client.wrap(b"%d" % index)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 400


def test_failed_constructor_is_safe_to_collect(monkeypatch: pytest.MonkeyPatch) -> None:
    no_gssapi(monkeypatch)
    with pytest.raises(gss.KerberosError):
        gss.AcceptorContext()
    # __del__ ran on a half-built object; closing one by hand is also harmless.
    context = gss.ClientContext.__new__(gss.ClientContext)
    context.close()


# -- XRootD's raw AP-REQ ----------------------------------------------------------------


def _token(
    wrapper: int = 0x60,
    mechanism: str = gss.KRB5_MECHANISM,
    prefix: bytes = b"\x01\x00",
    request: bytes = b"\x6e\x02\x30\x00",
) -> bytes:
    """An initiator token: RFC 2743 header, mechanism OID, TOK_ID, then the request."""
    return der.encode(wrapper, der.encode_oid(mechanism) + prefix + request)


def test_the_envelope_is_removed() -> None:
    assert gss.unwrap_ap_req(_token()) == b"\x6e\x02\x30\x00"


@pytest.mark.parametrize(
    "token",
    [
        b"",
        b"bad",
        _token(wrapper=0x30),
        _token(mechanism="1.2.3"),
        _token(prefix=b"\0\0"),
        _token(request=b"\x30\0"),
        _token(request=b"\x6e\0x"),
        _token() + b"x",
    ],
)
def test_anything_but_a_krb5_ap_req_envelope_is_refused(token: bytes) -> None:
    with pytest.raises(gss.KerberosError, match="malformed AP-REQ") as info:
        gss.unwrap_ap_req(token)
    assert info.value.code == errno.EPROTO


def test_the_library_makes_one_unflagged_token_and_the_envelope_comes_off(
    gssapi: FakeGssapi,
) -> None:
    made: list[dict[str, Any]] = []

    toy = gssapi.SecurityContext

    def step(self: Any, token: bytes | None) -> bytes:
        """The toy handshake, answering with a real envelope instead of its text token."""
        toy.step(self, token)
        made.append(self.kwargs)
        return _token()

    gssapi.SecurityContext = type("Envelope", (toy,), {"step": step})
    assert gss.initiator_ap_req("xrootd/server@EXAMPLE") == b"\x6e\x02\x30\x00"
    assert made[0]["flags"] == 0  # no delegation, no mutual authentication: one token
    assert made[0]["creds"] is None  # the library's default cache
    assert str(made[0]["name"]) == "xrootd/server@EXAMPLE"


def test_a_token_that_is_not_an_ap_req_is_not_sent(gssapi: FakeGssapi) -> None:
    with pytest.raises(gss.KerberosError, match="malformed AP-REQ"):
        gss.initiator_ap_req("xrootd/server@EXAMPLE")  # the toy mechanism's text token


# -- the stand-in itself -------------------------------------------------------------------


def test_the_fake_answers_like_the_package(gssapi: FakeGssapi) -> None:
    error = gssapi.exceptions.GSSError(13 << 16, 0)
    assert str(error) == f"GSS error {13 << 16:#x}/0"
    assert error.get_all_statuses(13 << 16, True) == []
    assert error.get_all_statuses(0, False) == []
    acceptor = gssapi.SecurityContext(usage="accept")
    assert acceptor.step(None) == b"KRB-ERROR"
    with pytest.raises(type(error), match="Invalid token"):
        _ = acceptor.complete
