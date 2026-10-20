# Changelog

Notable user-visible changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.4.1] - Unreleased

Fixes found moving data between the LHCb Tier-1 and Tier-2 storage elements
with xrdclient and xgfalclient (2026-10-20).

### Fixed

- A GSI proxy request from a dCache door is now read and signed. dCache puts
  a single `Extension` straight into the `extensionRequest` `SET` (no
  `SEQUENCE OF`) and the value as a bare `SEQUENCE` (no OCTET STRING); the
  parser refused it, so no proxy was ever delegated to a dCache site and
  root third-party copy through GRIDKA, IN2P3, PIC or SARA failed.
  Anything else malformed is still refused.
- The GSI server check trusts DNS as stock `XrdSecgsi` does
  (`XrdSecGSITRUSTDNS`, on by default; `trust_dns()`): a certificate that
  names neither the host nor a `$XrdSecGSISRVNAMES` pattern is checked
  against the forward-confirmed reverse-DNS names of the host's addresses
  (`dns_names()`, `ServerCheck.resolve`, asked only after a mismatch). A
  round-robin alias whose nodes hold certificates in their own names (CNAF's
  `xrootd-lhcb.cr.cnaf.infn.it`) failed on every other login. As in the
  stock client, a proxy is never delegated to a server only DNS vouched for;
  `check_server` now returns whether the certificate named the host itself.
- The GSS client no longer deadlocks against an acceptor that gives no
  TLS 1.3 turn (dCache's GridFTP door): once the acceptor answers with
  session tickets only, the delegation flag is sent.
- Certificates with a zero or negative serial (several IGTF CAs, and any
  Authority Key Identifier naming one) no longer print `cryptography`'s
  `CryptographyDeprecationWarning` three times per command; the filter is
  scoped to xrdsec's own calls and to that one message.

## [0.4.0] - 2026-10-19

The first release. Until now xrdclient, xgfalclient and xrdarc each carried
their own grid security code, or imported another client's private modules to
get it; this is that code as one library that depends on no client. Its public
names and signatures are xrdclient 0.4.0's public building blocks, minus
xrdclient's own types, so the clients re-export it rather than wrap it.

### Added

- `der`, `rsa`, `aes`, `p256`, `ed25519`, `signatures`, `x509`,
  `delegation`, `userproxy`, `trust` and `voms`, from `xrdclient.crypto`
  as of 0.4.0 (`ProxyCredential.to_pem()`, `proxy_identity`,
  `is_proxy_certificate`, `proxy_cert_info_extension` included). The x509
  helpers xgfalclient imported privately are public: `name_from_element`,
  `tbs_extensions`, `policy_language`; and the certificate building blocks
  `extension`, `key_usage`, `public_key_info`, `signature_algorithm` moved
  here from xgfalclient.
- `proxies`: xrdclient's one proxy issuer (`issue_proxy`, `create_proxy`,
  `write_proxy`, `load_credential`, `describe_proxy`/`ProxyInfo`,
  `voms_extension`) with its `rfc3820`, `arc`, `xrootd` and `globus-legacy`
  profiles, plus a `globus` profile: xgfalclient's `globus_gsi_proxy_sign_req`
  policy (key-hash serial, no VOMS carried forward, a GT2 signer begets a
  GT2 child). `issue_proxy(..., digest=)` picks the signature's hash
  (`sha256` by default; SHA-1 refused), which xgfalclient's `sign_request`
  passes through.
- `credentials`: xrdclient's environment-explicit discovery (`find_proxy`,
  `default_proxy_path`, `find_user_credential`, `find_bearer_token`,
  `bearer_token_files`, `grid_ca_path`, `grid_voms_dir`, `default_ca_path`,
  `read_private_file`, `write_private_file`), with gfal2's
  `skip_unreadable=True` added to `find_bearer_token`.
- `tls`: xrdclient's cached `client_context(cert=, key=, ca_path=,
  ca_file=, verify=, system_ca=, check_crl=, key_password=,
  present_default=, credential_pem=)`, `clear_cache`, `crl_mode`, with
  `x509_strict=False` for gfal2 and ARC, `check_hostname=False` for GSI
  peers (GridFTP, SRM, LFC, dcap), whose `host/<fqdn>` check is made
  against the certificate's DN after the handshake, and `alpn=` - both
  added for xgfalclient's TLS contexts, and both part of the cache key.
- `voms_client`: `find_vomses`, `parse_vomses`, `servers_for`, `fetch_ac`,
  `ac_extension` and the `VOMSError` family, from `xrdclient.voms_client`.
- `tokens`: a URL's own token in front of `credentials.find_bearer_token`,
  with the explicit-token-file rule, and the unverified JWT `check_token`,
  `token_claims` and `token_expiry`. The claim reading is xrdclient's
  strict one (canonical base64url only, RFC 7797 detached payloads have no
  claims, absurd JSON nesting is "no claims" rather than a `RecursionError`);
  `padding=True` is xrdclient's tolerance of whole-quantum `=` padding,
  which gfal2's reading (the default) refuses.
- `usercred`: xrdclient's `_usercred` (`load_pair`, `load_memory`,
  `password_supplier`) with its settings as arguments: `wanted`,
  `pass_phrase`, `present`, `memory_proxy`.
- `discovery`: X.509 credential and CA directory discovery with each tool's
  search order as a `Search` value (`XRDCLIENT`, `GFAL2`, `GFAL2_SEED`,
  `ARC`), built on `credentials`.
- `testing.pki`, `testing.voms`, `testing.https`: xrdclient's shared test
  PKI, VOMS fixtures and `FakeHTTPSServer` (subjects read `DC=xrdsec`).
- For xrdarc, built on xrdsec without a storage client:
  `discovery.discover_x509(..., uid=)` names another account's
  `x509up_u<uid>` (in `/tmp` and `$TMPDIR`), as `credentials` already did;
  `discovery.discover_ca_dir(..., grid_security=)` and the module attribute
  `credentials.GRID_SECURITY_DIRS` replace the platform's `grid-security`
  directories (for `grid_ca_path`, `grid_voms_dir`, `discover_ca_dir` and
  the `vomses` search), so a test suite no longer depends on the machine
  lacking `/etc/grid-security/certificates`;
  `voms_client.fetch_ac(..., x509_strict=)` passes through to
  `tls.client_context` (strict by default, as before), for ARC, which never
  applies Python's RFC 5280 strict checks;
  `testing.https.Request.header_fields` and `Request.get_all()` keep a
  repeated header's every line (`headers` is unchanged);
  `FakeHTTPSServer(join_timeout=)` makes `stop()` wait for connection
  threads.
- `testing.https` is the generic server only. Its range and WebDAV reply
  helpers (`ranged_reply`, `propfind_reply`, `multistatus`, `dav_entries`,
  `DAVEntry`, `BOUNDARY`) moved to `xrdhttp.testing`, the home of HTTP's
  test support (xrdsec's own fakes never needed them; xrdarc's A-REX fake
  and xrdclient's `testing.http` now take them from there). `Response`
  stays. For fakes that speak differently on the wire - xrdhttp's fake
  storage element is built on this server - `FakeHTTPSServer.handler_class`
  supplies the per-connection handler, `Listener` (was `_Server`) is the
  listener it names, `record()` and `take_fault()` (were `_record`,
  `_take_fault`) are what such a handler calls, `opened()` hears of each new
  connection, and `Fault(hold=)` / `hold()`
  model a server that goes silent (before any answer, or after a truncated
  body) until the client hangs up.
- Not added: a "check a CRL when one is there, don't fail when none is"
  mode (ARC's, through its own OpenSSL verify callback). The stdlib `ssl`
  module has no verify callback, and a context is built before the
  server's chain is known, so it can only check CRLs for every certificate
  or for none; any rule over the CA directory's contents (every CA has a
  CRL, some CA has one) would either still fail closed or check less than
  ARC does. `check_crl=` stays all-or-nothing.
- `lifetime`, from xrdwms's `credentials` module: `Credential`,
  `CredentialProvider`, `ProxyFile` and `BearerToken` (the credential in use
  now, re-read on every ask), plus what xrdwms's job manager and xrdarc's
  submission checks each computed for themselves: `Credential.of_proxy`,
  `Credential.remaining`, `chain_expiry` (a chain's earliest `notAfter`),
  `assess` (expired / short of a minimum / low / fine, in that order) and
  `CredentialWatch` (one warning per expiry; a renewed credential noticed
  per consumer). xrdwms re-exports the first four; xrdarc's `check_lifetime`
  and its expired-signer check are built on `assess` and `chain_expiry`.
- `krb5`: one Kerberos implementation for every client, from xrdclient's
  pure-Python client (`xrdclient.auth.kerberos.*` and
  `xrdclient.crypto.rfc3961` -> `krb5.model`, `asn1`, `ccache`, `kcm`,
  `keyring`, `caches`, `profile`, `kdc`, `tgs`, `rfc3961`; the
  credential-cache and TGS logic of `xrdclient.auth.krb5` -> `krb5.client`)
  and xgfalclient's GSS-API wrapper (`xgfalclient.crypto.krb5` -> `krb5.gss`
  with private `_gssapi` and `_status`). New in the move:
  `client.service_credentials` (the whole "ticket for this service, and a
  forwarded TGT if asked" path, returning `ServiceCredentials`),
  `client.target_principal`, `client.request_enctypes`, `client.clear_cache`
  and `client.inspect_cache` (principal and latest expiry of any readable
  cache - `FILE:`, `DIR:`, `KCM:`, `KEYRING:` - replacing xgfalclient's
  pykrb5-based diagnostics); `gss.initiator_ap_req` and `gss.unwrap_ap_req`
  (xrdclient's raw AP-REQ from the system library, now through the same
  contexts); `gss.KerberosError` is an `xrdcore.errors.AuthenticationError`
  carrying an `errno` (`code`), the GSS statuses and any error token, and
  `gss.load_backend`/`available` take the client's install `hint=`. What
  stays with each client is policy: xrdclient's `krb5\0` kXR_auth framing,
  offer parsing, `$XRD_KRB5_BACKEND` and `CredentialError` wording;
  xgfalclient's `$XGFAL_KRB5_BACKEND` (with its `ctypes` alias) and `GError`.
  The refusal of a macOS `API:` cache now names "python-gssapi (the 'krb5'
  extra)" rather than a client's extra.
- `testing.krb5`: `make_ticket`, `write_ccache`, `FakeKcm` (from xrdclient's
  `tests/_kcmd.py`, with `put()` to fill a cache) and `fake_gssapi_module`
  (from xgfalclient's `tests/krb5_fakes.py`; the dead ctypes `FakeGSS` was
  dropped).
- Kerberos tests moved with the code: xrdclient's `test_krb5_crypto.py`
  (now `test_krb5_rfc3961.py`), `test_krb5_protocol.py`,
  `test_krb5_mit.py` (with the MIT/xrdcp captures in `tests/_krb5_mit.py`),
  and the library parts of `test_krb5.py`, `test_krb5_kcm.py`,
  `test_krb5_keyring.py`, `test_portable_parsers.py` and
  `test_edge_paths.py` (now `test_krb5_ccache.py`, `test_krb5_client.py`,
  `test_krb5_kcm.py`, `test_krb5_keyring.py`); xgfalclient's status,
  backend and context cases (`test_krb5_gss.py`). The interoperability
  tests against a real MIT KDC and a real `xrootd` stay in xrdclient, whose
  `tests/_krb5kdc.py` regenerates the captures.
- `gsi`: every GSI implementation on the stack, in one package.
  `gsi.gss` is xgfalclient's Globus GSI GSS mechanism (`crypto/gsi.py`:
  `SecurityContext`, `DelegatedCredential`, `GSIError`, `check_host`,
  `dns_names`, `TURN`/`DELEGATE`/`NO_DELEGATION`) with the 3.11/3.12
  `peer_chain_der` bridge from its `_compat`; a delegating client passes any
  credential with a `chain` and a `key` (`DelegatingCredential`), and
  certificates come back as `x509.CertificateData`. `gsi.httpg` is the GSI
  half of xgfalclient's SRM transport (`plugins/srm/transport.py`):
  `HTTPGConnection`, `Handshake` and the turn-skipping `TurnSkippingResponse`.
  `gsi.secgsi` is xrdclient's XrdSecgsi protocol (`auth/gsi.py`: the bucket
  codec, Diffie-Hellman and its group checks, `seal`/`unseal`, both client
  rounds, the delegation round, `check_server`/`ServerCheck`/`server_names`,
  `read_proxy`, `client_ca_hashes`, `choose_digest`), with the round-by-round
  state machine that was `GSICredential`'s as `SecgsiClient`; every refusal
  is an `xrdcore.errors.CredentialError`, and `ServerCheck(bypass=)` lets a
  client name its own way of turning the server check off in the refusal.
  About 1,000 lines moved; xrdclient keeps the adapter to its `kXR_auth`
  framework, xgfalclient a compatibility alias (`crypto.gsi`).
- `delegation.make_proxy_request` (xgfalclient's `crypto.proxy.make_request`)
  and `delegation.sign_globus_request` (the `globus` profile behind its
  `sign_request`, now taking a DER chain and a key and raising
  `DelegationError`); `x509.split_der_certificates` (from xgfalclient's
  `crypto.x509`, returning `CertificateData`).
- `testing.gsi`: the acceptor side every fake GSI server needs, from
  xgfalclient's GridFTP, LFC, dcap and SRM fakes and xrdclient's GSI tests -
  `acceptor`/`accept_tokens` (the GSS token loop over any framing),
  `proxy_owner` (the user's DN behind a proxy subject), `httpg_context`/
  `accept_httpg` (the httpg preamble: TLS 1.3 turn byte, delegation flag) and
  `SecgsiServer`/`SecgsiLogin` (XrdSecgsi's server rounds: the signed or
  unsigned `kXGS_cert`, reading `kXGC_cert`, `kXGS_pxyreq`, reading
  `kXGC_sigpxy`), over RFC 3526 group 14 by default.
- GSI tests moved with the code: xgfalclient's `test_gsi.py` (now
  `test_gsi_gss.py`), the httpg and shim cases of its `test_srm_transport.py`
  and `test_basics.py` (`test_gsi_httpg.py`, `test_gsi_gss.py`), its request
  and DER-chain cases (`test_globus_requests.py`), and the protocol cases of
  xrdclient's `test_gsi.py` (`test_gsi_secgsi.py`, its hand-built server
  replaced by `testing.gsi.SecgsiServer`, which `test_testing_gsi.py` covers).
- Test cases that xgfalclient's suite held for code that now lives here -
  the certificate building blocks, the fallback name and extension readers -
  are in `tests/test_x509.py`; xgfalclient keeps only its own behaviour.
- `proxytool`: the workflow behind `voms-proxy-init`/`voms-proxy-info` and
  `arcproxy`, which xrdclient's `cli/proxy.py` and xrdarc's `proxy.py` +
  `cli/proxy.py` each carried: the user certificate and key search under a
  tool's `Conventions` (`VOMS_PROXY_INIT`, `ARCPROXY`: search order, a lone
  `--cert`, VOMS grouping), `find_user_pair`; `VOMSRequest`/`voms_requests`
  (`VO[:FQAN]` options); `ProxyRequest` (every option as one value);
  `fetch_acs` and `make_proxy` (expired signer refused first, ACs before the
  proxy, contact and warning hooks through a `Progress` protocol - the
  library never prints); `proxy_target` (the proxy file, and the rule that a
  link is followed only at a named path); `read_proxy_info` (read under the
  private-file rules, then `describe_proxy`). New errors
  `NoCredentialError` (a `CredentialError` and a `FileNotFoundError`) and
  `ExpiredCredentialError`.
- `tests/test_shared_core.py`: xgfalclient's shared-core suite run against
  xrdsec on a PKI viewed through xgfalclient's three `BasePKI` hooks, which
  also checks that its `testing.pki.PKI` subclass fits on xrdsec unchanged.
- `testing.fixtures`, a pytest plugin each suite loads with
  `pytest_plugins = ["xrdsec.testing.fixtures"]` (not a `pytest11` entry
  point: installing xrdsec changes no one else's test runs). It replaces the
  copies of the same fixtures in xrdsec's, xrdclient's, xgfalclient's,
  xrdarc's and xrdwms's conftests: the autouse `hermetic` fixture (every
  `X509_*`, `BEARER_TOKEN*` and `KRB5*` variable and `SSL_CERT_FILE`/
  `SSL_CERT_DIR` cleared; an empty `HOME` and `XDG_RUNTIME_DIR`;
  `KRB5CCNAME`/`KRB5_CONFIG` naming absent files; `credentials.TMP_DIR` and
  `GRID_SECURITY_DIRS` pointed at the test's own directories; the TLS
  context and Kerberos ticket caches emptied), the
  `pytest_xrdsec_hermetic(hermetic)` hook a conftest implements to add its
  own variables and paths, the `ambient` marker for interop tests that need
  the real environment, and the `home`, `tmp_dir`, `grid_security`, `pki`
  (session-wide) and `grid_env` fixtures. xrdsec's own suite runs under it,
  so it no longer sees the host's `/etc/grid-security` either; the tests of
  the platform defaults now ask for them explicitly.
- `xrdsec.testing.rawpki` (hand-assembled certificates and PKCS#10
  requests, for the malformed material `xrdsec.testing.pki` will not make)
  and `xrdsec.testing.proxygrid` (a grid laid out on disk and `FakeVOMS`):
  formerly identical private helpers of xrdsec's and xrdclient's suites
  (`tests/_pki.py`, `tests/_proxypki.py`), now one public copy both import.
  `xrdsec.testing.krb5.recording_tgs()`, the recording TGS stand-in both
  suites' `kdc` fixtures had verbatim.
- `xrdsec.gsi.gss.data_contexts(cert, key, ca_path)`: the cached
  `(initiator, acceptor)` TLS context pair of a GSI data channel (GridFTP
  `DCAU A`): both ends present the user's credential and accept a proxy
  chain, no host name check, no session tickets on the acceptor. Was
  xgfalclient's `plugins/gridftp/gsi.py`.
- `xrdsec.testing.pki.PKI.client_context` takes `anonymous=True` (present
  no certificate) and `check_hostname=False` (a GSI peer, named by its
  certificate). Each call is a fresh, uncached context a test may change;
  the clients' test suites, whose lint bans building contexts by hand, get
  theirs here.
- `testing.gsi.exchange_tokens(initiator, responder, rounds=20)`: both ends
  of a GSS exchange in-process, until both are complete and nothing is in
  flight; returns the responder's tokens, `GSIError` if it does not
  converge. It replaces the `drive` loops of xrdsec's `test_gsi_gss.py` and
  xgfalclient's `test_gridftp_gsi.py`.
- `krb5.kdc` reads TCP replies with `xrdcore.sockets.recv_exact`; a KDC
  that hangs up part-way is still an `OSError` (now `ShortRead`, "the peer
  closed the connection after N of M bytes"), so the next KDC is tried.

### Packaging

- Typed (`py.typed`, checked with `mypy --strict`); Python 3.11 to 3.14 on
  Linux and macOS.
- Runtime dependencies: `xrdcore`, `cryptography` and `asn1crypto` only.
- Optional `testing` extra: pytest, for the `testing.fixtures` pytest plugin
  only; nothing else of xrdsec imports pytest.
- Optional `krb5` extra: python-gssapi (`gssapi>=1.12,<2`), for
  `krb5.gss` only; nothing imports it until a GSS context is made. The
  pure-Python Kerberos client needs nothing beyond the runtime
  dependencies. xrdclient's and xgfalclient's own `krb5` extras now pull
  this one.
- The import-boundary tests (`tests/test_package.py`) start their
  `python -I` children with the installed xrdsec and xrdcore (from the
  modules' own `__file__`) and the parent's `sys.path`, not a sibling
  `xrdcore/src` checkout, so they also run from a wheel install or a Nix
  build, where every dependency is on `PYTHONPATH`.
- The test suite covers every line and branch, and the package is held to the
  family's take-over scorecard (every measurement better than the median of 39
  widely used Python libraries).
- A security policy ([SECURITY.md](SECURITY.md)) and contributor guide
  ([CONTRIBUTING.md](CONTRIBUTING.md)).
- The chain's tooling moved to the new
  [xrd-devtools](https://github.com/rob-c/xrd-devtools) repository, used from
  a checkout (it is not on PyPI and cannot be a dependency):
  `tests/test_scorecard.py` is now a few lines loading its scorecard plugin
  (found through pytest's `pythonpath`: `../xrd-devtools/src` or CI's
  `.dependencies/xrd-devtools/src`; it skips, saying so, without one), in
  place of the copy that located xrdclient's `tools/scorecard.py` through
  `XRDCLIENT_CHECKOUT`/`SCORECARD_REQUIRED`. `.github/scripts/check_dist.py`,
  identical in the three libraries, is xrd-devtools' `check_dist.py`; ruff,
  mypy and complexipy no longer list `.github/scripts`.
- CI (`.github/workflows/ci.yml`) calls xrd-devtools' reusable workflows -
  `static.yml` (ruff, mypy, complexipy, the scorecard, made required, and
  `xrddevtools conformance`), `tests.yml`, `package.yml` and `chain.yml` (the
  duplicate and conformance gates over all seven repositories) - with the
  candidates from its one candidates action; `publish.yml` checks
  xrd-devtools out to run `check_dist.py`. CI therefore needs
  `rob-c/xrd-devtools` to exist.

### Code health

- No grandfathered code: ruff's full rule set (`SIM` added) with nothing
  ignored, `mypy --strict` over the tests and release scripts as well as
  the package, complexipy at 15 with no snapshot, and every warning an
  error under pytest. Of 19 `type: ignore`, 2 `noqa` and 3 `pragma: no
  cover`, four ignores remain, all in tests that pass a wrong type or
  assign a frozen field on purpose to prove the runtime refusal, each with
  its reason. `VOMSStatus` is a `StrEnum` that keeps `Enum`'s `str()` and
  `format()`, so it prints exactly as before.
- Skips are environmental only (a tool missing from `PATH`, running as
  root, no scorecard checkout) and say so. The tests' shared helpers are
  modules of their own (`tests/_pki.py`, `tests/_proxypki.py`,
  `tests/_handshake.py`, `tests/_vomspki.py`), never imported from a test
  module.
- Banned APIs (ruff `TID251`; CONTRIBUTING.md explains the list): no
  third-party HTTP stack, no pykrb5, no botocore, no bare
  `ThreadPoolExecutor` (`xrdcore.fanout`), no unguarded XML parser
  (`xrdcore.safexml` - the VOMS fake's tests now parse through it), and
  nothing of xrdhttp or the clients. What xrdsec owns stays allowed: TLS
  context construction, `http.client` (VOMS, httpg) and `gssapi`
  (`krb5.gss` only).
- Release metadata is xrd-devtools' release gate:
  `tests/test_release_metadata.py` is `release_gate(__file__)` from
  `xrddevtools.pytest_plugin` - one version source (`_version.py`, read by
  hatch), a CHANGELOG led by exactly that version's well-formed section,
  project metadata and README that name this repository, and a release
  workflow built through the shared publish action.
- The publish workflow's build job is xrd-devtools' shared `publish`
  composite action (build, `twine check --strict`, the artifact or
  pre-flight checks, a clean install whose tag, runtime version and dated
  changelog section agree, the artifact upload); only the trusted-publishing
  upload to PyPI stays in this workflow's own job.
- The standard's settings in `pyproject.toml` (ruff rules, the banned-API
  table, mypy's strictness and allowed overrides, complexipy, coverage,
  pytest's warnings filter) and CONTRIBUTING's *The code standard*, *Banned
  APIs* table and *xrd-devtools* sections are managed blocks, written by
  `xrddevtools sync` from the standard kept once in xrd-devtools;
  `xrddevtools conformance` fails a hand edit between the markers. The
  repository's own keys and notes sit beside the blocks.
- Banned-API messages for importing a package of the chain built on this
  one now say so ("sits below ... dependency direction"), generated from the
  declared layering.
