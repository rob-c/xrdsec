# xrdsec

Grid security and credential handling shared by
[xrdclient](https://github.com/rob-c/xrdclient),
[xgfalclient](https://github.com/rob-c/xgfalclient) and
[xrdarc](https://github.com/rob-c/xrdarc): X.509 certificates and RFC 3820
proxies, proxy delegation, VOMS, WLCG bearer tokens, credential discovery
and client TLS.

Before this package each client carried its own copy of these pieces, or
imported another client's private modules to get them. xrdsec is the one
implementation, written on top of `cryptography` and `asn1crypto`; it
depends on [xrdcore](https://github.com/rob-c/xrdcore) for errors and logging, and on no client.

```python
from xrdsec import credentials, discovery, proxies, tls, tokens
from xrdsec.x509 import load_proxy

# The proxy and CA directory every grid tool would use, and a TLS context for them.
proxy = credentials.find_proxy()
context = tls.client_context(cert=proxy, ca_path=credentials.grid_ca_path())

# Or gfal2's whole search order, with gfal2's lenient X.509 checks.
found = discovery.discover_x509(discovery.GFAL2)
context = tls.client_context(
    cert=found.cert if found else None,
    key=None if found is None or found.is_proxy else found.key,
    ca_path=discovery.discover_ca_dir(discovery.GFAL2),
    x509_strict=False,
)

# Answer a GridFTP server's delegation request the way Globus would.
signer = load_proxy(proxy)
certificate = proxies.issue_proxy(signer, request, profile="globus")

# voms-proxy-init, in memory: a fresh key, its proxy, VOMS ACs embedded.
fresh = proxies.create_proxy(signer, voms_acs=acs)

# The WLCG bearer token, with a URL's own token and the caller's setting first.
token = tokens.discover_token(token=configured_token, query=url_query)
```

## `xrd-auth`: the command over this package

Everything here is reachable from one command, installed by
[xrdclient](https://github.com/rob-c/xrdclient) as **`xrd-auth`** — and, under its
older name, **`xrd-proxy`**. The two are the same program; the usage line, the
version banner and every error follow whichever you typed.

```sh
pip install xrdclient        # brings xrdsec with it, and the command
xrd-auth --version
xrd-auth doctor --summary     # one line per check, and what to do about each
```

It has grown past proxies, which is why it has two names: it makes and inspects
X.509 proxies, acquires WLCG bearer tokens, registers itself as a client when an
issuer allows it, and runs a doctor that explains what is wrong with your
credentials in words you can act on.

### The commands

| command | what it does | the tool it replaces |
|---|---|---|
| `xrd-auth init` | make a proxy from a certificate, a PKCS#12 bundle, or a proxy | `voms-proxy-init` |
| `xrd-auth info` | describe a proxy: subject, VOMS ACs, time left; `-verify` checks it | `voms-proxy-info` |
| `xrd-auth destroy` | remove it | `voms-proxy-destroy` |
| `xrd-auth doctor` | check the whole credential chain, and say who to ask | — |
| `xrd-auth token init` | get a WLCG bearer token | `htgettoken`, `oidc-agent` |
| `xrd-auth token info` | describe a token, or one embedded in a DIRAC proxy | `htgettoken -i` |
| `xrd-auth token destroy` | remove it | — |
| `xrd-auth token providers` | the named issuers, and what each one advertises | — |
| `xrd-auth token register` | register this tool as a public client (RFC 7591) | — |

Options take **one dash** as the VOMS tools do (`-voms lhcb`, `-valid 24:00`), and
the two-dash spellings work too. Every command takes `--json`/`--xml` and `-quiet`.

### Credentials

```sh
# from a PKCS#12 bundle, with LHCb's VO attributes
xrd-auth init -p12 ~/mycert.p12 -voms lhcb -valid 24:00 -out ~/.x509up

# what it made
xrd-auth info -file ~/.x509up -vo -fqan -timeleft

# a token, by the flow that fits
xrd-auth token init --provider wlcg --flow device      # browser + code
xrd-auth token init --provider wlcg --flow x509 --p12 ~/mycert.p12 --pwstdin
xrd-auth token init --flow exchange --from-token "$TOKEN" --scope storage.read:/
```

An issuer will not hand out a token to an unnamed client. `xrd-auth token register`
asks an issuer that allows self-registration (the WLCG reference IAM does; LHCb's
IAM answers `403 You do not have enough privileges`), and keeps the client id in
`~/.config/xrdsec/token-clients.json` (`0600`) so later runs find it. Issuers whose
own tools ship a public client need none — LHCb's DiracX is one:

```sh
xrd-auth token init --provider lhcbdiracx --flow device --out ~/.condor/tokens.d/lhcb
```

Tokens are written to `--out`, else `$BEARER_TOKEN_FILE`, else `bt_u<uid>` in the
working directory — `0600`, never through a symlink.

### What it knows about where things are

Four stages, in order: the environment (`X509_CERT_DIR`, `X509_USER_PROXY`,
`X509_VOMS_DIR`, `BEARER_TOKEN_FILE`), the machine (`/etc/grid-security/…`,
Homebrew's prefix, then a bundle in your home: `~/grid-ca/…`,
`~/.grid-security/…`), CVMFS (`/cvmfs/grid.cern.ch/etc/grid-security`, then
`/cvmfs/cvmfs-config.cern.ch`), and the working directory. `xrd-auth doctor`
prints each stage it tried, so a missing file is never a mystery.

Settings follow one precedence everywhere — **a command-line option beats the
environment, and the environment beats a profile**:

| variable | what it sets |
|---|---|
| `WLCG_TOKEN_ISSUER`, `WLCG_TOKEN_AUDIENCE`, `WLCG_TOKEN_SCOPE` | what to ask for |
| `WLCG_CLIENT_ID` (or `WLCG_TOKEN_CLIENT_ID`) | which client to be |
| `WLCG_TOKEN_ALGORITHM` | the signature to request (default `RS256`) |
| `DIRACX_URL`, `DIRACX_CLIENT_ID` | the same two, as LHCb's own clients name them |

### The doctor

`xrd-auth doctor` is the part worth running first, and it speaks to three
audiences on purpose — what you can do, what needs your admin, and what needs your
experiment:

```
!!  certs       no grid CA directory: X509_CERT_DIR is unset and no usual directory is there
                 -> do: mount the WLCG bundle at /cvmfs/grid.cern.ch/etc/grid-security/certificates
!!  voms        no VOMS server configured: a proxy would carry no VO attributes
                 -> ask your admin: install the VO's vomses file in ~/.voms/vomses
```

### One detail worth knowing

An HTCondor-CE can only verify **RS256** and **ES256** signatures
(`scitokens-cpp` has no Ed25519 support), so `token init` asks for RS256 by default
and reports the signature it got. When an issuer signs with something else — LHCb's
DiracX currently signs Ed25519 — it says so plainly, because such a token cannot be
presented at a CE at all.


## Modules

| module | what it is |
|---|---|
| `der`, `rsa`, `aes`, `p256`, `ed25519`, `signatures` | DER encoding and the primitives, as grid protocols shape them |
| `x509` | certificates and proxy files: reading, proxy rules (XrdCl's and Globus'), building blocks |
| `proxies` | the one proxy issuer - profiles `rfc3820` (default), `arc`, `xrootd`, `globus`, `globus-legacy` - with `issue_proxy`, `create_proxy`, `write_proxy`, `load_credential`, `load_p12`/`credential_from_p12` (a PKCS#12 bundle as a credential), `describe_proxy`/`ProxyInfo`, `voms_extension` |
| `delegation` | the PKCS#10 request parser, the certificate builder, XrdCrypto's `sign_proxy_request` (the `xrootd` profile), Globus' `sign_globus_request` (the `globus` profile) and `make_proxy_request` (what a delegation target sends) |
| `userproxy` | an in-memory proxy from a user certificate and key (`XrdSecgsi`'s `createpxy`) |
| `trust` | is this GSI server who it says it is, before delegating to it |
| `gsi` | GSI itself. `gsi.gss`: Globus GSI GSS-API - `SecurityContext` (TLS in tokens, the TLS 1.3 turn, the delegation byte, delegation both ways, `ssl_compatible`), `check_host` (`CN=host/fqdn`), `DelegatedCredential`, `data_contexts` (the cached TLS pair of a GridFTP `DCAU A` data channel). `gsi.httpg`: `HTTPGConnection`/`Handshake`, httpg as an `http.client` connection (SRM). `gsi.secgsi`: XRootD's XrdSecgsi - the XrdSut bucket codec, Diffie-Hellman over the server's group (signed and unsigned), the AES session, `SecgsiClient` (both rounds and delegation), the login-time `check_server`, `read_proxy` |
| `voms` (+ private `_voms`) | VOMS attribute certificates: inspect, validate, `vomses` |
| `voms_client` | obtaining ACs: `find_vomses`, `servers_for`, `fetch_ac` (VOMS REST, with fail-over) |
| `proxytool` | the `voms-proxy-init`/`voms-proxy-info`/`arcproxy` workflow behind `xrd-proxy` and `xrdarc proxy`: `Conventions` (`VOMS_PROXY_INIT`, `ARCPROXY`), `find_user_pair`, `voms_requests`, `ProxyRequest`, `Progress` hooks, `fetch_acs`, `require_alive`, `make_proxy`, `proxy_target`, `read_proxy_info`, `NoCredentialError`, `ExpiredCredentialError` |
| `credentials` | `find_proxy`, `default_proxy_path`, `find_user_credential`, `find_bearer_token`, `grid_ca_path`, `grid_voms_dir`, `read_private_file`, `write_private_file` - each taking `environ=`/`uid=`; `TMP_DIR` and `GRID_SECURITY_DIRS` point a test suite's `/tmp` and `grid-security` somewhere hermetic |
| `tokens` | a URL's own token in front of the WLCG search; unverified JWT claims and expiry (`token_claims`, `token_expiry`, `check_token`) |
| `lifetime` | the credential in use now: `ProxyFile`/`BearerToken` providers re-read on every `current()`, `Credential` (kind, path, expiry, identity; a token's value never in `repr`), `chain_expiry`, `assess` (expired / short of a minimum / low / fine) and `CredentialWatch` (warn once per expiry, notice a renewed credential per consumer) |
| `usercred` | presenting a user certificate and key - or a credential held in memory - without a combined file |
| `discovery` | each tool's whole X.509 search order as data: `XRDCLIENT`, `GFAL2`, `GFAL2_SEED`, `ARC`; `discover_x509(uid=)`, `discover_ca_dir(grid_security=)` |
| `tls` | `client_context(...)`: one cached builder for every client's TLS, with CRLs, the system store, `x509_strict`, GSI's `check_hostname=False` and ALPN |
| `krb5` | Kerberos 5. `krb5.client`: the pure-Python client - `service_credentials` (a service ticket from a `FILE:`/`DIR:`/`KCM:`/`KEYRING:` cache, from the KDC by a TGS exchange when the cache has only the TGT, and a forwarded TGT on request), `tickets`, `inspect_cache` (klist's headline), `clear_cache`; underneath it `model`, `rfc3961` (the AES enctypes), `asn1`, `ccache`, `kcm`, `keyring`, `caches`, `profile` (`krb5.conf`), `kdc` and `tgs` (`build_ap_req`, `build_krb_cred`). `krb5.gss`: GSS-API contexts through python-gssapi (the `krb5` extra) - `ClientContext`/`AcceptorContext`, wrap/unwrap/MIC, `KerberosError` with an `errno`, and `initiator_ap_req` (the system library's raw AP-REQ, for XRootD) |
| `testing.pki` | a throwaway CA directory, host, user and proxies of every kind, CRLs and fresh TLS contexts (a client's may present nothing or skip the host name) |
| `testing.voms` | VOMS ACs, `vomsdir`/`vomses` helpers, VOMS proxies and `FakeVOMSServer` |
| `testing.https` | `FakeHTTPSServer`: the route table, faults (including `hold=`, a server gone silent), request log (`Request.get_all` for repeated headers) and client identities every HTTP(S) fake builds on; `join_timeout=` for a deterministic `stop()`; `handler_class` for a fake with its own wire behaviour (xrdhttp's fake storage element). Range and WebDAV reply helpers are `xrdhttp.testing`'s. |
| `testing.gsi` | the acceptor side for fake servers: `acceptor`/`accept_tokens` (GSS token loops), `exchange_tokens` (both ends in-process, for tests), `proxy_owner`, `httpg_context`/`accept_httpg` (the httpg preamble), `SecgsiServer` (XrdSecgsi's server rounds, over RFC 3526 group 14 by default) |
| `testing.krb5` | `make_ticket` and `write_ccache` (a version 4 FILE cache), `FakeKcm` (a KCM daemon on a Unix socket, MIT's extensions or Heimdal's refusals) and `fake_gssapi_module` (python-gssapi with a toy mechanism and armable failures) |
| `testing.fixtures` | the pytest plugin each suite loads with `pytest_plugins = ["xrdsec.testing.fixtures"]` (deliberately not a `pytest11` entry point, so installing xrdsec changes no one else's pytest runs): the autouse `hermetic` fixture (every `X509_*`, `BEARER_TOKEN*`, `KRB5*`, `SSL_CERT_*` variable cleared; empty `HOME`, `XDG_RUNTIME_DIR`, `TMP_DIR` and `GRID_SECURITY_DIRS`; TLS and Kerberos caches emptied), the `pytest_xrdsec_hermetic(hermetic)` hook through which a suite's conftest adds its own variables and paths, the `ambient` marker that opts a test out, and the `home`, `tmp_dir`, `grid_security`, `pki` and `grid_env` fixtures |

`import xrdsec` imports no submodule; each loads when first named.
`xrdsec.credentials` imports neither `ssl` nor `cryptography`, so a client
may put it on every import path.

The public API has the names and signatures xrdclient 0.4.0 publishes as
`xrdclient.credentials`, `xrdclient.tls`, `xrdclient.voms_client`,
`xrdclient.crypto.*` and `xrdclient.testing.{pki,voms}`, without
xrdclient's types, so a client can re-export it.

## Installation

```sh
pip install xrdsec
pip install 'xrdsec[krb5]'    # GSS-API Kerberos through the system library (python-gssapi)
```

Python 3.11 to 3.14; wheels of every dependency exist for Linux and macOS, so
nothing is compiled. The package is typed (`py.typed`).

## Development

xrdsec is developed beside xrdcore and the clients, using the shared
virtual environment one directory up, with nothing installed into it -
`pyproject.toml` puts `src` and `../xrdcore/src` on the test path:

```sh
cd xrdsec
../.venv/bin/python -m pytest -q -n auto      # 100 % line and branch coverage with --cov
../.venv/bin/ruff check src tests && ../.venv/bin/ruff format --check src tests
../.venv/bin/mypy                             # strict, over src and tests
../.venv/bin/complexipy                       # no function above 15, no snapshot
```

See [CONTRIBUTING.md](https://github.com/rob-c/xrdsec/blob/main/CONTRIBUTING.md)
for a standalone setup and what a change needs, and
[SECURITY.md](https://github.com/rob-c/xrdsec/blob/main/SECURITY.md) for the
threat model, the guarantees and how to report a vulnerability. Changes are
in [CHANGELOG.md](https://github.com/rob-c/xrdsec/blob/main/CHANGELOG.md).

## Licence

LGPL-3.0-or-later; see `LICENSE` and `COPYING`.
