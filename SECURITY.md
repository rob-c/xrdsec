# Security

## Reporting a vulnerability

Mail <robert.andrew.currie@gmail.com> with a description and, if you have one,
a reproducer. Please do not open a public issue for anything that could expose
a credential, let one party act as another, or make a client trust a server it
should not. Expect an acknowledgement within a few working days. A fix is
released as a patch version of every supported minor release, and the clients
built on xrdsec (xrdclient, xgfalclient, xrdarc) are released against it at the
same time.

Supported versions: the latest `0.x` minor release. Until 1.0, fixes are not
back-ported to older minors.

## What this library is trusted with

xrdsec is the credential layer of a grid client. It finds, reads, writes and
issues X.509 proxies, reads user certificates and their (possibly encrypted)
private keys, finds WLCG bearer tokens, signs delegated proxies for servers,
fetches and validates VOMS attribute certificates, and builds every TLS client
context the clients use. The threat model has three parties:

- **The network.** Assumed hostile. Every connection xrdsec builds a context
  for is verified by default.
- **The far end.** Assumed to be the host that was named, but not assumed to be
  well behaved. A server's certificate, its delegation request and a VOMS
  server's answer are attacker-supplied data until checked against local trust.
- **The local machine.** Shared with other users, but its root and the user's
  own account are assumed sound. Anything that can read the process memory or
  the user's home directory already has the credentials.

## What the implementation guarantees

**Nothing turns TLS verification off implicitly.** `tls.client_context()`
starts from `ssl.create_default_context()` - chain and host name both checked -
and only `verify=False` relaxes it. A grid CA directory (`ca_path`) is trusted
*instead of* the system store unless `system_ca=True` adds the store back: an
IGTF-vouched storage element should not also be vouchable by every commercial
CA. `x509_strict=False` turns off only the RFC 5280 strictness Python 3.13
enables by default, which some grid CAs predate; verification itself stays on.

**Nothing is presented unless asked for.** A context presents no certificate
unless `cert`, `credential_pem` or `present_default=True` says so, so a
token-only or anonymous client never hands a server the proxy it happens to
find in `/tmp`.

**Revocation is checked when asked, and fails closed.** `check_crl` (or
`XRD_CHECKCRL`) checks the server certificate, or the whole chain, against the
`<hash>.r0` CRLs `fetch-crl` maintains. It is off by default because a missing
or stale CRL fails every handshake that CA signs for. The context cache is keyed
on the CA directory's `stat`, so a `fetch-crl` run takes effect on the next
connection without a restart.

**Credential files must be yours alone.** `credentials.read_private_file()` -
which every proxy, key and token-file read goes through - accepts only a
regular file owned by the effective uid (root included) with no group or other
permission bits, checked with `fstat` on the *open* descriptor, so the file
checked is the file read. At a predictable name (`/tmp/x509up_u<uid>`,
`/tmp/bt_u<uid>`, `$XDG_RUNTIME_DIR/bt_u<uid>`) a symbolic link is refused
(`O_NOFOLLOW`), and a FIFO or device is opened non-blocking and refused, so a
planted file can neither substitute an identity nor hang a login. A file that is
there but fails these checks raises `InsecureCredentialError` naming the file
and the fix; it is never skipped in favour of the next location, because that
would log in with whatever somebody else left at the first. Reads are bounded
(`MAX_CREDENTIAL_SIZE`).

**Credential files are written private and atomically.**
`credentials.write_private_file()` writes to a fresh `mkstemp` file (mode
`0600`, `O_EXCL|O_NOFOLLOW`, unpredictable name) beside the target, flushes it
and renames it into place: no reader ever sees half a credential, nobody else
can read it even briefly, and a symbolic link planted at the target is replaced,
not written through.

**Private keys are not written to disk to make a connection.** A separate key,
an encrypted key and a credential held only in memory (`credential_pem=`,
`ProxyCredential.to_pem()`) reach OpenSSL through pipes, never a temporary
file. `RSAPrivateKey`, `AES` and `ProxyCredential` print `<redacted>` in place
of key material, and no exception message carries a key or a token. Every
xrdsec logger carries `xrdcore.log`'s redaction filter, which interpolates a
record before redacting it, so a token is caught even when it only appears once
the format string and its arguments are joined.

**A GSI server proves who it is before it is delegated to.** `trust` builds the
server certificate's path to a CA *in the local certificate directory* -
anchors never come from the wire - checking every signature, every validity
period, `basicConstraints`, `keyCertSign` and `pathLenConstraint` (RFC 5280
section 6.1.4), and that the certificate names the host that was dialled.
Without the CA checks any user certificate could sign a "server" certificate for
any host.

**Issued proxies obey the rules a verifier enforces.** Whatever the profile, a
limited signer only issues limited proxies, `pCPathLenConstraint` is carried
down and a signer at `0` cannot issue, validity never outlasts the signer's
chain, RFC 3820's prohibitions (alternative names, `cA=TRUE`) cannot be added
through `extra_extensions`, and a delegation request's proof of possession is
checked before its key is certified. One deliberate difference from XrdCrypto:
it writes `inheritAll` whatever the signer was, which would let a delegation
lift a limitation; xrdsec does not.

**VOMS attribute certificates are attacker-supplied until validated.**
`voms.validate_voms()` checks an AC's signature, its signer chain against the
local CA directory and the `vomsdir` `.lsc` files, its validity and its holder
binding, and `inspect_voms()` makes no trust decision at all. Decoding is
bounded (chain depth, number of ACs), and `voms_client.fetch_ac()` reads at most
1 MiB of a VOMS server's answer.

**The cryptography is used, not invented.** TLS is `ssl`; ciphers, RSA,
elliptic-curve and Ed25519 signatures and X.509 parsing are `cryptography`'s;
ASN.1 structures are `asn1crypto`'s. What is local is protocol policy - RFC 3820
proxy rules, VOMS AC policy - and one private-key operation `cryptography`
will not perform: GSI's proof of possession is PKCS#1 v1.5 type-1 padding with
no DigestInfo, done in `rsa.py` with a blinded exponentiation so its timing does
not depend on the secret. These paths are pinned to test vectors and to the real
daemons' output, and are not offered as a general-purpose crypto library.

**A small dependency set and no dynamic execution.** The runtime depends on
`xrdcore` (no dependencies of its own), `cryptography` and `asn1crypto`. Nothing
in the package calls `eval`, `exec`, `pickle` or `subprocess`.

## Limits you should know about

- **JWT signatures are not verified.** `tokens.token_claims()` and
  `check_token()` decode a token's claims unverified, for one purpose: to say
  "your token has expired" before a server answers with a bare `401`.
  Validating the signature is the server's job.
- **GSI server checks do not consult CRLs.** As with a GSI server configured
  with `-crl:0`; CRL freshness is the operator's policy. TLS contexts do consult
  them when `check_crl` asks.
- **`verify=False` is a footgun and is meant to look like one.** It exists
  because self-signed test endpoints exist. Never set it in production.
- **`xrdsec.testing` is test support, not security.** Its eight RSA keys
  (`xrdsec.testing._keys`) are fixed and public, so every certificate made from
  them is forgeable by anyone. Never install a `testing.pki` CA, host or user
  outside a test.
- **A failed VOMS check after `fetch_ac` is a warning.** As with
  `voms-proxy-init`, the machine making a proxy is often not the one that must
  trust it, so `VOMSWarning` is raised as a warning, not an error. The server
  that later validates the AC is the one that decides.

## Auditing your own setup

    python -c "from xrdsec import credentials as c; print(c.find_proxy(), c.grid_ca_path())"
    python -c "from xrdsec.x509 import load_proxy; from xrdsec import credentials as c; print(load_proxy(c.find_proxy()))"

The first shows which proxy and CA directory a client on this machine would
use; the second loads that proxy - through the private-file checks - and prints
its subject with the key redacted.
