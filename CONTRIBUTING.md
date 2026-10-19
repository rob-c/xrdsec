# Contributing to xrdsec

xrdsec is the one implementation of grid security for xrdclient, xgfalclient
and xrdarc. Changes are welcome when they keep the three properties it is
built around: it does what the grid's own tools (XrdCl, gfal2, ARC,
`voms-proxy-init`) do, so a credential that works with them works here; it
never weakens a security check to make something work; and it depends on no
client.

## Development setup

Python 3.11 through 3.14 are supported. Until xrdcore is published, install it
from a sibling checkout first:

```console
$ git clone https://github.com/rob-c/xrdcore ../xrdcore
$ python3 -m venv .venv
$ .venv/bin/python -m pip install -U pip
$ .venv/bin/python -m pip install -e ../xrdcore -e '.[dev]'
$ .venv/bin/pytest -q -n auto
```

`pyproject.toml` also puts `src` and `../xrdcore/src` on the test and type-check
paths, so a suite run from the shared workspace virtual environment needs
nothing installed. The suite is hermetic: every server it talks to is an
in-process fake on loopback, and no grid credential of yours is read - the
`xrdsec.testing.fixtures` pytest plugin, which every client's suite loads
too, clears the credential environment for each test.

## Definition of done

A change is ready when all of these pass, as CI runs them:

```console
$ ruff check src tests
$ ruff format --check src tests
$ mypy
$ complexipy
$ pytest -q -p no:cacheprovider -n auto --cov --cov-report=term-missing:skip-covered
$ python -m build && twine check --strict dist/*
$ python ../xrd-devtools/src/xrddevtools/check_dist.py contents xrdsec dist
$ xrddevtools conformance --repo .
```

- **Coverage is 100 % of lines and branches** (`fail_under = 100`). Reach it
  with a test that makes the case happen - a malformed input, a refusal, a
  fallback - not with an exclusion.
- **The code standard** (below) holds for every line: nothing suppressed,
  nothing ignored, no snapshot. Fix the code rather than silencing a finding.
- **Types are `mypy --strict`.** The package ships `py.typed`; its
  annotations are part of the API.
- **The take-over scorecard.** `tests/test_scorecard.py` loads the chain's
  scorecard plugin (`xrddevtools.pytest_plugin`) from an
  [xrd-devtools](https://github.com/rob-c/xrd-devtools) checkout and fails if
  any of the twelve measurements of `src` is worse than the median of 39
  widely used Python libraries. Do not lower the bar to land a change; split
  the function, group its options, or explain the code.
- **The chain's gates** pass: the scorecard above, the release-metadata gate
  (`tests/test_release_metadata.py`: one version source, a CHANGELOG led by
  that version, metadata that agrees), `xrddevtools conformance` (the
  standard, and every managed block as `xrddevtools sync` writes it) and
  `xrddevtools dupes` (no function copied into another repository) - all
  from [xrd-devtools](#xrd-devtools).
- **Documentation.** Every module, class and function has a docstring that
  explains purpose, contract, failure modes and why - not a restatement of the
  signature. Name the specification or the tool behaviour being matched. The
  README's module table is the package's map; keep it current.
- **Changelog.** Add user-visible changes to [CHANGELOG.md](CHANGELOG.md) in
  the same pull request.

## The code standard

<!-- >>> xrddevtools sync: code-standard (generated from xrd-devtools/src/xrddevtools/standard) >>> -->
Every repository of the chain is held to one code standard, and every line
of it is held to the standard: old code passes the same checks as new code.

- **Ruff** selects `E`, `F`, `W`, `I`, `UP`, `B`, `C4`, `SIM`, `RUF`, the
  high-confidence security checks `S102`, `S307`, `S506`, `S602`, `S608`,
  `S609`, `S701` and the banned-API rule `TID251` (see *Banned APIs*), with
  `ignore = []` and no per-file ignores, over `src`, `tests`; `ruff format`
  formats it, 100 columns wide.
- **mypy** is strict (Python 3.11) over `src`, `tests`. A test function may
  leave its fixtures unannotated where `pyproject.toml` allows it, but its
  body is still checked; only a named third-party module that ships no types
  may be imported untyped, with the reason beside it.
- **complexipy** allows no function above 15, over `src`, `tests`, with no
  snapshot of old offenders.
- **Coverage** is 100 % of lines and branches, reached by a test that makes
  each case happen. The only exclusions are `if TYPE_CHECKING:`,
  `@overload`, `raise NotImplementedError`, `\.\.\.$`, `if __name__ ==
  .__main__.:`; there is no `omit`.
- **Every warning is an error** (`filterwarnings = ["error"]`): ours are
  fixed, not filtered.
- **No suppression comment**: no `# noqa`, `# pragma: no cover`, `# fmt:
  off`, `# complexipy: ignore` or `# nosec`. A `# type: ignore[code]` only
  where it cannot be avoided (a test passing a wrongly typed value on
  purpose), with its error code and the reason beside it or just above.
- **No snapshot or baseline** of old findings, for any tool.

The settings behind these rules are the managed blocks of `pyproject.toml`
(between `# >>> xrddevtools sync` markers), and this section is one of the
managed blocks of this file (between `<!-- >>> xrddevtools sync` markers).
`xrddevtools sync` writes them all from the standard, kept once in
xrd-devtools (`src/xrddevtools/standard`); `xrddevtools conformance`, which
CI runs, fails if one is edited by hand. To change the standard, change it
there and run `xrddevtools sync --workspace ..` over every repository.
<!-- <<< xrddevtools sync: code-standard <<< -->

## Banned APIs

<!-- >>> xrddevtools sync: banned-apis (generated from xrd-devtools/src/xrddevtools/standard) >>> -->
Ruff's `TID251` rule refuses the APIs whose job another part of the chain
does, in every tree ruff checks (`src`, `tests`), with no per-file ignore
and no `noqa`; the list is `[tool.ruff.lint.flake8-tidy-imports.banned-api]`
in `pyproject.toml`, and each entry's message names what to use instead. A
need for a banned API is met by the library that owns it growing an API,
with its tests - never by an exception here.

| Banned | Use instead | Why |
|---|---|---|
| `urllib3`, `requests`, `httpx` | xrdsec takes no third-party HTTP stack: its few HTTPS calls (voms_client) use http.client with xrdsec.tls contexts | one HTTP stack for the whole chain, with its TLS, redirect and retry rules |
| `urllib.request` | urllib's opener has none of the chain's TLS rules: use http.client with an xrdsec.tls context, as voms_client does | urllib's opener knows none of the grid's TLS (CAs, CRLs, proxies) and follows redirects with credentials attached |
| `krb5` | pykrb5 is not a dependency: credential caches are xrdsec.krb5.caches / xrdsec.krb5.ccache, GSS-API is xrdsec.krb5.gss | the pure-Python ccache, KCM and keyring readers replaced it |
| `botocore`, `boto3` | S3 signing and the S3 codec are xrdhttp.s3 (the xrdhttp[s3] extra); only xrdhttp.s3 imports botocore | S3 signing and the S3 codec, behind the `xrdhttp[s3]` extra |
| `concurrent.futures.ThreadPoolExecutor` | a fan-out is xrdcore.fanout.run_all (first failure raised, the rest stopped); a long-lived pool is xrdcore.fanout.Pool | the first failure raised as itself and the rest stopped; a long-lived pool made on first use and made again in a forked child |
| `xml.etree.ElementTree.XML`, `xml.etree.ElementTree.XMLParser`, `xml.etree.ElementTree.XMLPullParser`, `xml.etree.ElementTree.fromstring`, `xml.etree.ElementTree.fromstringlist`, `xml.etree.ElementTree.iterparse`, `xml.etree.ElementTree.parse`, `xml.dom.minidom`, `xml.dom.pulldom`, `xml.parsers.expat`, `xml.sax.make_parser`, `xml.sax.parse`, `xml.sax.parseString` | parse XML with xrdcore.safexml.fromstring, which refuses DOCTYPEs and entities | it refuses DOCTYPEs, so no entity is declared, expanded or fetched. Building and writing trees (`ET.Element`, `ET.tostring`) and `xml.sax.saxutils.escape` stay allowed |
| `xrdhttp`, `xrdclient`, `xgfalclient`, `xrdarc`, `xrdwms` | - | they are built on this repository; the dependency direction never points up |
<!-- <<< xrddevtools sync: banned-apis <<< -->

What xrdsec owns, it does not ban, though the clients do: building TLS
contexts (`ssl.create_default_context`, `ssl.PROTOCOL_TLS_*` - `tls`,
`gsi.gss.data_contexts`, `testing.pki`), `http.client` (`voms_client` and
`gsi.httpg` speak HTTP without xrdhttp, which xrdsec cannot import) and
`gssapi` (imported only by `krb5.gss`, the one wrapper, behind the `krb5`
extra). Ruff cannot ban an import in every module but one without a
per-file ignore, so that last boundary is a test instead:
`tests/test_package.py` fails if any other module imports `gssapi`.

## xrd-devtools

<!-- >>> xrddevtools sync: devtools (generated from xrd-devtools/src/xrddevtools/standard) >>> -->
The chain's gates and tools - the take-over scorecard and the
release-metadata and maintainability gates, `xrddevtools conformance`,
`dupes` and `sync`, the release pre-flight and the packaging tools - live in
[xrd-devtools](https://github.com/rob-c/xrd-devtools). It is never uploaded
to PyPI and cannot be a dependency (PyPI refuses direct-URL requirements),
so it is used from a checkout:

- **A developer** keeps it beside this repository (`../xrd-devtools`, the
  workspace layout). pytest's `pythonpath` lists `../xrd-devtools/src`, so
  the gate tests find it with nothing installed; `pip install -e
  ../xrd-devtools` once gives the `xrddevtools` command.
- **CI** checks it out under `.dependencies/xrd-devtools` (the shared
  `candidates` action always does), which `pythonpath` lists too. It loads
  the plugin with `pytest -p xrddevtools.pytest_plugin`, which fails at
  start-up if it cannot be imported, and sets `XRD_DEVTOOLS_REQUIRED=1`, so
  a missing radon or complexipy fails rather than skips. This repository's
  workflows are xrd-devtools' reusable workflows and actions: CI runs only
  once `rob-c/xrd-devtools` exists.
- **Anywhere else** - a wheel-only test environment, a distribution build -
  `pip install -e` a checkout or put its `src` on `PYTHONPATH`. Without one,
  the gate tests (`tests/test_scorecard.py`,
  `tests/test_release_metadata.py`) skip, saying why.
<!-- <<< xrddevtools sync: devtools <<< -->

## Layering and compatibility

- **Imports.** xrdsec depends on xrdcore, `cryptography` and `asn1crypto`,
  never on a client and never on xrdhttp. `import xrdsec` imports no
  submodule, and `xrdsec.credentials` must not import `ssl` or
  `cryptography`: it is on every client's import path, `--help` included.
  `tests/test_package.py` pins all three.
- **Security changes.** A change that touches what is trusted, what is
  presented or how a credential file is read or written needs a test that shows
  the refusal, and an update to [SECURITY.md](SECURITY.md) when it changes a
  guarantee or a limit stated there. Never add a fallback that skips a
  credential that failed a check in favour of the next one.
- **Public API.** The clients re-export these names, so a rename or a
  signature change is a change to their public API too. Add, deprecate, then
  remove; never change what an existing keyword means.

## Releasing

1. Set `__version__` in `src/xrdsec/_version.py` (the build reads it from there)
   and date the version's [CHANGELOG.md](CHANGELOG.md) entry.
2. Wait for CI on the release commit, then push an annotated `v<version>` tag.
   The publish workflow rebuilds the sdist and wheel, checks that the tag, the
   runtime version, the wheel metadata and a dated changelog entry agree, and
   uploads to PyPI through trusted publishing. Never upload a local build.
3. Release xrdcore before xrdsec, and xrdsec before the clients that pin it.
