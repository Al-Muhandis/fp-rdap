# Changelog

English | [Русский](CHANGELOG.ru.md)

Release history of fp-rdap. The release version has four components
`Major.Minor.Release.Build`, as shown by the OPM (Lazarus Online Package
Manager); the release tag is `v<version>`. An entry is added for every
release; observable behavior changes made during development are recorded
in the README, "Changelog" section.

## Unreleased

New: the `rdapcli` console utility. The package version and the OPM
artifacts are deliberately untouched here — the release steps (version
bump, tag, manifest rebuild) happen separately.

### Added

- `cli/rdapcli.lpi` — a console whois-style front end to the library:
  auto-detected query type (a valid IPv4/IPv6 literal → `ip`, `AS` + digits →
  `autnum`, anything else → `domain`; `--type=` override for entity handles),
  `--raw` output of the response body to stdout, `--bootstrap-dir=DIR` with
  the `https://rdap.org/` fallback, SOCKS5 options `--proxy=host:port` /
  `--proxy-user=` / `--proxy-pass=`, English `-h`/`--help`. Exit codes:
  0 — ok, 1 — not found (HTTP 404), 2 — rate limited (HTTP 429, with
  `Retry-After`), 3 — everything else. Results go to stdout, notices and
  errors to stderr. On Windows the UTF-8 arguments are parsed from the wide
  (UTF-16) command line — the RTL `ParamStr` goes through the system ANSI
  codepage and mangles non-ASCII queries (e.g. IDN domains) on hosts whose
  system codepage cannot represent them.
- `TRDAPQueryType` and the pure helper `DetectQueryType` (exported per the
  helpers-for-tests convention): query type auto-detection built on the
  exported IP parsers — the same syntax `QueryIP` accepts.
- The pure helper `AutNumToAsplain`: folds the optional case-insensitive
  "AS" prefix followed by digits to the asplain key required in the RFC
  9082 autnum path segment; anything else passes through unchanged.

### Changed

- **Behavior change:** `QueryAutNum` normalizes the query key to the
  asplain form required by RFC 9082 §3.1.2 (via `AutNumToAsplain`, like
  `QueryDomain` folds U-labels to A-labels): `QueryAutNum('AS15169')`
  queries `autnum/15169`, previously `autnum/AS15169` — a form redirectors
  like rdap.org answer with 404. The rdapcli utility dropped its own
  folding accordingly. Tests: 83 (three new, one updated).

## 1.1.0.1 — 2026-11-19

English-first documentation, per the OPM maintainer's recommendation on the
1.1.0.0 submission. No code changes: the library is identical to 1.1.0.0.

### Changed

- README.md and CHANGELOG.md are now English; the Russian text moved
  unchanged to README.ru.md and CHANGELOG.ru.md, cross-linked via a
  language switcher at the top of each file.
- The OPM repository package (FpRdap.zip) ships both language variants of
  the README and CHANGELOG from this release on.

## 1.1.0.0 — 2026-11-19

SOCKS5 proxy in the transport (roadmap stage 6). The first release available
for installation from the Lazarus Online Package Manager (OPM).

### Added

- `ProxyHost`/`ProxyPort`/`ProxyUser`/`ProxyPass`: when `ProxyHost` is not
  empty, queries go through a SOCKS5 proxy (no-auth when `ProxyUser` is
  empty, user/pass when set); when empty, the behavior has not changed in
  any way. The proxy-mode transport is Synapse `THTTPSend` (a new dependency
  of `rdap_rt.lpk` is `laz_synapse`), TLS over the tunnel goes through the
  `ssl_openssl` plugin; `ConnectTimeout`/`IOTimeout` apply in proxy mode too.
- Redirects in proxy mode are a manual loop of up to 5 hops, absolute
  `Location` only (a relative one — `ERDAPError`). `MaxResponseSize` in
  proxy mode is applied after the full body is downloaded — the divergence
  from the direct path is documented in the README ("Limitations").
- Demo: the CLI parameters `--proxy=host:port`, `--proxy-user=`,
  `--proxy-pass=`.
- Tests: a loopback SOCKS5 stub (`TThread` + a listening socket, no network
  or DNS) — 8 new tests, 80 in total.

## 1.0.0.0 — 2026-11-14

First public release: RDAP client for Free Pascal / Lazarus.

### Added

- `domain`, `ip`, `autnum`, `entity` queries (RFC 9082/9083).
- Routing via the IANA bootstrap files (RFC 8524/9224/9225): loading from
  disk or from a string, longest-prefix for IPs, multi-label TLDs for
  domains; the reload is fault-tolerant (parse-then-swap), `services`
  records are validated on lookup.
- IDNA: U-label domains are converted to A-labels — punycode (RFC 3492)
  plus fp-idn's pragmatic IDNA mapping (case folding for ASCII/Cyrillic/
  Greek, label separators, rejection of invalid names with `ERDAPError`)
  via the `fpidn_rt` package ≥ 1.1
  ([fp-idn](https://github.com/al-muhandis/fp-idn)).
- Result statuses `rqsOK`/`rqsNotFound`/`rqsRateLimited`/`rqsError`; parsing
  of the RFC 9083 error object and the `Retry-After` header (a number of
  seconds and an HTTP-date).
- `MaxResponseSize` — a response size limit (10 MB by default) with a
  download abort; connection/IO timeouts, User-Agent, redirects.
- `TRDAPClientMock` for network-free tests: body/code/response headers,
  URL history.
- All library strings are UTF-8 by contract; JSON parsing does not depend
  on the process code page.

### Requirements

FPC 3.2+, FCL (fpjson, fphttpclient), the `fpidn_rt` package, OpenSSL
libraries in PATH for HTTPS.
