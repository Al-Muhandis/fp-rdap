# Changelog

English | [Русский](CHANGELOG.ru.md)

Release history of fp-rdap. The release version has four components
`Major.Minor.Release.Build`, as shown by the OPM (Lazarus Online Package
Manager); the release tag is `v<version>`. An entry is added for every
release; observable behavior changes made during development are recorded
in the README, "Changelog" section.

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
