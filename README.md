# fp-rdap

English | [Русский](README.ru.md)

RDAP client for Free Pascal / Lazarus: queries to domain and IP registries over
the RDAP protocol ([RFC 9082]/[RFC 9083]) with routing through the official IANA
bootstrap files ([RFC 8524], [RFC 9224], [RFC 9225]).

## Features

- Queries: `domain`, `ip`, `autnum`, `entity`.
- IDNA: U-label domains (e.g. `пример.рф`) are converted to A-labels before the
  query and the bootstrap lookup — punycode (RFC 3492) plus fp-idn's pragmatic
  IDNA mapping (case folding, label separators, rejection of invalid names).
- Automatic RDAP server selection by domain (multi-label TLDs, `co.uk`) or IP
  (longest-prefix-wins) from the IANA bootstrap files; bootstrap files are
  loaded from disk or from a string.
- Result statuses: `rqsOK`, `rqsNotFound`, `rqsRateLimited`, `rqsError` + parsing
  of the RDAP error object (`errorCode`/`title`) and the `Retry-After` header.
- Connection/IO timeouts, User-Agent, redirects, response size limit
  (`MaxResponseSize`, 10 MB by default, 0 — no limit).
- SOCKS5 proxy: `ProxyHost`/`ProxyPort`/`ProxyUser`/`ProxyPass` — when `ProxyHost`
  is not empty queries go through the proxy (the transport switches to Synapse
  `THTTPSend`, TLS via the Synapse OpenSSL plugin); when empty — the previous
  behavior, unchanged (parity with fp-whois `TWhoisClient`).
- Built-in mock (`TRDAPClientMock`) for network-free tests.

## Layout

| Path | Purpose |
|------|---------|
| `src/rdapclient.pas` | The whole library: client, bootstrap, pure helpers (IP/CIDR/domains) |
| `rdap_rt.lpk` | Lazarus package (runtime-only) |
| `tests/` | FPCUnit tests: console and GUI runners |
| `demo/` | Console demo |

## Installation

Install the `rdap_rt.lpk` package into Lazarus (Package → Open → Install) or
simply add `src/rdapclient.pas` to your project. Requires FPC 3.2+, FCL
(fpjson, fphttpclient), the
[`fpidn_rt`](https://github.com/al-muhandis/fp-idn) package (fp-idn, punycode
for IDNA conversion), the Synapse package (`laz_synapse` — SOCKS5 proxy
transport) and OpenSSL libraries in PATH for HTTPS.

## Quick start

```pascal
uses rdapclient;

var
  B: TRDAPBootstrap;
  C: TRDAPClient;
begin
  // Put the files from https://data.iana.org/rdap/ next to the program
  B := TRDAPBootstrap.Create;
  try
    B.LoadFromLocalFiles('dns.json', 'ipv4.json', 'ipv6.json');
    // Or from a string: B.LoadDNSFromString(EmbeddedDNSSnapshot);

    C := TRDAPClient.Create;
    try
      C.Bootstrap := B;                       // the bootstrap is not owned by the client
      C.QueryDomain('example.com');
      case C.LastStatus of
        rqsOK:          Writeln(C.GetObjectTitle, ' | ', C.GetObjectType);
        rqsNotFound:    Writeln('Not found');
        rqsRateLimited: Writeln('Rate limited, retry after ', C.RetryAfter, 's');
      end;
    finally
      C.Free;
    end;
  finally
    B.Free;
  end;
end;
```

Without a bootstrap, set `C.BaseURL := 'https://rdap.org/'` — but then
`QueryAutNum`/`QueryEntity` will also require an explicit `BaseURL` (the
bootstrap does not cover them).

To test your own code, use `TRDAPClientMock`: `SetupMock(json, code)`,
`SetupMock(json, code, ['Retry-After: 120'])` (with response headers),
`SetupMockError(msg)`; URL history — `MockRequestURL(i)`.

## Tests

```bash
C:\laz-4.8\lazarus\lazbuild.exe --pcp=C:\laz-4.8\config_lazarus tests\rdap_tests.lpi
tests\rdap_tests.exe --all --format=plain
```

Unit tests never touch the network — the network layer is replaced by a mock.

## Demo

`demo/rdap_demo.lpi` — put the `dns.json`, `ipv4.json`, `ipv6.json` files from
https://data.iana.org/rdap/ next to the exe; without them the demo falls back
to `https://rdap.org/`.

On Windows the demo switches the console output to UTF-8 (`SetConsoleOutputCP`)
for the duration of the run and restores the previous code page on exit —
non-ASCII strings (object titles, error messages, JSON previews) are printed
without mojibake; a console font with Unicode support is required (modern
Windows has one by default).

Manual check of the SOCKS5 transport with a live proxy:

```bash
rdap_demo --proxy=127.0.0.1:1080 --proxy-user=u --proxy-pass=p
```

Without `--proxy` the demo goes direct, as before.

## Limitations

- The client is not thread-safe: one instance per thread.
- IDNA is punycode (RFC 3492) plus fp-idn's pragmatic IDNA mapping: case
  folding (ASCII, Cyrillic `U+0400..U+042F`, Greek), the `．`/`。`/`｡`
  separators are treated as `.`, invalid labels (control characters and space,
  `<>"/\?#@:|`, DNS length limits 63/253) are rejected with `ERDAPError`.
  No NFC normalization: the composed and decomposed forms of the same name
  encode to different A-labels — pass names in NFC.
- A response larger than `MaxResponseSize` (10 MB by default) is cut off with
  `ERDAPError`; 0 disables the limit.
- The SOCKS5 proxy mode (non-empty `ProxyHost`) differs from the direct path:
  - SOCKS5 only (`SocksType` — the Synapse default); SOCKS4 is not supported;
    no-auth when `ProxyUser` is empty, user/pass when set;
  - `MaxResponseSize` is applied **after** the full body is downloaded: there
    is no mid-read abort like on the direct path — a body over the limit is
    downloaded in full and only then rejected;
  - redirects are handled manually: up to 5 hops, absolute `Location` only
    (http/https); a relative `Location` yields `ERDAPError`;
  - TLS over the SOCKS5 tunnel is transparent, but HTTPS targets still need
    OpenSSL libraries — same as on the direct path;
  - network-level TLS-over-SOCKS is not covered by unit tests (the loopback
    stub does not speak TLS; the tunnel is transparent, the Synapse plugin is
    trusted).

## License

MIT — see [LICENSE](LICENSE).

## Changelog

Release history — in [CHANGELOG.md](CHANGELOG.md).

### 2026-11-15 — SOCKS5 proxy in the transport (roadmap stage 6)

- New: the `ProxyHost`/`ProxyPort`/`ProxyUser`/`ProxyPass` properties (parity
  with fp-whois `TWhoisClient`; `ProxyPort` has no hidden default). When
  `ProxyHost` is not empty queries go through a SOCKS5 proxy; when empty the
  behavior has not changed in any way (all previous tests stay green without
  edits).
- The proxy-mode transport is Synapse `THTTPSend`; a new dependency of
  `rdap_rt.lpk` is `laz_synapse`. No-auth when `ProxyUser` is empty, user/pass
  when set (verified against the Synapse 40.1 sources: `SocksOpen` always
  chooses SOCKS5 with the default `SocksType`, the roadmap's SOCKS4 concern
  does not apply to this version). `ConnectTimeout`/`IOTimeout` apply here
  too; TLS over the tunnel goes through the `ssl_openssl` plugin.
- Redirects in proxy mode are a manual loop of up to 5 hops (parity with
  `AllowRedirect`/`MaxRedirects=5` of the direct path), absolute `Location`
  only; a relative one is `ERDAPError`.
- `MaxResponseSize` in proxy mode is applied after the full body is downloaded
  (a mid-read abort, like on the direct path, is impossible) — the divergence
  is documented under "Limitations".
- `Retry-After`, response headers and error objects work identically on both
  paths (the header snapshot is normalized to the `:` separator — Synapse used
  `=`, which would break header lookups).
- Tests: a loopback SOCKS5 stub (`TThread` + a listening socket, no network or
  DNS): 8 new tests — 200/429+`Retry-After`/CONNECT refusal/302 redirect/
  relative `Location`/user-pass/property defaults; 80 tests in total.
- Demo: the CLI parameters `--proxy=host:port`, `--proxy-user=`, `--proxy-pass=`
  for manual checks with a live proxy.
- Build: the AGENTS.md/README commands were switched to the `C:\laz-4.8`
  installation (`--pcp=C:\laz-4.8\config_lazarus`) — the previous `C:\lazarus`
  is broken, and its config referenced a non-existent `laz_synapse` path.
- Release steps (the lpk version, `FpRdap.json` DependenciesAsString, a
  CHANGELOG entry, tag/CI) — at publication time, as agreed in the roadmap.

### 2026-11-14 — Adaptation to fp-idn 1.1.0.0: IDNA validation and case folding

- **Behavior change:** `DomainToASCII` raises `ERDAPError` ("Domain rejected by
  IDNA validation…") for domains rejected by fp-idn validation (space/control
  characters in a label, `<>"/\?#@:|`, DNS length limits). Previously (fp-idn
  before 1.1.0.0) an invalid domain silently produced an empty result and went
  out as a query with an empty path.
- Case folding (MVP: ASCII, Cyrillic, Greek): `Example.COM` → `example.com`,
  `ПРИМЕР.РФ` now encodes to the registered A-label `xn--e1afmkfd.xn--p1ai`
  (previously the name passed through byte-by-byte and produced an unrelated
  A-label). The `．`/`。`/`｡` separators are treated as `.`.
- The `rdap_rt` package declares a minimum `fpidn_rt` dependency version of 1.1.
- No NFC normalization — as before: pass names in NFC.
- Tests: case folding, rejection of an invalid domain by the helper and by the
  client (the query never reaches the network); "Limitations" rewritten.

### 2026-11-14 — IDNA: U-labels are converted to A-labels (backlog)

- **Behavior change:** `QueryDomain` no longer rejects non-ASCII domains
  (U-labels): every non-ASCII label is converted to a punycode A-label
  (`пример.рф` → `xn--e1afmkfd.xn--p1ai`, RFC 3492 via the fp-idn package)
  before the bootstrap server lookup and the query. Previously such a domain
  was rejected with `ERDAPError` ("Domain must be an ASCII A-label…").
- The conversion happens before the server selection: the official RFC 9224
  bootstrap files list IDN TLD keys in A-label form (`dns.json` is pure ASCII),
  so U-label domains are now routed correctly.
- New pure helper `DomainToASCII` (exported for tests): ASCII names, including
  ready A-labels, pass through byte-by-byte; the conversion is punycode only,
  without nameprep/UTS-46 normalization or case folding (see "Limitations").
- New dependency: the runtime package `fpidn_rt`
  ([fp-idn](https://github.com/al-muhandis/fp-idn)), required by `rdap_rt.lpk`.
- README: in "Limitations" an outdated note about the unlimited response size
  was fixed (it contradicted `MaxResponseSize` from the previous backlog
  entry).

### 2026-11-14 — HTTP response size limit (backlog)

- **Behavior change:** the new `TRDAPClient.MaxResponseSize` property — the
  maximum response body size in bytes, 10 MB by default; 0 (or less) disables
  the limit. A response over the limit is not read into memory in full: the
  real client aborts the download at the first overrun with `ERDAPError`
  ("Response from … exceeds the size limit…"). Previously a body of any size
  was read in full — a broken/hostile server could exhaust memory.
- On overrun: status `rqsError`, the body is not kept in `LastRawJSON`,
  `LastHTTPCode` holds the actual HTTP response code (if it arrived). The
  limit is inclusive: a body of exactly `MaxResponseSize` bytes passes. The
  limit also applies to the mock (the same contract in `ExecuteQuery`), so it
  is covered by network-free unit tests.

### 2026-11-13 — Cleanups and small fixes (roadmap stage 5)

- **Behavior change:** `QueryDomain` rejects non-ASCII domains (U-labels,
  e.g. `пример.рф`) with `ERDAPError` ("Domain must be an ASCII A-label…").
  RFC 9082 expects an A-label/punycode in the URL path; previously a U-label
  was sent percent-encoded as UTF-8, which RDAP servers do not answer with a
  correct result. IDNA conversion was not supported.
- Trailing `/` normalization of the base URL happens in one place — when the
  query URL is built. `Create` and the `BaseURL` property store the value as
  given (previously `Create` appended `/` in place). The resulting query URLs
  did not change.
- Demo: the saved file name `rdap_example_*.json` is sanitized — characters
  invalid in Windows file names (`:`, `/` etc.) are replaced with `_`.
- Compiler hints in the library sources are gone: the `FillChar` in
  `TryStrToIPv6` was replaced with explicit initialization by zero constants.

### 2026-11-13 — Bootstrap robustness (roadmap stage 4)

- All bootstrap loading methods
  (`LoadDNS`/`LoadIPv4`/`LoadIPv6`/`Load*FromString`) follow a
  parse-then-swap scheme: a failed reload (a broken or missing file, JSON
  without `services`) no longer leaves the bootstrap empty — the previously
  loaded data keeps working. Previously the fields were cleared before
  parsing.
- Base URL selection from a bootstrap record is validated strictly: the URL
  part of a record must be an array of strings (a single string is also
  acceptable), all elements must be strings, the URL must not be empty. A
  violation → `ERDAPError` with the record number ("Service N"); foreign
  fpjson exceptions (`EConvertError`/`EJSONError`) no longer escape.
- New methods `LoadIPv4FromString`/`LoadIPv6FromString` — symmetric to
  `LoadDNSFromString`.

### 2026-11-13 — RFC 9083 error codes (roadmap stage 3)

- **Breaking change:** HTTP 400/401/403/503 no longer raise an exception —
  like 404/429, they arrive as the `rqsError` status. The response body (the
  RFC 9083 §6.2 error object) is parsed into
  `LastErrorCode`/`LastErrorTitle`/`LastJSON`, the raw text stays in
  `LastRawJSON`; if the body is not JSON, the status is still `rqsError` and
  `LastErrorCode` = 0. Previously these codes led to `ERDAPError`
  ("Unexpected response status code").
- Responses with codes outside the `[200, 400, 401, 403, 404, 429, 503]` list
  (e.g. 500) still raise `ERDAPError`.

### 2026-11-13 — Response headers and Retry-After (roadmap stage 2)

- The headers of the last response are part of the general client machinery:
  the snapshot is stored in a protected field of `TRDAPClient` (cleared before
  every query), access via the protected virtual `GetResponseHeader`. The
  `Retry-After` parsing moved from `DoHTTPGetJSON` to `ProcessLastResponse` —
  a single path for the real client and the mock.
- `RetryAfter` now understands both RFC 7231 forms: a number of seconds and an
  HTTP-date (a date in the past → 0, an unreadable value → 0). Previously only
  the "number of seconds" form was recognized. New pure helper —
  `TryParseRetryAfter`.
- The mock can set response headers: `SetupMock(json, code, ['Retry-After: 120'])`.
- The observable behavior barely changed: `RetryAfter` is now non-zero for the
  date form of the header and resets to zero if the response never made it to
  parsing (e.g. 200 with broken JSON).

### 2026-11-13 — UTF-8 correctness (roadmap stage 1)

- All library strings are UTF-8 by contract. The `rdapclient` unit sets
  `DefaultSystemCodePage := CP_UTF8` for the whole process in its
  `initialization` section: without this, fcl-json from FPC 3.2.2 on Windows
  with a non-UTF-8 system encoding corrupts `\uXXXX` escapes and literal
  non-ASCII bytes when parsing responses, regardless of the `GetJSON` flag.
  Using the unit overrides the host application's default code page — keep
  this in mind if the application relies on the system ANSI encoding.
- Bootstrap files are read explicitly as UTF-8
  (`LoadFromFile(..., TEncoding.UTF8)`): previously `TStrings` decoded them
  with the system ANSI encoding.
- `ParseJSONSafe`/`TryParseJSON` use `GetJSON(..., True)`.

### 2026-11-14 — The parse boundary does not depend on the code page (backlog: fcl-json and UTF-8)

- A clarification to the 2026-11-13 entry: on Windows with a non-UTF-8 system
  encoding, fcl-json 3.2.2 corrupts literal non-ASCII bytes regardless of the
  `GetJSON` flag (a code page conversion at the `string` → `UTF8String` call
  boundary), while `\uXXXX` escapes are corrupted only with `UseUTF8=False`
  (verified with a probe on cp1251; with `UseUTF8=True` the escapes survive).
- `ParseJSONSafe`/`TryParseJSON` pass a private copy of the body to `GetJSON`,
  retagged to `CP_UTF8` without conversion (`Utf8JSONArg`): parsing no longer
  depends on the code page tag of the input string. On a host with a UTF-8
  code page this is a no-op, the observable behavior did not change.
- The global `DefaultSystemCodePage := CP_UTF8` setting remains necessary:
  reading parsed values (`AsString` → `String`) and bootstrap file loading
  convert the code page. Per the FPC 3.3.1 sources, fcl-json parses input
  code-page-independently (the scanner itself encodes escapes to UTF-8 and
  tags tokens `CP_UTF8`), but the output conversions do not: removing the
  global setting is possible only after refactoring all string boundaries
  (plan — in the roadmap).

[RFC 9082]: https://www.rfc-editor.org/rfc/rfc9082
[RFC 9083]: https://www.rfc-editor.org/rfc/rfc9083
[RFC 8524]: https://www.rfc-editor.org/rfc/rfc8524
[RFC 9224]: https://www.rfc-editor.org/rfc/rfc9224
[RFC 9225]: https://www.rfc-editor.org/rfc/rfc9225
