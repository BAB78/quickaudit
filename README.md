# QuickAudit

A one-click OWASP-style security checklist for the page in your browser tab. Ten checks,
pass/fail, in about a fifth of a second.

Runs on **Chrome, Edge, Brave, Opera, Vivaldi, and Firefox** from one source tree. A Safari
build exists but is unverified — see [BROWSERS.md](BROWSERS.md).

Not a scanner. No payloads, no crawling, no exploitation. It's the checklist you run *first*
so a real assessment isn't full of trivia.

```
QuickAudit https://example.com/
Score 49/100  ·  3 fail 4 warn 2 pass 1 skip

FAIL QA-02 Content-Security-Policy [high]
     No Content-Security-Policy.
     Any injected script — stored XSS, a compromised third-party tag, a malicious ad — runs unrestricted.
     Fix: default-src 'self'; object-src 'none'; base-uri 'self'; and serve scripts with a per-request nonce.
```

## The ten checks

| ID | Check | Severity | Sends requests? |
|---|---|---|---|
| QA-01 | Transport security (HTTPS + HSTS) | high | no |
| QA-02 | Content-Security-Policy | high | no |
| QA-03 | Clickjacking protection | medium | no |
| QA-04 | MIME-sniffing protection | low | no |
| QA-05 | Referrer & Permissions policy | low | no |
| QA-06 | Cookie security flags | high | no |
| QA-07 | Mixed content | medium | no |
| QA-08 | JS libraries with known CVEs (OSV.dev) | critical | lookup only |
| QA-09 | Exposed sensitive files | critical | **yes — off by default** |
| QA-10 | Server version disclosure | low | no |

Full definitions and rationale: [PRD.md](PRD.md).

## Install (development)

```bash
git clone https://github.com/BAB78/quickaudit && cd quickaudit
node tools/make-icons.mjs   # generates icons/
node tools/build.mjs        # generates build/{chrome,firefox,safari}/
```

- **Chrome / Edge / Brave / Opera / Vivaldi** — `chrome://extensions` → Developer mode →
  **Load unpacked** → select `build/chrome`
- **Firefox** — `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** → select
  `build/firefox/manifest.json`
- **Safari** — needs macOS and Xcode; see [BROWSERS.md](BROWSERS.md)

Click Scan. The browser will ask for access to that one origin — QuickAudit requests host
permissions per-site at scan time rather than for all sites at install.

## CLI

The same ten checks, without a browser:

```
node tools/cli.mjs https://example.com
node tools/cli.mjs https://localhost:3000 --json
node tools/cli.mjs https://your-own-site.com --active   # enables QA-09
```

Exits non-zero if any check fails, so it drops into CI as-is.

The CLI can't run page JavaScript, so QA-08 falls back to URL and banner detection and QA-07
sees only markup. The extension is strictly more accurate; the CLI exists so the checks can be
validated against real sites in CI.

## About QA-09

Nine of the ten checks are entirely passive. QA-09 requests ~14 well-known paths on the origin
you're already viewing.

It is **off by default** and enabling it requires an explicit authorisation acknowledgement.
It is capped, rate-limited, origin-locked, and has no crawler and no wordlist input. Findings
require the response body to match a content signature for that file type — status 200 alone
is never a finding — so single-page apps with catch-all routes don't produce a wall of false
positives. Evidence snippets are redacted, so a screenshot of a finding doesn't leak the
secret it found.

Use it on systems you own or are authorised to test.

## Privacy

The only data that leaves your machine is detected library `name@version` strings, sent to
`api.osv.dev` to look up known CVEs. No URLs, no page content, no cookie values (the code
reads cookie *flags* and discards values), no telemetry, no account. See [PRIVACY.md](PRIVACY.md).

## Tests

```bash
npm test                      # everything below except the live corpus
node test/run-tests.mjs       # 62 unit tests — checks, parsers, licence crypto
node test/compat.mjs          # 11 cross-browser manifest + source-portability tests
node test/integration.mjs     #  7 end-to-end tests against local fixture servers
node test/ext-smoke.mjs       # 13 extension-wiring tests × 2 namespace shapes
node test/real-sites.mjs      # 20-site validation corpus (passive only)
node test/audit-accuracy.mjs  # diffs the corpus against independently-written logic
```

**105 tests total.** `ext-smoke.mjs` runs the whole scan flow twice: once with a Chromium-style
promise namespace, once with Firefox's promise `browser` *plus* its callback-only `chrome`
alias — the shape that silently breaks Chrome-first extensions.

`test/fixture-server.mjs` serves three local sites — one deliberately sloppy (exposes `.env`,
`.git`, `phpinfo`, ships jQuery 1.8.3), one hardened, and one that returns HTTP 200 with an
identical shell for every path. That last one is the false-positive trap for QA-09.

Accuracy against the 20-site corpus, including the three false-positive classes it caught in
QuickAudit itself: [ACCURACY.md](ACCURACY.md).

## Architecture

The constraint that shaped everything: **checks must be testable without a browser.**

```text
src/core/      normalization + helpers (headers, cookies, CSP, library detection, OSV client)
src/checks/    ten pure functions: run(PageContext) -> CheckResult. No extension API in here.
src/ext/       MV3 shell: background collector, popup, options, licensing, report export
               browser-api.js is the only file allowed to touch chrome.* / browser.*
tools/         CLI, icon generator, multi-target builder, licence keygen/issuer
test/          unit + compat + integration + extension smoke + real-site corpus
manifest.base.json  shared manifest; tools/build.mjs layers per-engine overrides on top
```

`PageContext` is the seam. The extension builds one from `chrome.cookies` + `webRequest` +
injected collectors; the CLI builds one from `fetch`. The ten checks can't tell the difference,
which is what makes both the corpus run and CI possible.

## Not implemented in v1

Subresource Integrity coverage, CORS misconfiguration, TLS cipher/certificate grading, DNS
records (SPF/DMARC), cookie prefixes, open-redirect detection. Each is a reasonable v1.1
candidate and each needs its own false-positive validation before it ships.

## Licence

MIT. See [LICENSE](LICENSE).
