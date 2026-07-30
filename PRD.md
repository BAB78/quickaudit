# QuickAudit — PRD v1

**One line:** A one-click OWASP-style sanity check for the site in your browser tab. Ten concrete checks, pass/fail, in under five seconds.

**Status:** v1 spec, frozen. Buildable in under a week.

---

## 1. Problem

Before you pay for a pentest — or before you ship — there is a set of ~10 boring, mechanical
misconfigurations that show up on a depressing fraction of production sites: no HSTS, no CSP,
cookies without `Secure`, a `.git` directory served over HTTP, jQuery 1.8 with four known XSS
CVEs. Finding these today means running `curl -I`, eyeballing headers you half-remember,
checking DevTools for mixed content, and pasting library versions into a CVE search.

That's 15 minutes of tedium per site, so people skip it, so it ships broken.

## 2. Who it's for

- **Solo devs / small teams shipping web apps** — want a pre-deploy sanity check without learning ZAP.
- **Small security teams / freelance pentesters** — want a 5-second triage pass on a target
  before deciding where to spend real effort. Not a replacement for Burp; a way to skip
  writing the "you're missing HSTS" finding by hand.
- **Agencies doing client handoffs** — want a one-page artifact showing the basics are covered.

**Explicit non-goal:** this is not a scanner. No crawling, no fuzzing, no payloads, no auth
bypass attempts, no DAST. If you want that, use ZAP or Burp. QuickAudit is the checklist you
run *first* so the real tool's report isn't full of trivia.

## 3. Success criteria for v1

| | Target |
|---|---|
| Time from click to full result | < 5s on a typical page (passive checks < 1.5s) |
| False-positive rate on the 10 checks | < 5% across a 20-site validation corpus |
| Checks that produce a *specific, actionable* line of remediation | 10 / 10 |
| Install → first result | < 30 seconds, no config, no account |
| Build effort | ~5 days |

---

## 4. The ten checks in v1

Every check is a pure function `run(PageContext) -> CheckResult` with a deterministic verdict
and evidence. Nothing is "advisory vibes"; every FAIL cites the header or artifact that caused it.

Severity is QuickAudit's own rating of *this misconfiguration on a typical production site*,
not a CVSS score.

### Passive checks (1–7, 10) — read only what the page already sent

**QA-01 · Transport security (HTTPS + HSTS)** — severity: **high**
- FAIL if the page is served over `http:`.
- FAIL if `Strict-Transport-Security` is absent on an HTTPS page.
- WARN if present but `max-age` < 15552000 (180d), or `includeSubDomains` is missing.
- PASS if `max-age >= 15552000` and `includeSubDomains` present.
- Evidence: the raw header value. Fix: exact `Strict-Transport-Security` line to add.

**QA-02 · Content-Security-Policy** — severity: **high**
- FAIL if no `Content-Security-Policy` header (a `<meta>` CSP counts, but downgrades to WARN —
  it can't cover framing or sandbox).
- WARN if present but `script-src` (or `default-src` fallback) contains `'unsafe-inline'`,
  `'unsafe-eval'`, `*`, `http:`, or `data:` — these defeat the point.
- WARN if `object-src` and `base-uri` are unset and no `default-src` covers them.
- PASS otherwise. Report-only policies are detected and reported as WARN, never PASS.
- Evidence: the offending directive. Fix: a starter policy for the detected framework.

**QA-03 · Clickjacking protection** — severity: **medium**
- PASS if CSP `frame-ancestors` is present (modern, correct answer).
- PASS if `X-Frame-Options` is `DENY` or `SAMEORIGIN` and no conflicting `frame-ancestors`.
- WARN if only `X-Frame-Options` with the obsolete `ALLOW-FROM` form, or both present and
  contradicting each other.
- FAIL if neither is present.

**QA-04 · MIME-sniffing protection** — severity: **low**
- FAIL if `X-Content-Type-Options: nosniff` is absent. PASS if present. Binary, no nuance.

**QA-05 · Referrer & Permissions policy** — severity: **low**
- WARN if `Referrer-Policy` is absent (browser defaults are now decent, so not a FAIL).
- FAIL if `Referrer-Policy` is `unsafe-url` or `no-referrer-when-downgrade` — actively leaks
  full URLs cross-origin.
- WARN if `Permissions-Policy` is absent (camera/mic/geo left at defaults).
- PASS if `Referrer-Policy` is a same-origin-or-stricter value and `Permissions-Policy` exists.

**QA-06 · Cookie security flags** — severity: **high**
- Reads real cookie objects (`chrome.cookies`) plus any `Set-Cookie` on this response.
- FAIL for any cookie on an HTTPS page missing `Secure`.
- FAIL for any *session-looking* cookie (name matches `sess|sid|auth|token|jwt|login|remember`)
  missing `HttpOnly`.
- WARN for any cookie with `SameSite=None` or unset (Chrome defaults to Lax, but the header
  should be explicit).
- PASS if all cookies are `Secure` + session cookies are `HttpOnly` + `SameSite` explicit.
- Evidence: per-cookie table of which flag is missing. Cookie *values* are never read or stored.

**QA-07 · Mixed content** — severity: **medium**
- On an HTTPS page, FAIL if any subresource was requested over `http:` (script/iframe/xhr =
  active mixed content, FAIL at high confidence; image/media/font = passive, WARN).
- Collected from the content script via `PerformanceResourceTiming` + a DOM sweep of
  `src`/`href`/`srcset`/inline `url()`.
- Mitigating: if CSP has `upgrade-insecure-requests` or `block-all-mixed-content`, downgrade
  to WARN and say so.

**QA-10 · Server version disclosure** — severity: **low**
- WARN if `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`,
  or `X-Drupal-*` disclose a *version number* (regex `\d+\.\d+`).
- INFO (pass) if the header exists but is version-less (`Server: cloudflare`).
- Rationale: version banners turn "scan the internet" into "grep for this version."

### Library check (8) — passive collection, network lookup

**QA-08 · JavaScript libraries with known CVEs** — severity: **critical**
- Detects library + version from three sources, in confidence order:
  1. **In-page globals** (`jQuery.fn.jquery`, `angular.version.full`, `React.version`,
     `Vue.version`, `_.VERSION`, `moment.version`, `bootstrap.Tooltip.VERSION`, `d3.version`,
     `Handlebars.VERSION`, `DOMPurify.version`, `axios.VERSION`, …) — highest confidence.
  2. **Script URL patterns** — `/jquery-3.4.1.min.js`, `/npm/lodash@4.17.11/`, cdnjs and
     unpkg path shapes.
  3. **Source-comment banners** in the first 2KB of a script (`/*! jQuery v3.4.1`).
- Queries **OSV.dev** `POST /v1/querybatch` (npm ecosystem) — one request for all detected
  libraries — then `GET /v1/vulns/{id}` for details on hits only.
- FAIL if any library has a HIGH or CRITICAL vuln; WARN for MODERATE/LOW.
- Evidence: library, detected version, CVE IDs, severity, one-line summary, fixed version.
- **Why OSV and not a bundled list:** a hardcoded table is stale the week you ship it. OSV is
  maintained, free, no API key, and covers the npm ecosystem these libraries publish to.
  Results are cached 6h in `chrome.storage.local` keyed by `name@version` so repeat scans are
  free and offline-tolerant.
- Degrades to SKIP (not FAIL) if OSV is unreachable — never invent a verdict.

### Active check (9) — sends requests, off by default

**QA-09 · Exposed sensitive files** — severity: **critical**
- Probes a fixed list of ~13 paths on the current origin: `/.env`, `/.git/HEAD`, `/.git/config`,
  `/.svn/entries`, `/.DS_Store`, `/.htpasswd`, `/.npmrc`, `/.aws/credentials`, `/phpinfo.php`,
  `/server-status`, `/actuator/env`, `/backup.sql`, `/wp-config.php.bak`.
- **False-positive control (this is the whole difficulty of the check):**
  1. First request a random non-existent path to *calibrate*. If the origin returns 200 for
     garbage (SPA catch-all), record the body fingerprint.
  2. A path is only flagged if status is 200 **and** the body matches a
     **content signature** for that specific file type (e.g. `/.git/HEAD` must match
     `^ref:\s+refs/`, `/.env` must match `^\s*[A-Z_][A-Z0-9_]*\s*=`), **and** the body is not
     the calibration body.
  3. Status alone never produces a finding.
- **Consent gate:** this is the only check that sends unsolicited requests. It is **OFF by
  default**. Turning it on requires an explicit one-time acknowledgement that the user owns or
  is authorized to test the target. Requests are `GET` only, capped at 14, serialized with a
  150ms delay, and only ever hit the origin of the tab you are looking at. There is no crawl,
  no wordlist mode, and no way to point it at a host you aren't on.

### Deliberately out of scope for v1

Subresource Integrity coverage, CORS misconfiguration, `robots.txt`/`sitemap` leakage, TLS
cipher/cert-chain grading, DNS records (SPF/DMARC), cookie-prefix checks, and open-redirect
detection. All are reasonable v1.1 candidates; none are needed to make the first version
useful, and each adds a false-positive surface that needs its own validation corpus.

---

## 5. Architecture

The build constraint that matters: **checks must be testable without a browser.**

```
src/core/      normalization + helpers (headers, cookies, library detection, OSV client)
src/checks/    10 pure functions: run(PageContext) -> CheckResult.  No chrome.* here.
src/ext/       Chrome MV3 shell: service worker (collector), content script, popup UI
tools/cli.mjs  same checks, run from Node against any URL
test/          unit tests over fixtures + a local fixture server + the real-site harness
```

`PageContext` is the seam. The extension builds one from `chrome.cookies` + `webRequest` +
content-script collection; the Node CLI builds one from `fetch`. The ten checks can't tell the
difference, which is what makes Phase 3 (20 real sites) and CI both possible.

## 6. Permissions & privacy

- `storage` — settings + OSV cache. `cookies` — read cookie *flags* for QA-06.
- `scripting`/`activeTab` — inject the collector on demand.
- **Host permissions are optional and requested per-origin at scan time**, not granted at
  install. You click Scan on `example.com`, Chrome asks about `example.com`.
- **No data leaves the browser except:** library `name@version` strings sent to OSV.dev.
  No URLs, no page content, no cookie values, no telemetry, no accounts. Stated plainly in
  the listing and the README.

## 7. Monetization (v1)

Free tier is the full ten checks, unlimited, forever — that's the thing worth having.
**Pro, one-time $19**, unlocks: PDF/HTML report export, custom check sets (enable/disable +
severity overrides per profile), scan history, and CSV export. Offline license-key check
(signed key, verified locally) so there is no subscription billing, no server, and no account
system to build or run.

## 8. Risks

| Risk | Mitigation |
|---|---|
| QA-09 flagged as "hacking tool" in store review | Off by default, consent gate, no wordlist, single origin, documented in listing |
| `<all_urls>` slows store review | Optional per-origin permissions instead |
| OSV npm ecosystem ≠ CDN-hosted builds | Version-range matching only; SKIP on lookup failure; never guess |
| False positives destroy trust faster than missed findings | Content signatures for QA-09, calibration request, 20-site corpus with documented accuracy |
