# Phase 3 — accuracy report

**Corpus:** 20 real sites, 10 chosen as likely-hardened (security vendors, large engineering
orgs) and 10 as likely-looser (older stacks, CMS-driven, content properties).
**Run date:** 2026-07-30. Raw evidence: `test/real-sites-results.json`.

**Passive checks only.** QA-09 (exposed sensitive files) was *not* run against any
third-party site. Probing other people's servers for `/.env` to benchmark a tool is not
something to do casually, so QA-09 is validated against local fixture servers instead
(`test/integration.mjs`), including the SPA catch-all case that is its main false-positive risk.

---

## Headline numbers

| | |
|---|---|
| Sites scanned | 20 |
| Sites yielding reportable results | **17** (3 correctly declined — see below) |
| Auto-gradeable verdicts audited | **102** |
| Verdicts agreeing with independent logic | **101 / 102 (99.0%)** |
| Verdicts correct after manual adjudication | **102 / 102 (100%)** |
| Confirmed false positives | **0** |
| Median scan time | **172 ms** |
| Hardened-bucket average score | 86 / 100 |
| Mixed-bucket average score | 78 / 100 |

Method: `test/audit-accuracy.mjs` re-derives the expected verdict for QA-01/02/03/04/05/10
straight from the recorded raw headers, using logic written separately from `src/checks/`,
then diffs it against what QuickAudit reported. Disagreements are adjudicated by hand against
an independent `Invoke-WebRequest` fetch of the live site.

**The one disagreement — and QuickAudit was right.** On `about.gitlab.com` the audit script
expected `QA-02: fail` (no CSP header); QuickAudit reported `warn`. QuickAudit had parsed a
`<meta http-equiv="Content-Security-Policy">` out of the page body, which the header-only
audit script never looks at. Independently confirmed present. The naive checker was wrong.

## Three false positives found and fixed during this phase

The corpus earned its keep — it exposed three real bugs, all now fixed and regression-tested.

**1. WAF challenge pages were being audited as if they were the site.**
`sourceforge.net` was reported as "No Strict-Transport-Security". An independent fetch showed
sourceforge sends `max-age=31536000; includeSubDomains; preload`. QuickAudit had been served a
Cloudflare bot-protection interstitial (`cf-mitigated` header, 44 ms response) and was
faithfully describing *the challenge page's* headers.

This is a false-positive class that would have made the tool untrustworthy on any WAF-fronted
site. `detectChallenge()` now recognises `cf-mitigated`, `x-amzn-waf-action: challenge`,
interstitial titles, and WAF 403/429/503s; when one fires, every header-dependent check
returns `skip` with an explanation rather than a finding. Three corpus sites — npmjs.com,
sourceforge.net, imdb.com — are now correctly declined rather than wrongly reported.

Note this affects the CLI far more than the extension: the extension reads the headers the
user's own browser received on a real navigation, which has already passed any challenge.

**2. `origin-when-cross-origin` was graded as a URL leak.** It isn't — it sends the origin
alone cross-origin, not the path. It was in the same bucket as `unsafe-url`. Now only
`unsafe-url` fails; `no-referrer-when-downgrade` and `origin-when-cross-origin` warn. This
also stopped `stripe.com` being marked FAIL for a policy that leaks far less than the label
implied.

**3. `X-Frame-Options`-only sites were warned at.** Every current browser still honours XFO,
so `X-Frame-Options: SAMEORIGIN` is genuine clickjacking protection, not a defect. It now
passes with a note recommending `frame-ancestors`. This had been firing on stripe, python.org,
nasa.gov and sourceforge — four warnings that were pedantry, not findings. (It was also a
deviation from the PRD, which specified PASS.)

## QA-08 (vulnerable libraries) — spot-checked individually

Six sites produced a detection; the CVE-bearing one was verified by hand.

| Site | Detected | Verdict | Verified |
|---|---|---|---|
| python.org | jquery@1.8.2, jquery-ui@1.12.1 | warn | ✅ Page source confirms `jquery-1.8.2.min.js` and `jquery-ui-1.12.1.min.js`; live page globals independently report `jQuery.fn.jquery = 1.8.2` and `jQuery.ui.version = 1.12.1`. 5 + 4 real advisories (CVE-2020-11023, CVE-2019-11358, CVE-2021-41182, …), all MODERATE, so `warn` not `fail` — correct. |
| owasp.org | jquery@3.7.1 | pass | ✅ current, no advisories |
| apache.org | jquery@3.7.1 (banner) | pass | ✅ |
| nasa.gov | jquery@3.7.1 (banner) | pass | ✅ |
| jquery.com | jquery@4.0.0 | pass | ✅ |
| w3schools.com | html5shiv@3.7.0, respond.js@1.4.2 | pass | ✅ no npm advisories |

Zero spurious library detections across all 20 sites — the URL denylist (`app`, `main`,
`bundle`, `vendor`, …) and the date-version filter did their job. No `/static/app-1.2.3.js`
was ever mistaken for a library.

**Recall is the real limitation, not precision.** 11 of 17 scannable sites yielded no library
detection at all. Modern bundlers strip version markers, and the Node collector cannot read
page globals. This is why QA-08 returns **`skip`, never `pass`**, when nothing is detected, and
says so: *"A clean result here is not a clean bill of health — audit your lockfile instead."*
The extension does materially better here, since it reads live globals: on python.org the
in-browser probe recovered `jquery@1.8.2` and `jquery-ui@1.12.1` directly from `window`.

## Per-site results

Legend: `+` pass · `~` warn · `X` fail · `.` skip

```
                                     01 02 03 04 05 06 07 08 09 10   score
https://github.com/                   +  +  +  +  ~  +  +  .  .  +     98
https://www.cloudflare.com/           +  ~  +  +  +  ~  +  .  .  +     84
https://www.mozilla.org/en-US/        ~  ~  +  +  ~  +  +  .  .  +     82
https://stripe.com/                   +  +  +  +  ~  +  +  .  .  +     98
https://about.gitlab.com/             ~  ~  X  X  ~  +  +  .  .  +     64
https://www.npmjs.com/                .  .  .  .  .  .  .  .  .  .    n/a  (WAF challenge)
https://bitwarden.com/                ~  ~  +  +  +  +  +  .  .  +     84
https://1password.com/                +  ~  +  +  ~  X  +  .  .  +     70
https://owasp.org/                    +  ~  +  +  +  +  +  +  .  +     92
https://www.hackerone.com/            +  ~  +  +  ~  +  +  .  .  +     90
https://news.ycombinator.com/         ~  ~  +  +  ~  +  +  .  .  +     82
https://www.wikipedia.org/            +  X  X  X  ~  ~  +  .  .  ~     49
https://www.python.org/               +  ~  +  X  ~  +  +  ~  .  +     72
https://www.apache.org/               +  ~  +  X  ~  +  +  +  .  +     84
https://jquery.com/                   X  +  +  X  ~  +  +  +  .  ~     69
https://www.w3schools.com/            X  ~  +  X  ~  +  +  +  .  +     64
https://sourceforge.net/              .  .  .  .  .  .  .  .  .  .    n/a  (WAF challenge)
https://www.imdb.com/                 .  .  .  .  .  .  .  .  .  .    n/a  (WAF challenge)
https://www.bbc.co.uk/                ~  +  +  +  +  +  +  .  .  +     92
https://www.nasa.gov/                 +  X  +  X  ~  +  +  +  .  +     72
```

Notable true positives, all independently confirmed:

- **wikipedia.org** (the portal page) — no CSP, no `X-Frame-Options`, no `nosniff`.
- **about.gitlab.com** — no framing protection and no `nosniff` on GitLab's marketing site.
- **1password.com** — `unleash-session-id` cookie set without `Secure` on an HTTPS origin.
  The accompanying HttpOnly flag comes from a *name* heuristic and the report now says so;
  the missing `Secure` is a plain fact about the header.
- **jquery.com, w3schools.com** — no HSTS at all.
- **nasa.gov, imdb.com, wikipedia.org** — no CSP.

## Honest limitations

- **The header checks are the reliable ones.** QA-01/03/04/10 are near-deterministic. QA-02
  grades *policy quality*, which is a judgement call; it deliberately warns rather than fails
  on weakened-but-present policies.
- **QA-06 depends on where cookies come from.** In Node only `Set-Cookie` on this one response
  is visible; in the extension the browser cookie store is authoritative and complete. The
  `HttpOnly` finding is name-heuristic and is labelled as such.
- **QA-07 under-reports in the CLI**, which sees only markup, not runtime-injected resources.
  The extension reads `PerformanceResourceTiming` plus a DOM sweep and catches both — verified
  in a real browser, where it correctly caught an `http://` script the browser had *blocked*
  (blocked resources leave no performance entry, which is why both sources are needed).
- **A 100 score means "the ten common misconfigurations are absent."** It is not a statement
  about the application's security. Both the report footer and the store listing say this.
- **Three sites could not be assessed at all** because their WAF never showed us the page.
  Reporting that honestly is the correct outcome; users on those sites should run the
  extension while actually viewing the page.
