# Store listings — QuickAudit v1.0.0

**Status: DRAFT. Nothing has been submitted anywhere.** The copy below is shared across
stores; the per-store notes at the bottom cover what differs.

| Store | Package | Fee | Notes |
|---|---|---|---|
| Chrome Web Store | `quickaudit-1.0.0-chrome.zip` | $5 one-time | Reaches Chrome; Brave/Opera/Vivaldi users install from here too |
| Microsoft Edge Add-ons | `quickaudit-1.0.0-chrome.zip` | **free** | Same package, no code changes |
| addons.mozilla.org | `quickaudit-1.0.0-firefox.zip` | **free** | Human review for extensions requesting `webRequest` |
| Apple App Store | `quickaudit-1.0.0-safari.zip` | **already paid** | Existing BAB Studios membership covers it; needs macOS + Xcode; unverified — see BROWSERS.md |

**Recommendation: submit Chrome + Edge + Firefox first.** Two of the three are free, and
together they cover essentially the entire desktop developer audience.

Safari is now free to publish — the Apple Developer Program membership used for Amora covers
unlimited apps. But it still costs about a day of work that the other three don't: the
extension must be wrapped in a macOS container app with real UI of its own (Apple rejects empty
wrappers under guideline 4.2), signed with a **Mac** App Distribution certificate that doesn't
exist yet, and put through a review that is less predictable than Google's or Mozilla's on a
tool with an active-probing check. Get feedback from the lenient stores first.

---

## Name (45 char limit)

`QuickAudit — web security checklist`

## Short description (132 char limit)

`Run a 10-point OWASP-style security check on any page in one click. Headers, cookies, mixed content, vulnerable JS libraries.`

*(123 characters)*

## Category

Developer Tools

## Detailed description

**A pre-pentest sanity check that takes five seconds instead of fifteen minutes.**

Before you pay for a penetration test — or before you ship — there's a set of boring,
mechanical misconfigurations that show up on a depressing share of production sites. No HSTS.
No CSP. Session cookies without HttpOnly. A `.git` directory served to the public internet.
jQuery 1.8 with four known XSS advisories.

Finding these today means running `curl -I`, squinting at headers you half-remember, checking
DevTools for mixed content, and pasting library versions into a CVE search. That's fifteen
minutes per site, so people skip it, so it ships broken.

QuickAudit is that checklist, as one button.

**The ten checks**

1. **Transport security** — HTTPS, plus HSTS with a `max-age` that actually means something
2. **Content-Security-Policy** — present, enforcing (not report-only), and not defeated by
   `'unsafe-inline'` / `'unsafe-eval'` / wildcards. Nonces and `'strict-dynamic'` are
   understood, so a modern strict policy passes instead of being nagged at
3. **Clickjacking protection** — CSP `frame-ancestors` or `X-Frame-Options`
4. **MIME-sniffing** — `X-Content-Type-Options: nosniff`
5. **Referrer & Permissions policy** — flags policies that leak full URLs to third parties
6. **Cookie security flags** — `Secure`, `HttpOnly` on session cookies, explicit `SameSite`
7. **Mixed content** — `http://` subresources on an HTTPS page, split into active and passive
8. **JavaScript libraries with known CVEs** — versions read from live page globals, script
   URLs and source banners, looked up against **OSV.dev**. Not a hardcoded list that goes
   stale the week it ships
9. **Exposed sensitive files** — `/.env`, `/.git/HEAD`, `/.htpasswd`, `/actuator/env` and
   nine more. **Off by default** (see below)
10. **Server version disclosure** — banners that hand attackers your exact build number

Every finding cites the header or artifact that caused it, and gives you the specific line to
add. No "consider reviewing your security posture."

**About check 9**

Nine of the ten checks are entirely passive — they read what the page already sent your
browser. Check 9 is the exception: it requests about a dozen well-known paths on the site
you're looking at.

It ships **disabled**. Enabling it requires ticking a box confirming you own the site or are
authorised to test it. There's no crawling, no wordlists, no way to aim it at a host you
aren't already on, and it's rate-limited. A finding requires the response body to match a
content signature for that file type, so single-page apps that return HTTP 200 for every path
don't generate a wall of false positives.

**What it is not**

QuickAudit is not a vulnerability scanner and does not replace one. It sends no payloads,
attempts no exploits, and cannot find a business-logic flaw or an IDOR. It is the checklist
you run *first* so a real assessment isn't full of trivia. A perfect score means the ten
common misconfigurations are absent — not that the application is secure. The tool says so
in the report footer.

**Privacy**

QuickAudit sends exactly one kind of data off your machine: detected library `name@version`
strings, to `api.osv.dev`, to look up known CVEs. No URLs. No page content. No cookie values —
the code reads cookie *flags* and deliberately discards values. No analytics. No account. No
telemetry. Results are stored in local extension storage and nowhere else.

Host access is requested **one site at a time, when you click Scan** — not for all sites at
install. Click Scan on `example.com` and Chrome asks you about `example.com`.

**Free vs Pro**

All ten checks are free, unlimited, forever. Pro is a one-time $19 purchase — no
subscription, no account, no server — that unlocks HTML/PDF report export, saved custom check
sets, and scan history. Licence keys verify offline against a public key inside the
extension.

Source: https://github.com/YOURNAME/quickaudit

---

## Permission justifications (required by store review)

Reviewers reject vague answers here, so each is tied to a specific check.

| Permission | Justification |
|---|---|
| `activeTab` | Identifies the page the user explicitly asked to scan when they click the toolbar button. |
| `scripting` | Injects two short collectors into the audited page on demand: one reads `<meta>` CSP tags and the list of loaded subresources (checks 2, 3, 7); one reads library version globals such as `jQuery.fn.jquery` (check 8). Nothing is injected until the user clicks Scan. |
| `cookies` | Check 6 inspects the `Secure`, `HttpOnly` and `SameSite` **flags** of cookies for the audited origin. Cookie values are never read, stored, or transmitted. |
| `webRequest` | Used observationally (no blocking) to capture the response headers of the main-frame navigation, which is the input to checks 1–5 and 10. Reading them from the real navigation is more accurate than re-fetching the page. |
| `storage` | Stores the user's settings, the most recent report, the Pro licence key, and a 6-hour cache of OSV.dev lookups so repeat scans don't re-query the API. |
| `downloads` | Saves the exported HTML report to disk when a Pro user clicks Export. |
| Optional host permissions | Requested **per-origin at scan time**, never at install. Needed to read the audited site's response headers and cookie flags. The user grants access to one site at a time. |

**Remote code:** none. No external scripts, no `eval` of remote content, no CDN. Everything
executes from the packaged files.

**Data usage disclosures to select:**
- Does not collect or use personally identifiable information — ✅
- Does not collect health, financial, authentication, personal communications, location, or
  user activity data — ✅
- Does not collect website content — ✅ (library version strings only, and no page text)
- Not sold to third parties, not used for creditworthiness, not used for unrelated purposes — ✅

**Anticipated review question — "is this a hacking tool?"**
Check 9 is the only one that sends requests. Answer plainly: it is disabled by default,
requires an explicit authorisation acknowledgement, is limited to ~14 fixed paths on the
single origin the user is already viewing, has no crawler and no wordlist input, and exists
so developers can confirm their own deploy isn't leaking `.env`. Point reviewers at the
consent screen in `src/ext/options.html` and screenshot 4.

---

## Screenshots to capture (1280×800)

1. **Popup with a real failing site** — score ring at ~49, several red FAIL rows, one expanded
   showing the offending header and the exact fix line. This is the money shot.
2. **Popup on a well-configured site** — mostly green, score 98. Shows it isn't a fear machine.
3. **QA-08 expanded** — jQuery 1.8.2 with CVE IDs, severities and "fixed in 1.9.0".
4. **Options page, active-check section** — the consent gate, visible and unticked. Doubles as
   the answer to the reviewer question above.
5. **Exported HTML report** — the Pro artifact you'd hand a client.

## Small promo tile (440×280)

Shield mark on white, `QuickAudit` wordmark, strapline *"Ten security checks. One click."*

---

## Per-store notes

**Microsoft Edge Add-ons** — takes the Chromium package unmodified. Registration is free.
The listing form is near-identical to Chrome's, so the copy above pastes straight in. Worth
doing purely because it costs nothing.

**addons.mozilla.org** — free, but extensions requesting `webRequest` get human review, so
expect days rather than hours. Two things AMO reviewers specifically want:

- **Source-code submission.** The extension ships unminified, unbundled ES modules, so the
  uploaded package *is* the source. Say so; there is no build step to reproduce.
- **A clear justification for `webRequest`.** Use the wording from the permissions table
  above: observational only, no blocking, used solely to read main-frame response headers.

AMO also enforces the extension id (`quickaudit@babstudios.dev`) declared in
`browser_specific_settings` — it must stay stable across versions or you lose the listing's
update path.

**Apple App Store** — needs macOS, Xcode, and a $99/year membership. Deferred; see
[BROWSERS.md](BROWSERS.md).

---

## Pre-submission checklist

- [ ] Choose the publishing account (see MONETIZATION.md — this decision is yours)
- [ ] Pay the one-time $5 Chrome Web Store registration fee (Edge and AMO are free)
- [ ] Replace `YOURNAME` in the source URL above and in `README.md`
- [ ] Set a real contact address on the AMO listing (required, and publicly visible)
- [ ] Host a privacy policy at a public URL (text is in `PRIVACY.md`)
- [ ] Capture the five screenshots
- [ ] `npm test` green (unit + compat + integration + both namespace modes)
- [ ] `node tools/build.mjs` → upload the per-store zips from `build/`
- [ ] Load unpacked in **Chrome and Firefox** and click through every check by hand —
      the automated suite stubs the browser APIs; it does not replace one real run per engine
