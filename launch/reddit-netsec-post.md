# r/netsec submission

**Flair:** Tool
**Post 2–3 days after the dev.to piece. Never the same day.**

Read r/netsec's rules before posting — tool posts have to be substantive and technical rather
than promotional, and low-effort drops get removed. Post from your own account.

---

## Title

QuickAudit — a 10-check browser extension for the boring pre-pentest stuff, and how the `.env` check avoids the false positives these usually have

---

## Body

I kept doing the same fifteen minutes of manual work before every assessment and every deploy: `curl -I`, squint at the headers, check DevTools for mixed content, paste library versions into a CVE search. So I automated exactly that and nothing more.

It's a browser extension (Chrome/Edge/Firefox, MV3). Ten checks against whatever tab you're on: HSTS, CSP quality, `frame-ancestors`/XFO, `nosniff`, Referrer/Permissions-Policy, cookie flags, mixed content, exposed sensitive files, vulnerable JS libraries, version-disclosing banners.

**It is not a scanner.** No payloads, no crawling, no exploitation, no auth testing. It's the checklist you run first so a real assessment isn't full of trivia. A clean result means the ten common misconfigurations are absent — not that the app is secure, and the tool says so in the report footer.

Three implementation details worth discussing:

### The `/.env` check, which is the only genuinely hard one

Naive versions of this flag any HTTP 200, which means every SPA with a catch-all route reports thirteen critical findings and the tool becomes noise.

This one does three things instead:

1. **Calibrates first.** Requests a random nonexistent path and fingerprints what the origin does with garbage. If it 200s, that body is recorded.
2. **Requires a content signature per file type.** `/.git/HEAD` must match `^ref:\s+refs/`. `/.env` must look like actual `KEY=value` lines *and* must not be HTML. `/.DS_Store` must start with the `Bud1` magic. `/actuator/env` must contain `"propertySources"`.
3. **Never treats status as evidence.** A 200 with no signature match is at most a "worth a manual look", never a finding.

Evidence snippets are also redacted (`KEY=[redacted]`), so a screenshot of a finding doesn't leak the secret it found.

That check is **off by default**, behind an explicit acknowledgement that you own or are authorised to test the target. It's capped at ~14 fixed paths on the origin of the tab you already have open, rate-limited, no crawler, no wordlist input, and there is no way to point it at a host you aren't on. It exists so you can check your own deploy.

### Library CVEs come from OSV.dev, not a bundled list

Versions are read from live page globals (`jQuery.fn.jquery`, `angular.version.full`, …), script URL shapes, and `/*!` source banners, then batch-queried against OSV's npm ecosystem.

A hardcoded advisory table is stale the week you ship it. Two deliberate choices:

- When OSV is unreachable, the check returns **SKIP, not PASS**. I'd rather say nothing than invent a clean bill of health.
- When no version can be determined — which is most bundled apps — it also returns **SKIP**, and says "audit your lockfile instead." Recall here is genuinely poor and pretending otherwise would be the worst thing the tool could do.

The globals are read by walking property paths, not by evaluating expression strings. There is no `eval` or `new Function` anywhere in the shipped source, and a build test fails on either.

### The bug I'd flag for anyone writing something similar

Testing against 20 real sites found three false-positive classes in my own code. The one worth your attention:

I reported **sourceforge.net as missing HSTS**. It isn't — it sends `max-age=31536000; includeSubDomains; preload`. I'd been served a Cloudflare bot-protection interstitial and was faithfully auditing *the challenge page's* headers.

Any header-checking tool that fetches a URL rather than reading a real navigation has this, and it fails toward confident wrongness — no error, no warning, just a clean and completely false finding. It now detects `cf-mitigated`, `x-amzn-waf-action: challenge`, interstitial titles, and WAF 4xx/5xx, and skips every header-dependent check with an explanation. Three of my twenty corpus sites turned out to be unassessable that way.

The other two: I was grading `origin-when-cross-origin` as a full-URL leak (it isn't — origin only), and warning on `X-Frame-Options`-only sites as though XFO were unsupported (every current browser honours it). Both were making the tool cry wolf, which is how you train people to ignore the finding that matters.

### Accuracy

20-site corpus, passive checks only — I did not run the active file-exposure check against third-party hosts, and validated it against local fixture servers instead, including an SPA that returns 200 with an identical shell for every path.

- 102 auto-gradeable verdicts, cross-checked against independently written logic
- 102/102 correct after adjudication; zero confirmed false positives
- 3 of 20 sites declined as unassessable (WAF challenge) rather than guessed at
- Median scan 172 ms

Full matrix with raw headers is in the repo, including the disagreement where my own audit script was wrong and the tool was right.

### Privacy

The only thing that leaves the browser is library `name@version` strings sent to OSV.dev. No URLs, no page content, no cookie values (it reads flags and discards values), no telemetry, no account. Host permissions are requested **per-origin at scan time**, not `<all_urls>` at install — which is also why it doesn't use `webRequest` at all, since Chrome only delivers those events to extensions holding host permissions at install time.

---

Free, unlimited, MIT. Source and the full accuracy write-up: https://github.com/BAB78/quickaudit

Happy to have any of the ten checks torn apart — that's most of why I'm posting.

---

## Prepared answers

**"Why not just use securityheaders.com / Wappalyzer / Retire.js?"**

> Fair — each does one slice of this well. securityheaders.com can't see your cookie flags or your authenticated response and can't reach staging or localhost. Retire.js is the closest prior art on the library check and is good; I use OSV so the advisory data isn't mine to keep current, and fold it into one sheet with the header and file checks. If you already run all three, this mostly saves you the tab-switching.

**"This is just a header checker with extra steps."**

> Largely yes, and that's the point. Six of the ten are header checks and they're the deterministic ones. The value is that it's one click on the page you're already looking at, with the authenticated response and the real cookie store, rather than a form you paste a URL into.

**"Isn't the `.env` probing irresponsible?"**

> It's off by default, gated behind an authorisation acknowledgement, capped at ~14 fixed paths on the origin you already have open, rate-limited, and has no crawler or wordlist input. It sends the same requests you'd send by hand while checking your own deploy. If you think the gate is insufficient I'd genuinely like to hear what would satisfy you — that's the part I'm least certain about.

**If someone reports a false positive:** thank them, ask for the URL and the check ID, and fix it. A false positive in public is worth more than a quiet one, and fixing it fast in the thread is the best possible advertisement for the tool.
