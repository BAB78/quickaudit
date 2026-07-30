# Phase 6 — launch copy

**Status: drafts. Nothing posted.** Both communities punish self-promotion, so these are
written as "here's a thing I made and what I learned," with the tool as the footnote.

Before posting anywhere: read r/netsec's rules on tool posts. They require the tool to be
substantive and the post to be technical rather than promotional; low-effort tool drops get
removed. **Post from your own account, and don't post to both on the same day.**

---

## r/netsec

Suggested flair: **Tool**

**Title**

> QuickAudit — a 10-check browser extension for the boring pre-pentest stuff (headers, cookie
> flags, mixed content, OSV-backed library CVEs)

**Body**

> I kept doing the same fifteen minutes of manual work before every assessment and every
> deploy: `curl -I`, squint at the headers, check DevTools for mixed content, paste library
> versions into a CVE search. So I automated exactly that and nothing more.
>
> It's a Chrome MV3 extension. Ten checks, pass/fail, on whatever tab you're looking at:
> HSTS, CSP quality, frame-ancestors/XFO, nosniff, Referrer/Permissions-Policy, cookie flags,
> mixed content, exposed sensitive files, vulnerable JS libraries, version-disclosing banners.
>
> **It is not a scanner.** No payloads, no crawling, no exploitation. It's the checklist you
> run first so a real assessment isn't full of trivia.
>
> Three implementation notes that might be interesting:
>
> **Library CVEs come from OSV.dev, not a bundled list.** Versions are read from live page
> globals (`jQuery.fn.jquery`, `angular.version.full`, …), script URL shapes, and `/*!` source
> banners, then batch-queried against OSV's npm ecosystem. A hardcoded advisory table is stale
> the week you ship it. When OSV is unreachable the check returns SKIP, not PASS — I'd rather
> say nothing than invent a clean bill of health. Same when no version can be determined,
> which is most bundled apps: "audit your lockfile instead."
>
> **The `/.env` check is the whole difficulty of the tool.** Naive versions flag any HTTP 200,
> which means every SPA with a catch-all route reports thirteen critical findings. This one
> first requests a random nonexistent path to fingerprint what the origin does with garbage,
> then requires the response body to match a content signature for that specific file type —
> `/.git/HEAD` must match `^ref:\s+refs/`, `/.env` must look like actual `KEY=value` lines and
> must not be HTML. Status alone is never a finding. Evidence snippets are redacted so a
> screenshot of a finding doesn't leak the secret it found.
>
> That check is also **off by default** behind an authorisation acknowledgement, capped at ~14
> fixed paths, rate-limited, and locked to the origin of the tab you're already on. No
> wordlists, no crawler. It's there so you can check your own deploy.
>
> **Testing it against 20 real sites found three false-positive classes in my own code**, which
> was the most useful part of building it. The one I'd flag for anyone writing something
> similar: I reported sourceforge.net as missing HSTS. It isn't — I'd been served a Cloudflare
> bot-protection interstitial and was faithfully auditing *the challenge page's* headers. Any
> header-checking tool that fetches rather than reading a real navigation has this bug. It now
> detects `cf-mitigated` / `x-amzn-waf-action` / interstitial titles and skips every
> header-dependent check with an explanation, instead of confidently describing a page that
> isn't yours. Three of my twenty corpus sites turned out to be unassessable that way.
>
> The other two: I was grading `origin-when-cross-origin` as a full-URL leak (it isn't — it
> sends the origin only), and warning about `X-Frame-Options`-only sites as though XFO were
> unsupported (every current browser honours it). Both were making the tool cry wolf.
>
> Accuracy write-up with the full 20-site matrix and raw headers is in the repo. 102/102
> auto-gradeable verdicts correct after adjudication, zero confirmed false positives —
> though precision was never the hard part; recall on bundled libraries is genuinely poor and
> the tool says so rather than pretending otherwise.
>
> Privacy, since it's a security tool and you should ask: the only thing that leaves the
> browser is library `name@version` strings to OSV.dev. No URLs, no page content, no cookie
> values (it reads flags and discards values), no telemetry, no account. Host permissions are
> requested per-origin at scan time rather than `<all_urls>` at install.
>
> Free and unlimited. Source and the accuracy report are linked below. Happy to take apart any
> check that's wrong — that's most of why I'm posting.
>
> [repo] [store listing]

**If asked "why not just use securityheaders.com / Wappalyzer / Retire.js":**

> Fair — each does one slice of this well. securityheaders.com can't see your cookie flags or
> your authenticated response, and can't reach staging or localhost. Retire.js is the closest
> prior art on the library check and is good; QuickAudit uses OSV so the advisory data isn't
> mine to keep current, and folds the result into one pass/fail sheet with the header and file
> checks. If you already run all three, this mostly saves you the tab-switching.

---

## dev.to

**Title**

> I tested my security extension against 20 real sites and found three bugs — in my own tool

**Tags:** `security`, `webdev`, `javascript`, `showdev`

**Canonical:** set to your own site if you cross-post.

**Body outline** — the post is the *testing*, not the tool. The tool appears in paragraph one
and then at the end.

> **Opening.** I built QuickAudit, a browser extension that runs ten OWASP-style checks on the
> page you're on. Then I pointed it at twenty real sites — ten security vendors, ten older
> properties — expecting a validation exercise. It was a bug hunt, and the bugs were mine.
>
> **Bug 1: I was auditing Cloudflare's challenge page and calling it your website.**
> Show the actual output: QuickAudit reporting `sourceforge.net` has no HSTS, next to a
> `curl -I` showing `max-age=31536000; includeSubDomains; preload`. Explain the 44ms response
> time and the `cf-mitigated` header that gave it away. Land the general lesson: *any* tool
> that fetches a URL instead of reading a real navigation inherits this, and it fails toward
> confident wrongness — the worst direction. Show `detectChallenge()` and the decision to skip
> every header check rather than report on a page that isn't the user's.
>
> **Bug 2: I misread a spec I'd have sworn I knew.** I had `origin-when-cross-origin` bucketed
> with `unsafe-url` as a "leaks full URLs cross-origin" failure. It doesn't — it sends the
> origin and drops the path. Include the MDN table. Lesson: when you encode a spec into a
> lookup table, the table is where your misconceptions get frozen and shipped.
>
> **Bug 3: pedantry disguised as a finding.** I warned on `X-Frame-Options: SAMEORIGIN`
> because `frame-ancestors` is the modern spelling. But every current browser honours XFO —
> those sites were protected. It fired on Stripe, python.org and nasa.gov. A warning that
> means "technically you could be more fashionable" trains users to ignore warnings, and then
> they ignore the real one. It now passes with a note.
>
> **The part I'd repeat on any project: the fixture server.**
> Show `test/fixture-server.mjs` — three local sites, one deliberately sloppy, one hardened,
> and one that returns HTTP 200 with an identical HTML shell for *every* path. That third one
> is the false-positive trap for the file-exposure check, and it's a test I could never have
> written safely against someone else's server. Show the calibration-plus-content-signature
> approach that beats it.
>
> **Closing.** Twenty sites took an afternoon and changed three checks. If you're building
> anything that renders a verdict about someone else's system, the corpus isn't optional — and
> the sites you *can't* assess are a result worth reporting, not an error to swallow. Link the
> extension (free), the accuracy report, and the source.

**Why this framing:** dev.to rewards specific, self-critical engineering stories and punishes
launch announcements. A post about finding your own bugs is credible in a way "I made a
security tool" is not, and it demonstrates the judgement that makes people trust a security
tool in the first place.

---

## Follow-ups worth queuing

- **Hacker News (Show HN)** — only if the dev.to post does well. HN title should be plain:
  `Show HN: QuickAudit – ten security checks on the page you're on`. Expect the top comment to
  be a securityheaders.com comparison; have the answer above ready.
- **r/webdev** — a lighter framing than r/netsec, focused on the "ship checklist" angle.
- **Not doing:** mass DMs, cold email, or paid promotion. This audience is unusually hostile
  to it and the damage lasts longer than the campaign.
