# Phase 5 — monetization

**Status: mechanism built and tested. No store, product, or payment account has been created.**
Every step below that touches money is waiting on your go-ahead.

## The model

**Free:** all ten checks, unlimited scans, forever. This is the part worth having, and
crippling it would kill the word-of-mouth that makes a tool like this spread.

**Pro: one-time $19.** No subscription, no account, no server.

| Pro feature | Status |
|---|---|
| HTML report export (print-to-PDF ready, self-contained, client-ready) | ✅ built — `src/ext/report.js` |
| Custom check sets — enable/disable checks | ✅ built — options page |
| Scan history | ⬜ v1.1 |
| CSV export | ⬜ v1.1 |

$19 sits in the middle of your $15–25 range. It's an expense-without-asking amount for a
developer, and it's above the "is this abandonware?" line that $5 tools fall below.

## Why one-time, and why no licence server

A subscription for a local checklist tool is a hard sell and would need billing
infrastructure, dunning emails, and a server that must stay up for years. A one-time unlock
with an **offline-verifiable key** needs none of that.

**How it works (already implemented and tested):**

- `tools/keygen.mjs` generated an ECDSA P-256 keypair. The private key is in `.keys/`
  (gitignored; `tools/package.mjs` refuses to build if it would ever land in the zip).
- The public key is embedded in `src/ext/license.js`.
- `tools/issue-license.mjs buyer@example.com ORDER-123` signs a tiny payload and prints a
  `QA1.<payload>.<signature>` key. That's what goes in the delivery email.
- The extension verifies the signature locally with WebCrypto. Nothing phones home. It works
  on a plane.
- Re-verified on every read, so hand-editing `chrome.storage` unlocks nothing.

Covered by tests: a genuine key verifies; a tampered payload fails; a forged signature fails;
junk input is rejected without throwing.

**On piracy:** a determined user can patch any client-side unlock. That's true of every
extension. Building auth infrastructure to stop them costs more than the leakage on a $19
product. Not a problem worth solving.

## Gumroad vs LemonSqueezy

**Recommendation: LemonSqueezy.**

| | LemonSqueezy | Gumroad |
|---|---|---|
| Fees | 5% + 50¢ | 10% flat |
| Merchant of record | Yes — handles EU VAT / US sales tax | Yes |
| Licence key API | Built in, plus webhooks | Add-on |
| Net on a $19 sale | ~$17.55 | ~$17.10 |

LemonSqueezy is cheaper and its licensing support means you can automate issuance later. But
this matters less than it looks: **for v1, issue keys manually.** At the volume a launch
produces, running `node tools/issue-license.mjs` when an order email arrives takes ten seconds
and costs nothing. Automate it via webhook once it's actually annoying — that's a good problem
to have and a wasted afternoon before then.

Either platform works with the mechanism as built; nothing in the extension depends on which
you pick.

## Store costs

| Store | Cost | Status |
|---|---|---|
| Microsoft Edge Add-ons | free | — |
| addons.mozilla.org | free | — |
| Chrome Web Store | $5 one-time | not yet registered |
| Apple App Store | $99/year | **already paid** — the existing BAB Studios membership (Team ID on file, used for the Amora iOS build) covers unlimited apps |

So the only new money required to publish on Chrome, Edge and Firefox is **$5, once**. Safari
adds no fee at all; what it adds is roughly a day of work — a macOS container app with real UI,
a Mac App Distribution certificate that doesn't exist yet, and a stricter review. See
[BROWSERS.md](BROWSERS.md).

## Store account decision — needs your call

Your earlier releases went out under the BAB Studios Google Play account. **Chrome Web Store
is a separate developer program with its own one-time $5 registration fee**, so publishing
QuickAudit means either registering the existing Google account for the Chrome Web Store, or
creating a new one. I haven't touched either. Two things worth weighing:

- Publishing a **security tool** under the same identity as your consumer apps (Amora,
  DailyFocus, Realm of Legend) ties the reputations together in both directions.
- Check 9 is dual-use enough that a store dispute, however unlikely, would be attached to
  whichever account ships it.

My recommendation is a dedicated developer identity for security tooling, but this is a
business decision, not a technical one.

## Launch sequence (nothing here is done)

1. You confirm the publishing account and pay the $5 registration.
2. Submit v1.0.0 free-only. Get through review before money is involved — a store rejection
   with a live payment page is a worse day than one without.
3. Once approved, create the LemonSqueezy product and drop the URL into the options page.
4. Launch posts (see `LAUNCH.md`) point at the **free** tool. Pro is a line in the footer.
5. Issue keys by hand. Automate if and when volume justifies it.

**Revenue expectation, stated plainly:** a well-received r/netsec + dev.to launch might put
2,000–5,000 people on the listing over a week, converting to a few hundred installs and
plausibly 5–20 Pro sales. That's $100–400. This is a portfolio and credibility play with a
small revenue tail, not an income stream — worth doing with clear eyes about which it is.
