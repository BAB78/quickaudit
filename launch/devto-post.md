---
title: I wrote 111 tests for my security extension. They caught none of the real bugs.
published: false
description: Six genuine defects, each found by a different kind of looking — a 20-site corpus, a browser render, a debugger attached to the live service worker. None by the test suite.
tags: security, webdev, javascript, showdev
---

I built a browser extension called QuickAudit. It runs ten OWASP-style checks against whatever page you're on — HSTS, CSP quality, cookie flags, mixed content, exposed `.env` files, JavaScript libraries with known CVEs — and gives you a pass/fail sheet in about 200ms.

By the time I thought it was finished it had 111 passing tests: unit tests over the check functions, integration tests against local fixture servers, cross-browser compatibility tests, and extension-wiring tests run twice under two different API namespaces.

Then I started actually *looking* at it, and found six real bugs.

The test suite caught none of them. Not one. And the interesting part isn't that I under-tested — it's that each bug needed a completely different kind of looking to find, and no amount of the previous kind would have surfaced the next.

Here they are, worst first.

---

## 1. I audited Cloudflare's challenge page and called it your website

I pointed the tool at twenty real sites as a validation exercise. It reported that **sourceforge.net has no HSTS header**.

Sourceforge has HSTS. Here's what an independent request returns:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Two clues gave it away. The response came back in 44ms, far too fast for a real page load. And the header list contained this:

```
cf-mitigated: challenge
```

I hadn't been served sourceforge. I'd been served a Cloudflare bot-protection interstitial, and my scanner faithfully described *the challenge page's* headers as though they were the site's.

This is the failure mode that scares me most, because it fails toward **confident wrongness**. The tool didn't error. It didn't warn. It produced a clean, specific, professional-looking finding that was entirely false. Take that report to your team and you'd spend an afternoon "fixing" a header that was already there.

It isn't a bug unique to me either. *Any* tool that fetches a URL rather than reading the response your browser actually received inherits this. If you've built something that curls a site and reports on the headers, go and check what it does behind a WAF.

The fix isn't to guess better. It's to notice you can't see:

```js
export function detectChallenge(status, headers, html) {
  if (headers['cf-mitigated']) return 'Cloudflare served a bot-protection challenge…';
  if (String(headers['x-amzn-waf-action']?.[0]).toLowerCase() === 'challenge') return 'AWS WAF served a challenge…';
  if (/<title>\s*(Just a moment|Attention Required!|Access denied)/i.test(html)) return 'Interstitial challenge page…';
  if ([401, 403, 429, 503].includes(status) && /cloudflare|akamai|incapsula|imperva/i.test(headers.server?.[0] || '')) {
    return `WAF returned HTTP ${status} rather than the page…`;
  }
  return null;
}
```

When that fires, every header-dependent check now returns **skip** with an explanation instead of a finding. Three of my twenty corpus sites turned out to be unassessable this way. Reporting "I couldn't see your site" is a result. Reporting a confident lie is not.

---

## 2. The main button locked up forever, and 111 tests were fine with it

Here's the code. See if you spot it faster than I did:

```js
async function scan() {
  const btn = $('scan');
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  $('idle').innerHTML = '<p>Running ten checks…</p>';   // ← here

  try {
    const report = await sendMessage({ type: 'scan', tabId: tab.id });
    render(report);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Rescan';
  }
}
```

`#idle` is a placeholder node inside the results container. And `render()` clears that container.

So a first scan works fine. But the actual user sequence is: open the popup, see the report from last time, click **Rescan**. By then `#idle` no longer exists, `$('idle')` is `null`, and the dereference throws — **before** the `try` block. The `finally` never runs. The button stays disabled, reading "Scanning…", forever. The primary control of the extension, dead, in a completely ordinary flow.

Every one of my tests stubbed the browser away. None of them rendered a DOM. So I built a small harness that serves the real popup with the extension APIs faked and a real scan report loaded, opened it in an actual browser, and clicked the button twice.

That's the whole technique. Two clicks.

The lesson: **if your tests mock the environment, they cannot test the environment.** Something has to run the real thing, even crudely.

---

## 3. A permission that could never work, hidden by a fallback that did

The extension requested `webRequest` to read response headers from the real navigation. Nothing appeared broken. It worked.

But Chrome showed a red **"Errors"** badge on the extension card. I attached a debugger to the live service worker and got this, verbatim:

> `You need to request host permissions in the manifest file in order to be notified about requests from the webRequest API.`

Chrome only delivers `webRequest` events to extensions holding host permissions **at install time**. QuickAudit deliberately asks for one origin at a time, when you click Scan — that's the entire privacy pitch. The two are fundamentally incompatible.

So the listener registered, never fired once, and logged a permanent error for every user.

It kept working because I'd written a `fetch` fallback for the case where the header cache was empty — and the cache was *always* empty. The fallback wasn't a fallback. It was the whole implementation, and it had been quietly carrying the feature the entire time.

The tempting fix is to widen permissions to `<all_urls>`. I deleted the permission instead. A tool whose selling point is "I don't ask for access to every site you visit" doesn't get to ask for access to every site you visit in exchange for marginally more faithful headers.

**A feature that works is not proof that its implementation works.** Sometimes it means your fallback is better than you knew.

---

## 4. The paid feature was invisible on half of all machines

QuickAudit has a Pro tier whose main artifact is an exported HTML report you'd hand to a client. Its stylesheet looked like this:

```css
:root { --fg: #16181d; --muted: #6b7280; }
body { color: var(--fg); }   /* no background */
```

Dark text. No background declared. So in any browser set to dark mode, the page painted the browser's dark default and rendered **near-black text on near-black**. Every check title and every summary line: invisible. The one thing people would pay for, unreadable for anyone not on a light theme.

I found it while composing a screenshot for the store listing.

The fix is one line, but the reasoning matters more than the line. This is a document you print and send to someone — it shouldn't follow the *reader's* theme at all:

```css
:root { color-scheme: light; }
html, body { background: #fff; }
```

---

## 5 & 6. Two places I encoded a spec wrong, then froze it

Less dramatic, more common, and I suspect more of you have them right now.

**I graded `Referrer-Policy: origin-when-cross-origin` as a full-URL leak.** It isn't. It sends the *origin* cross-origin and drops the path. I'd bucketed it with `unsafe-url`, which genuinely does leak everything. Result: Stripe got a red FAIL for a policy that leaks far less than my label implied.

**I warned on sites using only `X-Frame-Options`.** My reasoning was that `frame-ancestors` is the modern spelling. But every current browser still honours XFO — those sites *were* protected. That warning fired on Stripe, python.org and nasa.gov, and it meant nothing beyond "you could be more fashionable."

The second is the worse sin. A warning that doesn't correspond to a real risk trains people to ignore warnings, and then they ignore the one that mattered. If you're building anything that renders verdicts, every finding you can't defend costs you the credibility of the findings you can.

Both share a shape: I turned a spec into a lookup table, and the table became the place my misconceptions got frozen and shipped. Nobody reviews a constant array as carefully as they review a function.

---

## The thing I'd repeat on any project

Not the corpus. The **fixture server**.

Three deliberately broken local sites on three ports:

- **`:8081` sloppy** — serves `.env`, `.git/HEAD`, `phpinfo.php`, ships jQuery 1.8.3, no security headers
- **`:8083` tight** — everything configured correctly
- **`:8082` the trap** — returns HTTP 200 with an *identical HTML shell for every single path*

That third one is the whole ballgame for the exposed-files check. Naive implementations flag any 200, which means every single-page app with a catch-all route reports thirteen critical findings. Mine first requests a random nonexistent path to fingerprint what the origin does with garbage, then requires the response body to match a content signature for that specific file type — `/.git/HEAD` must match `^ref:\s+refs/`, `/.env` must look like real `KEY=value` lines and must not be HTML. **Status alone is never a finding.**

I could never have written that test safely against someone else's server. And it runs in 40ms, on a plane, forever.

---

## What I'd actually take from this

Six bugs, six different kinds of looking:

| Bug | Found by |
|---|---|
| WAF challenge audited as the site | running against 20 real sites |
| Dead Rescan button | rendering the real UI and clicking twice |
| Impossible `webRequest` permission | attaching a debugger to the live service worker |
| Invisible Pro report | making a screenshot |
| Two spec misreadings | an independently-written checker disagreeing |

None by the test suite. And the suite isn't bad — it catches regressions in all six now. It structurally could not have found them the first time, because each one lived somewhere the tests had abstracted away.

Oh, and a seventh, for humility: my *compatibility test* had a comment-stripper that treated the `/*` and `*/` inside the string `'http://*/*'` as a comment and ate the surrounding code. The tool that checks the tool needed checking too.

If you're building anything that renders a verdict about someone else's system: the corpus isn't optional, and **the cases you can't assess are a result worth reporting, not an error to swallow**.

---

QuickAudit is free and open source. Ten checks, no account, and the only thing that leaves your browser is library `name@version` strings sent to OSV.dev to look up CVEs — no URLs, no page content, no cookie values.

- **Source + the full 20-site accuracy write-up:** https://github.com/BAB78/quickaudit
- **Chrome / Edge:** https://chromewebstore.google.com/detail/kbhfdiianifmneefgfmlmloejffekjdm
- **Firefox:** https://addons.mozilla.org/en-US/firefox/addon/quickaudit-web-security/

Happy to have any of the ten checks torn apart — that's most of why I'm posting.
