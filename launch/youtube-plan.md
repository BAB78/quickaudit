# YouTube

**Recommendation: a 3 to 4 minute screen-recorded demo, not a dev log.**

The demo is by far the higher return. QuickAudit's whole pitch is "one click, five seconds",
which is inherently visual and almost impossible to convey in text. A build-story video needs
twenty minutes of footage and an audience that already cares who you are. A short demo needs
one take and a real website.

---

## Title

Pick one. Both are searchable and neither over-promises.

1. `I built a browser extension that security-checks any website in 5 seconds`
2. `Checking Wikipedia's security in one click (free browser extension I built)`

Option 1 is better for discovery. Option 2 is better for click-through, because a named site
in a thumbnail reads as a real demonstration rather than a pitch.

---

## Script

Aim for 3:30. Timings are guides, not marks to hit.

### 0:00 to 0:15  Cold open, no intro

Do not say hello. Do not say who you are. Show the result first.

> Open a browser already on wikipedia.org. Click the QuickAudit icon. Click Scan.
> Score lands on 49. Three red failures.

Say, over the top:

> "That's Wikipedia. Three security problems, found in about a fifth of a second, in one click.
> Let me show you what it actually checked."

### 0:15 to 0:45  What it is

> "This is QuickAudit. It's a free browser extension I built. It runs ten security checks
> against whatever page you're on, the ones you'd otherwise do by hand with curl and DevTools
> before shipping or before a pentest."

Scroll the popup slowly while talking. Let the viewer read.

> "It is not a scanner. No payloads, nothing intrusive. It's the checklist you run first so a
> real assessment isn't full of trivia."

### 0:45 to 1:45  Walk two findings

Expand **QA-02 Content-Security-Policy**.

> "No Content-Security-Policy. That means if anything injects a script into this page, a
> compromised third-party tag, a malicious ad, it runs unrestricted. And it doesn't just tell
> me that. It gives me the exact line to add."

Point at the fix block.

Expand **QA-03 Clickjacking**.

> "Same again. No framing protection, so any site could load this page in an invisible iframe.
> Every finding cites the header that caused it and the specific fix."

### 1:45 to 2:30  The one that sells it

Navigate to **python.org**. Scan. Expand **QA-08**.

> "This is the check I'm proudest of. python.org ships jQuery 1.8.2. QuickAudit read that
> version off the live page, then looked it up against OSV.dev, which is Google's open source
> vulnerability database."

Point at the CVE list.

> "Five advisories. Real CVE numbers. And it tells me it's fixed in 1.9.0. That's live data,
> not a list I hardcoded that goes stale the week I ship it."

### 2:30 to 3:00  Contrast

Navigate to **github.com**. Scan.

> "And it isn't a fear machine. GitHub scores 98. Mostly green. If your site is configured
> properly it says so, because a tool that finds problems everywhere is a tool you stop
> trusting."

### 3:00 to 3:30  Privacy and close

Open Settings, scroll to the privacy section.

> "One thing that matters for a security tool: the only thing that leaves your browser is
> library names and version numbers, sent to OSV to look up CVEs. No URLs, no page content, no
> cookie values. And it asks for permission one site at a time, when you click Scan, not for
> every site you visit when you install it."

> "It's free, it's open source, and it's on Chrome, Edge and Firefox. Links in the description.
> If you find a check that's wrong, tell me, I'd genuinely rather know."

---

## Description

```
QuickAudit runs a ten-point OWASP-style security checklist against whatever page you're on, in about a fifth of a second. Free and open source.

It checks: HTTPS and HSTS, Content-Security-Policy quality, clickjacking protection, MIME-sniffing, referrer and permissions policy, cookie security flags, mixed content, JavaScript libraries with known CVEs, exposed sensitive files, and server version disclosure.

Every finding cites the header that caused it and gives you the exact line to add.

INSTALL
Chrome and Edge: https://chromewebstore.google.com/detail/kbhfdiianifmneefgfmlmloejffekjdm
Firefox: https://addons.mozilla.org/en-US/firefox/addon/quickaudit-web-security/
Source: https://github.com/BAB78/quickaudit

WHAT IT IS NOT
Not a vulnerability scanner. No payloads, no crawling, no exploitation. It's the checklist you run first so a real assessment isn't full of trivia. A clean result means the ten common misconfigurations are absent, not that the application is secure.

PRIVACY
The only data that leaves your browser is detected library name@version strings, sent to OSV.dev to look up known CVEs. No URLs, no page content, no cookie values, no analytics, no account.

CHAPTERS
0:00 Scanning Wikipedia
0:15 What QuickAudit is
0:45 Reading a finding
1:45 Vulnerable libraries and live CVE data
2:30 What a well configured site looks like
3:00 Privacy

I also wrote up the four bugs this tool found in itself, and how testing it against twenty real sites exposed them: https://github.com/BAB78/quickaudit
```

---

## Thumbnail

Use the popup screenshot you already have, at `store-assets/1-ten-checks-one-click.png`.

Overlay two words in large text: **49/100**, with the Wikipedia logo or wordmark beside it.

A recognisable site plus a bad-looking number is the entire hook. Resist adding a face, an
arrow, or a shocked expression. The audience for a developer security tool reacts badly to
that styling and it will cost you more clicks than it earns.

---

## Practical notes

**Record at 1920x1080 and zoom the browser to 125 percent** before you start. The popup is
400 pixels wide, and at default zoom it is unreadable on a phone, which is where most of your
views will come from.

**Do it in one take.** Three and a half minutes of screen recording with live narration will
be better than something heavily edited, and you will actually finish it.

**Turn off notifications and use a clean browser profile.** You already have one at
`build/chrome` loaded unpacked; use a profile with no other extensions and no personal
bookmarks visible.

**Pin the extension first** so the icon is visible in the toolbar before you start recording.

**Expect this to outlive the other posts.** A demo video for a tool keeps getting found through
search for years, where a LinkedIn post is dead in 48 hours. If you only have energy for one
channel, this is the one with the longest tail.
