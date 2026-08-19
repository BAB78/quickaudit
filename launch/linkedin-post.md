# LinkedIn post

**Format rules that matter on LinkedIn:**

- The first two lines are all anyone sees before "…see more". They decide everything.
- **Put the link in the first comment, not the post.** LinkedIn demotes posts containing
  external links, sometimes heavily.
- Short beats long here. This runs about 200 words, which is right.
- Line breaks between almost every sentence. Dense paragraphs get skipped on mobile.
- 3 to 5 hashtags at the end. More looks like spam.

---

## Post

I wrote 111 automated tests for my security tool.

They caught none of the four real bugs.

I spent a month building QuickAudit, a browser extension that runs a ten-point security check on any website in about a fifth of a second. Missing headers, insecure cookies, JavaScript libraries with known CVEs.

Before shipping, I pointed it at twenty real websites to check its accuracy.

It told me sourceforge.net had no HSTS security header.

It does. What I had actually scanned was a Cloudflare bot-protection page, and my tool had confidently described that page's headers as though they were the site's.

No error. No warning. Just a clean, professional-looking finding that was completely false.

That is the failure mode worth fearing in any tool that renders a verdict. Not crashing. Being confidently wrong.

Three more followed. A button that locked up forever on second use. A paid feature that was invisible in dark mode. A browser permission that could never have worked.

Each one was found by a different kind of looking. None by the test suite.

The lesson I keep coming back to: passing tests tell you the code does what you told it to. They cannot tell you whether what you told it was right.

QuickAudit is free and open source. Live on Chrome, Edge and Firefox. Link in the comments.

#softwaredevelopment #cybersecurity #webdevelopment #buildinpublic

---

## First comment (post this immediately after)

Source, plus the full write-up of all twenty sites and every bug it found in my own code:
https://github.com/BAB78/quickaudit

Chrome and Edge: https://chromewebstore.google.com/detail/kbhfdiianifmneefgfmlmloejffekjdm
Firefox: https://addons.mozilla.org/en-US/firefox/addon/quickaudit-web-security/

---

## Notes

**Attach the cover image** (`store-assets/devto-cover-1000x420.png`). LinkedIn gives image
posts noticeably more reach than text alone, and you already have one sized close enough.

**Reply to every comment for the first few hours.** LinkedIn's ranking is driven by early
engagement more than almost any other platform. Ten replies in the first hour is worth more
than a hundred views on day three.

**Be honest about the audience.** LinkedIn is mostly recruiters, founders and business
contacts rather than the security engineers this tool is built for. The realistic value here
is credibility with people who already know you, not installs. Treat installs as a bonus.
