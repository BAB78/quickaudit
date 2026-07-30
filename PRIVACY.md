# QuickAudit privacy policy

_Last updated: 2026-07-30_

QuickAudit is a browser extension that checks the security configuration of the page you are
viewing. This policy describes every piece of data it handles.

## What leaves your device

**One thing.** When the vulnerable-library check runs, QuickAudit sends the names and versions
of JavaScript libraries it detected on the page — for example `jquery@1.8.2` — to the public
[OSV.dev](https://osv.dev) vulnerability database to look up known advisories.

That is the entire list. Specifically, QuickAudit does **not** transmit:

- the URL of the page you scanned, or any URL
- page content, text, form data, or HTML
- cookie values (the extension reads cookie *flags* — `Secure`, `HttpOnly`, `SameSite` — and
  discards values)
- your IP address to any service operated by us — there is no such service
- usage analytics, crash reports, or telemetry of any kind
- any identifier for you, your device, or your browser

There is no QuickAudit account, no login, and no server operated by the developer. The
extension has no way to send data to the developer even in principle.

## What is stored on your device

Held in local extension storage (`chrome.storage.local`), never synced or transmitted:

- your settings (which checks are enabled; whether active probing is on)
- your most recent scan report, so reopening the popup isn't a blank screen
- a 6-hour cache of OSV.dev lookups, so repeat scans don't re-query the API
- your Pro licence key, if you bought one

Uninstalling the extension deletes all of it. You can clear the report and cache at any time
from Chrome's extension storage controls.

## Requests QuickAudit makes

**To the site you are scanning.** QuickAudit makes one request to the page you are already
viewing in order to read its response headers. It is sent with your existing cookies so the
result reflects the page as you actually see it.

**Active file-exposure checking (QA-09), disabled by default.** If you explicitly enable it and
acknowledge that you are authorised to test the target, QuickAudit sends up to about 14 `GET`
requests for well-known paths (`/.env`, `/.git/HEAD`, and similar) to the origin of the tab you
are viewing. These requests are rate-limited, sent without credentials, and cannot be aimed at
any host other than the one you are already on. Nothing is recorded or transmitted anywhere;
results are shown to you and stored locally.

**To api.osv.dev.** As described above. OSV.dev is operated by the Open Source Security
Foundation and has its own privacy policy.

## Permissions and why they exist

QuickAudit does not request access to all websites at install. It asks for access to one
origin at a time, when you click Scan on that site. Full per-permission justifications are in
[STORE_LISTING.md](STORE_LISTING.md).

## Changes

Material changes to this policy will be accompanied by an extension version bump and noted in
the changelog.

## Contact

Questions or a privacy concern: open an issue on the project repository.
