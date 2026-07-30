# Browser support

One source tree, three packages. Every engine difference lives in the manifest or behind a
feature flag in [src/ext/browser-api.js](src/ext/browser-api.js) — no forked code, so what the
tests exercise is what ships.

```
node tools/build.mjs           # builds all three
node tools/build.mjs firefox   # or just one
```

| Browser | Build | Status | Store |
|---|---|---|---|
| Chrome 116+ | `chrome` | Full | Chrome Web Store |
| Edge 116+ | `chrome` | Full | Microsoft Edge Add-ons |
| Brave, Opera, Vivaldi | `chrome` | Full | Chrome Web Store (or sideload) |
| Firefox 128+ | `firefox` | Full | addons.mozilla.org |
| Safari 17+ (macOS) | `safari` | Code-complete, **unverified** — see below | App Store, via Xcode |

## What actually differs

**Background context.** Firefox has never implemented `background.service_worker` for MV3; it
uses a non-persistent event page (`background.scripts`). Chromium and Safari use a service
worker. Both are non-persistent, so nothing in the background may rely on module state
surviving between messages — the header cache is explicitly best-effort and falls back to a
fetch. ES modules in a Firefox MV3 background script need **Firefox 128+**, which is the
declared `strict_min_version`.

**The `chrome` alias trap.** Firefox exposes a promise-based `browser.*` *and* a
callback-based `chrome.*` alias. So `await chrome.storage.local.get('x')` resolves to
`undefined` on Firefox — no error, no warning, the feature just quietly does nothing. The shim
resolves `globalThis.browser ?? globalThis.chrome`, and `test/compat.mjs` fails the build if any
file outside the shim references a raw namespace. `test/ext-smoke.mjs` runs the entire scan
flow a second time with a deliberately callback-only `chrome` alias installed alongside
`browser`, so a regression here fails loudly in CI instead of silently in the wild.

**Permission prompts.** Firefox only honours `permissions.request()` inside a user-input
handler, so it can never be proxied through the background. The prompt is raised directly in
the popup's click handler, which is also the more correct pattern on Chromium. Enforced by a
compat test.

**No `webRequest`, on any engine.** Chrome only delivers `webRequest` events to extensions
holding host permissions *at install time*, which is fundamentally incompatible with asking
per-origin at scan time — the listener registers, never fires, and Chrome records a permanent
error badge in every user's extensions page. Found by attaching to the live service worker,
which logged it verbatim: *"You need to request host permissions in the manifest file in order
to be notified about requests from the webRequest API."* Response headers now come from a
credentialed `fetch`, which keeps the per-origin permission model intact.

**Downloads.** Safari has no `downloads` API. The Safari manifest doesn't request the
permission, and report export falls back to a synthesized `<a download>` click, which works
everywhere.

**Main-world injection.** Reading page globals (`jQuery.fn.jquery` and friends) needs
`world: 'MAIN'`: Chrome 111+, Firefox 128+, Safari 17+. If an engine refuses, the scan degrades
to URL-based library detection and says so in the report notes rather than silently reporting
fewer libraries.

## Safari: honest status

The code is Safari-compatible and the `safari` target builds, but **I could not verify it on a
real Safari install** — packaging a Safari Web Extension requires macOS and Xcode, and this was
built on Windows. Treat Safari as untested until someone runs it.

To package it on a Mac:

```bash
xcrun safari-web-extension-converter build/safari --project-location ./safari-app
# then open the generated Xcode project, set signing, and run
```

Distribution needs an Apple Developer Program membership ($99/year). **This is already paid** —
BAB Studios holds an active membership used for the Amora iOS build, and one membership covers
unlimited apps, so Safari costs nothing extra to publish.

What the membership does *not* cover, and what actually gates this:

- **It ships as a native app, not an extension package.** The converter produces a macOS app
  that wraps the extension; that app needs its own bundle id, its own App Store Connect record,
  and a **Mac App Distribution** certificate — the existing iOS distribution cert doesn't apply.
- **macOS + Xcode are still required.** The existing Codemagic pipeline (already used for the
  iOS builds) runs macOS VMs with Xcode and is a viable way to convert, sign and upload without
  owning a Mac. Use automatic code signing with the App Store Connect API key so Codemagic
  provisions the new macOS certificate itself.
- **App Review is stricter here than on the Chrome or Firefox stores.** Two specific risks:
  guideline 4.2 (minimum functionality) — Apple rejects bare extension wrappers whose container
  app does nothing, so the container needs real UI; and QA-09, where Apple's reviewers are less
  predictable than Google's on tools that send probe requests.

**Recommendation: ship Chrome, Edge and Firefox first.** Get review feedback from the lenient
stores before spending a day on an Xcode container app for the strictest one. The cost argument
against Safari is gone; the effort argument isn't.

## Testing across engines

```
node test/compat.mjs      # 11 tests: manifest validity per engine + source portability
node test/ext-smoke.mjs   # 13 tests × 2 namespace shapes (chromium, firefox)
```

`compat.mjs` enforces the invariants that keep the tree portable: `src/checks/` and `src/core/`
must contain no extension API, no `document`, and no `window`; the background must not touch
the DOM; capabilities must be feature-detected rather than engine-sniffed.

## Not supported

- **Manifest V2** — not worth carrying; Chrome has removed it and Firefox MV3 is stable.
- **Chrome < 116 / Firefox < 128** — both predate the APIs this relies on.
- **Mobile Chrome** — Android Chrome doesn't support extensions at all. Firefox for Android
  does, and the `firefox` build should install there, but the 400px popup is not designed for
  it. Untested.
