#!/usr/bin/env node
/**
 * Cross-browser compatibility checks that don't need a browser.
 *
 * Two jobs: validate each target's generated manifest against what that engine actually
 * accepts, and enforce that no code outside browser-api.js touches a raw extension namespace
 * (the Firefox `chrome.*` alias is callback-based, so `await chrome.storage.local.get()`
 * resolves to undefined — a bug that is invisible until a Firefox user hits it).
 */
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, TARGETS } from '../tools/build.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
let passed = 0, failed = 0;
const t = (name, fn) => {
  try { fn(); passed++; console.log(`\x1b[32mok\x1b[0m   ${name}`); }
  catch (e) { failed++; console.error(`\x1b[31mFAIL\x1b[0m ${name}\n     ${e.message.split('\n').slice(0, 4).join('\n     ')}`); }
};

const built = Object.fromEntries(Object.keys(TARGETS).map((k) => [k, build(k)]));

// ── manifest validity per engine ────────────────────────────────────────────────
t('manifest fields fit the store limits', () => {
  // The Chrome Web Store rejects the upload outright rather than truncating, so these are
  // hard limits, not style guidance.
  for (const [name, { manifest }] of Object.entries(built)) {
    assert.ok(manifest.description.length <= 132,
      `${name}: description is ${manifest.description.length} chars, limit is 132`);
    assert.ok(manifest.name.length <= 75, `${name}: name is ${manifest.name.length} chars, limit is 75`);
    assert.ok(manifest.description.length > 20, `${name}: description is too short to be useful`);
  }
});

t('every target produces a valid MV3 manifest with the shared essentials', () => {
  for (const [name, { manifest }] of Object.entries(built)) {
    assert.equal(manifest.manifest_version, 3, `${name}: must be MV3`);
    assert.ok(manifest.action?.default_popup, `${name}: needs a popup`);
    assert.ok(manifest.optional_host_permissions?.length, `${name}: host access must stay optional`);
    assert.equal(manifest.host_permissions, undefined, `${name}: must not request host permissions at install`);
    assert.ok(manifest.options_ui?.page, `${name}: options_ui is the cross-browser options key`);
    for (const p of ['activeTab', 'storage', 'cookies', 'scripting']) {
      assert.ok(manifest.permissions.includes(p), `${name}: missing ${p}`);
    }
    // webRequest only fires for extensions holding host permissions at install time, which
    // is incompatible with asking per-origin at scan time. Requesting it anyway earns a
    // permanent error badge in every user's extensions page for an API that never fires.
    assert.ok(!manifest.permissions.includes('webRequest'),
      `${name}: webRequest cannot work alongside optional host permissions`);
  }
});

t('Chromium and Safari use a service worker; Firefox uses an event page', () => {
  assert.equal(built.chrome.manifest.background.service_worker, 'src/ext/background.js');
  assert.equal(built.safari.manifest.background.service_worker, 'src/ext/background.js');
  // Firefox has never implemented background.service_worker for MV3.
  assert.equal(built.firefox.manifest.background.service_worker, undefined);
  assert.deepEqual(built.firefox.manifest.background.scripts, ['src/ext/background.js']);
  for (const target of ['chrome', 'firefox', 'safari']) {
    assert.equal(built[target].manifest.background.type, 'module',
      `${target}: background must load as an ES module`);
  }
});

t('Firefox declares the add-on id and a version floor that supports module event pages', () => {
  const gecko = built.firefox.manifest.browser_specific_settings?.gecko;
  assert.ok(gecko?.id, 'AMO requires an explicit extension id');
  assert.ok(parseFloat(gecko.strict_min_version) >= 128,
    'ES modules in MV3 background scripts need Firefox 128+');
});

t('downloads permission is only requested where the API exists', () => {
  assert.ok(built.chrome.manifest.permissions.includes('downloads'));
  assert.ok(built.firefox.manifest.permissions.includes('downloads'));
  // Safari has no downloads API — requesting it would be a review flag for no benefit.
  assert.ok(!built.safari.manifest.permissions.includes('downloads'),
    'Safari build must not request a permission the engine does not implement');
});

t('no target ships a private key', () => {
  for (const [name, r] of Object.entries(built)) {
    const files = walk(r.stage);
    assert.ok(!files.some((f) => /\.keys|private\.pem/.test(f)), `${name}: key material staged`);
  }
});

t('every packaged file is reachable and non-empty', () => {
  for (const [name, r] of Object.entries(built)) {
    for (const f of walk(r.stage)) {
      assert.ok(statSync(f).size > 0, `${name}: ${path.relative(r.stage, f)} is empty`);
    }
  }
});

// ── source-level portability ────────────────────────────────────────────────────
const extFiles = walk(path.join(root, 'src')).filter((f) => f.endsWith('.js'));

/** Comments legitimately discuss chrome.* and permissions.request; only code counts. */
const stripComments = (src) => src
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:])\/\/.*$/gm, '$1');
const codeOf = (file) => stripComments(readFileSync(file, 'utf8'));

/**
 * Also drop string literals. libdetect.js stores probe expressions like
 * "window.jQuery && ..." as *data* — they are evaluated inside the page, never here, so they
 * must not count as the module reaching for a browser global.
 */
const stripStrings = (src) => src.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''");

t('only browser-api.js touches a raw extension namespace', () => {
  const offenders = [];
  for (const f of extFiles) {
    if (f.endsWith('browser-api.js')) continue;
    const code = codeOf(f);
    for (const ns of ['chrome.', 'browser.']) {
      if (code.includes(ns)) offenders.push(`${path.relative(root, f)} uses ${ns}`);
    }
  }
  assert.deepEqual(offenders, [],
    `raw namespace access outside the shim:\n       ${offenders.join('\n       ')}`);
});

t('no Chromium-only API is used without a feature guard', () => {
  const shim = readFileSync(path.join(root, 'src/ext/browser-api.js'), 'utf8');
  // Anything the shim exposes as a capability must be guarded before use.
  for (const cap of ['downloads', 'cookies']) {
    assert.ok(new RegExp(`${cap}:\\s*Boolean\\(`).test(shim), `capability flag missing for ${cap}`);
  }
  // Read raw here, not codeOf: URL patterns like 'http://*/*' contain both `/*` and `*/`,
  // so naive comment stripping eats the code around them. Match on API access instead of
  // the bare word, which lets the comments explain why webRequest is absent.
  const bg = readFileSync(path.join(root, 'src/ext/background.js'), 'utf8');
  assert.ok(!/(api|chrome|browser)\.webRequest/.test(bg),
    'the background must not call webRequest — it can never fire under optional host permissions');
  assert.ok(/if \(can\.cookies\)/.test(bg), 'cookies access must be feature-guarded');
  const popup = readFileSync(path.join(root, 'src/ext/popup.js'), 'utf8');
  assert.ok(/if \(can\.downloads\)/.test(popup), 'downloads must be feature-guarded');
});

t('permissions.request is raised from the popup, never the background', () => {
  const bg = codeOf(path.join(root, 'src/ext/background.js'));
  const popup = codeOf(path.join(root, 'src/ext/popup.js'));
  // Firefox only honours permissions.request() inside a user-input handler, so proxying it
  // through a message to the background silently fails there.
  assert.ok(!/permissions\.request/.test(bg), 'background must not call permissions.request');
  assert.ok(/requestOrigin\(/.test(popup), 'popup must request the origin itself');
});

t('nothing in the shipped source evaluates code at runtime', () => {
  // Store reviewers treat any dynamic code path in a security extension as a red flag, and
  // QuickAudit has no need for one — library probes walk property paths instead.
  for (const f of extFiles) {
    const code = stripStrings(codeOf(f));
    for (const pattern of [/\bnew Function\b/, /\beval\s*\(/, /setTimeout\s*\(\s*['"`]/, /\bnew\s+AsyncFunction\b/]) {
      assert.ok(!pattern.test(code), `${path.relative(root, f)} contains dynamic code execution (${pattern})`);
    }
  }
});

t('no DOM or window access in code the background loads', () => {
  // Service workers have no document. The injected collectors do use it, but they are
  // serialized into the page rather than executed here — so split before stripping comments.
  const raw = readFileSync(path.join(root, 'src/ext/background.js'), 'utf8');
  const beforeInjected = stripStrings(stripComments(raw.split('── injected functions')[0]));
  for (const forbidden of ['document.', 'window.', 'localStorage']) {
    assert.ok(!beforeInjected.includes(forbidden),
      `service worker context cannot use ${forbidden}`);
  }
});

t('checks and core stay free of any extension API', () => {
  const portable = extFiles.filter((f) => /[\\/](checks|core)[\\/]/.test(f));
  assert.ok(portable.length >= 14, 'expected the full checks+core tree');
  for (const f of portable) {
    const code = stripStrings(codeOf(f));
    for (const ns of ['chrome.', 'browser.', 'document.', 'window.']) {
      assert.ok(!code.includes(ns), `${path.relative(root, f)} must stay portable (found ${ns})`);
    }
  }
});

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}compat: ${passed} passed, ${failed} failed\x1b[0m`);
process.exit(failed ? 1 : 0);
