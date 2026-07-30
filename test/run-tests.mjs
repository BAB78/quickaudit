#!/usr/bin/env node
/** Unit tests for the ten checks and the core helpers. No network, no browser. */
import assert from 'node:assert/strict';
import { ctx, cookie, fakeOsv } from './helpers.mjs';

import * as qa01 from '../src/checks/qa01-transport.js';
import * as qa02 from '../src/checks/qa02-csp.js';
import * as qa03 from '../src/checks/qa03-framing.js';
import * as qa04 from '../src/checks/qa04-nosniff.js';
import * as qa05 from '../src/checks/qa05-referrer-permissions.js';
import * as qa06 from '../src/checks/qa06-cookies.js';
import * as qa07 from '../src/checks/qa07-mixed-content.js';
import * as qa08 from '../src/checks/qa08-libraries.js';
import * as qa09 from '../src/checks/qa09-exposed-paths.js';
import * as qa10 from '../src/checks/qa10-disclosure.js';
import { runAll, score } from '../src/checks/index.js';
import { detectFromUrl, detectFromBanner, mergeLibraries } from '../src/core/libdetect.js';
import { parseSetCookie, looksLikeSessionCookie } from '../src/core/cookies.js';
import { parseCsp, effective, scriptSrcWeaknesses } from '../src/core/csp.js';
import { normalizeHeaders, parseDirectiveList } from '../src/core/headers.js';
import { memoryCache } from '../src/core/osv.js';

let passed = 0, failed = 0;
const only = process.argv[2];

async function t(name, fn) {
  if (only && !name.toLowerCase().includes(only.toLowerCase())) return;
  try {
    await fn();
    passed++;
  } catch (e) {
    failed++;
    console.error(`\x1b[31mFAIL\x1b[0m ${name}\n      ${e.message.split('\n').slice(0, 4).join('\n      ')}`);
  }
}
const st = (r) => r.status;

// ── core helpers ────────────────────────────────────────────────────────────────
await t('headers: normalizes arrays, objects and duplicate keys', () => {
  assert.deepEqual(normalizeHeaders({ 'X-Foo': 'a' }), { 'x-foo': ['a'] });
  assert.deepEqual(normalizeHeaders([{ name: 'Set-Cookie', value: 'a=1' }, { name: 'Set-Cookie', value: 'b=2' }]),
    { 'set-cookie': ['a=1', 'b=2'] });
  assert.deepEqual(normalizeHeaders({ 'set-cookie': ['a=1', 'b=2'] })['set-cookie'], ['a=1', 'b=2']);
});

await t('headers: parseDirectiveList handles flags and values', () => {
  assert.deepEqual(parseDirectiveList('max-age=100; includeSubDomains; preload'),
    { 'max-age': '100', includesubdomains: true, preload: true });
});

await t('csp: parses, applies default-src fallback, respects no-fallback directives', () => {
  const p = parseCsp("default-src 'self'; script-src 'self' cdn.example.com; object-src 'none'");
  assert.deepEqual(p['script-src'], ["'self'", 'cdn.example.com']);
  assert.deepEqual(effective(p, 'img-src'), ["'self'"]);
  assert.equal(effective(p, 'frame-ancestors'), null, 'frame-ancestors must not fall back to default-src');
});

await t('csp: nonce neutralizes unsafe-inline, strict-dynamic neutralizes host allowlists', () => {
  assert.equal(scriptSrcWeaknesses(["'self'", "'unsafe-inline'"]).length, 1);
  assert.equal(scriptSrcWeaknesses(["'nonce-abc123'", "'unsafe-inline'"]).length, 0);
  assert.equal(scriptSrcWeaknesses(["'strict-dynamic'", "'nonce-x'", 'https:']).length, 0);
  assert.ok(scriptSrcWeaknesses(["'unsafe-eval'", "'self'"]).some((w) => w.token === "'unsafe-eval'"));
});

await t('cookies: parses attributes and drops the value', () => {
  const c = parseSetCookie('sid=SUPERSECRET; Path=/; Secure; HttpOnly; SameSite=Strict');
  assert.equal(c.name, 'sid');
  assert.equal(c.secure, true);
  assert.equal(c.httpOnly, true);
  assert.equal(c.sameSite, 'strict');
  assert.ok(!JSON.stringify(c).includes('SUPERSECRET'), 'cookie value must never be retained');
  assert.equal(parseSetCookie('bare=1').sameSite, 'unspecified');
  assert.equal(parseSetCookie('novalue'), null);
});

await t('cookies: session-name heuristic catches frameworks, ignores preferences', () => {
  for (const n of ['PHPSESSID', 'connect.sid', 'auth_token', 'jwt', 'remember_me', 'XSRF-TOKEN', 'JSESSIONID'])
    assert.ok(looksLikeSessionCookie(n), `${n} should look like a session cookie`);
  for (const n of ['theme', 'locale', 'consent', 'ab_variant'])
    assert.ok(!looksLikeSessionCookie(n), `${n} should not`);
});

// ── QA-01 transport ─────────────────────────────────────────────────────────────
await t('QA-01: plaintext http fails', () => {
  assert.equal(st(qa01.run(ctx({ url: 'http://example.com/' }))), 'fail');
});
await t('QA-01: https without HSTS fails', () => {
  assert.equal(st(qa01.run(ctx())), 'fail');
});
await t('QA-01: short max-age warns, strong policy passes', () => {
  assert.equal(st(qa01.run(ctx({ headers: { 'strict-transport-security': 'max-age=300' } }))), 'warn');
  assert.equal(st(qa01.run(ctx({ headers: { 'strict-transport-security': 'max-age=31536000' } }))), 'warn'); // no includeSubDomains
  assert.equal(st(qa01.run(ctx({ headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains; preload' } }))), 'pass');
});
await t('QA-01: max-age=0 is a failure, not a pass', () => {
  const r = qa01.run(ctx({ headers: { 'strict-transport-security': 'max-age=0' } }));
  assert.equal(r.status, 'fail');
  assert.match(r.summary, /disabled/i);
});

// ── QA-02 CSP ───────────────────────────────────────────────────────────────────
await t('QA-02: absent CSP fails', () => assert.equal(st(qa02.run(ctx())), 'fail'));
await t('QA-02: report-only alone warns and says nothing is blocked', () => {
  const r = qa02.run(ctx({ headers: { 'content-security-policy-report-only': "default-src 'self'" } }));
  assert.equal(r.status, 'warn');
  assert.match(r.summary, /report-only/i);
});
await t('QA-02: unsafe-inline warns', () => {
  const r = qa02.run(ctx({ headers: { 'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'" } }));
  assert.equal(r.status, 'warn');
  assert.ok(r.details.some((d) => d.includes('unsafe-inline')));
});
await t('QA-02: strict nonce policy passes', () => {
  assert.equal(st(qa02.run(ctx({ headers: { 'content-security-policy': "default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'self'" } }))), 'pass');
});
await t('QA-02: meta-only CSP is never a full pass', () => {
  const r = qa02.run(ctx({ metaCsp: ["default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"] }));
  assert.equal(r.status, 'warn');
  assert.ok(r.details.some((d) => /meta/i.test(d)));
});

// ── QA-03 framing ───────────────────────────────────────────────────────────────
await t('QA-03: nothing set fails', () => assert.equal(st(qa03.run(ctx())), 'fail'));
await t('QA-03: frame-ancestors none passes', () => {
  assert.equal(st(qa03.run(ctx({ headers: { 'content-security-policy': "frame-ancestors 'none'" } }))), 'pass');
});
await t('QA-03: frame-ancestors * fails', () => {
  assert.equal(st(qa03.run(ctx({ headers: { 'content-security-policy': 'frame-ancestors *' } }))), 'fail');
});
await t('QA-03: XFO alone passes (browsers still honour it); ALLOW-FROM fails', () => {
  assert.equal(st(qa03.run(ctx({ headers: { 'x-frame-options': 'DENY' } }))), 'pass');
  assert.equal(st(qa03.run(ctx({ headers: { 'x-frame-options': 'SAMEORIGIN' } }))), 'pass');
  assert.equal(st(qa03.run(ctx({ headers: { 'x-frame-options': 'ALLOW-FROM https://a.com' } }))), 'fail');
  assert.equal(st(qa03.run(ctx({ headers: { 'x-frame-options': 'ALLOWALL' } }))), 'fail');
});
await t('QA-03: frame-ancestors overrides a contradictory XFO', () => {
  const r = qa03.run(ctx({ headers: { 'content-security-policy': "frame-ancestors 'self'", 'x-frame-options': 'ALLOWALL' } }));
  assert.equal(r.status, 'pass');
  assert.ok(r.details.some((d) => /ignored/i.test(d)));
});

// ── QA-04 nosniff ───────────────────────────────────────────────────────────────
await t('QA-04: binary pass/fail', () => {
  assert.equal(st(qa04.run(ctx())), 'fail');
  assert.equal(st(qa04.run(ctx({ headers: { 'x-content-type-options': 'nosniff' } }))), 'pass');
  assert.equal(st(qa04.run(ctx({ headers: { 'x-content-type-options': 'NOSNIFF' } }))), 'pass');
  assert.equal(st(qa04.run(ctx({ headers: { 'x-content-type-options': 'yes' } }))), 'fail');
});

// ── QA-05 referrer / permissions ────────────────────────────────────────────────
await t('QA-05: both missing warns', () => assert.equal(st(qa05.run(ctx())), 'warn'));
await t('QA-05: unsafe-url fails, but legacy defaults only warn', () => {
  assert.equal(st(qa05.run(ctx({ headers: { 'referrer-policy': 'unsafe-url' } }))), 'fail');
  // These leak less than unsafe-url and were browser defaults for years — warn, don't fail.
  for (const v of ['no-referrer-when-downgrade', 'origin-when-cross-origin']) {
    const r = qa05.run(ctx({ headers: { 'referrer-policy': v, 'permissions-policy': 'camera=()' } }));
    assert.equal(r.status, 'warn', `${v} should warn, got ${r.status}`);
  }
});
await t('QA-05: fallback list uses the last understood token', () => {
  // "no-referrer, unsafe-url" means a modern browser applies unsafe-url.
  assert.equal(st(qa05.run(ctx({ headers: { 'referrer-policy': 'no-referrer, unsafe-url' } }))), 'fail');
  assert.equal(st(qa05.run(ctx({
    headers: { 'referrer-policy': 'no-referrer, strict-origin-when-cross-origin', 'permissions-policy': 'camera=()' },
  }))), 'pass');
});
await t('QA-05: good referrer policy but no permissions policy warns', () => {
  assert.equal(st(qa05.run(ctx({ headers: { 'referrer-policy': 'strict-origin-when-cross-origin' } }))), 'warn');
});

// ── QA-06 cookies ───────────────────────────────────────────────────────────────
await t('QA-06: no cookies passes', () => assert.equal(st(qa06.run(ctx())), 'pass'));
await t('QA-06: missing Secure on https fails', () => {
  assert.equal(st(qa06.run(ctx({ cookies: [cookie('prefs', { sameSite: 'lax' })] }))), 'fail');
});
await t('QA-06: session cookie without HttpOnly fails and names it', () => {
  const r = qa06.run(ctx({ cookies: [cookie('PHPSESSID', { secure: true, sameSite: 'lax' })] }));
  assert.equal(r.status, 'fail');
  assert.ok(r.details.some((d) => d.includes('PHPSESSID') && /HttpOnly/i.test(d)));
});
await t('QA-06: SameSite unset only warns', () => {
  assert.equal(st(qa06.run(ctx({ cookies: [cookie('theme', { secure: true })] }))), 'warn');
});
await t('QA-06: fully-flagged cookies pass', () => {
  assert.equal(st(qa06.run(ctx({ cookies: [cookie('sid', { secure: true, httpOnly: true, sameSite: 'strict' })] }))), 'pass');
});
await t('QA-06: http page does not demand Secure', () => {
  const r = qa06.run(ctx({ url: 'http://example.com/', cookies: [cookie('theme', { sameSite: 'lax' })] }));
  assert.equal(r.status, 'pass');
});

// ── QA-07 mixed content ─────────────────────────────────────────────────────────
await t('QA-07: skipped on http pages', () => {
  assert.equal(st(qa07.run(ctx({ url: 'http://example.com/' }))), 'skip');
});
await t('QA-07: active mixed content fails, passive warns', () => {
  assert.equal(st(qa07.run(ctx({ resources: [{ url: 'http://cdn.com/a.js', type: 'script' }] }))), 'fail');
  assert.equal(st(qa07.run(ctx({ resources: [{ url: 'http://cdn.com/a.png', type: 'img' }] }))), 'warn');
});
await t('QA-07: upgrade-insecure-requests downgrades to warn', () => {
  const r = qa07.run(ctx({
    headers: { 'content-security-policy': 'upgrade-insecure-requests' },
    resources: [{ url: 'http://cdn.com/a.js', type: 'script' }],
  }));
  assert.equal(r.status, 'warn');
  assert.ok(r.details.some((d) => /upgrade-insecure-requests/.test(d)));
});
await t('QA-07: all-https passes', () => {
  assert.equal(st(qa07.run(ctx({ resources: [{ url: 'https://cdn.com/a.js', type: 'script' }] }))), 'pass');
});

// ── QA-08 libraries ─────────────────────────────────────────────────────────────
await t('libdetect: reads versions out of real CDN URL shapes', () => {
  assert.deepEqual(pick(detectFromUrl('https://code.jquery.com/jquery-1.8.3.min.js')), { name: 'jquery', version: '1.8.3' });
  assert.deepEqual(pick(detectFromUrl('https://cdn.jsdelivr.net/npm/lodash@4.17.11/lodash.min.js')), { name: 'lodash', version: '4.17.11' });
  // cdnjs calls it angular.js; OSV indexes the npm package as `angular`.
  assert.deepEqual(pick(detectFromUrl('https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.2/angular.min.js')), { name: 'angular', version: '1.4.2' });
  assert.deepEqual(pick(detectFromUrl('https://unpkg.com/vue@2.6.10/dist/vue.js')), { name: 'vue', version: '2.6.10' });
  assert.deepEqual(pick(detectFromUrl('/static/jquery/3.4.1/jquery.min.js')), { name: 'jquery', version: '3.4.1' });
});
await t('libdetect: refuses generic app bundles and date-like versions', () => {
  assert.equal(detectFromUrl('/static/app-1.2.3.js'), null);
  assert.equal(detectFromUrl('/assets/main.4f3a2b1c.js'), null);
  assert.equal(detectFromUrl('/vendor/bundle-2.0.1.min.js'), null);
  assert.equal(detectFromUrl('/js/build/2024.10.1/thing.js'), null);
});
await t('libdetect: reads banners and pads partial versions', () => {
  assert.deepEqual(pick(detectFromBanner('/*! jQuery v3.4.1 | (c) JS Foundation */')), { name: 'jquery', version: '3.4.1' });
  assert.deepEqual(pick(detectFromUrl('/js/jquery-1.7.js')), { name: 'jquery', version: '1.7.0' });
});
await t('libdetect: merge keeps distinct versions and prefers the confident source', () => {
  const merged = mergeLibraries([
    { name: 'jquery', version: '3.4.1', source: 'url' },
    { name: 'jquery', version: '3.4.1', source: 'global' },
    { name: 'jquery', version: '1.8.3', source: 'url' },
  ]);
  assert.equal(merged.length, 2);
  assert.equal(merged.find((m) => m.version === '3.4.1').source, 'global');
});

await t('QA-08: high-severity advisory fails with CVE and fixed version', async () => {
  const osv = fakeOsv({
    'jquery@1.8.3': [{ id: 'GHSA-x', severity: 'HIGH', cves: ['CVE-2020-11023'], summary: 'XSS in jQuery', fixed: '3.5.0' }],
  });
  const r = await qa08.run(ctx({ libraries: [{ name: 'jquery', version: '1.8.3', source: 'url' }] }),
    { fetch: osv, cache: memoryCache() });
  assert.equal(r.status, 'fail');
  assert.ok(r.details.join(' ').includes('CVE-2020-11023'));
  assert.ok(r.details.join(' ').includes('3.5.0'));
});
await t('QA-08: moderate-only advisory warns rather than fails', async () => {
  const osv = fakeOsv({ 'marked@0.3.9': [{ id: 'GHSA-m', severity: 'MODERATE', cves: [], summary: 'ReDoS' }] });
  const r = await qa08.run(ctx({ libraries: [{ name: 'marked', version: '0.3.9', source: 'url' }] }),
    { fetch: osv, cache: memoryCache() });
  assert.equal(r.status, 'warn');
});
await t('QA-08: clean library passes', async () => {
  const r = await qa08.run(ctx({ libraries: [{ name: 'jquery', version: '3.7.1', source: 'global' }] }),
    { fetch: fakeOsv({}), cache: memoryCache() });
  assert.equal(r.status, 'pass');
});
await t('QA-08: OSV unreachable is SKIP, never a fabricated verdict', async () => {
  const r = await qa08.run(ctx({ libraries: [{ name: 'jquery', version: '1.8.3', source: 'url' }] }), {
    fetch: async () => { throw new Error('ENOTFOUND'); }, cache: memoryCache(),
  });
  assert.equal(r.status, 'skip');
  assert.match(r.summary, /OSV/i);
});
await t('QA-08: no detectable libraries is SKIP, not PASS', async () => {
  const r = await qa08.run(ctx(), { fetch: fakeOsv({}), cache: memoryCache() });
  assert.equal(r.status, 'skip');
});
await t('QA-08: cache prevents a second network call', async () => {
  let calls = 0;
  const osv = fakeOsv({});
  const counting = async (...a) => { calls++; return osv(...a); };
  const cache = memoryCache();
  const c = ctx({ libraries: [{ name: 'jquery', version: '3.7.1', source: 'global' }] });
  await qa08.run(c, { fetch: counting, cache });
  await qa08.run(c, { fetch: counting, cache });
  assert.equal(calls, 1, 'second scan should be served from cache');
});

// ── QA-09 exposed paths ─────────────────────────────────────────────────────────
const ENV_BODY = 'APP_KEY=base64:abcdef\nDB_PASSWORD=hunter2\n';
const GIT_HEAD = 'ref: refs/heads/main\n';

function proberFrom(map, fallback = { status: 404, body: 'Not Found' }) {
  return async (path) => {
    const key = Object.keys(map).find((k) => path.startsWith(k));
    return key ? { status: 200, headers: {}, body: map[key] } : { ...fallback, headers: {} };
  };
}

await t('QA-09: skipped unless the user consented', async () => {
  const r = await qa09.run(ctx({ probe: proberFrom({ '/.env': ENV_BODY }) }));
  assert.equal(r.status, 'skip');
});
await t('QA-09: finds a real .env and .git/HEAD', async () => {
  const r = await qa09.run(ctx({ activeAllowed: true, probe: proberFrom({ '/.env': ENV_BODY, '/.git/HEAD': GIT_HEAD }) }));
  assert.equal(r.status, 'fail');
  assert.ok(r.summary.includes('/.env') && r.summary.includes('/.git/HEAD'));
});
await t('QA-09: redacts secret values in the evidence snippet', async () => {
  const r = await qa09.run(ctx({ activeAllowed: true, probe: proberFrom({ '/.env': ENV_BODY }) }));
  assert.ok(!r.details.join(' ').includes('hunter2'), 'must not echo the secret back');
  assert.ok(r.details.join(' ').includes('[redacted]'));
});
await t('QA-09: SPA catch-all 200 does not produce findings', async () => {
  const shell = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>';
  const r = await qa09.run(ctx({ activeAllowed: true, probe: async () => ({ status: 200, headers: {}, body: shell }) }));
  assert.equal(r.status, 'pass', 'identical catch-all bodies must be calibrated away');
});
await t('QA-09: 200 with HTML at /.env is not an env file', async () => {
  const r = await qa09.run(ctx({
    activeAllowed: true,
    probe: proberFrom({ '/.env': '<!doctype html><html>A=1 landing page</html>' }),
  }));
  assert.notEqual(r.status, 'fail');
});
await t('QA-09: clean origin passes and lists what it probed', async () => {
  const r = await qa09.run(ctx({ activeAllowed: true, probe: proberFrom({}) }));
  assert.equal(r.status, 'pass');
  assert.ok(r.details.join(' ').includes('/.git/HEAD'));
});
await t('QA-09: every probe stays on the current origin', () => {
  for (const p of qa09.PROBES) assert.ok(p.path.startsWith('/'), `${p.path} must be origin-relative`);
});

// ── QA-10 disclosure ────────────────────────────────────────────────────────────
await t('QA-10: version banners warn, version-less banners pass', () => {
  assert.equal(st(qa10.run(ctx({ headers: { server: 'Apache/2.4.29 (Ubuntu)' } }))), 'warn');
  assert.equal(st(qa10.run(ctx({ headers: { 'x-powered-by': 'PHP/7.2.24' } }))), 'warn');
  assert.equal(st(qa10.run(ctx({ headers: { server: 'cloudflare' } }))), 'pass');
  assert.equal(st(qa10.run(ctx({ headers: { 'x-powered-by': 'Express' } }))), 'pass');
  assert.equal(st(qa10.run(ctx())), 'pass');
});

// ── runner ──────────────────────────────────────────────────────────────────────
await t('runner: a throwing check produces an error result, not a dead scan', async () => {
  const bad = { ...ctx(), get headers() { throw new Error('boom'); } };
  const report = await runAll(bad, { cache: memoryCache(), fetch: fakeOsv({}) });
  assert.equal(report.results.length, 10);
  assert.ok(report.results.some((r) => r.status === 'error'));
});
await t('runner: worst findings sort to the top', async () => {
  const report = await runAll(ctx({ headers: {} }), { cache: memoryCache(), fetch: fakeOsv({}) });
  assert.equal(report.results[0].status, 'fail');
  const statuses = report.results.map((r) => r.status);
  assert.ok(statuses.indexOf('pass') > statuses.lastIndexOf('fail'));
});
await t('runner: score rewards a well-configured site', async () => {
  assert.equal(score([]), 100);
  assert.ok(score([{ status: 'fail', severity: 'critical' }]) <= 70);
  assert.ok(score([{ status: 'warn', severity: 'low' }]) > 95);
});
await t('runner: a WAF challenge skips every header check instead of guessing', async () => {
  const c = ctx();
  c.challenge = 'Cloudflare served a bot-protection challenge (cf-mitigated) instead of the page.';
  const report = await runAll(c, { cache: memoryCache(), fetch: fakeOsv({}) });
  const headerChecks = report.results.filter((r) => r.id !== 'QA-09');
  assert.ok(headerChecks.every((r) => r.status === 'skip'),
    'a challenge page must not produce header findings about the real site');
  assert.ok(headerChecks[0].details.join(' ').includes('cf-mitigated'));
  assert.equal(report.score, 100, 'skipped checks must not be scored as failures');
});

await t('collector: recognises the WAF signatures that caused a real false positive', async () => {
  const { detectChallenge } = await import('../src/core/collect-node.js');
  assert.ok(detectChallenge(200, { 'cf-mitigated': ['challenge'] }, ''));
  assert.ok(detectChallenge(202, { 'x-amzn-waf-action': ['challenge'] }, ''));
  assert.ok(detectChallenge(200, {}, '<html><head><title>Just a moment...</title>'));
  assert.ok(detectChallenge(403, { server: ['cloudflare'] }, ''));
  // A normal page from the same CDNs must not be mistaken for a challenge.
  assert.equal(detectChallenge(200, { server: ['cloudflare'] }, '<html><title>Home</title>'), null);
  assert.equal(detectChallenge(200, { 'x-amzn-waf-action': ['allow'] }, ''), null);
});

await t('runner: enabled filter runs only the requested checks', async () => {
  const report = await runAll(ctx(), { enabled: ['QA-04'], cache: memoryCache() });
  assert.equal(report.results.length, 1);
  assert.equal(report.results[0].id, 'QA-04');
});

// ── licensing ───────────────────────────────────────────────────────────────────
// license.js reads storage through the shim, so it needs a namespace to resolve against.
const licStore = {};
globalThis.chrome = {
  storage: {
    local: {
      get: async (k) => (k in licStore ? { [k]: licStore[k] } : {}),
      set: async (o) => { Object.assign(licStore, o); },
      remove: async (k) => { delete licStore[k]; },
    },
  },
  runtime: { getManifest: () => ({ version: '1.0.0' }) },
};
const { verifyKey, activate, getLicense, isPro } = await import('../src/ext/license.js');

/** Issued with `m: 1` — unlocks 1.x only. */
const V1_KEY = 'QA1.eyJlIjoiYnV5ZXJAZXhhbXBsZS5jb20iLCJvIjoiT1JERVItOTAwMSIsInQiOiIyMDI2LTA3LTMwIiwicCI6InBybyIsInYiOjEsIm0iOjF9.SDMRYt79qNYJtyP1inj4iYyqL2LOKoL6RaLKSLzMN8Yepr3FDAqzqhCczFsREqtSRJUS-hT3tuou98SynkVA2g';
/** Issued with `m: 2` — a buyer given the next major version too. */
const V2_KEY = 'QA1.eyJlIjoiZWFybHlAZXhhbXBsZS5jb20iLCJvIjoiT1JERVItOTAwMiIsInQiOiIyMDI2LTA3LTMwIiwicCI6InBybyIsInYiOjEsIm0iOjJ9.N3eVdvxblbN2eusE98GkTSQ7fHtgUyNuaz4MWV8kNXlI7O8jx9Rw8Q9DmKGRjczclk5q9EabTN46ihwWa9M-zA';
/** Pre-ceiling key with no `m` field at all — must be grandfathered, never rejected. */
const LEGACY_KEY = 'QA1.eyJlIjoiYnV5ZXJAZXhhbXBsZS5jb20iLCJvIjoiT1JERVItOTAwMSIsInQiOiIyMDI2LTA3LTMwIiwicCI6InBybyIsInYiOjF9.ntgp22WlsMJdK4qW35JSTAdLK7NtHMPLMXu-uIk6YY9sXWuI7P8Y7kwMgRhVr_XAoWy9qkagBwfOZ5IdTmf_WA';
const VALID_KEY = V1_KEY;

await t('license: a key signed by the real private key verifies offline', async () => {
  const r = await verifyKey(VALID_KEY);
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.email, 'buyer@example.com');
  assert.equal(r.maxMajor, 1);
});

await t('license: version ceiling covers its own major and blocks the next', async () => {
  await activate(V1_KEY);
  assert.equal(await isPro({ major: 1 }), true, 'a 1.x key must unlock 1.x');
  assert.equal(await isPro({ major: 2 }), false, 'a 1.x key must not unlock 2.x');

  // The distinction that matters for support: still a genuine key, just not for this version.
  const lic = await getLicense({ major: 2 });
  assert.equal(lic.valid, true);
  assert.equal(lic.covered, false);
  assert.match(lic.reason, /unlocks QuickAudit 1\.x.*running 2\.x/i);
});

await t('license: a key sold with headroom unlocks the next major too', async () => {
  await activate(V2_KEY);
  assert.equal(await isPro({ major: 1 }), true);
  assert.equal(await isPro({ major: 2 }), true);
  assert.equal(await isPro({ major: 3 }), false);
});

await t('license: keys issued before the ceiling existed are grandfathered forever', async () => {
  await activate(LEGACY_KEY);
  const r = await verifyKey(LEGACY_KEY);
  assert.equal(r.maxMajor, Infinity, 'a missing `m` must not lock the buyer out');
  assert.equal(await isPro({ major: 9 }), true);
});
await t('license: tampering with the payload invalidates the key', async () => {
  const [, body, sig] = VALID_KEY.split('.');
  const forged = Buffer.from(JSON.stringify({ e: 'pirate@example.com', o: '', t: '2026-07-30', p: 'pro', v: 1 }))
    .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  assert.equal((await verifyKey(`QA1.${forged}.${sig}`)).valid, false);
  assert.equal((await verifyKey(`QA1.${body}.${'A'.repeat(86)}`)).valid, false);
});
await t('license: junk input is rejected without throwing', async () => {
  for (const junk of ['', 'not-a-key', 'QA1.abc', 'QA2.a.b', null, undefined]) {
    const r = await verifyKey(junk);
    assert.equal(r.valid, false);
    assert.ok(r.reason);
  }
});

function pick(o) { return o && { name: o.name, version: o.version }; }

console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}${passed} passed, ${failed} failed\x1b[0m`);
process.exit(failed ? 1 : 0);
