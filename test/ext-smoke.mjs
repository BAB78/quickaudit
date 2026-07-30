#!/usr/bin/env node
/**
 * Exercises the background collector end-to-end with stubbed extension APIs, against the
 * local fixture servers. Catches the wiring bugs unit tests can't see: permission gating,
 * cookie-store merging, the message contract the popup depends on, prober construction.
 *
 * Runs the whole suite twice, once per namespace shape:
 *
 *   chromium — only `chrome`, promise-based (MV3).
 *   firefox  — `browser` promise-based AND a callback-only `chrome` alias alongside it.
 *              The alias returns undefined instead of a promise, so any code that reaches for
 *              `chrome.*` directly fails loudly here instead of silently in the wild.
 *
 * Each mode needs a fresh module graph, so the runner re-spawns itself per mode.
 */
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const MODES = ['chromium', 'firefox'];
const mode = process.argv.find((a) => a.startsWith('--mode='))?.slice(7);

if (!mode) {
  let bad = 0;
  for (const m of MODES) {
    console.log(`\n\x1b[1m── namespace: ${m} ──\x1b[0m`);
    const r = spawnSync(process.execPath, [fileURLToPath(import.meta.url), `--mode=${m}`], { stdio: 'inherit' });
    if (r.status !== 0) bad++;
  }
  process.exit(bad ? 1 : 0);
}

const server = spawn(process.execPath, [path.join(here, 'fixture-server.mjs')], { stdio: 'ignore' });
await new Promise((r) => setTimeout(r, 700));

// ── stub state ──────────────────────────────────────────────────────────────────
const state = {
  storage: {},
  grantedOrigins: new Set(),
  tabs: { 1: { id: 1, url: 'http://127.0.0.1:8081/' } },
  cookies: [
    { name: 'PHPSESSID', secure: false, httpOnly: false, sameSite: 'unspecified', domain: '127.0.0.1' },
    { name: 'theme', secure: false, httpOnly: false, sameSite: 'lax', domain: '127.0.0.1' },
  ],
  executed: [],
  webRequestArgs: null,
};
let onMessage;

const promiseNamespace = () => ({
  webRequest: {
    onHeadersReceived: {
      addListener: (_fn, filter, extra) => { state.webRequestArgs = { filter, extra }; },
    },
  },
  tabs: {
    onRemoved: { addListener() {} },
    get: async (id) => state.tabs[id],
    query: async () => [state.tabs[1]],
    create() {},
  },
  runtime: {
    onMessage: { addListener: (fn) => { onMessage = fn; } },
    getURL: (p) => `moz-extension://x/${p}`,
    openOptionsPage() {},
  },
  storage: {
    local: {
      get: async (k) => {
        if (k == null) return { ...state.storage };
        const keys = Array.isArray(k) ? k : [k];
        return Object.fromEntries(keys.filter((x) => x in state.storage).map((x) => [x, state.storage[x]]));
      },
      set: async (obj) => { Object.assign(state.storage, obj); },
      remove: async (k) => { delete state.storage[k]; },
    },
  },
  permissions: {
    contains: async ({ origins }) => origins.every((o) => state.grantedOrigins.has(o)),
    request: async ({ origins }) => { origins.forEach((o) => state.grantedOrigins.add(o)); return true; },
  },
  cookies: { getAll: async () => state.cookies },
  scripting: {
    executeScript: async ({ world, func, args }) => {
      state.executed.push(world);
      if (world === 'MAIN') return [{ result: func(...(args || [])) }];
      return [{ result: {
        metaCsp: [],
        resources: [
          { url: 'https://code.jquery.com/jquery-1.8.3.min.js', type: 'script' },
          { url: 'https://cdn.jsdelivr.net/npm/lodash@4.17.11/lodash.min.js', type: 'script' },
          { url: 'http://insecure.example.com/ads.js', type: 'script' },
          { url: 'http://insecure.example.com/tracker.gif', type: 'img' },
        ],
      } }];
    },
  },
  downloads: { download: async () => 1 },
});

/**
 * Firefox's `chrome` alias: callback-based, returns undefined. Awaiting anything on it
 * yields undefined rather than data — exactly the failure this mode exists to catch.
 */
function callbackAlias(promised) {
  return {
    ...promised,
    storage: {
      local: {
        get: (k, cb) => { promised.storage.local.get(k).then(cb); return undefined; },
        set: (o, cb) => { promised.storage.local.set(o).then(() => cb && cb()); return undefined; },
        remove: (k, cb) => { promised.storage.local.remove(k).then(() => cb && cb()); return undefined; },
      },
    },
    permissions: {
      contains: (p, cb) => { promised.permissions.contains(p).then(cb); return undefined; },
      request: (p, cb) => { promised.permissions.request(p).then(cb); return undefined; },
    },
    tabs: { ...promised.tabs, get: (id, cb) => { promised.tabs.get(id).then(cb); return undefined; } },
    cookies: { getAll: (q, cb) => { promised.cookies.getAll(q).then(cb); return undefined; } },
  };
}

const ns = promiseNamespace();
if (mode === 'firefox') {
  globalThis.browser = ns;
  globalThis.chrome = callbackAlias(ns); // the trap
} else {
  globalThis.chrome = ns;
}

const { engine } = await import('../src/ext/browser-api.js');
await import('../src/ext/background.js');

const send = (msg) => new Promise((resolve) => { onMessage(msg, {}, resolve); });

let passed = 0, failed = 0;
const t = async (name, fn) => {
  try { await fn(); passed++; console.log(`\x1b[32mok\x1b[0m   ${name}`); }
  catch (e) { failed++; console.error(`\x1b[31mFAIL\x1b[0m ${name}\n     ${e.message.split('\n').slice(0, 4).join('\n     ')}`); }
};

await t(`shim resolves the ${mode} namespace`, () => {
  assert.equal(engine, mode === 'firefox' ? 'firefox' : 'chromium');
});

await t('webRequest listener uses extraHeaders only where it is supported', () => {
  // Firefox rejects 'extraHeaders' outright; Chromium needs it to observe Set-Cookie.
  const extra = state.webRequestArgs.extra;
  assert.ok(extra.includes('responseHeaders'));
  assert.equal(extra.includes('extraHeaders'), mode === 'chromium');
});

await t('scan is refused until the origin permission is granted', async () => {
  const r = await send({ type: 'scan', tabId: 1 });
  assert.equal(r.needsPermission, 'http://127.0.0.1:8081/*');
  assert.equal(r.origin, 'http://127.0.0.1:8081');
});

await t('a granted scan returns a full ten-check report', async () => {
  state.grantedOrigins.add('http://127.0.0.1:8081/*');
  const r = await send({ type: 'scan', tabId: 1 });
  assert.ok(!r.error, r.error);
  assert.equal(r.results.length, 10);
  assert.equal(typeof r.score, 'number');
  assert.ok(r.results.every((x) => x.id && x.status && x.summary), 'popup contract fields missing');
});

await t('settings are read back through the storage shim', async () => {
  // On Firefox this only works because the shim preferred `browser`; the callback alias
  // would have resolved qaSettings to undefined and left active checks off.
  state.storage.qaSettings = { activeChecks: true };
  const r = await send({ type: 'scan', tabId: 1 });
  const qa09 = r.results.find((x) => x.id === 'QA-09');
  assert.equal(qa09.status, 'fail', `active checks did not take effect: ${qa09.summary}`);
  assert.ok(qa09.summary.includes('/.env'));
});

await t('cookie flags come from the cookie store, not just Set-Cookie', async () => {
  const r = await send({ type: 'scan', tabId: 1 });
  const qa06 = r.results.find((x) => x.id === 'QA-06');
  assert.equal(qa06.status, 'fail');
  assert.ok(qa06.details.join(' ').includes('PHPSESSID'));
});

await t('libraries merge page globals with script URLs', async () => {
  const r = await send({ type: 'scan', tabId: 1 });
  const qa08 = r.results.find((x) => x.id === 'QA-08');
  assert.ok(/jquery|lodash/i.test(JSON.stringify(qa08)));
  assert.ok(state.executed.includes('MAIN'), 'must read page globals from the MAIN world');
  assert.ok(state.executed.includes('ISOLATED'), 'must sweep the DOM from the ISOLATED world');
});

await t('a main-world refusal degrades to URL detection with a note', async () => {
  const real = ns.scripting.executeScript;
  ns.scripting.executeScript = async (opts) => {
    if (opts.world === 'MAIN') throw new Error('world MAIN not supported');
    return real(opts);
  };
  const r = await send({ type: 'scan', tabId: 1 });
  assert.ok(r.notes.some((n) => /main-world/i.test(n)), `expected a degradation note, got ${r.notes}`);
  assert.ok(/jquery/i.test(JSON.stringify(r.results.find((x) => x.id === 'QA-08'))),
    'URL-based detection must still work without page globals');
  ns.scripting.executeScript = real;
});

await t('QA-09 goes back to skip when the user disables it', async () => {
  state.storage.qaSettings = { activeChecks: false };
  const r = await send({ type: 'scan', tabId: 1 });
  assert.equal(r.results.find((x) => x.id === 'QA-09').status, 'skip');
});

await t('the report is persisted for the popup to re-open', async () => {
  await send({ type: 'scan', tabId: 1 });
  assert.equal(state.storage.lastReport?.results?.length, 10);
});

await t('non-http pages are refused with a readable message', async () => {
  state.tabs[2] = { id: 2, url: 'about:addons' };
  const r = await send({ type: 'scan', tabId: 2 });
  assert.match(r.error, /http/i);
});

await t('the SPA fixture produces no QA-09 false positive', async () => {
  state.tabs[3] = { id: 3, url: 'http://127.0.0.1:8082/' };
  state.grantedOrigins.add('http://127.0.0.1:8082/*');
  state.storage.qaSettings = { activeChecks: true };
  const r = await send({ type: 'scan', tabId: 3 });
  assert.equal(r.results.find((x) => x.id === 'QA-09').status, 'pass');
});

await t('background never calls permissions.request (Firefox rejects it there)', async () => {
  let called = false;
  ns.permissions.request = async () => { called = true; return true; };
  state.grantedOrigins.clear();
  const r = await send({ type: 'scan', tabId: 1 });
  assert.ok(r.needsPermission, 'should hand the request back to the popup');
  assert.equal(called, false, 'the background must not raise the permission prompt itself');
});

server.kill();
console.log(`${failed ? '\x1b[31m' : '\x1b[32m'}${mode}: ${passed} passed, ${failed} failed\x1b[0m`);
process.exit(failed ? 1 : 0);
