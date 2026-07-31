/**
 * Background collector: builds a PageContext from WebExtension APIs, then runs the same ten
 * checks the CLI runs. Nothing security-relevant is decided in here — this file only collects.
 *
 * Runs as a service worker on Chromium/Safari and as an event page on Firefox. Both are
 * non-persistent, so nothing here may rely on module state surviving between messages.
 */
import { api, can, storage } from './browser-api.js';
import { runAll } from '../checks/index.js';
import { normalizeHeaders, getAll } from '../core/headers.js';
import { parseSetCookies, mergeCookies } from '../core/cookies.js';
import { detectFromUrl, mergeLibraries, GLOBAL_PROBES } from '../core/libdetect.js';
import { extensionStorageCache } from '../core/osv.js';
import { PROBE_BODY_LIMIT } from '../core/types.js';

/**
 * Headers are read with a credentialed fetch rather than by observing the navigation.
 *
 * The webRequest API would give the exact bytes of the original response, but Chrome only
 * delivers those events to extensions holding host permissions *at install time* — and
 * QuickAudit deliberately asks for one origin at a time, when you click Scan. Requesting
 * access to every site up front to gain slightly more faithful headers is a bad trade for a
 * tool whose selling point is that it doesn't do that. Chrome also logs a permanent error
 * badge for any extension that registers a webRequest listener it can never receive.
 *
 * The fetch below sends the page's own cookies, so it still sees the authenticated response.
 */
api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'scan') {
    scanTab(msg.tabId).then(sendResponse).catch((e) => sendResponse({ error: e.message }));
    return true; // keep the channel open for the async reply
  }
  return false;
});

async function settings() {
  const { qaSettings } = await storage.get('qaSettings');
  return { activeChecks: false, enabled: null, ...(qaSettings || {}) };
}

async function scanTab(tabId) {
  const tab = await api.tabs.get(tabId);
  const url = tab.url || '';
  if (!/^https?:/i.test(url)) {
    return { error: 'QuickAudit only works on http:// and https:// pages.' };
  }
  const u = new URL(url);
  const originPattern = `${u.origin}/*`;

  // The popup must request this itself — Firefox only allows permissions.request() inside a
  // user-input handler, so it can never be proxied through here.
  const hasPerm = await api.permissions.contains({ origins: [originPattern] });
  if (!hasPerm) return { needsPermission: originPattern, origin: u.origin };

  const cfg = await settings();
  const notes = [];

  // ── headers ────────────────────────────────────────────────────────────────
  // Credentialed so we see the response a logged-in user actually gets.
  let headers = {};
  try {
    const res = await fetch(url, { credentials: 'include', cache: 'reload', redirect: 'follow' });
    headers = normalizeHeaders(res.headers);
    notes.push('Headers were read from a fresh request to this URL, not from the original page load. A site that varies headers per request may differ slightly.');
  } catch (e) {
    notes.push(`Could not read response headers: ${e.message}`);
  }

  // ── cookies ────────────────────────────────────────────────────────────────
  // The cookie store is authoritative for flags; Set-Cookie only shows this one response.
  let storeCookies = [];
  if (can.cookies) {
    try {
      storeCookies = (await api.cookies.getAll({ url })).map((c) => ({
        name: c.name,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: (c.sameSite || 'unspecified').toLowerCase().replace('no_restriction', 'none'),
        domain: c.domain,
      }));
    } catch (e) {
      notes.push(`Cookie flags unavailable: ${e.message}`);
    }
  }
  const cookies = mergeCookies(parseSetCookies(getAll(headers, 'set-cookie')), storeCookies);

  // ── page-side collection ───────────────────────────────────────────────────
  const dom = await exec(tabId, 'ISOLATED', collectDom);
  const globals = await exec(tabId, 'MAIN', collectGlobals, [GLOBAL_PROBES]);

  const resources = dom?.resources || [];
  const libraries = mergeLibraries([
    ...(globals || []),
    ...resources.filter((r) => r.type === 'script').map((r) => detectFromUrl(r.url)).filter(Boolean),
  ]);
  if (!dom) notes.push('Could not inject the page collector — mixed-content and library detection are incomplete.');
  if (dom && !globals) {
    notes.push('This browser blocked main-world injection, so library versions came from script URLs only. Bundled libraries may be missed.');
  }

  const ctx = {
    url,
    origin: u.origin,
    protocol: u.protocol,
    headers,
    metaCsp: dom?.metaCsp || [],
    cookies,
    resources,
    libraries,
    activeAllowed: Boolean(cfg.activeChecks),
    notes,
    probe: cfg.activeChecks ? makeProber(u.origin) : null,
  };

  const report = await runAll(ctx, {
    enabled: cfg.enabled,
    cache: extensionStorageCache(storage),
  });
  await storage.set({ lastReport: report });
  return report;
}

/**
 * Inject a collector. Returns null rather than throwing when the engine refuses — Safari and
 * older Firefox reject `world: 'MAIN'`, and losing global detection is a degraded scan, not a
 * failed one.
 */
async function exec(tabId, world, func, args = []) {
  try {
    const out = await api.scripting.executeScript({ target: { tabId }, world, func, args });
    return out?.[0]?.result ?? null;
  } catch {
    return null;
  }
}

/** Serialized, capped, origin-locked prober. QA-09 is the only caller. */
function makeProber(origin, delayMs = 150, max = 20) {
  let chain = Promise.resolve();
  let sent = 0;
  return (path) => {
    if (++sent > max) return Promise.resolve(null);
    chain = chain.then(() => new Promise((r) => setTimeout(r, delayMs)));
    return chain.then(async () => {
      const target = new URL(path, origin);
      if (target.origin !== origin) throw new Error('probe escaped origin');
      const res = await fetch(target.href, { credentials: 'omit', redirect: 'manual', cache: 'no-store' });
      const buf = await res.arrayBuffer();
      return {
        status: res.status,
        headers: normalizeHeaders(res.headers),
        body: new TextDecoder('utf-8', { fatal: false }).decode(buf.slice(0, PROBE_BODY_LIMIT)),
      };
    });
  };
}

// ── injected functions (serialized into the page, so they must be self-contained) ──

function collectDom() {
  const metaCsp = [...document.querySelectorAll('meta[http-equiv]')]
    .filter((m) => m.getAttribute('http-equiv').toLowerCase() === 'content-security-policy')
    .map((m) => m.content)
    .filter(Boolean);

  const typeOf = (initiator) => ({
    script: 'script', link: 'css', css: 'css', img: 'img', image: 'img',
    iframe: 'iframe', frame: 'iframe', xmlhttprequest: 'xhr', fetch: 'xhr',
    video: 'media', audio: 'media', beacon: 'other', other: 'other',
  }[initiator] || 'other');

  const seen = new Set();
  const resources = [];
  const add = (url, type) => {
    if (!url || !/^https?:/i.test(url)) return;
    const key = `${type}|${url}`;
    if (seen.has(key)) return;
    seen.add(key);
    resources.push({ url, type });
  };

  // Everything the page actually fetched, including anything JS injected at runtime.
  for (const e of performance.getEntriesByType('resource')) add(e.name, typeOf(e.initiatorType));
  // Plus declared markup, which catches resources the browser blocked before fetching —
  // blocked mixed content leaves no performance entry, so both sources are needed.
  for (const el of document.querySelectorAll('script[src]')) add(el.src, 'script');
  for (const el of document.querySelectorAll('link[rel~="stylesheet"][href]')) add(el.href, 'css');
  for (const el of document.querySelectorAll('iframe[src]')) add(el.src, 'iframe');
  for (const el of document.querySelectorAll('img[src]')) add(el.src, 'img');
  for (const el of document.querySelectorAll('video[src],audio[src],source[src]')) add(el.src, 'media');
  for (const el of document.querySelectorAll('object[data]')) add(el.data, 'object');

  return { metaCsp, resources: resources.slice(0, 400) };
}

/**
 * Read library versions off the page's globals by walking property paths.
 *
 * Deliberately contains no evaluator — no eval, no `new Function`, no string that becomes
 * code. A security extension that ships a dynamic code path invites exactly the review it
 * does not need, and reading a property path does the same job.
 */
function collectGlobals(probes) {
  const read = (path) => {
    let node = globalThis;
    for (const key of path) {
      if (node == null) return undefined;
      try {
        node = node[key];
      } catch {
        return undefined; // a getter that throws is not a version we can read
      }
    }
    return node;
  };

  const out = [];
  for (const probe of probes) {
    try {
      if (probe.excludes && read(probe.excludes) !== undefined) continue;
      if (probe.requires && read(probe.requires) === undefined) continue;

      let value = read(probe.path);
      if (probe.format === 'revision' && typeof value === 'number') value = `0.${value}.0`;
      if (typeof value !== 'string' || !/^\d+\.\d+/.test(value)) continue;

      const parts = value.match(/^\d+\.\d+(?:\.\d+)?/)[0].split('.');
      while (parts.length < 3) parts.push('0');
      out.push({
        name: probe.pkg,
        version: parts.join('.'),
        source: 'global',
        evidence: `${probe.path.join('.')} = ${value}`,
      });
    } catch { /* a global that throws on access is not a library we can version */ }
  }
  return out;
}
