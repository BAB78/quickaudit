/**
 * Node collector: builds a PageContext with fetch only.
 *
 * Limitation, stated up front: Node does not run the page's JavaScript, so the high-confidence
 * `global` library detection is unavailable here and we fall back to URL and banner parsing.
 * The extension collector fills that gap. Everything else is identical.
 */
import { normalizeHeaders, getAll } from './headers.js';
import { parseSetCookies } from './cookies.js';
import { detectFromUrl, detectFromBanner, mergeLibraries } from './libdetect.js';
import { PROBE_BODY_LIMIT } from './types.js';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 QuickAudit/1.0';

export async function collect(url, opts = {}) {
  const timeout = opts.timeout ?? 15000;
  const notes = [];

  const res = await fetchWithTimeout(url, { headers: { 'user-agent': UA, accept: 'text/html,*/*' }, redirect: 'follow' }, timeout);
  const finalUrl = res.url || url;
  const html = await res.text();
  const headers = normalizeHeaders(res.headers);
  const u = new URL(finalUrl);

  if (finalUrl !== url) notes.push(`Followed redirect: ${url} → ${finalUrl}`);
  if (!res.ok) notes.push(`Origin responded HTTP ${res.status} — header checks still apply, but this may not be the real page.`);

  const challenge = detectChallenge(res.status, headers, html);
  if (challenge) notes.push(challenge);

  const metaCsp = extractMetaCsp(html);
  const resources = extractResources(html, finalUrl);
  const cookies = parseSetCookies(getAll(headers, 'set-cookie'));
  notes.push('Collected without a browser: cookie flags come from Set-Cookie only, and JS-injected resources are not visible.');

  const libraries = await detectLibraries(html, resources, finalUrl, opts, notes);

  return {
    url: finalUrl,
    origin: u.origin,
    protocol: u.protocol,
    headers,
    metaCsp,
    cookies,
    resources,
    libraries,
    activeAllowed: Boolean(opts.active),
    challenge,
    notes,
    probe: opts.active ? makeProber(u.origin, timeout) : null,
    raw: { status: res.status, html },
  };
}

async function detectLibraries(html, resources, baseUrl, opts, notes) {
  const found = [];
  for (const r of resources) {
    if (r.type !== 'script') continue;
    const hit = detectFromUrl(r.url);
    if (hit) found.push(hit);
  }
  // Inline banners in the document itself.
  const inline = detectFromBanner(html);
  if (inline) found.push(inline);

  // Fetch the head of a few same-origin scripts to read banners the URL didn't reveal.
  if (opts.fetchScripts !== false) {
    const candidates = resources
      .filter((r) => r.type === 'script' && !found.some((f) => f.evidence && r.url.includes(f.evidence)))
      .slice(0, opts.maxScripts ?? 6);
    const banners = await Promise.all(candidates.map(async (r) => {
      try {
        const res = await fetchWithTimeout(r.url, { headers: { 'user-agent': UA } }, 8000);
        if (!res.ok) return null;
        const text = (await res.text()).slice(0, 4096);
        return detectFromBanner(text);
      } catch {
        return null;
      }
    }));
    for (const b of banners) if (b) found.push(b);
  }

  const libs = mergeLibraries(found);
  if (!libs.length) notes.push('No library versions detected from URLs or banners.');
  return libs;
}

function extractMetaCsp(html) {
  const out = [];
  const re = /<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi;
  for (const tag of html.match(re) || []) {
    const m = tag.match(/content\s*=\s*["']([^"']+)["']/i);
    if (m) out.push(m[1]);
  }
  return out;
}

const RESOURCE_PATTERNS = [
  { re: /<script[^>]+src\s*=\s*["']([^"']+)["']/gi, type: 'script' },
  { re: /<link[^>]+rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["']([^"']+)["']/gi, type: 'css' },
  { re: /<link[^>]+href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["']stylesheet["']/gi, type: 'css' },
  { re: /<iframe[^>]+src\s*=\s*["']([^"']+)["']/gi, type: 'iframe' },
  { re: /<img[^>]+src\s*=\s*["']([^"']+)["']/gi, type: 'img' },
  { re: /<(?:video|audio|source)[^>]+src\s*=\s*["']([^"']+)["']/gi, type: 'media' },
  { re: /<object[^>]+data\s*=\s*["']([^"']+)["']/gi, type: 'object' },
];

function extractResources(html, baseUrl) {
  const seen = new Set();
  const out = [];
  for (const { re, type } of RESOURCE_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(html)) !== null) {
      let abs;
      try {
        abs = new URL(m[1], baseUrl).href;
      } catch {
        continue;
      }
      if (!/^https?:/i.test(abs)) continue;
      const key = `${type}|${abs}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ url: abs, type });
    }
  }
  return out;
}

/** Serialized, rate-limited prober for QA-09. Only ever touches the given origin. */
export function makeProber(origin, timeout = 8000, delayMs = 150) {
  let chain = Promise.resolve();
  return (path) => {
    chain = chain.then(() => new Promise((r) => setTimeout(r, delayMs)));
    return chain.then(async () => {
      const target = new URL(path, origin);
      if (target.origin !== origin) throw new Error('probe escaped origin');
      const res = await fetchWithTimeout(target.href, {
        headers: { 'user-agent': UA }, redirect: 'manual',
      }, timeout);
      const buf = await res.arrayBuffer();
      const body = new TextDecoder('utf-8', { fatal: false })
        .decode(buf.slice(0, PROBE_BODY_LIMIT));
      return { status: res.status, headers: normalizeHeaders(res.headers), body };
    });
  };
}

/**
 * Detect a WAF / bot-protection interstitial.
 *
 * This matters more than it looks. When Cloudflare or AWS WAF serves a challenge, the
 * response headers belong to the *challenge*, not to the site — so a scanner happily reports
 * "no HSTS, no CSP" about a site that sets both. Found exactly this way on sourceforge.net
 * during the Phase 3 corpus run.
 */
export function detectChallenge(status, headers, html) {
  const head = String(html || '').slice(0, 4000);
  if (headers['cf-mitigated']) return 'Cloudflare served a bot-protection challenge (cf-mitigated) instead of the page. Header findings describe the challenge, not the site.';
  if (String(headers['x-amzn-waf-action']?.[0] || '').toLowerCase() === 'challenge') return 'AWS WAF served a challenge instead of the page. Header findings describe the challenge, not the site.';
  if (/<title>\s*(Just a moment|Attention Required!|Access denied|Please Wait\.\.\.)/i.test(head)) return 'The origin served an interstitial challenge page. Header findings describe the challenge, not the site.';
  if ([401, 403, 429, 503].includes(status) && /cloudflare|akamai|incapsula|imperva|sucuri/i.test(String(headers.server?.[0] || ''))) {
    return `The origin returned HTTP ${status} from a WAF rather than the page. Header findings may describe the block page, not the site.`;
  }
  return null;
}

export async function fetchWithTimeout(url, init, ms) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(t);
  }
}
