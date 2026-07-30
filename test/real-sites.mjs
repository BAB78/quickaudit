#!/usr/bin/env node
/**
 * Phase 3 validation corpus: 20 real sites, a deliberate mix of security-conscious
 * organisations and older/looser properties.
 *
 * PASSIVE CHECKS ONLY. The active file-exposure check (QA-09) is never run here — probing
 * third-party servers for /.env is not something to do casually, and it is validated against
 * the local fixture servers instead (test/integration.mjs).
 *
 * Writes test/real-sites-results.json with the raw headers alongside each verdict, so every
 * result can be audited by hand rather than taken on trust.
 */
import { writeFileSync } from 'node:fs';
import { collect } from '../src/core/collect-node.js';
import { runAll } from '../src/checks/index.js';
import { memoryCache } from '../src/core/osv.js';

const SITES = [
  // Expected to be tight — security vendors, big engineering orgs
  { url: 'https://github.com/', bucket: 'hardened' },
  { url: 'https://www.cloudflare.com/', bucket: 'hardened' },
  { url: 'https://www.mozilla.org/en-US/', bucket: 'hardened' },
  { url: 'https://stripe.com/', bucket: 'hardened' },
  { url: 'https://about.gitlab.com/', bucket: 'hardened' },
  { url: 'https://www.npmjs.com/', bucket: 'hardened' },
  { url: 'https://bitwarden.com/', bucket: 'hardened' },
  { url: 'https://1password.com/', bucket: 'hardened' },
  { url: 'https://owasp.org/', bucket: 'hardened' },
  { url: 'https://www.hackerone.com/', bucket: 'hardened' },
  // Expected to be looser — older stacks, CMS-driven, or simply not header-focused
  { url: 'https://news.ycombinator.com/', bucket: 'mixed' },
  { url: 'https://www.wikipedia.org/', bucket: 'mixed' },
  { url: 'https://www.python.org/', bucket: 'mixed' },
  { url: 'https://www.apache.org/', bucket: 'mixed' },
  { url: 'https://jquery.com/', bucket: 'mixed' },
  { url: 'https://www.w3schools.com/', bucket: 'mixed' },
  { url: 'https://sourceforge.net/', bucket: 'mixed' },
  { url: 'https://www.imdb.com/', bucket: 'mixed' },
  { url: 'https://www.bbc.co.uk/', bucket: 'mixed' },
  { url: 'https://www.nasa.gov/', bucket: 'mixed' },
];

const IDS = ['QA-01', 'QA-02', 'QA-03', 'QA-04', 'QA-05', 'QA-06', 'QA-07', 'QA-08', 'QA-09', 'QA-10'];
const GLYPH = { pass: '+', warn: '~', fail: 'X', skip: '.', error: '!' };
const cache = memoryCache(); // shared, so OSV is queried once per name@version across all sites

const out = [];
console.log('Scanning 20 sites (passive checks only)…\n');

for (const site of SITES) {
  process.stdout.write(site.url.padEnd(38));
  const started = Date.now();
  try {
    const ctx = await collect(site.url, { active: false, timeout: 20000, maxScripts: 4 });
    const report = await runAll(ctx, { cache });
    const row = Object.fromEntries(report.results.map((r) => [r.id, r.status]));
    const ms = Date.now() - started;
    console.log(`${IDS.map((id) => GLYPH[row[id]] ?? '?').join(' ')}   score ${String(report.score).padStart(3)}  ${ms}ms`);

    out.push({
      url: site.url,
      finalUrl: ctx.url,
      bucket: site.bucket,
      score: report.score,
      ms,
      verdicts: row,
      libraries: ctx.libraries.map((l) => `${l.name}@${l.version} (${l.source})`),
      // Raw evidence, so every verdict above can be checked by hand.
      rawHeaders: Object.fromEntries(Object.entries(ctx.headers)
        .filter(([k]) => !['set-cookie', 'date', 'age', 'content-length', 'etag', 'last-modified', 'expires', 'vary', 'accept-ranges', 'connection', 'transfer-encoding', 'alt-svc', 'cache-control'].includes(k))),
      cookieFlags: ctx.cookies.map((c) => `${c.name}: secure=${c.secure} httpOnly=${c.httpOnly} sameSite=${c.sameSite}`),
      insecureResources: ctx.resources.filter((r) => r.url.startsWith('http://')).map((r) => `[${r.type}] ${r.url}`),
      findings: report.results.filter((r) => r.status === 'fail' || r.status === 'warn')
        .map((r) => ({ id: r.id, status: r.status, summary: r.summary, details: r.details })),
    });
  } catch (e) {
    console.log(`ERROR ${e.message}`);
    out.push({ url: site.url, bucket: site.bucket, error: e.message });
  }
}

console.log(`\nLegend: + pass  ~ warn  X fail  . skip  ! error`);
console.log(`Columns: ${IDS.join(' ')}\n`);

const ok = out.filter((r) => !r.error);
const avg = (list) => list.length ? Math.round(list.reduce((s, r) => s + r.score, 0) / list.length) : 0;
console.log(`hardened bucket average score: ${avg(ok.filter((r) => r.bucket === 'hardened'))}`);
console.log(`mixed bucket average score:    ${avg(ok.filter((r) => r.bucket === 'mixed'))}`);
console.log(`median scan time:              ${median(ok.map((r) => r.ms))}ms`);

writeFileSync(new URL('real-sites-results.json', import.meta.url), JSON.stringify(out, null, 2));
console.log(`\nFull evidence written to test/real-sites-results.json`);

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)] : 0;
}
