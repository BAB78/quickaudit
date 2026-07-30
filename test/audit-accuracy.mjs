#!/usr/bin/env node
/**
 * Phase 3 accuracy audit.
 *
 * Re-derives the expected verdict for each site from the recorded raw headers using logic
 * written independently of src/checks (deliberately naive, straight from the header text),
 * then diffs it against what QuickAudit actually reported. Every disagreement is printed in
 * full for manual adjudication — the point is to surface disagreements, not to auto-grade.
 */
import { readFileSync } from 'node:fs';

const data = JSON.parse(readFileSync(new URL('real-sites-results.json', import.meta.url)));
const h = (s, n) => (s.rawHeaders[n] ? s.rawHeaders[n][0] : '');

/** Independent expectations. Only the deterministic header checks are auto-gradeable. */
const EXPECT = {
  'QA-01': (s) => {
    if (!s.finalUrl.startsWith('https:')) return 'fail';
    const v = h(s, 'strict-transport-security');
    if (!v) return 'fail';
    const m = /max-age\s*=\s*(\d+)/i.exec(v);
    if (!m || Number(m[1]) === 0) return 'fail';
    if (Number(m[1]) < 15552000 || !/includesubdomains/i.test(v)) return 'warn';
    return 'pass';
  },
  'QA-02': (s) => {
    const v = h(s, 'content-security-policy');
    if (!v) return h(s, 'content-security-policy-report-only') ? 'warn' : 'fail';
    return 'warn_or_pass'; // policy quality needs judgement; adjudicated by hand below
  },
  'QA-03': (s) => {
    const csp = h(s, 'content-security-policy');
    const fa = /(?:^|;)\s*frame-ancestors\s+([^;]+)/i.exec(csp);
    if (fa) return /(^|\s)\*(\s|$)/.test(fa[1]) ? 'fail' : 'pass';
    const xfo = h(s, 'x-frame-options').trim().toUpperCase();
    if (!xfo) return 'fail';
    return xfo === 'DENY' || xfo === 'SAMEORIGIN' ? 'pass' : 'fail';
  },
  'QA-04': (s) => (h(s, 'x-content-type-options').trim().toLowerCase() === 'nosniff' ? 'pass' : 'fail'),
  'QA-05': (s) => {
    const rp = h(s, 'referrer-policy').trim().toLowerCase();
    const pp = h(s, 'permissions-policy') || h(s, 'feature-policy');
    const tokens = rp.split(',').map((t) => t.trim()).filter(Boolean);
    const last = tokens[tokens.length - 1];
    if (last === 'unsafe-url') return 'fail';
    if (!rp || !pp) return 'warn';
    if (['no-referrer-when-downgrade', 'origin-when-cross-origin'].includes(last)) return 'warn';
    return 'pass';
  },
  'QA-10': (s) => {
    const banners = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator', 'x-runtime'];
    const leak = banners.some((n) => /(?:^|[\/\s-])v?\d+\.\d+/.test(h(s, n)));
    return leak ? 'warn' : 'pass';
  },
};

let checked = 0, agree = 0;
const disagreements = [];

for (const s of data) {
  if (s.error || !s.verdicts) continue;
  if (Object.values(s.verdicts).every((v) => v === 'skip')) continue; // WAF-challenged, excluded
  for (const [id, expect] of Object.entries(EXPECT)) {
    const want = expect(s);
    const got = s.verdicts[id];
    if (want === 'warn_or_pass') {
      if (got === 'warn' || got === 'pass') { checked++; agree++; }
      else disagreements.push({ site: s.url, id, want, got, s });
      continue;
    }
    checked++;
    if (want === got) agree++;
    else disagreements.push({ site: s.url, id, want, got, s });
  }
}

console.log(`Auto-gradeable verdicts: ${checked}`);
console.log(`Agreement with independent logic: ${agree}/${checked} (${((agree / checked) * 100).toFixed(1)}%)\n`);

if (disagreements.length) {
  console.log('Disagreements needing manual adjudication:\n');
  for (const d of disagreements) {
    console.log(`  ${d.site}  ${d.id}: independent=${d.want}  quickaudit=${d.got}`);
    for (const n of ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'server']) {
      if (d.s.rawHeaders[n]) console.log(`      ${n}: ${String(d.s.rawHeaders[n][0]).slice(0, 110)}`);
    }
    console.log('');
  }
} else {
  console.log('No disagreements.');
}

// Library check needs separate treatment: it is graded on whether detections are real.
console.log('\nQA-08 detections (verify each version is genuinely what the site ships):');
for (const s of data) {
  if (s.libraries?.length) console.log(`  ${s.url.padEnd(34)} ${s.libraries.join(', ')}  → ${s.verdicts['QA-08']}`);
}

console.log('\nSites excluded as WAF-challenged (QuickAudit declined to report):');
for (const s of data) {
  if (s.verdicts && Object.values(s.verdicts).every((v) => v === 'skip')) console.log(`  ${s.url}`);
}
