import * as qa01 from './qa01-transport.js';
import * as qa02 from './qa02-csp.js';
import * as qa03 from './qa03-framing.js';
import * as qa04 from './qa04-nosniff.js';
import * as qa05 from './qa05-referrer-permissions.js';
import * as qa06 from './qa06-cookies.js';
import * as qa07 from './qa07-mixed-content.js';
import * as qa08 from './qa08-libraries.js';
import * as qa09 from './qa09-exposed-paths.js';
import * as qa10 from './qa10-disclosure.js';
import { compareResults } from '../core/types.js';

export const CHECKS = [qa01, qa02, qa03, qa04, qa05, qa06, qa07, qa08, qa09, qa10];

export const CHECK_META = CHECKS.map((c) => ({ ...c.def }));

/**
 * Run every enabled check over a PageContext.
 * A check that throws produces an `error` result rather than taking the whole scan down —
 * a scanner that dies on one bad header is worse than useless.
 */
export async function runAll(ctx, opts = {}) {
  const enabled = opts.enabled ? new Set(opts.enabled) : null;
  const selected = CHECKS.filter((c) => !enabled || enabled.has(c.def.id));

  const results = await Promise.all(selected.map(async (check) => {
    // If a WAF served a challenge instead of the page, we never saw the site's real headers
    // or resources. Reporting "no CSP" about a Cloudflare interstitial is worse than
    // reporting nothing, so everything that reads the response is skipped outright.
    if (ctx.challenge && check.def.id !== 'QA-09') {
      return {
        id: check.def.id,
        title: check.def.title,
        status: 'skip',
        severity: 'info',
        summary: 'Skipped — the origin served a bot-protection challenge, not the page.',
        details: [ctx.challenge, 'Run the scan from the extension while viewing the real page, which sees the headers your browser actually received.'],
        fix: '',
        ref: check.def.ref || '',
      };
    }
    try {
      return await check.run(ctx, opts);
    } catch (e) {
      return {
        id: check.def.id,
        title: check.def.title,
        status: 'error',
        severity: 'info',
        summary: `Check failed to run: ${e.message}`,
        details: [String(e.stack || e).split('\n').slice(0, 3).join('\n')],
        fix: '',
        ref: check.def.ref || '',
      };
    }
  }));

  results.sort(compareResults);
  return { url: ctx.url, scannedAt: new Date().toISOString(), notes: ctx.notes || [], results, score: score(results) };
}

/** A blunt 0-100 headline number. Failures cost more than warnings, weighted by severity. */
export function score(results) {
  const weight = { critical: 30, high: 20, medium: 12, low: 6, info: 0 };
  let penalty = 0;
  for (const r of results) {
    if (r.status === 'fail') penalty += weight[r.severity] ?? 5;
    else if (r.status === 'warn') penalty += (weight[r.severity] ?? 5) * 0.4;
  }
  return Math.max(0, Math.round(100 - penalty));
}

export function summarize(results) {
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0, error: 0 };
  for (const r of results) counts[r.status] = (counts[r.status] || 0) + 1;
  return counts;
}
