import { get, getAll, has } from '../core/headers.js';
import { parseCsp, effective, scriptSrcWeaknesses } from '../core/csp.js';
import { result } from '../core/types.js';

export const def = {
  id: 'QA-02',
  title: 'Content-Security-Policy',
  severity: 'high',
  active: false,
  ref: 'https://owasp.org/www-project-secure-headers/#content-security-policy',
  fix: "Start with: default-src 'self'; object-src 'none'; base-uri 'self'; and serve scripts with a per-request nonce.",
};

export function run(ctx) {
  const enforced = getAll(ctx.headers, 'content-security-policy');
  const reportOnly = getAll(ctx.headers, 'content-security-policy-report-only');
  const meta = ctx.metaCsp || [];

  if (!enforced.length && !meta.length) {
    if (reportOnly.length) {
      return result(def, 'warn',
        'Only a report-only CSP is set — nothing is actually blocked.',
        [`Content-Security-Policy-Report-Only: ${reportOnly[0].slice(0, 300)}`,
         'Report-only policies observe violations but never stop them.'],
        'Once the report stream is clean, ship the same policy as Content-Security-Policy.');
    }
    return result(def, 'fail',
      'No Content-Security-Policy.',
      ['Any injected script — stored XSS, a compromised third-party tag, a malicious ad — runs unrestricted.']);
  }

  const source = enforced.length ? 'header' : 'meta tag';
  const policy = parseCsp(enforced[0] || meta[0]);
  const details = [`Policy (${source}): ${(enforced[0] || meta[0]).slice(0, 300)}`];
  const problems = [];

  const scriptSrc = effective(policy, 'script-src');
  for (const w of scriptSrcWeaknesses(scriptSrc)) {
    problems.push(`script-src: ${w.why}.`);
  }

  // object-src and base-uri are the two directives default-src covers in name only —
  // people set default-src 'self' and still leave <base> injection open.
  if (!policy['object-src'] && !policy['default-src']) {
    problems.push("object-src is unset — <object>/<embed> can load plugin content.");
  }
  if (!policy['base-uri']) {
    problems.push("base-uri is unset — an injected <base> tag can redirect every relative script URL.");
  }

  if (!enforced.length) {
    problems.push('Delivered via <meta>, which cannot enforce frame-ancestors, sandbox, or report-uri.');
  }

  if (problems.length) {
    return result(def, 'warn', `CSP present but weakened (${problems.length} issue${problems.length > 1 ? 's' : ''}).`,
      [...details, ...problems]);
  }
  return result(def, 'pass', 'CSP present with a restrictive script-src.', details);
}
