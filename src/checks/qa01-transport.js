import { get, has, parseDirectiveList } from '../core/headers.js';
import { result } from '../core/types.js';

const SIX_MONTHS = 15552000;

export const def = {
  id: 'QA-01',
  title: 'Transport security (HTTPS + HSTS)',
  severity: 'high',
  active: false,
  ref: 'https://owasp.org/www-project-secure-headers/#http-strict-transport-security',
  fix: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
};

export function run(ctx) {
  if (ctx.protocol !== 'https:') {
    return result(def, 'fail',
      'Page is served over plaintext HTTP.',
      [`Document URL: ${ctx.url}`,
       'Everything on this page — cookies, form posts, tokens — is readable and modifiable in transit.'],
      'Serve the site over HTTPS and 301-redirect all HTTP traffic, then add HSTS.');
  }

  if (!has(ctx.headers, 'strict-transport-security')) {
    return result(def, 'fail',
      'No Strict-Transport-Security header.',
      ['The first request of every session can still be downgraded to HTTP by an on-path attacker.']);
  }

  const raw = get(ctx.headers, 'strict-transport-security');
  const d = parseDirectiveList(raw);
  const maxAge = parseInt(d['max-age'], 10);
  const evidence = `Strict-Transport-Security: ${raw}`;
  const problems = [];

  if (!Number.isFinite(maxAge)) {
    return result(def, 'fail', 'HSTS header present but has no valid max-age.', [evidence]);
  }
  if (maxAge === 0) {
    return result(def, 'fail',
      'HSTS is explicitly disabled (max-age=0).', [evidence,
      'max-age=0 tells browsers to forget the HSTS policy for this host.']);
  }
  if (maxAge < SIX_MONTHS) {
    problems.push(`max-age is ${maxAge}s (~${Math.round(maxAge / 86400)}d); 15552000s (180d) is the accepted floor.`);
  }
  if (!d.includesubdomains) {
    problems.push('includeSubDomains is missing, so subdomains can still be reached over HTTP.');
  }

  if (problems.length) {
    return result(def, 'warn', 'HSTS is present but weakened.', [evidence, ...problems]);
  }
  return result(def, 'pass',
    `HTTPS with HSTS (max-age ${maxAge}s${d.preload ? ', preload' : ''}).`, [evidence]);
}
