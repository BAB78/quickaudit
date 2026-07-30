import { get, has } from '../core/headers.js';
import { result } from '../core/types.js';

export const def = {
  id: 'QA-05',
  title: 'Referrer & Permissions policy',
  severity: 'low',
  active: false,
  ref: 'https://owasp.org/www-project-secure-headers/#referrer-policy',
  fix: 'Referrer-Policy: strict-origin-when-cross-origin\nPermissions-Policy: camera=(), microphone=(), geolocation=()',
};

/** Sends the full URL to every cross-origin request, including on a downgrade to http. */
const LEAKY_FAIL = ['unsafe-url'];
/**
 * Weaker than they should be, but not a full-URL leak in the way `unsafe-url` is:
 * `no-referrer-when-downgrade` was the browser default for years and only leaks on
 * same-scheme cross-origin requests; `origin-when-cross-origin` sends the origin alone.
 */
const LEAKY_WARN = ['no-referrer-when-downgrade', 'origin-when-cross-origin'];
const SAFE = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'origin'];

export function run(ctx) {
  const rp = get(ctx.headers, 'referrer-policy').trim().toLowerCase();
  const pp = get(ctx.headers, 'permissions-policy') || get(ctx.headers, 'feature-policy');
  const details = [];
  const problems = [];

  if (!rp) {
    problems.push('Referrer-Policy is absent; the browser default applies and can differ between browsers.');
  } else {
    details.push(`Referrer-Policy: ${rp}`);
    // A policy can list fallbacks: "no-referrer, strict-origin-when-cross-origin".
    // Browsers use the last value they understand, so that is the one that matters.
    const tokens = rp.split(',').map((t) => t.trim()).filter(Boolean);
    const known = (t) => SAFE.includes(t) || LEAKY_FAIL.includes(t) || LEAKY_WARN.includes(t);
    const effectiveValue = [...tokens].reverse().find(known) || tokens[0];

    if (LEAKY_FAIL.includes(effectiveValue)) {
      return result(def, 'fail',
        `Referrer-Policy "${effectiveValue}" leaks full URLs cross-origin.`,
        [`Referrer-Policy: ${rp}`,
         `"${effectiveValue}" sends the full URL — path, query, any token in it — to every cross-origin request, including plaintext ones.`,
         pp ? `Permissions-Policy: ${pp.slice(0, 160)}` : 'Permissions-Policy is also absent.']);
    }
    if (LEAKY_WARN.includes(effectiveValue)) {
      problems.push(effectiveValue === 'no-referrer-when-downgrade'
        ? 'Referrer-Policy "no-referrer-when-downgrade" sends the full URL — path and query — on same-scheme cross-origin requests.'
        : 'Referrer-Policy "origin-when-cross-origin" sends your origin to third parties even on a downgrade to http.');
    } else if (!SAFE.includes(effectiveValue)) {
      problems.push(`Referrer-Policy value "${effectiveValue}" is not a recognised token and will be ignored.`);
    }
  }

  if (!pp) {
    problems.push('Permissions-Policy is absent; camera, microphone and geolocation are left at browser defaults for embedded frames.');
  } else {
    details.push(`Permissions-Policy: ${pp.slice(0, 200)}`);
  }

  if (problems.length) {
    const summary = !rp && !pp
      ? 'Both Referrer-Policy and Permissions-Policy are missing.'
      : problems[0];
    return result(def, 'warn', summary, [...details, ...problems]);
  }
  return result(def, 'pass', 'Referrer-Policy and Permissions-Policy are both set sensibly.', details);
}
