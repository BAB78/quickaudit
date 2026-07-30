import { get, has } from '../core/headers.js';
import { parseCsp } from '../core/csp.js';
import { result } from '../core/types.js';

export const def = {
  id: 'QA-03',
  title: 'Clickjacking protection',
  severity: 'medium',
  active: false,
  ref: 'https://owasp.org/www-community/attacks/Clickjacking',
  fix: "Add Content-Security-Policy: frame-ancestors 'none' (or 'self'), plus X-Frame-Options: DENY for old browsers.",
};

export function run(ctx) {
  const csp = get(ctx.headers, 'content-security-policy') || (ctx.metaCsp || [])[0] || '';
  const frameAncestors = parseCsp(csp)['frame-ancestors'];
  const xfo = get(ctx.headers, 'x-frame-options');
  const xfoVal = xfo.trim().toUpperCase();

  if (frameAncestors) {
    const list = frameAncestors.join(' ');
    if (frameAncestors.some((s) => s === '*' || s.toLowerCase() === 'http:' || s.toLowerCase() === 'https:')) {
      return result(def, 'fail',
        'CSP frame-ancestors allows any origin to frame this page.',
        [`frame-ancestors ${list}`]);
    }
    // frame-ancestors, when present, overrides X-Frame-Options entirely — worth saying,
    // because people spend time "fixing" a contradictory XFO that browsers ignore.
    const note = xfo && xfoVal !== 'DENY' && xfoVal !== 'SAMEORIGIN'
      ? [`Note: X-Frame-Options: ${xfo} is present but ignored by browsers that support frame-ancestors.`]
      : [];
    return result(def, 'pass', `Framing restricted by CSP frame-ancestors.`,
      [`frame-ancestors ${list}`, ...note]);
  }

  if (!has(ctx.headers, 'x-frame-options')) {
    return result(def, 'fail',
      'Neither frame-ancestors nor X-Frame-Options is set.',
      ['Any site can load this page in an invisible iframe and trick users into clicking through it.']);
  }

  if (xfoVal === 'DENY' || xfoVal === 'SAMEORIGIN') {
    // Every current browser still honours X-Frame-Options, so this is genuinely protected.
    // frame-ancestors is the modern spelling, but flagging XFO-only sites as a problem is
    // pedantry that would fire on a large share of correctly-configured sites.
    return result(def, 'pass',
      `Framing restricted by X-Frame-Options: ${xfoVal}.`,
      [`X-Frame-Options: ${xfo}`,
       `Consider also setting Content-Security-Policy: frame-ancestors ${xfoVal === 'DENY' ? "'none'" : "'self'"} — the standardised replacement.`]);
  }

  if (xfoVal.startsWith('ALLOW-FROM')) {
    return result(def, 'fail',
      'X-Frame-Options uses the obsolete ALLOW-FROM form, which no current browser honours.',
      [`X-Frame-Options: ${xfo}`, 'Chrome, Firefox and Safari all ignore ALLOW-FROM — this page is effectively unprotected.']);
  }

  return result(def, 'fail',
    `X-Frame-Options value is not recognised: "${xfo}".`,
    [`X-Frame-Options: ${xfo}`, 'An invalid value is treated as no protection at all.']);
}
