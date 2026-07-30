import { get } from '../core/headers.js';
import { parseCsp } from '../core/csp.js';
import { result } from '../core/types.js';

export const def = {
  id: 'QA-07',
  title: 'Mixed content',
  severity: 'medium',
  active: false,
  ref: 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
  fix: 'Serve every subresource over HTTPS. As a stopgap add: Content-Security-Policy: upgrade-insecure-requests',
};

/** Active mixed content can execute or read; passive can only be swapped visually. */
const ACTIVE_TYPES = new Set(['script', 'iframe', 'xhr', 'fetch', 'css', 'link', 'worker', 'object']);

export function run(ctx) {
  if (ctx.protocol !== 'https:') {
    return result(def, 'skip',
      'Page is not HTTPS, so mixed content does not apply.',
      ['Fix QA-01 first — the whole page is plaintext.']);
  }

  const insecure = (ctx.resources || []).filter((r) => /^http:\/\//i.test(r.url || ''));
  if (!insecure.length) {
    const n = (ctx.resources || []).length;
    return result(def, 'pass',
      n ? `All ${n} observed subresources load over HTTPS.` : 'No insecure subresources observed.',
      n ? [] : ['No subresources were captured — a page with no external assets, or the collector ran before load.']);
  }

  const csp = get(ctx.headers, 'content-security-policy') || (ctx.metaCsp || [])[0] || '';
  const policy = parseCsp(csp);
  const upgraded = 'upgrade-insecure-requests' in policy || 'block-all-mixed-content' in policy;

  const active = insecure.filter((r) => ACTIVE_TYPES.has(r.type));
  const passive = insecure.filter((r) => !ACTIVE_TYPES.has(r.type));

  const details = [];
  if (active.length) details.push(`Active mixed content (${active.length}): ${active.slice(0, 5).map((r) => `[${r.type}] ${r.url}`).join(' | ')}${active.length > 5 ? ` … +${active.length - 5} more` : ''}`);
  if (passive.length) details.push(`Passive mixed content (${passive.length}): ${passive.slice(0, 5).map((r) => `[${r.type}] ${r.url}`).join(' | ')}${passive.length > 5 ? ` … +${passive.length - 5} more` : ''}`);

  if (upgraded) {
    details.push('CSP includes upgrade-insecure-requests, so browsers rewrite these to HTTPS before they leave the machine — the markup is still wrong, but users are not exposed.');
    return result(def, 'warn', `${insecure.length} http:// subresource(s), mitigated by CSP upgrade.`, details);
  }

  if (active.length) {
    details.push('Active mixed content is blocked outright by modern browsers — these resources are almost certainly failing to load for real users.');
    return result(def, 'fail', `${active.length} active http:// subresource(s) on an HTTPS page.`, details);
  }
  return result(def, 'warn', `${passive.length} passive http:// subresource(s) on an HTTPS page.`, details);
}
