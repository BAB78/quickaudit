/** Minimal CSP parser — enough to answer "is this policy actually doing anything?" */

/**
 * Parse a CSP header value into {directive: [sources]}.
 * Directive names are lowercased; source values keep their case (paths are case-sensitive).
 */
export function parseCsp(value) {
  const out = {};
  for (const part of String(value).split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    // Repeated directives: the first occurrence wins, per spec.
    if (!(name in out)) out[name] = tokens.slice(1);
  }
  return out;
}

/** Resolve a directive through the default-src fallback chain. */
export function effective(policy, directive) {
  if (policy[directive]) return policy[directive];
  // fetch directives fall back to default-src; frame-ancestors and base-uri do not.
  const noFallback = ['frame-ancestors', 'base-uri', 'form-action', 'report-uri', 'sandbox'];
  if (noFallback.includes(directive)) return null;
  return policy['default-src'] || null;
}

/** Source expressions that make a script-src decorative rather than protective. */
const DANGEROUS = [
  { token: "'unsafe-inline'", why: "'unsafe-inline' permits inline <script> and event handlers" },
  { token: "'unsafe-eval'", why: "'unsafe-eval' permits eval() and Function()" },
  { token: '*', why: '* allows scripts from any origin' },
  { token: 'http:', why: 'http: allows scripts over plaintext' },
  { token: 'https:', why: 'a bare https: scheme allows scripts from any HTTPS origin' },
  { token: 'data:', why: 'data: allows attacker-authored inline payloads' },
];

/**
 * Report the ways a script-src is weakened.
 * A nonce or hash neutralizes 'unsafe-inline' in CSP3 browsers, so we say so rather than
 * crying wolf about a policy that is actually fine.
 */
export function scriptSrcWeaknesses(sources) {
  if (!sources) return [{ token: '(none)', why: 'no script-src or default-src is set' }];
  const lower = sources.map((s) => s.toLowerCase());
  const hasNonceOrHash = lower.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha"));
  const strictDynamic = lower.includes("'strict-dynamic'");

  const found = [];
  for (const d of DANGEROUS) {
    if (!lower.includes(d.token)) continue;
    if (d.token === "'unsafe-inline'" && hasNonceOrHash) continue; // ignored by CSP3 browsers
    // strict-dynamic makes host/scheme allowlists inert for scripts.
    if (strictDynamic && ['*', 'http:', 'https:', 'data:'].includes(d.token)) continue;
    found.push(d);
  }
  return found;
}

/** True if the policy is delivered report-only (observes but never blocks). */
export function isReportOnly(headerName) {
  return headerName.toLowerCase() === 'content-security-policy-report-only';
}
