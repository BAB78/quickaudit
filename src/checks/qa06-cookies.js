import { looksLikeSessionCookie } from '../core/cookies.js';
import { result } from '../core/types.js';

export const def = {
  id: 'QA-06',
  title: 'Cookie security flags',
  severity: 'high',
  active: false,
  ref: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
  fix: 'Set-Cookie: <name>=<value>; Secure; HttpOnly; SameSite=Lax; Path=/',
};

export function run(ctx) {
  const cookies = ctx.cookies || [];
  if (!cookies.length) {
    return result(def, 'pass', 'No cookies set for this origin.', []);
  }

  const https = ctx.protocol === 'https:';
  const missingSecure = [];
  const missingHttpOnly = [];
  const looseSameSite = [];

  for (const c of cookies) {
    if (https && !c.secure) missingSecure.push(c.name);
    if (looksLikeSessionCookie(c.name) && !c.httpOnly) missingHttpOnly.push(c.name);
    const ss = (c.sameSite || 'unspecified').toLowerCase();
    if (ss === 'none') looseSameSite.push(`${c.name} (SameSite=None)`);
    else if (ss === 'unspecified' || ss === 'no_restriction') looseSameSite.push(`${c.name} (SameSite not set)`);
  }

  const details = [`${cookies.length} cookie${cookies.length > 1 ? 's' : ''} inspected: ${cookies.map((c) => c.name).join(', ')}`];
  if (missingSecure.length) details.push(`Missing Secure: ${missingSecure.join(', ')} — these are sent over plaintext HTTP too.`);
  if (missingHttpOnly.length) details.push(`Session-like cookie readable by JavaScript (no HttpOnly): ${missingHttpOnly.join(', ')} — any XSS steals the session. (Flagged by cookie name; confirm it really carries a session before acting.)`);
  if (looseSameSite.length) details.push(`SameSite not restrictive: ${looseSameSite.join(', ')}.`);

  if (missingSecure.length || missingHttpOnly.length) {
    // Lead with the Secure finding: it is a fact about the header, whereas HttpOnly is
    // flagged from a name heuristic and is the one a user might reasonably dispute.
    const parts = [];
    if (missingSecure.length) parts.push(`${missingSecure.length} cookie(s) missing Secure`);
    if (missingHttpOnly.length) parts.push(`${missingHttpOnly.length} session-like cookie(s) missing HttpOnly`);
    return result(def, 'fail', `${parts.join('; ')}.`, details);
  }
  if (looseSameSite.length) {
    return result(def, 'warn', `${looseSameSite.length} cookie(s) without a restrictive SameSite.`, details,
      'Set SameSite=Lax (or Strict for session cookies). SameSite=None requires Secure and a genuine cross-site need.');
  }
  return result(def, 'pass', `All ${cookies.length} cookie(s) are Secure with sensible flags.`, details);
}
