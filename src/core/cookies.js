import { parseDirectiveList } from './headers.js';

/**
 * Parse one Set-Cookie header value into a CookieInfo.
 * We deliberately keep the name and drop the value — QuickAudit never reads secrets.
 */
export function parseSetCookie(raw) {
  const s = String(raw);
  const firstSemi = s.indexOf(';');
  const pair = firstSemi === -1 ? s : s.slice(0, firstSemi);
  const eq = pair.indexOf('=');
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const attrs = parseDirectiveList(firstSemi === -1 ? '' : s.slice(firstSemi + 1));

  return {
    name,
    secure: attrs.secure === true,
    httpOnly: attrs.httponly === true,
    sameSite: typeof attrs.samesite === 'string' ? attrs.samesite.toLowerCase() : 'unspecified',
    domain: typeof attrs.domain === 'string' ? attrs.domain : undefined,
  };
}

export function parseSetCookies(values = []) {
  return values.map(parseSetCookie).filter(Boolean);
}

/**
 * Names that suggest the cookie carries a session or credential, and therefore must be
 * HttpOnly. Broad enough to catch the common frameworks, narrow enough not to flag
 * `theme` or `locale`.
 */
const SESSION_NAME = /(^|[._-])(sess|sid|auth|token|jwt|login|remember|csrf|xsrf|user|account|identity|access|refresh)/i;

export function looksLikeSessionCookie(name) {
  return SESSION_NAME.test(name) || /^(phpsessid|jsessionid|asp\.net_sessionid|connect\.sid)$/i.test(name);
}

/** Merge cookies from the browser cookie store and from Set-Cookie, de-duped by name. */
export function mergeCookies(...lists) {
  const byName = new Map();
  for (const list of lists) {
    for (const c of list || []) {
      if (!c || !c.name) continue;
      // Later sources refine earlier ones; the browser store is authoritative so it goes last.
      byName.set(c.name, { ...(byName.get(c.name) || {}), ...c });
    }
  }
  return [...byName.values()];
}
