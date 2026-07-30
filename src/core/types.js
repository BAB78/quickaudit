/**
 * Shared shapes. QuickAudit's whole design rests on one seam: every check is a pure
 * function over a PageContext, so the same code runs in the extension and in Node.
 *
 * @typedef {Object} PageContext
 * @property {string}   url          Final URL of the main document.
 * @property {string}   origin       Scheme + host + port.
 * @property {string}   protocol     'https:' or 'http:'.
 * @property {Object<string,string[]>} headers  Response headers, lowercase name -> values.
 * @property {string[]} metaCsp      CSP values found in <meta http-equiv> tags.
 * @property {CookieInfo[]} cookies  Cookie flags (never values) for this origin.
 * @property {Resource[]} resources  Subresources the page loaded.
 * @property {Library[]} libraries   Detected JS libraries with versions.
 * @property {?function(string): Promise<ProbeResult|null>} probe  Active-check fetcher.
 * @property {boolean}  activeAllowed  User consented to active checks on this origin.
 * @property {string[]} notes        Collector-level caveats surfaced in the UI.
 *
 * @typedef {Object} CookieInfo
 * @property {string} name
 * @property {boolean} secure
 * @property {boolean} httpOnly
 * @property {string} sameSite   'strict' | 'lax' | 'none' | 'unspecified'
 * @property {string} [domain]
 *
 * @typedef {Object} Resource
 * @property {string} url
 * @property {string} type   'script'|'iframe'|'xhr'|'img'|'css'|'media'|'font'|'other'
 *
 * @typedef {Object} Library
 * @property {string} name       npm package name, for OSV lookup.
 * @property {string} version
 * @property {'global'|'url'|'banner'} source  Detection confidence, high to low.
 * @property {string} [evidence]
 *
 * @typedef {Object} ProbeResult
 * @property {number} status
 * @property {Object<string,string[]>} headers
 * @property {string} body   Truncated to PROBE_BODY_LIMIT bytes.
 *
 * @typedef {Object} CheckResult
 * @property {string} id
 * @property {string} title
 * @property {'pass'|'warn'|'fail'|'skip'|'error'} status
 * @property {Severity} severity
 * @property {string} summary
 * @property {string[]} details
 * @property {string} fix
 * @property {string} [ref]
 *
 * @typedef {'critical'|'high'|'medium'|'low'|'info'} Severity
 */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export const STATUS_ORDER = ['fail', 'warn', 'error', 'skip', 'pass'];

export const PROBE_BODY_LIMIT = 4096;

/** Build a CheckResult without repeating the boilerplate in ten files. */
export function result(def, status, summary, details = [], fix = '') {
  return {
    id: def.id,
    title: def.title,
    status,
    // A passing check has no severity worth shouting about.
    severity: status === 'pass' ? 'info' : def.severity,
    summary,
    details: details.filter(Boolean),
    fix: fix || def.fix || '',
    ref: def.ref || '',
  };
}

/** Sort worst-first for display: failures before warnings, critical before low. */
export function compareResults(a, b) {
  const s = STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status);
  if (s !== 0) return s;
  return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
}
