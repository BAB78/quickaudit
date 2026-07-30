import { get } from '../core/headers.js';
import { result } from '../core/types.js';

export const def = {
  id: 'QA-10',
  title: 'Server version disclosure',
  severity: 'low',
  active: false,
  ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
  fix: 'Strip or blank the banner: nginx `server_tokens off;`, Apache `ServerTokens Prod`, Express `app.disable("x-powered-by")`.',
};

const BANNER_HEADERS = [
  'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
  'x-generator', 'x-drupal-cache', 'x-runtime', 'x-version', 'x-served-by-version',
];

/** A version is a number pair not attached to a word like "HTTP/2" or a date. */
const VERSION_RE = /(?:^|[\/\s-])v?(\d+\.\d+(?:\.\d+)*)/;

export function run(ctx) {
  const leaks = [];
  const present = [];

  for (const name of BANNER_HEADERS) {
    const value = get(ctx.headers, name);
    if (!value) continue;
    present.push(`${name}: ${value}`);
    const m = value.match(VERSION_RE);
    if (m && !/^20\d\d$/.test(m[1].split('.')[0])) {
      leaks.push(`${name}: ${value}  → discloses version ${m[1]}`);
    }
  }

  if (leaks.length) {
    return result(def, 'warn',
      `${leaks.length} header(s) disclose exact software versions.`,
      [...leaks,
       'Version banners let an attacker skip reconnaissance and go straight to exploits matching your exact build.']);
  }
  if (present.length) {
    return result(def, 'pass', 'Server headers present but no version numbers disclosed.', present);
  }
  return result(def, 'pass', 'No server or framework banner headers.', []);
}
