import { get, has } from '../core/headers.js';
import { result } from '../core/types.js';

export const def = {
  id: 'QA-04',
  title: 'MIME-sniffing protection',
  severity: 'low',
  active: false,
  ref: 'https://owasp.org/www-project-secure-headers/#x-content-type-options',
  fix: 'X-Content-Type-Options: nosniff',
};

export function run(ctx) {
  if (!has(ctx.headers, 'x-content-type-options')) {
    return result(def, 'fail',
      'No X-Content-Type-Options header.',
      ['Browsers may sniff a response body and execute a user-uploaded file as script or CSS.']);
  }
  const value = get(ctx.headers, 'x-content-type-options').trim();
  if (value.toLowerCase() !== 'nosniff') {
    return result(def, 'fail',
      `X-Content-Type-Options has an invalid value: "${value}".`,
      ['"nosniff" is the only valid value; anything else is ignored.']);
  }
  return result(def, 'pass', 'X-Content-Type-Options: nosniff is set.', []);
}
