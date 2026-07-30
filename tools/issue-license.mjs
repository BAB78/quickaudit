#!/usr/bin/env node
/**
 * Sign a QuickAudit Pro licence key for a buyer.
 *
 *   node tools/issue-license.mjs buyer@example.com ORDER-1234
 *
 * Output is what you paste into the Gumroad/LemonSqueezy delivery email. Verification is
 * offline: the extension checks the signature against the embedded public key.
 */
import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';

const [email, order, majorArg] = process.argv.slice(2);
if (!email) {
  console.error('usage: node tools/issue-license.mjs <buyer-email> [order-id] [max-major]');
  console.error('  max-major defaults to the current manifest major version.');
  process.exit(2);
}

const key = createPrivateKey(readFileSync(new URL('../.keys/private.pem', import.meta.url)));

/**
 * The key unlocks up to and including this major version. Defaults to whatever is shipping,
 * so a buyer today gets all of 1.x free and a future 2.0 is a new purchase. Pass an explicit
 * value to be more generous — e.g. `2` for someone who bought just before a major release.
 */
const manifest = JSON.parse(readFileSync(new URL('../manifest.base.json', import.meta.url), 'utf8'));
const maxMajor = Number(majorArg ?? manifest.version.split('.')[0]);
if (!Number.isFinite(maxMajor)) {
  console.error(`max-major must be a number, got "${majorArg}"`);
  process.exit(2);
}

const payload = {
  e: email.trim().toLowerCase(),
  o: order || '',
  t: new Date().toISOString().slice(0, 10),
  p: 'pro',
  v: 1,
  m: maxMajor,
};
const body = b64u(Buffer.from(JSON.stringify(payload)));
// ieee-p1363 because that is the only signature encoding WebCrypto's ECDSA verify accepts.
const sig = b64u(sign('sha256', Buffer.from(body), { key, dsaEncoding: 'ieee-p1363' }));

console.log(`\nQuickAudit Pro licence for ${payload.e}`);
console.log(`Unlocks QuickAudit ${maxMajor}.x — all updates within that major version.\n`);
console.log(`QA1.${body}.${sig}\n`);

function b64u(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
