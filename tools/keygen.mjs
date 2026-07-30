#!/usr/bin/env node
/**
 * Generate the QuickAudit licensing keypair.
 *
 * The private key stays on the seller's machine and signs license keys; the public key is
 * embedded in the extension, which verifies offline. No licence server, no phone-home,
 * no subscription plumbing — that's the whole point of a one-time unlock.
 *
 *   node tools/keygen.mjs        writes .keys/private.pem and prints the public key JWK
 */
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';

const dir = new URL('../.keys/', import.meta.url);
mkdirSync(dir, { recursive: true });
const privPath = new URL('private.pem', dir);

if (existsSync(privPath)) {
  console.error('.keys/private.pem already exists — refusing to overwrite it.');
  console.error('Deleting it would invalidate every licence key you have already sold.');
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));

const jwk = publicKey.export({ format: 'jwk' });
writeFileSync(new URL('public.jwk.json', dir), JSON.stringify(jwk, null, 2));

console.log('Wrote .keys/private.pem  (keep this secret, never commit it)');
console.log('Public key JWK — paste into src/ext/license.js as PUBLIC_JWK:\n');
console.log(JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, null, 2));
