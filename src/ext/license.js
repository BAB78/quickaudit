/**
 * Offline Pro licence verification.
 *
 * Keys are ECDSA P-256 signatures over a tiny JSON payload. The extension holds only the
 * public key, so there is no licence server to run, nothing phones home, and the check
 * works on a plane. A determined user can patch the extension — that is true of every
 * client-side unlock, and building auth infrastructure to stop them is not worth it for a
 * $19 one-time purchase.
 *
 * WebCrypto ECDSA P-256 is available in every engine this ships to (Chromium, Firefox,
 * Safari), so verification is identical everywhere.
 */
import { storage } from './browser-api.js';

const PUBLIC_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'iwpkS_yD1r8ISogGkB0wPsvWP36Q8mNGqRPRbrf6cBc',
  y: 'LaKBr_ayC3xXp67DIGIaJhEeNNvc3wOf7l48HVLwpPg',
};

/** @returns {Promise<{valid: boolean, email?: string, issued?: string, reason?: string}>} */
export async function verifyKey(key) {
  const raw = String(key || '').trim();
  const parts = raw.split('.');
  if (parts.length !== 3 || parts[0] !== 'QA1') {
    return { valid: false, reason: 'That does not look like a QuickAudit licence key.' };
  }
  const [, body, sig] = parts;

  try {
    const pub = await crypto.subtle.importKey('jwk', PUBLIC_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pub,
      b64uToBytes(sig),
      new TextEncoder().encode(body)
    );
    if (!ok) return { valid: false, reason: 'Signature does not match. Check for a copy-paste error.' };

    const payload = JSON.parse(new TextDecoder().decode(b64uToBytes(body)));
    if (payload.p !== 'pro' || payload.v !== 1) {
      return { valid: false, reason: 'Unsupported licence version.' };
    }
    return { valid: true, email: payload.e, issued: payload.t, order: payload.o };
  } catch (e) {
    return { valid: false, reason: `Could not read that key (${e.message}).` };
  }
}

export async function activate(key) {
  const res = await verifyKey(key);
  if (res.valid) {
    await storage.set({ qaLicense: { key: key.trim(), email: res.email, issued: res.issued } });
  }
  return res;
}

export async function deactivate() {
  await storage.remove('qaLicense');
}

export async function getLicense() {
  const { qaLicense } = await storage.get('qaLicense');
  if (!qaLicense?.key) return null;
  // Re-verify on every read: a hand-edited storage entry should not unlock anything.
  const res = await verifyKey(qaLicense.key);
  return res.valid ? { ...qaLicense, ...res } : null;
}

export async function isPro() {
  return Boolean(await getLicense());
}

function b64uToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
