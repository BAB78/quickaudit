// addons.mozilla.org (Firefox) publishing via the AMO API v5, with a JWT from the developer's API key.
// Credentials: A:/quickaudit-secrets/firefox-amo.txt (never committed, never printed).
// Usage: node tools/publish-amo.mjs info
//        node tools/publish-amo.mjs upload build/quickaudit-1.0.1-firefox.zip "Release notes"
//        node tools/publish-amo.mjs listing <json-file>     (PATCH name/summary/description)
// Docs: https://mozilla.github.io/addons-server/topics/api/addons.html
import fs from 'node:fs';
import crypto from 'node:crypto';

const SECRETS = process.env.AMO_SECRETS || 'A:/quickaudit-secrets/firefox-amo.txt';
const env = Object.fromEntries(fs.readFileSync(SECRETS, 'utf8').split(/\r?\n/)
  .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1).trim()]));
if (!env.JWT_ISSUER || !env.JWT_SECRET) throw new Error('firefox-amo.txt needs JWT_ISSUER and JWT_SECRET');
const API = 'https://addons.mozilla.org/api/v5';
const SLUG = 'quickaudit-web-security';
const b64u = (b) => Buffer.from(b).toString('base64url');
function jwt() {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify({ iss: env.JWT_ISSUER, jti: crypto.randomUUID(), iat: now, exp: now + 60 }));
  const sig = crypto.createHmac('sha256', env.JWT_SECRET).update(`${head}.${body}`).digest('base64url');
  return `JWT ${head}.${body}.${sig}`;
}
async function call(path, opts = {}) {
  const res = await fetch(API + path, { ...opts, headers: { Authorization: jwt(), ...(opts.headers || {}) } });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) throw new Error(`${res.status} ${typeof data === 'string' ? data.slice(0, 300) : JSON.stringify(data).slice(0, 600)}`);
  return data;
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

const [cmd, a, b] = process.argv.slice(2);
if (cmd === 'info') {
  const ad = await call(`/addons/addon/${SLUG}/`);
  console.log(JSON.stringify({ id: ad.id, guid: ad.guid, status: ad.status, name: ad.name, summary: ad.summary, current: ad.current_version?.version, homepage: ad.homepage, support_url: ad.support_url, has_privacy_policy: ad.has_privacy_policy }, null, 1));
  console.log('DESCRIPTION:\n' + (ad.description?.['en-US'] || JSON.stringify(ad.description)));
} else if (cmd === 'upload') {
  const form = new FormData();
  form.append('upload', new Blob([fs.readFileSync(a)], { type: 'application/zip' }), a.split(/[\\/]/).pop());
  form.append('channel', 'listed');
  let up = await call('/addons/upload/', { method: 'POST', body: form });
  console.log('uploaded, validating:', up.uuid);
  for (let i = 0; i < 60 && !up.processed; i++) { await wait(5000); up = await call(`/addons/upload/${up.uuid}/`); }
  const v = up.validation || {};
  console.log('processed:', up.processed, 'valid:', up.valid, 'errors:', v.errors, 'warnings:', v.warnings, 'notices:', v.notices);
  for (const m of (v.messages || []).filter((m) => m.type !== 'notice').slice(0, 15)) console.log(` - ${m.type}: ${m.message} ${m.file ? '(' + m.file + ')' : ''}`);
  if (!up.valid) process.exit(1);
  const ad = await call(`/addons/addon/${SLUG}/`);
  const ver = await call(`/addons/addon/${ad.id}/versions/`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ upload: up.uuid, release_notes: { 'en-US': b || '' } }) });
  console.log('version created:', ver.version, 'file status:', ver.file?.status, 'id:', ver.id);
} else if (cmd === 'listing') {
  const ad = await call(`/addons/addon/${SLUG}/`);
  const patch = JSON.parse(fs.readFileSync(a, 'utf8'));
  const r = await call(`/addons/addon/${ad.id}/`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) });
  console.log('listing updated:', JSON.stringify({ name: r.name, summary: r.summary }));
} else if (cmd === 'policy') {
  const ad = await call(`/addons/addon/${SLUG}/`);
  const patch = JSON.parse(fs.readFileSync(a, 'utf8'));
  const r = await call(`/addons/addon/${ad.id}/eula_policy/`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) });
  console.log('privacy policy updated:', JSON.stringify(r.privacy_policy).length, 'chars');
} else {
  console.log('usage: info | upload <zip> "<notes>" | listing <json> | policy <json>');
}
