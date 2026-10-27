// Upload a package to Microsoft Edge Add-ons and (optionally) submit it, via the Edge Add-ons API v1.1.
// Credentials are read from A:/quickaudit-secrets/edge-partner.txt (never committed, never printed).
// Usage: node tools/publish-edge.mjs upload build/quickaudit-1.0.1-chrome.zip
//        node tools/publish-edge.mjs publish "Release notes"
//        node tools/publish-edge.mjs status <operationId> [upload|publish]
// Docs: https://learn.microsoft.com/microsoft-edge/extensions/publish/api/using-addons-api
import fs from 'node:fs';

const SECRETS = process.env.EDGE_SECRETS || 'A:/quickaudit-secrets/edge-partner.txt';
const env = Object.fromEntries(fs.readFileSync(SECRETS, 'utf8').split(/\r?\n/)
  .filter((l) => /^[A-Z_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1).trim()]));
const productId = (env.PRODUCT_PAGE_URL.match(/microsoftedge\/([0-9a-f-]{36})/i) || [])[1];
if (!env.CLIENT_ID || !env.API_KEY || !productId) throw new Error('edge-partner.txt needs CLIENT_ID, API_KEY and PRODUCT_PAGE_URL');
const BASE = `https://api.addons.microsoftedge.microsoft.com/v1/products/${productId}/submissions`;
const auth = { Authorization: `ApiKey ${env.API_KEY}`, 'X-ClientID': env.CLIENT_ID };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function poll(url) {
  for (let i = 0; i < 60; i++) {
    const res = await fetch(url, { headers: auth });
    const body = await res.json().catch(() => ({}));
    if (body.status && body.status !== 'InProgress') return body;
    await wait(5000);
  }
  return { status: 'Timeout' };
}

const [cmd, arg, kind] = process.argv.slice(2);
if (cmd === 'upload') {
  const res = await fetch(`${BASE}/draft/package`, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/zip' }, body: fs.readFileSync(arg) });
  const op = (res.headers.get('location') || '').split('/').pop();
  console.log('upload accepted:', res.status, 'operation', op || '(none)');
  if (res.status !== 202) { console.log(await res.text()); process.exit(1); }
  const r = await poll(`${BASE}/draft/package/operations/${op}`);
  console.log('upload result:', r.status, r.message || '', (r.errors || []).map((e) => e.message).join(' | '));
} else if (cmd === 'publish') {
  const res = await fetch(BASE, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: JSON.stringify({ notes: arg || '' }) });
  const op = (res.headers.get('location') || '').split('/').pop();
  console.log('publish accepted:', res.status, 'operation', op || '(none)');
  if (res.status !== 202) { console.log(await res.text()); process.exit(1); }
  const r = await poll(`${BASE}/operations/${op}`);
  console.log('publish result:', r.status, r.message || '', (r.errors || []).map((e) => e.message).join(' | '));
} else if (cmd === 'status') {
  const r = await poll(kind === 'upload' ? `${BASE}/draft/package/operations/${arg}` : `${BASE}/operations/${arg}`);
  console.log(JSON.stringify(r).slice(0, 600));
} else {
  console.log('usage: upload <zip> | publish "<notes>" | status <operationId> [upload|publish]');
}
