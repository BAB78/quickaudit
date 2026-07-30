#!/usr/bin/env node
/** End-to-end: real HTTP, real collector, real checks — against the local fixture servers. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { collect } from '../src/core/collect-node.js';
import { runAll } from '../src/checks/index.js';
import { memoryCache } from '../src/core/osv.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const server = spawn(process.execPath, [path.join(here, 'fixture-server.mjs')], { stdio: 'inherit' });
await new Promise((r) => setTimeout(r, 700));

let passed = 0, failed = 0;
const t = async (name, fn) => {
  try { await fn(); passed++; console.log(`\x1b[32mok\x1b[0m   ${name}`); }
  catch (e) { failed++; console.error(`\x1b[31mFAIL\x1b[0m ${name}\n     ${e.message.split('\n').slice(0, 4).join('\n     ')}`); }
};

const scan = async (url) => {
  const ctx = await collect(url, { active: true, fetchScripts: false });
  return runAll(ctx, { cache: memoryCache() });
};
const by = (r, id) => r.results.find((x) => x.id === id);

await t('sloppy site: QA-09 finds the exposed files it really serves', async () => {
  const r = await scan('http://127.0.0.1:8081/');
  const qa09 = by(r, 'QA-09');
  assert.equal(qa09.status, 'fail');
  for (const p of ['/.env', '/.git/HEAD', '/.git/config', '/phpinfo.php', '/.htpasswd'])
    assert.ok(qa09.summary.includes(p), `expected ${p} in: ${qa09.summary}`);
});

await t('sloppy site: secrets never appear in the report', async () => {
  const r = await scan('http://127.0.0.1:8081/');
  const dump = JSON.stringify(r);
  for (const secret of ['hunter2', 'sk_live_abc', 'base64:9ZxQ1'])
    assert.ok(!dump.includes(secret), `report leaked ${secret}`);
});

await t('sloppy site: header + cookie + disclosure checks all fire', async () => {
  const r = await scan('http://127.0.0.1:8081/');
  assert.equal(by(r, 'QA-01').status, 'fail');   // plaintext http
  assert.equal(by(r, 'QA-02').status, 'fail');   // no CSP
  assert.equal(by(r, 'QA-03').status, 'fail');   // no framing protection
  assert.equal(by(r, 'QA-04').status, 'fail');   // no nosniff
  assert.equal(by(r, 'QA-06').status, 'fail');   // PHPSESSID with no HttpOnly
  assert.equal(by(r, 'QA-07').status, 'skip');   // not https, so mixed content N/A
  assert.equal(by(r, 'QA-10').status, 'warn');   // Apache/2.4.29 + PHP/7.2.24
  assert.ok(r.score < 40, `expected a low score, got ${r.score}`);
});

await t('sloppy site: vulnerable jQuery 1.8.3 and lodash 4.17.11 are detected', async () => {
  const ctx = await collect('http://127.0.0.1:8081/', { fetchScripts: false });
  const names = ctx.libraries.map((l) => `${l.name}@${l.version}`);
  assert.ok(names.includes('jquery@1.8.3'), `got ${names}`);
  assert.ok(names.includes('lodash@4.17.11'), `got ${names}`);
});

await t('SPA catch-all: QA-09 reports no exposure despite 200 on every path', async () => {
  const r = await scan('http://127.0.0.1:8082/');
  const qa09 = by(r, 'QA-09');
  assert.equal(qa09.status, 'pass', `false positives: ${qa09.summary}`);
});

await t('tight site: every header check passes', async () => {
  const r = await scan('http://127.0.0.1:8083/');
  for (const id of ['QA-02', 'QA-03', 'QA-04', 'QA-05', 'QA-06'])
    assert.equal(by(r, id).status, 'pass', `${id}: ${by(r, id).summary}`);
  assert.equal(by(r, 'QA-10').status, 'pass');
  // QA-01 fails only because the fixture is plain http on localhost; that is correct behaviour.
  assert.equal(by(r, 'QA-01').status, 'fail');
});

await t('probe never escapes the origin it was built for', async () => {
  const { makeProber } = await import('../src/core/collect-node.js');
  const probe = makeProber('http://127.0.0.1:8081');
  await assert.rejects(() => probe('https://evil.example.com/.env'), /escaped origin/);
  await assert.rejects(() => probe('//evil.example.com/.env'), /escaped origin/);
});

server.kill();
console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}integration: ${passed} passed, ${failed} failed\x1b[0m`);
process.exit(failed ? 1 : 0);
