#!/usr/bin/env node
/**
 * Runs ci/action.mjs exactly as GitHub would: INPUT_* environment variables, a GITHUB_OUTPUT
 * file, a GITHUB_STEP_SUMMARY file, and the real process exit code. Targets the local fixture
 * servers, so no third-party host is involved.
 */
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const server = spawn(process.execPath, [path.join(here, 'fixture-server.mjs')], { stdio: 'ignore' });
await new Promise((r) => setTimeout(r, 800));

let passed = 0, failed = 0;
const t = (name, fn) => {
  try { fn(); passed++; console.log(`\x1b[32mok\x1b[0m   ${name}`); }
  catch (e) { failed++; console.error(`\x1b[31mFAIL\x1b[0m ${name}\n     ${e.message.split('\n').slice(0, 5).join('\n     ')}`); }
};

/** Invoke the action with the given inputs and capture everything GitHub would see. */
function runAction(inputs, extraEnv = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'qa-ci-'));
  const outputFile = path.join(dir, 'output');
  const summaryFile = path.join(dir, 'summary.md');
  writeFileSync(outputFile, '');
  writeFileSync(summaryFile, '');

  const env = { ...process.env, GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile, ...extraEnv };
  for (const [k, v] of Object.entries(inputs)) {
    env[`INPUT_${k.replace(/-/g, '_').toUpperCase()}`] = String(v);
  }

  const res = spawnSync(process.execPath, [path.join(root, 'ci', 'action.mjs')], {
    env, encoding: 'utf8', timeout: 90000,
  });

  const raw = readFileSync(outputFile, 'utf8');
  const outputs = {};
  // Parse the heredoc form the action writes. GITHUB_OUTPUT is written with os.EOL, so on
  // Windows the separators are CRLF and a \n-only pattern silently matches nothing.
  const norm = raw.replace(/\r\n/g, '\n');
  for (const m of norm.matchAll(/^([\w-]+)<<(\S+)\n([\s\S]*?)\n\2$/gm)) outputs[m[1]] = m[3];

  return {
    code: res.status,
    stdout: res.stdout || '',
    stderr: res.stderr || '',
    outputs,
    summary: readFileSync(summaryFile, 'utf8'),
  };
}

// ── the sloppy fixture: should block the build ──────────────────────────────────
const sloppy = runAction({ url: 'http://127.0.0.1:8081/', 'fail-on': 'high' });

t('a badly configured site fails the build', () => {
  assert.equal(sloppy.code, 1, `expected exit 1, got ${sloppy.code}\n${sloppy.stderr}`);
});

t('outputs are written for later steps', () => {
  assert.ok(Number(sloppy.outputs.score) < 50, `score was ${sloppy.outputs.score}`);
  assert.equal(sloppy.outputs.passed, 'false');
  assert.ok(Number(sloppy.outputs.failed) > 0);
  const parsed = JSON.parse(sloppy.outputs['report-json']);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].results.length, 10);
});

t('the job summary is real markdown a developer can read', () => {
  assert.match(sloppy.summary, /## QuickAudit — failed/);
  assert.match(sloppy.summary, /\| Score \| Failed \| Warnings \| Passed \| Skipped \|/);
  assert.match(sloppy.summary, /QA-02/);
  assert.match(sloppy.summary, /How to fix/);
});

t('findings are emitted as workflow annotations', () => {
  assert.match(sloppy.stdout, /::error::/);
  assert.match(sloppy.stdout, /QA-04/);
});

// ── the tight fixture: should pass ──────────────────────────────────────────────
const tight = runAction({ url: 'http://127.0.0.1:8083/', 'fail-on': 'high' });

t('a well configured site passes the build', () => {
  // The fixture is plain http on localhost, so QA-01 fails by design. That is a `high`
  // finding, which correctly blocks — so the meaningful assertion is that everything else
  // passed and the only blocker is the one we expect.
  const parsed = JSON.parse(tight.outputs['report-json'])[0];
  const blocking = parsed.results.filter((r) => r.status === 'fail');
  assert.deepEqual(blocking.map((r) => r.id), ['QA-01'], `unexpected failures: ${blocking.map((r) => r.id)}`);
});

t('the same site passes once transport is excluded', () => {
  const res = runAction({ url: 'http://127.0.0.1:8083/', checks: 'QA-02,QA-03,QA-04,QA-05,QA-06' });
  assert.equal(res.code, 0, `expected a clean pass, got ${res.code}`);
  assert.equal(res.outputs.passed, 'true');
  assert.match(res.summary, /## QuickAudit — passed/);
});

// ── policy controls ─────────────────────────────────────────────────────────────
t('fail-on never reports without blocking', () => {
  const res = runAction({ url: 'http://127.0.0.1:8081/', 'fail-on': 'never' });
  assert.equal(res.code, 0);
  assert.equal(res.outputs.passed, 'true');
  assert.match(res.summary, /disabled/);
  assert.match(res.summary, /QA-02/, 'findings must still be reported');
});

t('an unknown check id is rejected with a usable message', () => {
  const res = runAction({ url: 'http://127.0.0.1:8081/', checks: 'QA-99' });
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /Unknown check id/);
});

t('a missing url fails immediately', () => {
  const res = runAction({ 'fail-on': 'high' });
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /url` input is required/);
});

t('an unreachable host fails the job rather than reporting clean', () => {
  // CI that goes green because the deploy was down is worse than no CI at all.
  const res = runAction({ url: 'http://127.0.0.1:9/', timeout: '3000' });
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /Could not scan/);
});

t('several urls are audited in one run', () => {
  const res = runAction({ url: 'http://127.0.0.1:8081/, http://127.0.0.1:8083/', 'fail-on': 'never' });
  assert.equal(res.code, 0);
  const parsed = JSON.parse(res.outputs['report-json']);
  assert.equal(parsed.length, 2);
  assert.match(res.summary, /127\.0\.0\.1:8081/);
  assert.match(res.summary, /127\.0\.0\.1:8083/);
});

t('active probing stays off unless asked for, and warns when enabled', () => {
  const off = runAction({ url: 'http://127.0.0.1:8081/', 'fail-on': 'never' });
  assert.match(off.summary, /Active check disabled/);

  const on = runAction({ url: 'http://127.0.0.1:8081/', active: 'true', 'fail-on': 'never' });
  assert.match(on.stdout, /::warning::.*authorised to test/i, 'enabling it must warn in the log');
  assert.match(on.summary, /\/\.env/, 'the fixture really does expose /.env');
});

server.kill();
console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}ci integration: ${passed} passed, ${failed} failed\x1b[0m`);
process.exit(failed ? 1 : 0);
