#!/usr/bin/env node
/**
 * Tests for the CI layer: the fail/pass policy and the job summary.
 *
 * The threshold logic decides whether someone's deploy is blocked, so it gets the same
 * scrutiny as the checks themselves. A scanner that fails builds unpredictably gets removed
 * from the pipeline within a week.
 */
import assert from 'node:assert/strict';
import { evaluate, meetsThreshold, parseThreshold } from '../ci/threshold.mjs';
import { renderSummary } from '../ci/github.mjs';

let passed = 0, failed = 0;
const t = (name, fn) => {
  try { fn(); passed++; }
  catch (e) { failed++; console.error(`\x1b[31mFAIL\x1b[0m ${name}\n      ${e.message.split('\n').slice(0, 4).join('\n      ')}`); }
};

const r = (id, status, severity, extra = {}) => ({
  id, status, severity, title: `${id} title`, summary: `${id} summary`, details: [], fix: 'do the thing', ...extra,
});
const report = (results) => ({ url: 'https://example.com/', score: 50, notes: [], results });

// ── threshold parsing ───────────────────────────────────────────────────────────
t('parseThreshold accepts the documented values and defaults to high', () => {
  assert.equal(parseThreshold(undefined), 'high');
  for (const v of ['critical', 'high', 'medium', 'low', 'never']) assert.equal(parseThreshold(v), v);
  assert.equal(parseThreshold('  HIGH '), 'high');
  assert.throws(() => parseThreshold('severe'), /fail-on must be one of/);
});

t('meetsThreshold includes everything at or above the bar', () => {
  assert.equal(meetsThreshold('critical', 'high'), true);
  assert.equal(meetsThreshold('high', 'high'), true);
  assert.equal(meetsThreshold('medium', 'high'), false);
  assert.equal(meetsThreshold('low', 'low'), true);
  assert.equal(meetsThreshold('critical', 'never'), false, 'never must disable gating entirely');
  assert.equal(meetsThreshold('info', 'low'), false, 'info must never gate a build');
});

// ── the policy ──────────────────────────────────────────────────────────────────
t('a high failure blocks at the default threshold', () => {
  const v = evaluate(report([r('QA-02', 'fail', 'high')]), {});
  assert.equal(v.shouldFail, true);
  assert.equal(v.exitCode, 1);
  assert.match(v.reason, /QA-02 \(high\)/);
});

t('a low failure does not block at the default threshold', () => {
  const v = evaluate(report([r('QA-04', 'fail', 'low')]), {});
  assert.equal(v.shouldFail, false);
  assert.equal(v.exitCode, 0);
});

t('lowering the threshold catches the same low failure', () => {
  const v = evaluate(report([r('QA-04', 'fail', 'low')]), { failOn: 'low' });
  assert.equal(v.shouldFail, true);
});

t('warnings never block unless explicitly asked to', () => {
  const results = [r('QA-05', 'warn', 'critical')];
  assert.equal(evaluate(report(results), { failOn: 'low' }).shouldFail, false);
  assert.equal(evaluate(report(results), { failOn: 'low', warningsAsErrors: true }).shouldFail, true);
});

t('fail-on never disables gating but still reports', () => {
  const v = evaluate(report([r('QA-08', 'fail', 'critical')]), { failOn: 'never' });
  assert.equal(v.shouldFail, false);
  assert.equal(v.blocking.length, 0);
  assert.match(v.reason, /disabled/);
});

t('a check that errored always fails the build', () => {
  // A broken scan must never read as a clean site.
  const v = evaluate(report([r('QA-01', 'error', 'info')]), { failOn: 'never' });
  assert.equal(v.shouldFail, true);
  assert.match(v.reason, /failed to run/);
});

t('skips and passes never block', () => {
  const v = evaluate(report([
    r('QA-08', 'skip', 'info'), r('QA-09', 'skip', 'info'), r('QA-01', 'pass', 'info'),
  ]), { failOn: 'low' });
  assert.equal(v.shouldFail, false);
  assert.match(v.reason, /No findings at or above/);
});

t('the reason names every blocking check, so the log explains itself', () => {
  const v = evaluate(report([
    r('QA-02', 'fail', 'high'), r('QA-06', 'fail', 'critical'), r('QA-04', 'fail', 'low'),
  ]), { failOn: 'high' });
  assert.match(v.reason, /QA-02/);
  assert.match(v.reason, /QA-06/);
  assert.ok(!/QA-04/.test(v.reason), 'a finding below the threshold must not be listed as blocking');
});

// ── job summary ─────────────────────────────────────────────────────────────────
t('summary reports the score, the verdict and each finding', () => {
  const rep = report([r('QA-02', 'fail', 'high'), r('QA-01', 'pass', 'info'), r('QA-09', 'skip', 'info')]);
  const v = evaluate(rep, {});
  const md = renderSummary(rep, v, { url: 'https://example.com/' });
  assert.match(md, /## QuickAudit — failed/);
  assert.match(md, /50\/100/);
  assert.match(md, /QA-02/);
  assert.match(md, /https:\/\/example\.com\//);
  assert.match(md, /1 check\(s\) skipped/, 'skips must be disclosed, not hidden');
  assert.match(md, /do the thing/, 'remediation must be included');
});

t('summary says passed when nothing blocks', () => {
  const rep = report([r('QA-01', 'pass', 'info')]);
  assert.match(renderSummary(rep, evaluate(rep, {}), { url: 'https://x.com/' }), /## QuickAudit — passed/);
});

t('summary escapes pipes so a finding cannot break the table', () => {
  const rep = report([r('QA-02', 'fail', 'high', { summary: 'script-src has | a pipe' })]);
  const md = renderSummary(rep, evaluate(rep, {}), { url: 'https://x.com/' });
  assert.match(md, /script-src has \\\| a pipe/);
});

console.log(`${failed ? '\x1b[31m' : '\x1b[32m'}ci: ${passed} passed, ${failed} failed\x1b[0m`);
process.exit(failed ? 1 : 0);
