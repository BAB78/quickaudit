#!/usr/bin/env node
/**
 * QuickAudit GitHub Action entry point.
 *
 * Runs the same ten checks the extension runs, against a deployed URL, on every push or pull
 * request. The checks themselves are untouched: this file only adapts inputs, renders the
 * result for the Actions UI, and decides the exit code.
 */
import { collect } from '../src/core/collect-node.js';
import { runAll, CHECK_META } from '../src/checks/index.js';
import { memoryCache } from '../src/core/osv.js';
import { evaluate } from './threshold.mjs';
import {
  input, boolInput, setOutput, notice, warning, error,
  summaryWrite, renderSummary, upsertPullRequestComment,
} from './github.mjs';

const VALID_IDS = new Set(CHECK_META.map((c) => c.id));

async function main() {
  const urls = input('url')
    .split(/[\s,]+/)
    .map((u) => u.trim())
    .filter(Boolean)
    .map((u) => (/^https?:\/\//i.test(u) ? u : `https://${u}`));

  if (!urls.length) throw new Error('The `url` input is required.');

  const enabled = parseChecks(input('checks'));
  const active = boolInput('active', false);
  const failOn = input('fail-on', 'high');
  const warningsAsErrors = boolInput('warnings-as-errors', false);
  const timeout = Number(input('timeout', '20000'));

  if (active) {
    warning(
      'Active file-exposure probing is enabled. This sends GET requests for well-known paths ' +
      'to the target origin. Only enable it for hosts you own or are authorised to test.'
    );
  }

  const cache = memoryCache(); // shared, so OSV is queried once per library across all URLs
  const reports = [];
  let worstExit = 0;

  for (const url of urls) {
    const report = await scan(url, { enabled, active, timeout, cache });
    const verdict = evaluate(report, { failOn, warningsAsErrors });
    reports.push({ url, report, verdict });

    emitAnnotations(report, verdict, url, urls.length > 1);

    const summary = renderSummary(report, verdict, {
      url,
      title: urls.length > 1 ? `QuickAudit — ${hostOf(url)}` : 'QuickAudit',
    });
    if (!summaryWrite(summary)) console.log(summary);

    if (verdict.exitCode > worstExit) worstExit = verdict.exitCode;
  }

  // Outputs describe the run as a whole so later steps can branch on them.
  const worst = reports.reduce((a, b) => (b.report.score < a.report.score ? b : a));
  setOutput('score', String(worst.report.score));
  setOutput('failed', String(reports.reduce((n, r) => n + r.verdict.blocking.length, 0)));
  setOutput('passed', String(worstExit === 0));
  setOutput('report-json', JSON.stringify(reports.map((r) => ({ url: r.url, ...r.report }))));

  if (boolInput('comment', false)) {
    const token = input('github-token');
    const body = reports
      .map((r) => renderSummary(r.report, r.verdict, { url: r.url, title: 'QuickAudit' }))
      .join('\n\n---\n\n');
    const res = await upsertPullRequestComment({ token, body });
    if (!res.posted) notice(`Pull request comment not posted: ${res.reason}`);
  }

  // Set the code and let Node drain naturally. Calling process.exit() here races the
  // still-closing HTTP sockets and trips a libuv assertion on Windows, which surfaces as a
  // garbage exit status — fatal for an Action, where the exit code *is* the result.
  process.exitCode = worstExit;
}

async function scan(url, { enabled, active, timeout, cache }) {
  try {
    const ctx = await collect(url, { active, timeout, maxScripts: 6 });
    return await runAll(ctx, { enabled, cache });
  } catch (e) {
    // A site that cannot be reached is a failed job, not a clean report. CI that goes green
    // because the deploy was unreachable is worse than no CI at all.
    throw new Error(`Could not scan ${url}: ${e.message}`);
  }
}

function parseChecks(raw) {
  if (!raw) return null;
  const ids = raw.split(/[\s,]+/).map((s) => s.trim().toUpperCase()).filter(Boolean);
  const unknown = ids.filter((id) => !VALID_IDS.has(id));
  if (unknown.length) {
    throw new Error(`Unknown check id(s): ${unknown.join(', ')}. Valid ids: ${[...VALID_IDS].join(', ')}`);
  }
  return ids;
}

function emitAnnotations(report, verdict, url, multi) {
  const prefix = multi ? `${hostOf(url)}: ` : '';
  for (const r of report.results) {
    const line = `${prefix}${r.id} ${r.title} — ${r.summary}`;
    if (r.status === 'error') error(`${line} (check failed to run)`);
    else if (r.status === 'fail') {
      verdict.blocking.includes(r) ? error(line) : warning(line);
    } else if (r.status === 'warn' && verdict.blocking.includes(r)) error(line);
  }
  (verdict.shouldFail ? error : notice)(`${prefix}${verdict.reason}`);
}

function hostOf(u) {
  try { return new URL(u).host; } catch { return u; }
}

main().catch((e) => {
  error(e.message);
  process.exitCode = 1;
});
