/**
 * The GitHub-shaped half of the Action: inputs, outputs, annotations, job summary and the
 * pull-request comment.
 *
 * Deliberately hand-rolled rather than using @actions/core and @actions/github. QuickAudit
 * has no dependencies, which means this Action needs no bundler and no `dist/` committed to
 * the repo — the source you read is the code that runs. That property is worth more here
 * than the small convenience those packages provide.
 */
import { appendFileSync } from 'node:fs';
import { EOL } from 'node:os';

/** Action inputs arrive as INPUT_<NAME>, uppercased with spaces and dashes as underscores. */
export function input(name, fallback = '') {
  const key = `INPUT_${name.replace(/[\s-]/g, '_').toUpperCase()}`;
  const v = process.env[key];
  return v === undefined || v === '' ? fallback : v.trim();
}

export function boolInput(name, fallback = false) {
  const v = input(name, String(fallback)).toLowerCase();
  return v === 'true' || v === '1' || v === 'yes';
}

/** Write a step output for later steps to consume. */
export function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  const val = typeof value === 'string' ? value : JSON.stringify(value);
  if (!file) return;
  // Multi-line values need the heredoc form or the file format breaks.
  const delim = `ghadelim_${Math.random().toString(36).slice(2)}`;
  appendFileSync(file, `${name}<<${delim}${EOL}${val}${EOL}${delim}${EOL}`);
}

/** Workflow annotations. These surface inline in the Actions UI. */
export function annotate(level, message) {
  // Newlines terminate a workflow command, so they must be escaped.
  const safe = String(message).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  process.stdout.write(`::${level}::${safe}${EOL}`);
}

export const notice = (m) => annotate('notice', m);
export const warning = (m) => annotate('warning', m);
export const error = (m) => annotate('error', m);

export function summaryWrite(markdown) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (!file) return false;
  appendFileSync(file, markdown + EOL);
  return true;
}

const ICON = { fail: '🔴', warn: '🟠', pass: '🟢', skip: '⚪', error: '⚠️' };

/** The job summary is the main artifact a developer actually reads in the Actions UI. */
export function renderSummary(report, verdict, { url, title = 'QuickAudit' } = {}) {
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0, error: 0 };
  for (const r of report.results) counts[r.status] = (counts[r.status] || 0) + 1;

  const lines = [];
  lines.push(`## ${title} — ${verdict.shouldFail ? 'failed' : 'passed'}`);
  lines.push('');
  lines.push(`**${url}**`);
  lines.push('');
  lines.push(`| Score | Failed | Warnings | Passed | Skipped |`);
  lines.push(`|---|---|---|---|---|`);
  lines.push(`| **${report.score}/100** | ${counts.fail} | ${counts.warn} | ${counts.pass} | ${counts.skip + counts.error} |`);
  lines.push('');
  lines.push(verdict.reason);
  lines.push('');

  const notable = report.results.filter((r) => r.status === 'fail' || r.status === 'warn' || r.status === 'error');
  if (notable.length) {
    lines.push('| | Check | Severity | Finding |');
    lines.push('|---|---|---|---|');
    for (const r of notable) {
      lines.push(`| ${ICON[r.status]} | ${r.id} ${r.title} | ${r.severity} | ${escapeCell(r.summary)} |`);
    }
    lines.push('');
    lines.push('<details><summary>How to fix</summary>');
    lines.push('');
    for (const r of notable) {
      if (!r.fix) continue;
      lines.push(`**${r.id} ${r.title}**`);
      lines.push('');
      lines.push('```');
      lines.push(r.fix);
      lines.push('```');
      lines.push('');
    }
    lines.push('</details>');
    lines.push('');
  }

  const skipped = report.results.filter((r) => r.status === 'skip');
  if (skipped.length) {
    // Skips matter: a skipped check is not a passing check, and silently hiding them is how
    // a scanner ends up implying a clean bill of health it never established.
    lines.push(`<details><summary>${skipped.length} check(s) skipped</summary>`);
    lines.push('');
    for (const r of skipped) lines.push(`- **${r.id}** ${r.title} — ${escapeCell(r.summary)}`);
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  if (report.notes?.length) {
    for (const n of report.notes) lines.push(`> ${n}`);
    lines.push('');
  }

  return lines.join('\n');
}

function escapeCell(s) {
  return String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

/**
 * Post or update a single comment on the pull request.
 *
 * Updates in place rather than adding one per run — a bot that posts a fresh comment on
 * every push turns a busy PR into a wall of noise, which is how teams end up muting the
 * tool that was supposed to help them.
 */
export async function upsertPullRequestComment({ token, body, marker = '<!-- quickaudit -->' }) {
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!token || !repo || !eventPath) return { posted: false, reason: 'not a pull request context' };

  let prNumber;
  try {
    const { readFileSync } = await import('node:fs');
    const event = JSON.parse(readFileSync(eventPath, 'utf8'));
    prNumber = event.pull_request?.number ?? event.issue?.number;
  } catch {
    return { posted: false, reason: 'could not read the event payload' };
  }
  if (!prNumber) return { posted: false, reason: 'no pull request number in the event' };

  const api = `https://api.github.com/repos/${repo}`;
  const headers = {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'content-type': 'application/json',
    'user-agent': 'quickaudit-action',
  };
  const payload = `${marker}\n${body}`;

  try {
    const listed = await fetch(`${api}/issues/${prNumber}/comments?per_page=100`, { headers });
    if (listed.ok) {
      const comments = await listed.json();
      const mine = comments.find((c) => typeof c.body === 'string' && c.body.startsWith(marker));
      if (mine) {
        const res = await fetch(`${api}/issues/comments/${mine.id}`, {
          method: 'PATCH', headers, body: JSON.stringify({ body: payload }),
        });
        return { posted: res.ok, updated: true, reason: res.ok ? '' : `HTTP ${res.status}` };
      }
    }
    const res = await fetch(`${api}/issues/${prNumber}/comments`, {
      method: 'POST', headers, body: JSON.stringify({ body: payload }),
    });
    return { posted: res.ok, updated: false, reason: res.ok ? '' : `HTTP ${res.status}` };
  } catch (e) {
    return { posted: false, reason: e.message };
  }
}
