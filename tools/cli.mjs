#!/usr/bin/env node
/**
 * QuickAudit CLI — the same ten checks the extension runs, from a terminal.
 * Exists mostly so the checks can be validated against real sites in CI without a browser.
 *
 *   node tools/cli.mjs https://example.com [--active] [--json]
 */
import { collect } from '../src/core/collect-node.js';
import { runAll, summarize } from '../src/checks/index.js';
import { memoryCache } from '../src/core/osv.js';

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', blue: '\x1b[34m', grey: '\x1b[90m',
};
const BADGE = {
  fail: `${C.red}FAIL${C.reset}`, warn: `${C.yellow}WARN${C.reset}`,
  pass: `${C.green}PASS${C.reset}`, skip: `${C.grey}SKIP${C.reset}`, error: `${C.red}ERR ${C.reset}`,
};

export async function scan(url, { active = false } = {}) {
  const ctx = await collect(url, { active });
  return runAll(ctx, { cache: memoryCache() });
}

async function main() {
  const args = process.argv.slice(2);
  const url = args.find((a) => !a.startsWith('-'));
  if (!url) {
    console.error('usage: node tools/cli.mjs <url> [--active] [--json]');
    process.exit(2);
  }
  const active = args.includes('--active');
  const json = args.includes('--json');

  if (active) {
    console.error(`${C.yellow}Active checks enabled: QuickAudit will send ~14 GET requests to ${url}.`);
    console.error(`Only do this against hosts you own or are authorised to test.${C.reset}\n`);
  }

  const report = await scan(url.startsWith('http') ? url : `https://${url}`, { active });

  if (json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  const counts = summarize(report.results);
  console.log(`\n${C.bold}QuickAudit${C.reset} ${report.url}`);
  console.log(`${C.dim}${report.scannedAt}${C.reset}`);
  console.log(`Score ${C.bold}${report.score}/100${C.reset}  ·  ` +
    `${C.red}${counts.fail} fail${C.reset} ${C.yellow}${counts.warn} warn${C.reset} ` +
    `${C.green}${counts.pass} pass${C.reset} ${C.grey}${counts.skip} skip${C.reset}\n`);

  for (const r of report.results) {
    console.log(`${BADGE[r.status]} ${C.bold}${r.id}${C.reset} ${r.title} ${C.grey}[${r.severity}]${C.reset}`);
    console.log(`     ${r.summary}`);
    for (const d of r.details) console.log(`     ${C.dim}${d.replace(/\n/g, '\n     ')}${C.reset}`);
    if (r.status === 'fail' || r.status === 'warn') {
      if (r.fix) console.log(`     ${C.blue}Fix:${C.reset} ${r.fix.replace(/\n/g, '\n          ')}`);
    }
    console.log('');
  }
  for (const n of report.notes) console.log(`${C.grey}note: ${n}${C.reset}`);

  // exitCode rather than exit(): calling exit() while HTTP sockets are still closing trips
  // a libuv assertion on Windows and returns a garbage status.
  process.exitCode = counts.fail > 0 ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}` ||
    process.argv[1]?.endsWith('cli.mjs')) {
  main().catch((e) => {
    console.error(`${C.red}scan failed:${C.reset} ${e.message}`);
    process.exitCode = 2;
  });
}
