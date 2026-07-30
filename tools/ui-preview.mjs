#!/usr/bin/env node
/**
 * Renders the popup and options pages in an ordinary browser, with the extension APIs stubbed
 * and a *real* scan report loaded from the CLI.
 *
 * Automated tests stub the browser away entirely, so nothing in the suite proves the UI is
 * not visually broken. This serves the real popup.html/popup.js unmodified — only an inline
 * stub is injected ahead of the module script — so layout, CSS and render logic get exercised
 * by a genuine engine.
 *
 *   node tools/ui-preview.mjs [url]      # defaults to a canned wikipedia.org report
 *   → http://127.0.0.1:8090/popup.html
 *   → http://127.0.0.1:8090/options.html
 */
import http from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { collect } from '../src/core/collect-node.js';
import { runAll } from '../src/checks/index.js';
import { memoryCache } from '../src/core/osv.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
/**
 * Served root is src/, not src/ext/ — options.js imports `../checks/index.js`, so flattening
 * the tree would 404 exactly the import the real extension resolves fine.
 */
const srcDir = path.join(root, 'src');
const PORT = 8090;

const target = process.argv[2] || 'https://www.wikipedia.org/';
process.stderr.write(`Scanning ${target} for preview data…\n`);

let report;
try {
  const ctx = await collect(target, { active: false, timeout: 15000, maxScripts: 3 });
  report = await runAll(ctx, { cache: memoryCache() });
} catch (e) {
  process.stderr.write(`Live scan failed (${e.message}); using a synthetic report.\n`);
  report = SYNTHETIC();
}

/**
 * Injected before the page's module script. Classic inline scripts run during parsing while
 * modules are deferred, so `chrome` exists by the time browser-api.js reads it.
 */
const stub = (reportJson) => `<script>
(function () {
  const REPORT = ${reportJson};
  const store = { lastReport: REPORT, qaSettings: { activeChecks: false, enabled: null } };
  globalThis.chrome = {
    tabs: {
      query: async () => [{ id: 1, url: REPORT.url }],
      create: (o) => window.open(o.url, '_blank'),
    },
    runtime: {
      sendMessage: async (msg) => (msg.type === 'scan' ? REPORT : { granted: true }),
      getURL: (p) => '/' + p.split('/').pop(),
      openOptionsPage: () => { location.href = '/options.html'; },
      getManifest: () => ({ version: '1.0.0' }),
    },
    storage: {
      local: {
        get: async (k) => (k == null ? { ...store }
          : Object.fromEntries((Array.isArray(k) ? k : [k]).filter((x) => x in store).map((x) => [x, store[x]]))),
        set: async (o) => { Object.assign(store, o); },
        remove: async (k) => { delete store[k]; },
      },
    },
    permissions: { contains: async () => true, request: async () => true },
    downloads: { download: async ({ url }) => window.open(url, '_blank') },
    scripting: { executeScript: async () => [{ result: null }] },
  };
  document.documentElement.dataset.preview = '1';
})();
</script>`;

const server = http.createServer((req, res) => {
  let name = (req.url.split('?')[0] || '/').replace(/^\//, '') || 'ext/popup.html';
  if (name === '' || name === 'popup.html') name = 'ext/popup.html';
  if (name === 'options.html') name = 'ext/options.html';
  const file = path.join(srcDir, name);
  if (!file.startsWith(srcDir) || !existsSync(file)) {
    res.writeHead(404); return res.end('not found');
  }
  const ext = path.extname(file);
  const type = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' }[ext] || 'text/plain';
  let body = readFileSync(file, 'utf8');
  if (ext === '.html') {
    // Inject ahead of the first module script so the stub wins the race.
    body = body.replace('<script type="module"', `${stub(JSON.stringify(report))}\n  <script type="module"`);
    // The popup is a fixed 400px panel; give it room to breathe in a normal tab.
    body = body.replace('</head>', '<style>body{margin:0 auto;box-shadow:0 0 0 1px rgba(128,128,128,.3)}</style></head>');
  }
  res.writeHead(200, { 'content-type': type });
  res.end(body);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`popup   http://127.0.0.1:${PORT}/ext/popup.html`);
  console.log(`options http://127.0.0.1:${PORT}/ext/options.html`);
  console.log(`report  ${report.url} — score ${report.score}`);
});

process.on('SIGINT', () => { server.close(); process.exit(0); });

function SYNTHETIC() {
  return {
    url: 'https://example.com/', scannedAt: new Date().toISOString(), score: 49, notes: [],
    results: [
      { id: 'QA-02', title: 'Content-Security-Policy', status: 'fail', severity: 'high', summary: 'No Content-Security-Policy.', details: ['Any injected script runs unrestricted.'], fix: "default-src 'self'", ref: '' },
      { id: 'QA-04', title: 'MIME-sniffing protection', status: 'pass', severity: 'info', summary: 'nosniff is set.', details: [], fix: '', ref: '' },
    ],
  };
}
