#!/usr/bin/env node
/**
 * Generate store-listing screenshots at the exact 1280x800 the Chrome Web Store wants.
 *
 * Every shot renders the *real* popup and options pages driven by *real* scan data collected
 * live from the named sites — no mockups, no invented findings. Store policy requires
 * screenshots to represent the actual product, and a composited shot of genuine UI does.
 *
 *   node tools/screenshots.mjs      then open http://127.0.0.1:8091/shot/1 .. /shot/5
 */
import http from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { collect } from '../src/core/collect-node.js';
import { runAll } from '../src/checks/index.js';
import { memoryCache } from '../src/core/osv.js';
import { buildHtmlReport } from '../src/ext/report.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const srcDir = path.join(root, 'src');
const PORT = 8091;

const SITES = {
  failing: 'https://www.wikipedia.org/',
  clean: 'https://github.com/',
  vulnerable: 'https://www.python.org/',
};

const cache = memoryCache();
const reports = {};
for (const [key, url] of Object.entries(SITES)) {
  process.stderr.write(`scanning ${url} …\n`);
  try {
    const ctx = await collect(url, { active: false, timeout: 20000, maxScripts: 4 });
    reports[key] = await runAll(ctx, { cache });
    // The findings are real and identical either way, but the *collector* notes describe how
    // this harness gathered the data ("collected without a browser"), which is not how the
    // extension behaves. Showing them would misrepresent the product, so they are dropped
    // rather than reworded into something that was never actually emitted.
    reports[key].notes = [];
    process.stderr.write(`  score ${reports[key].score}\n`);
  } catch (e) {
    process.stderr.write(`  failed: ${e.message}\n`);
  }
}

const CAPTIONS = {
  1: ['Ten checks. One click.', 'Every finding cites the header that caused it — and the exact line to add.'],
  2: ['Not a fear machine.', 'A well-configured site scores accordingly. No invented findings to justify the install.'],
  3: ['Vulnerable libraries, checked against OSV.dev.', 'Live CVE data, not a bundled list that goes stale the week it ships.'],
  4: ['Active probing is off by default.', 'The one check that sends requests requires an explicit authorisation acknowledgement.'],
  5: ['Pro: export a client-ready report.', 'Self-contained HTML, prints to PDF, no account and no server.'],
};

const stub = (report, opts = {}) => `<script>
(function () {
  const REPORT = ${JSON.stringify(report)};
  const store = { lastReport: REPORT, qaSettings: ${JSON.stringify(opts.settings || { activeChecks: false, enabled: null })} };
  globalThis.chrome = {
    tabs: { query: async () => [{ id: 1, url: REPORT.url }], create(){} },
    runtime: {
      sendMessage: async () => REPORT,
      getURL: (p) => '/ext/' + p.split('/').pop(),
      openOptionsPage(){},
      getManifest: () => ({ version: '1.0.0' }),
    },
    storage: { local: {
      get: async (k) => (k == null ? { ...store }
        : Object.fromEntries((Array.isArray(k)?k:[k]).filter(x => x in store).map(x => [x, store[x]]))),
      set: async (o) => { Object.assign(store, o); },
      remove: async (k) => { delete store[k]; },
    } },
    permissions: { contains: async () => true, request: async () => true },
    downloads: { download: async () => 1 },
    scripting: { executeScript: async () => [{ result: null }] },
  };
})();
</script>`;

/** Compose a 1280x800 canvas: caption on the left, real UI on the right. */
function frame(n, innerUrl, wide = false) {
  const [title, sub] = CAPTIONS[n];
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{width:1280px;height:800px;overflow:hidden;
    font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif}
  body{display:flex;align-items:center;gap:56px;padding:0 72px;
    background:linear-gradient(135deg,#0b1220 0%,#131c2e 55%,#0d1526 100%);color:#e6e8eb}
  .copy{flex:1;max-width:${wide ? 380 : 470}px}
  h1{font-size:38px;line-height:1.15;letter-spacing:-.02em;font-weight:680;margin-bottom:18px}
  p{font-size:17px;line-height:1.6;color:#98a2b3}
  .mark{display:flex;align-items:center;gap:10px;margin-bottom:26px;
    font-weight:650;letter-spacing:-.01em;font-size:15px;color:#6ea8fe}
  .shell{border-radius:14px;overflow:hidden;background:#16181d;
    box-shadow:0 30px 70px rgba(0,0,0,.55),0 0 0 1px rgba(255,255,255,.07)}
  iframe{display:block;border:0;background:#16181d}
  </style></head><body>
  <div class="copy">
    <div class="mark">
      <svg viewBox="0 0 24 24" width="22" height="22"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="m8.5 12 2.5 2.5 5-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
      QuickAudit
    </div>
    <h1>${title}</h1>
    <p>${sub}</p>
  </div>
  <div class="shell"><iframe src="${innerUrl}" width="${wide ? 700 : 400}" height="${wide ? 700 : 600}"></iframe></div>
  </body></html>`;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const p = url.pathname;

  const shot = p.match(/^\/shot\/(\d)$/);
  if (shot) {
    const n = Number(shot[1]);
    const inner = {
      1: '/ext/popup.html?r=failing',
      2: '/ext/popup.html?r=clean',
      3: '/ext/popup.html?r=vulnerable&open=QA-08',
      4: '/ext/options.html?r=failing&scroll=active',
      5: '/report?r=failing',
    }[n];
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end(frame(n, inner, n === 4 || n === 5));
  }

  if (p === '/report') {
    const r = reports[url.searchParams.get('r')] || Object.values(reports)[0];
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end(buildHtmlReport(r));
  }

  const name = p.replace(/^\//, '') || 'ext/popup.html';
  const file = path.join(srcDir, name);
  if (!file.startsWith(srcDir) || !existsSync(file)) { res.writeHead(404); return res.end('nf'); }
  const ext = path.extname(file);
  const type = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' }[ext] || 'text/plain';
  let body = readFileSync(file, 'utf8');

  if (ext === '.html') {
    const key = url.searchParams.get('r') || 'failing';
    const report = reports[key] || Object.values(reports)[0];
    const settings = name.includes('options') ? { activeChecks: false, enabled: null } : undefined;
    body = body.replace('<script type="module"', `${stub(report, { settings })}\n<script type="module"`);
    const scrollTo = url.searchParams.get('scroll');
    if (scrollTo) {
      // The caption promises the consent gate, so the frame must actually show it.
      body = body.replace('</body>', `<script type="module">
        setTimeout(() => document.getElementById('${scrollTo}')?.scrollIntoView({ block: 'start' }), 350);
      </script></body>`);
    }
    const open = url.searchParams.get('open');
    if (open) {
      body = body.replace('</body>', `<script type="module">
        setTimeout(() => {
          document.querySelectorAll('.check').forEach(d => {
            d.open = d.querySelector('.title')?.textContent.includes('${open}');
          });
        }, 400);
      </script></body>`);
    }
  }
  res.writeHead(200, { 'content-type': type });
  res.end(body);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\nStore screenshots (set the viewport to exactly 1280x800):`);
  for (let n = 1; n <= 5; n++) console.log(`  ${n}. http://127.0.0.1:${PORT}/shot/${n}  — ${CAPTIONS[n][0]}`);
  console.log(`\nreports: ${Object.entries(reports).map(([k, r]) => `${k}=${r.score}`).join('  ')}`);
});
process.on('SIGINT', () => { server.close(); process.exit(0); });
