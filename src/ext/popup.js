import { api, can, sendMessage, requestOrigin, openOptions, storage } from './browser-api.js';
import { isPro } from './license.js';
import { buildHtmlReport } from './report.js';

const $ = (id) => document.getElementById(id);
const CIRC = 2 * Math.PI * 19;

let currentReport = null;
let tab = null;

init();

async function init() {
  [tab] = await api.tabs.query({ active: true, currentWindow: true });
  $('target').textContent = tab?.url || '';
  $('settings').addEventListener('click', () => openOptions());
  $('scan').addEventListener('click', scan);
  $('export').addEventListener('click', exportReport);

  // Show the previous result for this URL so reopening the popup isn't a blank slate.
  const { lastReport } = await storage.get('lastReport');
  if (lastReport && lastReport.url === tab?.url) render(lastReport);
}

async function scan() {
  const btn = $('scan');
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  $('idle').innerHTML = '<p>Running ten checks…</p>';

  try {
    const report = await sendMessage({ type: 'scan', tabId: tab.id });
    if (report?.needsPermission) return askPermission(report);
    if (report?.error) return showError(report.error);
    render(report);
  } catch (e) {
    showError(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Rescan';
  }
}

/**
 * The permission prompt is raised here rather than in the background, because Firefox only
 * honours permissions.request() inside a user-input handler. The click below is that handler.
 */
function askPermission({ needsPermission, origin }) {
  $('results').innerHTML = '';
  const box = el('div', 'banner');
  box.innerHTML = `<b>Permission needed for ${escapeHtml(origin)}</b>
    QuickAudit asks for access one site at a time rather than all sites at install.
    It reads this page's response headers, cookie flags and loaded scripts.`;
  const go = el('button', 'primary');
  go.textContent = `Allow ${origin}`;
  go.addEventListener('click', async () => {
    let granted = false;
    try {
      granted = await requestOrigin(needsPermission);
    } catch (e) {
      return showError(`Could not request permission: ${e.message}`);
    }
    if (granted) scan();
    else showError('Permission denied — QuickAudit cannot read this page.');
  });
  box.appendChild(go);
  $('results').appendChild(box);
}

function showError(msg) {
  $('scoreboard').hidden = true;
  $('results').innerHTML = '';
  const box = el('div', 'banner');
  box.innerHTML = `<b>Scan failed</b>${escapeHtml(msg)}`;
  $('results').appendChild(box);
}

async function render(report) {
  currentReport = report;
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0, error: 0 };
  for (const r of report.results) counts[r.status] = (counts[r.status] || 0) + 1;

  $('scoreboard').hidden = false;
  $('score-num').textContent = report.score;
  const ring = $('ring');
  ring.style.strokeDashoffset = String(CIRC * (1 - report.score / 100));
  ring.style.stroke = report.score >= 80 ? 'var(--pass)' : report.score >= 50 ? 'var(--warn)' : 'var(--fail)';
  $('n-fail').textContent = counts.fail;
  $('n-warn').textContent = counts.warn;
  $('n-pass').textContent = counts.pass;
  $('n-skip').textContent = counts.skip + counts.error;

  const list = $('results');
  list.innerHTML = '';
  for (const r of report.results) list.appendChild(renderCheck(r));

  const notes = $('notes');
  notes.innerHTML = '';
  notes.hidden = !report.notes?.length;
  for (const n of report.notes || []) notes.appendChild(Object.assign(el('p'), { textContent: n }));

  $('export').hidden = false;
  $('export').textContent = (await isPro()) ? 'Export report' : 'Export report (Pro)';
}

function renderCheck(r) {
  const d = el('details', 'check');
  // Open the things that need attention; leave passes collapsed.
  if (r.status === 'fail') d.open = true;

  const s = el('summary');
  const pill = el('span', `pill ${r.status}`);
  pill.textContent = r.status.toUpperCase();
  const head = el('div', 'head');
  head.appendChild(Object.assign(el('div', 'title'), { textContent: `${r.id} · ${r.title}` }));
  head.appendChild(Object.assign(el('div', 'sum'), { textContent: r.summary }));
  if (r.status !== 'pass' && r.status !== 'skip') {
    head.appendChild(Object.assign(el('div', 'sev'), { textContent: `${r.severity} severity` }));
  }
  s.append(pill, head);

  const body = el('div', 'body');
  for (const line of r.details) body.appendChild(Object.assign(el('p'), { textContent: line }));
  if (r.fix && (r.status === 'fail' || r.status === 'warn')) {
    body.appendChild(Object.assign(el('p', 'fix'), { textContent: r.fix }));
  }
  if (r.ref) {
    const a = el('a');
    a.href = r.ref;
    a.target = '_blank';
    a.rel = 'noreferrer';
    a.textContent = 'Reference →';
    body.appendChild(a);
  }
  d.append(s, body);
  return d;
}

async function exportReport() {
  if (!currentReport) return;
  if (!(await isPro())) {
    api.tabs.create({ url: api.runtime.getURL('src/ext/options.html#pro') });
    return;
  }
  const html = buildHtmlReport(currentReport);
  const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
  const filename = `quickaudit-${safeHost(currentReport.url)}-${todayStamp()}.html`;
  await saveFile(url, filename);
}

/** Safari has no downloads API, so fall back to a synthesized anchor click. */
async function saveFile(url, filename) {
  if (can.downloads) {
    try {
      await api.downloads.download({ url, filename, saveAs: true });
      return;
    } catch { /* fall through to the anchor path */ }
  }
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function safeHost(u) {
  try { return new URL(u).hostname.replace(/[^a-z0-9.-]/gi, '_'); } catch { return 'report'; }
}
function todayStamp() { return new Date().toISOString().slice(0, 10); }
function el(tag, cls) { const n = document.createElement(tag); if (cls) n.className = cls; return n; }
function escapeHtml(s) { return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
