// Builds the small public site (site/) that hosts QuickAudit's privacy policy and a home page.
// The Chrome Web Store could not reach the GitHub-hosted policy, so it is served as plain HTML.
// Usage: node tools/site.mjs   then deploy site/ to Cloudflare Pages.
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..');
const out = path.join(root, 'site');
fs.mkdirSync(out, { recursive: true });
const repo = 'https://github.com/BAB78/quickaudit';

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function inline(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>')
    .replace(/(^|\s)_([^_]+)_/g, '$1<em>$2</em>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, t, u) => `<a href="${/^https?:/.test(u) ? u : `${repo}/blob/master/${u}`}">${t}</a>`);
}
// Enough Markdown for PRIVACY.md: headings, paragraphs, bullet lists with wrapped lines.
function markdown(md) {
  const html = [];
  let para = [], list = null;
  const flushPara = () => { if (para.length) { html.push(`<p>${inline(para.join(' '))}</p>`); para = []; } };
  const flushList = () => { if (list) { html.push(`<ul>${list.map((i) => `<li>${inline(i)}</li>`).join('')}</ul>`); list = null; } };
  for (const raw of md.replace(/\r\n/g, '\n').split('\n')) {
    const line = raw.trimEnd();
    if (/^#{1,3} /.test(line)) { flushPara(); flushList(); const n = line.match(/^#+/)[0].length; html.push(`<h${n}>${inline(line.slice(n + 1))}</h${n}>`); continue; }
    if (/^- /.test(line)) { flushPara(); (list ||= []).push(line.slice(2)); continue; }
    if (list && /^\s{2,}\S/.test(raw)) { list[list.length - 1] += ' ' + line.trim(); continue; }
    if (!line.trim()) { flushPara(); flushList(); continue; }
    flushList(); para.push(line.trim());
  }
  flushPara(); flushList();
  return html.join('\n');
}

const css = `:root{--bg:#f7f8fa;--card:#ffffff;--ink:#14181f;--muted:#4b5563;--line:#dde1e7;--accent:#0f766e;--code:#eef1f4}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#161b22;--ink:#e6e9ee;--muted:#a3acb9;--line:#2a313b;--accent:#5eead4;--code:#1f2630}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.65 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:720px;margin:0 auto;padding:40px 16px 64px}header{display:flex;align-items:center;gap:12px;margin-bottom:28px}
header img{width:40px;height:40px;border-radius:8px}header a{color:var(--ink);text-decoration:none;font-weight:700;font-size:18px}
h1{font-size:30px;line-height:1.2;margin:0 0 8px;text-wrap:balance}h2{font-size:20px;margin:32px 0 8px}
p,li{color:var(--ink)}.muted{color:var(--muted)}a{color:var(--accent)}code{background:var(--code);padding:1px 5px;border-radius:4px;font-size:.92em}
ul{padding-left:22px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px 22px;margin:20px 0}
.links{display:flex;flex-wrap:wrap;gap:10px;margin:18px 0}.links a{border:1px solid var(--line);border-radius:8px;padding:8px 14px;text-decoration:none;background:var(--card)}
footer{margin-top:40px;font-size:14px;color:var(--muted)}`;

const page = (title, desc, body) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><meta name="description" content="${esc(desc)}">
<link rel="icon" href="/icon-128.png"><style>${css}</style></head>
<body><main><header><img src="/icon-128.png" alt=""><a href="/">QuickAudit</a></header>
${body}
<footer>QuickAudit is made by BAB Studios. Contact: <a href="mailto:babstudios.app@gmail.com">babstudios.app@gmail.com</a>. Source: <a href="${repo}">GitHub</a>.</footer>
</main></body></html>
`;

const policy = fs.readFileSync(path.join(root, 'PRIVACY.md'), 'utf8')
  .replace('Questions or a privacy concern: open an issue on the project repository.',
    'Questions or a privacy concern: email babstudios.app@gmail.com or open an issue on the project repository.');
fs.writeFileSync(path.join(out, 'privacy.html'), page('QuickAudit privacy policy', 'What data the QuickAudit browser extension handles: only detected library versions are sent, to OSV.dev.', markdown(policy)));

const home = `<h1>QuickAudit: web security checklist</h1>
<p class="muted">Ten OWASP-style security checks on the page you are viewing, in one click: HTTPS and HSTS, Content-Security-Policy, clickjacking protection, cookie flags, mixed content, JavaScript libraries with known CVEs, and more.</p>
<div class="links">
<a href="https://chromewebstore.google.com/detail/kbhfdiianifmneefgfmlmloejffekjdm">Chrome Web Store</a>
<a href="https://addons.mozilla.org/en-US/firefox/addon/quickaudit-web-security/">Firefox Add-ons</a>
<a href="${repo}">Source code</a>
<a href="/privacy">Privacy policy</a>
</div>
<div class="card"><p><strong>Private by design.</strong> The only data that leaves your device is the name and version of JavaScript libraries found on the page, sent to the public OSV.dev database to look up known advisories. No URLs, no page content, no cookie values, no analytics, no account.</p></div>
<p>Nine of the ten checks are passive: they read what the page already sent your browser. The exposed-files check is off by default and only runs on the site you are on, after you confirm you are authorised to test it.</p>`;
fs.writeFileSync(path.join(out, 'index.html'), page('QuickAudit: web security checklist', 'A one-click, ten-point security checklist for the page in your browser tab. Free browser extension for Chrome, Edge and Firefox.', home));
fs.copyFileSync(path.join(root, 'store-assets', 'store-icon-128.png'), path.join(out, 'icon-128.png'));
fs.writeFileSync(path.join(out, '_headers'), `/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: strict-origin-when-cross-origin\n  X-Frame-Options: DENY\n  Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\n  Strict-Transport-Security: max-age=31536000\n`);
console.log('site built in', out, fs.readdirSync(out).join(', '));
