#!/usr/bin/env node
/**
 * Two deliberately-broken local sites, so the active check (QA-09) and the full pipeline can
 * be validated end-to-end without sending probe traffic to anyone else's servers.
 *
 *   :8081  "sloppy"  — exposes .env, .git, phpinfo; no security headers; insecure cookies
 *   :8082  "spa"     — returns 200 + the same shell for every path (the false-positive trap)
 *   :8083  "tight"   — everything configured correctly; should score 100 minus the http caveat
 */
import http from 'node:http';

const SHELL = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/static/main.4f3a2b.js"></script></body></html>';

const SLOPPY_FILES = {
  '/.env': 'APP_ENV=production\nAPP_KEY=base64:9ZxQ1\nDB_PASSWORD=hunter2\nSTRIPE_SECRET=sk_live_abc\n',
  '/.git/HEAD': 'ref: refs/heads/main\n',
  '/.git/config': '[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:acme/app.git\n',
  '/phpinfo.php': '<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.2.24</h1></body></html>',
  '/.htpasswd': 'admin:$apr1$xyz$abcdefghijklmnop\n',
};

const servers = [
  {
    port: 8081, name: 'sloppy',
    handle(req, res) {
      if (SLOPPY_FILES[req.url]) {
        res.writeHead(200, { 'content-type': 'text/plain' });
        return res.end(SLOPPY_FILES[req.url]);
      }
      if (req.url !== '/') { res.writeHead(404); return res.end('Not Found'); }
      res.writeHead(200, {
        'content-type': 'text/html',
        'server': 'Apache/2.4.29 (Ubuntu)',
        'x-powered-by': 'PHP/7.2.24',
        'set-cookie': ['PHPSESSID=abc123; Path=/', 'theme=dark; Path=/'],
      });
      res.end(`<!doctype html><html><head>
        <script src="https://code.jquery.com/jquery-1.8.3.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.11/lodash.min.js"></script>
        <img src="http://insecure.example.com/tracker.gif">
        <script src="http://insecure.example.com/ads.js"></script>
        </head><body>sloppy</body></html>`);
    },
  },
  {
    port: 8082, name: 'spa',
    handle(req, res) {
      // The trap: 200 for literally everything, including /.env and /.git/HEAD.
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(SHELL);
    },
  },
  {
    port: 8083, name: 'tight',
    handle(req, res) {
      if (req.url !== '/') { res.writeHead(404); return res.end('Not Found'); }
      res.writeHead(200, {
        'content-type': 'text/html',
        'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        'content-security-policy': "default-src 'self'; script-src 'nonce-r4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=(), microphone=(), geolocation=()',
        'set-cookie': ['sid=x; Path=/; Secure; HttpOnly; SameSite=Strict'],
      });
      res.end('<!doctype html><html><body>tight</body></html>');
    },
  },
];

const running = servers.map((s) => {
  const srv = http.createServer(s.handle);
  srv.listen(s.port, '127.0.0.1', () => console.log(`  ${s.name.padEnd(7)} http://127.0.0.1:${s.port}`));
  return srv;
});

console.log('QuickAudit fixture servers:');
process.on('SIGINT', () => { running.forEach((s) => s.close()); process.exit(0); });
export { running };
