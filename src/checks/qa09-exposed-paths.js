import { result } from '../core/types.js';

export const def = {
  id: 'QA-09',
  title: 'Exposed sensitive files',
  severity: 'critical',
  active: true, // the only check that sends requests; gated on ctx.activeAllowed
  ref: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
  fix: 'Block dotfiles and backups at the web server or CDN, and stop deploying them: `location ~ /\\. { deny all; }`.',
};

/**
 * Each probe carries a content signature. Status 200 alone is never enough — SPAs and
 * catch-all rewrites happily return 200 with an HTML shell for every path on the site,
 * and that is where naive scanners generate their false positives.
 */
export const PROBES = [
  { path: '/.env', label: 'Environment file', sig: /^\s*(?:#[^\n]*\n)*\s*[A-Z][A-Z0-9_]{2,}\s*=/m, deny: /<html|<!doctype/i },
  { path: '/.git/HEAD', label: 'Git repository', sig: /^ref:\s+refs\/(heads|remotes)\//m },
  { path: '/.git/config', label: 'Git config', sig: /\[core\][\s\S]*repositoryformatversion/m },
  { path: '/.svn/entries', label: 'Subversion metadata', sig: /^(\d+\s*$|<\?xml[\s\S]*svn:)/m },
  { path: '/.DS_Store', label: 'macOS directory index', sig: /^\x00\x00\x00\x01Bud1/ },
  { path: '/.htpasswd', label: 'Basic-auth password file', sig: /^[^:\s<]{1,64}:(\$(apr1|1|2y|6)\$|[A-Za-z0-9./]{13})/m },
  { path: '/.npmrc', label: 'npm credentials', sig: /_auth(Token)?\s*=|\/\/.+\/:_authToken/m },
  { path: '/.aws/credentials', label: 'AWS credentials', sig: /\[\w+\][\s\S]*aws_access_key_id\s*=/m },
  { path: '/phpinfo.php', label: 'phpinfo() output', sig: /phpinfo\(\)|PHP Version\s*<\/td|<title>phpinfo\(\)/i },
  { path: '/server-status', label: 'Apache mod_status', sig: /Apache Server Status|Server uptime:/i },
  { path: '/actuator/env', label: 'Spring Boot actuator', sig: /"(activeProfiles|propertySources)"\s*:/ },
  { path: '/backup.sql', label: 'Database dump', sig: /(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)/i },
  { path: '/wp-config.php.bak', label: 'WordPress config backup', sig: /DB_PASSWORD|DB_NAME|<\?php/ },
];

const CALIBRATION_PATH = () => `/quickaudit-calibration-${Math.random().toString(36).slice(2, 10)}`;

/** Cheap fingerprint so we can tell "the SPA shell again" from a real file. */
function fingerprint(body) {
  const s = String(body || '');
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return `${s.length}:${h}`;
}

export async function run(ctx) {
  if (!ctx.activeAllowed) {
    return result(def, 'skip',
      'Active check disabled.',
      ['This is the only check that sends requests to the server. Enable it in QuickAudit settings, for sites you own or are authorised to test.']);
  }
  if (typeof ctx.probe !== 'function') {
    return result(def, 'skip', 'No probe transport available in this context.', []);
  }

  // Calibrate: learn what this origin does with a path that certainly does not exist.
  let baseline = null;
  try {
    const cal = await ctx.probe(CALIBRATION_PATH());
    if (cal && cal.status === 200) {
      baseline = { fp: fingerprint(cal.body), len: (cal.body || '').length };
    }
  } catch {
    /* Calibration is best-effort; without it we simply rely on the signatures. */
  }

  const hits = [];
  const softHits = [];

  for (const probe of PROBES) {
    let res;
    try {
      res = await ctx.probe(probe.path);
    } catch {
      continue;
    }
    if (!res || res.status !== 200) continue;
    const body = res.body || '';
    if (!body) continue;

    // A catch-all origin returning its usual shell is not a finding.
    if (baseline && fingerprint(body) === baseline.fp) continue;

    if (probe.deny && probe.deny.test(body.slice(0, 512))) continue;

    if (probe.sig.test(body)) {
      hits.push({ ...probe, snippet: redact(body) });
    } else if (baseline && Math.abs(body.length - baseline.len) > baseline.len * 0.5) {
      // 200 + a body clearly unlike the catch-all shell, but no signature match.
      // Worth a look, never a hard finding.
      softHits.push(probe);
    }
  }

  if (hits.length) {
    const details = hits.map((h) => `${h.path} → ${h.label} served with HTTP 200.\n    Signature matched. First bytes: ${h.snippet}`);
    if (baseline) details.push('Calibration: this origin returns 200 for non-existent paths, so every finding above required a content-signature match.');
    if (softHits.length) details.push(`Unverified 200 responses worth a manual look: ${softHits.map((s) => s.path).join(', ')}`);
    return result(def, 'fail',
      `${hits.length} sensitive file(s) publicly readable: ${hits.map((h) => h.path).join(', ')}.`,
      details);
  }

  if (softHits.length) {
    return result(def, 'warn',
      `${softHits.length} path(s) returned 200 without matching a known signature.`,
      [`Paths: ${softHits.map((s) => s.path).join(', ')}`,
       'Probably a catch-all route rather than a real exposure — confirm by hand before reporting.']);
  }

  return result(def, 'pass',
    `None of the ${PROBES.length} probed paths are exposed.`,
    [`Probed: ${PROBES.map((p) => p.path).join(', ')}`,
     baseline ? 'Note: this origin returns 200 for unknown paths, so signature matching was required.' : '']);
}

/** Show enough to prove the finding, never enough to be a secret in a screenshot. */
function redact(body) {
  const first = String(body).slice(0, 120).replace(/\s+/g, ' ');
  return first.replace(/(=|:)\s*\S{6,}/g, '$1 [redacted]');
}
