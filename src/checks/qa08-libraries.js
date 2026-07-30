import { lookupVulnerabilities, rankOf, worstRank } from '../core/osv.js';
import { result } from '../core/types.js';

export const def = {
  id: 'QA-08',
  title: 'JavaScript libraries with known CVEs',
  severity: 'critical',
  active: false,
  ref: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
  fix: 'Upgrade to the fixed version listed for each advisory, or drop the library if it is unused.',
};

export async function run(ctx, opts = {}) {
  const libs = ctx.libraries || [];
  if (!libs.length) {
    return result(def, 'skip',
      'No library versions could be determined.',
      ['Bundled/minified apps often strip version markers. A clean result here is not a clean bill of health — audit your lockfile instead.']);
  }

  const inventory = libs.map((l) => `${l.name}@${l.version} (${l.source})`).join(', ');

  const { ok, error, findings } = await lookupVulnerabilities(libs, opts);
  if (!ok && !findings.length) {
    // Never invent a verdict when the database is unreachable.
    return result(def, 'skip', 'Could not reach the OSV.dev vulnerability database.',
      [error || 'Lookup failed.', `Detected: ${inventory}`],
      'Re-run when online, or check these versions manually at https://osv.dev.');
  }

  if (!findings.length) {
    return result(def, 'pass', `No known vulnerabilities in ${libs.length} detected librar${libs.length > 1 ? 'ies' : 'y'}.`,
      [`Detected: ${inventory}`, 'Source: OSV.dev, npm ecosystem.']);
  }

  const details = [];
  let worst = 0;
  for (const f of findings) {
    worst = Math.max(worst, worstRank(f.vulns));
    const cves = f.vulns.flatMap((v) => v.cves);
    const fixed = f.vulns.map((v) => v.fixed).find(Boolean);
    const extra = f.totalVulns && f.totalVulns > f.vulns.length ? ` (+${f.totalVulns - f.vulns.length} more advisories)` : '';
    details.push(
      `${f.name} ${f.version} — ${f.vulns.length} advisor${f.vulns.length > 1 ? 'ies' : 'y'}${extra}` +
      `${fixed ? `, fixed in ${fixed}` : ''}` +
      `\n    ${f.vulns.slice(0, 3).map((v) => `[${v.severity}] ${v.id}${v.cves.length ? ` (${v.cves.join(', ')})` : ''}: ${v.summary}`).join('\n    ')}`
    );
    if (cves.length > 3) details.push(`    All CVEs for ${f.name}: ${cves.join(', ')}`);
  }
  details.push(`Detected inventory: ${inventory}`);
  if (!ok) details.push(`Partial result — ${error}`);

  const label = findings.map((f) => `${f.name} ${f.version}`).join(', ');
  if (worst >= rankOf('HIGH')) {
    return result(def, 'fail', `High-severity known vulnerabilities in ${label}.`, details);
  }
  return result(def, 'warn', `Known moderate/low vulnerabilities in ${label}.`, details);
}
