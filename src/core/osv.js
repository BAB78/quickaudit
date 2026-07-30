/**
 * OSV.dev client.
 *
 * Two calls: querybatch tells us which name@version pairs have vulns (IDs only), then we
 * fetch details for the hits. A bundled CVE list would be stale the week we shipped it.
 */

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MODERATE: 2, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

/** Cache interface the caller supplies (chrome.storage.local in the extension, Map in Node). */
const noopCache = { get: async () => undefined, set: async () => {} };

/**
 * @param {Library[]} libraries
 * @param {{fetch?: Function, cache?: {get:Function,set:Function}, maxDetails?: number, signal?: AbortSignal}} opts
 * @returns {Promise<{ok: boolean, error?: string, findings: Object[]}>}
 */
export async function lookupVulnerabilities(libraries, opts = {}) {
  const doFetch = opts.fetch || globalThis.fetch;
  const cache = opts.cache || noopCache;
  const maxDetails = opts.maxDetails ?? 6;
  if (!libraries.length) return { ok: true, findings: [] };

  const findings = [];
  const toQuery = [];

  for (const lib of libraries) {
    const cached = await cache.get(`${lib.name}@${lib.version}`);
    if (cached) {
      if (cached.vulns.length) findings.push({ ...lib, vulns: cached.vulns, cached: true });
    } else {
      toQuery.push(lib);
    }
  }

  if (toQuery.length) {
    let batch;
    try {
      const res = await doFetch(OSV_BATCH, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        signal: opts.signal,
        body: JSON.stringify({
          queries: toQuery.map((l) => ({
            package: { name: l.name, ecosystem: 'npm' },
            version: l.version,
          })),
        }),
      });
      if (!res.ok) return { ok: false, error: `OSV returned HTTP ${res.status}`, findings };
      batch = await res.json();
    } catch (e) {
      // Offline or blocked: report SKIP upstream rather than inventing a verdict.
      return { ok: false, error: `OSV unreachable: ${e.message}`, findings };
    }

    const results = batch.results || [];
    for (let i = 0; i < toQuery.length; i++) {
      const lib = toQuery[i];
      const ids = (results[i]?.vulns || []).map((v) => v.id);
      if (!ids.length) {
        await cache.set(`${lib.name}@${lib.version}`, { vulns: [] });
        continue;
      }
      const vulns = await fetchDetails(ids.slice(0, maxDetails), doFetch, opts.signal);
      await cache.set(`${lib.name}@${lib.version}`, { vulns });
      // Note when we truncated, so the UI can say "+N more" honestly.
      findings.push({ ...lib, vulns, totalVulns: ids.length });
    }
  }

  findings.sort((a, b) => worstRank(b.vulns) - worstRank(a.vulns));
  return { ok: true, findings };
}

async function fetchDetails(ids, doFetch, signal) {
  const out = await Promise.all(ids.map(async (id) => {
    try {
      const res = await doFetch(OSV_VULN + encodeURIComponent(id), { signal });
      if (!res.ok) return { id, severity: 'UNKNOWN', summary: '', cves: [] };
      const v = await res.json();
      return {
        id: v.id,
        severity: (v.database_specific?.severity || cvssToSeverity(v.severity) || 'UNKNOWN').toUpperCase(),
        summary: (v.summary || v.details || '').split('\n')[0].slice(0, 200),
        cves: (v.aliases || []).filter((a) => a.startsWith('CVE-')),
        fixed: firstFixedVersion(v),
      };
    } catch {
      return { id, severity: 'UNKNOWN', summary: '', cves: [] };
    }
  }));
  return out.sort((a, b) => rankOf(b.severity) - rankOf(a.severity));
}

/** Pull the first `fixed` event out of the npm affected ranges, if OSV gives us one. */
function firstFixedVersion(vuln) {
  for (const aff of vuln.affected || []) {
    if (aff.package?.ecosystem !== 'npm') continue;
    for (const range of aff.ranges || []) {
      for (const ev of range.events || []) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return '';
}

function cvssToSeverity(severityArr) {
  const entry = (severityArr || []).find((s) => String(s.type).startsWith('CVSS'));
  if (!entry) return null;
  // Fall back to the qualitative band from the vector's own base metrics is overkill here;
  // OSV nearly always supplies database_specific.severity for GHSA records.
  return /\/C:H/.test(entry.score) ? 'HIGH' : 'MODERATE';
}

export function rankOf(sev) {
  return SEVERITY_RANK[String(sev).toUpperCase()] ?? 0;
}

export function worstRank(vulns) {
  return (vulns || []).reduce((m, v) => Math.max(m, rankOf(v.severity)), 0);
}

/** A cache backed by WebExtension storage.local with a TTL. Engine-agnostic. */
export function extensionStorageCache(storage, ttlMs = 6 * 60 * 60 * 1000) {
  return {
    async get(key) {
      const k = `osv:${key}`;
      const bag = await storage.get(k);
      const entry = bag[k];
      if (!entry || Date.now() - entry.t > ttlMs) return undefined;
      return entry.v;
    },
    async set(key, value) {
      await storage.set({ [`osv:${key}`]: { t: Date.now(), v: value } });
    },
  };
}

/** In-memory cache for Node/tests. */
export function memoryCache() {
  const m = new Map();
  return { async get(k) { return m.get(k); }, async set(k, v) { m.set(k, v); } };
}
