import { normalizeHeaders } from '../src/core/headers.js';

/** Build a PageContext for tests without repeating twenty default fields. */
export function ctx(overrides = {}) {
  const url = overrides.url || 'https://example.com/';
  const u = new URL(url);
  return {
    url,
    origin: u.origin,
    protocol: u.protocol,
    headers: normalizeHeaders(overrides.headers || {}),
    metaCsp: overrides.metaCsp || [],
    cookies: overrides.cookies || [],
    resources: overrides.resources || [],
    libraries: overrides.libraries || [],
    activeAllowed: overrides.activeAllowed ?? false,
    probe: overrides.probe || null,
    notes: [],
  };
}

export function cookie(name, opts = {}) {
  return {
    name,
    secure: opts.secure ?? false,
    httpOnly: opts.httpOnly ?? false,
    sameSite: opts.sameSite ?? 'unspecified',
  };
}

/** A fake OSV transport so library tests never touch the network. */
export function fakeOsv(map) {
  return async (url, init) => {
    if (url.includes('querybatch')) {
      const { queries } = JSON.parse(init.body);
      return json({
        results: queries.map((q) => {
          const ids = map[`${q.package.name}@${q.version}`] || [];
          return ids.length ? { vulns: ids.map((v) => ({ id: v.id })) } : {};
        }),
      });
    }
    const id = decodeURIComponent(url.split('/v1/vulns/')[1]);
    for (const list of Object.values(map)) {
      const hit = list.find((v) => v.id === id);
      if (hit) {
        return json({
          id: hit.id,
          aliases: hit.cves || [],
          summary: hit.summary || '',
          database_specific: { severity: hit.severity },
          affected: hit.fixed
            ? [{ package: { ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: hit.fixed }] }] }]
            : [],
        });
      }
    }
    return json({}, 404);
  };
}

function json(body, status = 200) {
  return { ok: status < 400, status, json: async () => body };
}
