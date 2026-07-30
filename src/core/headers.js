/** Header access helpers. Everything downstream assumes lowercase keys -> array of values. */

/** Normalize any of the shapes a collector might hand us into {name: [values]}. */
export function normalizeHeaders(input) {
  const out = {};
  if (!input) return out;
  const push = (k, v) => {
    const key = String(k).toLowerCase().trim();
    if (!out[key]) out[key] = [];
    out[key].push(String(v).trim());
  };

  if (Array.isArray(input)) {
    // chrome.webRequest style: [{name, value}, ...]. Must be tested before the Headers
    // branch below — arrays have an entries() method too, and would iterate as [index, value].
    for (const h of input) push(h.name, h.value ?? h.binaryValue ?? '');
    return out;
  }
  if (typeof input.forEach === 'function' && typeof input.entries === 'function') {
    // A fetch Headers object. getSetCookie() is the only way to see multiple
    // Set-Cookie values without them being comma-joined into nonsense.
    if (typeof input.getSetCookie === 'function') {
      for (const c of input.getSetCookie()) push('set-cookie', c);
    }
    for (const [k, v] of input.entries()) {
      if (k.toLowerCase() === 'set-cookie') continue;
      push(k, v);
    }
    return out;
  }
  for (const [k, v] of Object.entries(input)) {
    if (Array.isArray(v)) v.forEach((x) => push(k, x));
    else push(k, v);
  }
  return out;
}

/** First value of a header, or '' — the common case. */
export function get(headers, name) {
  const v = headers[name.toLowerCase()];
  return v && v.length ? v[0] : '';
}

/** All values of a header. */
export function getAll(headers, name) {
  return headers[name.toLowerCase()] || [];
}

export function has(headers, name) {
  return Boolean(headers[name.toLowerCase()]?.length);
}

/** Parse `key=value; flag; k2=v2` into a lowercase-keyed map. Flags map to `true`. */
export function parseDirectiveList(value) {
  const out = {};
  for (const part of String(value).split(';')) {
    const s = part.trim();
    if (!s) continue;
    const eq = s.indexOf('=');
    if (eq === -1) out[s.toLowerCase()] = true;
    else out[s.slice(0, eq).trim().toLowerCase()] = s.slice(eq + 1).trim();
  }
  return out;
}
