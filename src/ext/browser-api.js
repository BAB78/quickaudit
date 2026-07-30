/**
 * Cross-browser WebExtension API shim.
 *
 * The important subtlety: Firefox and Safari expose a promise-based `browser.*`, and Firefox
 * *also* exposes a `chrome.*` alias that is callback-based. So `await chrome.storage.local.get()`
 * silently resolves to undefined on Firefox. Preferring `browser` when it exists is the whole
 * fix, and it must be done everywhere — which is why no other file touches the raw namespace.
 */
export const api = globalThis.browser ?? globalThis.chrome;

/** Which engine we're on. Used for capability notes, never for feature gating. */
export const engine = (() => {
  if (typeof globalThis.browser !== 'undefined' && typeof globalThis.chrome === 'undefined') return 'safari';
  if (typeof globalThis.browser !== 'undefined') return 'firefox';
  return 'chromium';
})();

/**
 * Capabilities that genuinely differ between browsers. Everything here is feature-detected
 * rather than sniffed, because the same engine differs across versions.
 */
export const can = {
  /** Safari has no downloads API; the popup falls back to an <a download> click. */
  downloads: Boolean(api?.downloads?.download),
  /** Observing real navigation headers. Absent or restricted on some Safari versions. */
  webRequest: Boolean(api?.webRequest?.onHeadersReceived),
  /** Reading page globals needs MAIN-world injection: Chrome 111+, Firefox 128+, Safari 17+. */
  mainWorld: Boolean(api?.scripting?.executeScript),
  cookies: Boolean(api?.cookies?.getAll),
};

/**
 * Firefox rejects permissions.request() outside a user-input handler, so it can never be
 * proxied through the background page. Callers must invoke this directly from a click.
 */
export function requestOrigin(originPattern) {
  return api.permissions.request({ origins: [originPattern] });
}

export function hasOrigin(originPattern) {
  return api.permissions.contains({ origins: [originPattern] });
}

/**
 * Normalise sendMessage, which resolves differently across engines.
 * Chrome MV3 and Firefox both return a promise here; Safari has historically been erratic
 * about it, so a callback path is kept as a fallback.
 */
export function sendMessage(msg) {
  try {
    const out = api.runtime.sendMessage(msg);
    if (out && typeof out.then === 'function') return out;
  } catch { /* fall through to the callback form */ }
  return new Promise((resolve, reject) => {
    api.runtime.sendMessage(msg, (res) => {
      const err = api.runtime.lastError;
      err ? reject(new Error(err.message)) : resolve(res);
    });
  });
}

/** storage.local with a guaranteed promise, whichever namespace we landed on. */
export const storage = {
  get(keys) {
    const out = api.storage.local.get(keys);
    if (out && typeof out.then === 'function') return out;
    return new Promise((resolve) => api.storage.local.get(keys, resolve));
  },
  set(obj) {
    const out = api.storage.local.set(obj);
    if (out && typeof out.then === 'function') return out;
    return new Promise((resolve) => api.storage.local.set(obj, resolve));
  },
  remove(key) {
    const out = api.storage.local.remove(key);
    if (out && typeof out.then === 'function') return out;
    return new Promise((resolve) => api.storage.local.remove(key, resolve));
  },
};

/** Open the options page, whichever key the manifest used to declare it. */
export function openOptions() {
  if (api.runtime.openOptionsPage) return api.runtime.openOptionsPage();
  return api.tabs.create({ url: api.runtime.getURL('src/ext/options.html') });
}
