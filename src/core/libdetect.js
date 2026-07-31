/**
 * JS library detection.
 *
 * Three sources, in descending confidence:
 *   global  — read off the live page object (jQuery.fn.jquery). Can't be wrong.
 *   url     — parsed from the script URL (jquery-3.4.1.min.js, /npm/lodash@4.17.11/).
 *   banner  — the /*! jQuery v3.4.1 comment at the top of a bundle.
 *
 * Names map to npm package names because that is the ecosystem OSV indexes these in.
 */

/**
 * Globals the injected collector reads, expressed as **property paths rather than code**.
 *
 * These were once expression strings evaluated with `new Function()`. That is dynamic code
 * execution inside a security extension — the thing store reviewers are most likely to stop
 * on, and entirely avoidable: walking a path array does the same job with no evaluator.
 *
 *   path     properties to walk from the page's global object
 *   excludes if this path resolves, skip (disambiguates libraries sharing a global)
 *   requires this path must resolve for the probe to count
 *   format   post-processing for libraries that don't expose a plain semver string
 */
export const GLOBAL_PROBES = [
  { pkg: 'jquery', path: ['jQuery', 'fn', 'jquery'] },
  // jQuery UI hangs off jQuery rather than the global, and ships its own advisories.
  { pkg: 'jquery-ui', path: ['jQuery', 'ui', 'version'] },
  { pkg: 'angular', path: ['angular', 'version', 'full'] },
  { pkg: 'react', path: ['React', 'version'] },
  { pkg: 'react-dom', path: ['ReactDOM', 'version'] },
  { pkg: 'vue', path: ['Vue', 'version'] },
  // lodash and underscore both claim `_`; only lodash has chunk().
  { pkg: 'lodash', path: ['_', 'VERSION'], requires: ['_', 'chunk'] },
  { pkg: 'underscore', path: ['_', 'VERSION'], excludes: ['_', 'chunk'] },
  { pkg: 'moment', path: ['moment', 'version'] },
  { pkg: 'bootstrap', path: ['bootstrap', 'Tooltip', 'VERSION'] },
  { pkg: 'd3', path: ['d3', 'version'] },
  { pkg: 'handlebars', path: ['Handlebars', 'VERSION'] },
  { pkg: 'dompurify', path: ['DOMPurify', 'version'] },
  { pkg: 'axios', path: ['axios', 'VERSION'] },
  { pkg: 'core-js', path: ['core', 'version'] },
  { pkg: 'backbone', path: ['Backbone', 'VERSION'] },
  { pkg: 'knockout', path: ['ko', 'version'] },
  { pkg: 'ember-source', path: ['Ember', 'VERSION'] },
  { pkg: 'video.js', path: ['videojs', 'VERSION'] },
  { pkg: 'chart.js', path: ['Chart', 'version'] },
  // three.js exposes an integer revision, not a semver.
  { pkg: 'three', path: ['THREE', 'REVISION'], format: 'revision' },
  { pkg: 'swiper', path: ['Swiper', 'version'] },
  { pkg: 'marked', path: ['marked', 'version'] },
];

const SEMVERISH = '(\\d+\\.\\d+(?:\\.\\d+)?(?:-[0-9A-Za-z.-]+)?)';

/**
 * Filename shapes we can read a version out of. `alias` maps a CDN/file name to its npm name.
 */
const URL_PATTERNS = [
  // jsDelivr: /npm/lodash@4.17.11/lodash.min.js
  { re: new RegExp(`/npm/(@?[a-z0-9._-]+(?:/[a-z0-9._-]+)?)@${SEMVERISH}`, 'i'), nameFrom: 1, verFrom: 2 },
  // unpkg / esm.sh put the package at the root of the path: /vue@2.6.10/dist/vue.js
  { re: new RegExp(`^/(@?[a-z0-9._-]+(?:/[a-z0-9._-]+)?)@${SEMVERISH}`, 'i'), nameFrom: 1, verFrom: 2 },
  // cdnjs: /ajax/libs/jquery/3.4.1/jquery.min.js
  { re: new RegExp(`/ajax/libs/([a-z0-9._-]+)/${SEMVERISH}/`, 'i'), nameFrom: 1, verFrom: 2 },
  // Plain filename: jquery-3.4.1.min.js, angular.1.7.9.js, bootstrap-4.3.1.js
  { re: new RegExp(`/([a-z0-9_.]+?)[-.@_]v?${SEMVERISH}(?:\\.min)?\\.js`, 'i'), nameFrom: 1, verFrom: 2 },
  // Versioned directory: /jquery/3.4.1/jquery.min.js
  { re: new RegExp(`/([a-z0-9_.-]+)/${SEMVERISH}/[a-z0-9_.-]+\\.js`, 'i'), nameFrom: 1, verFrom: 2 },
];

/**
 * CDN/file names that differ from the npm package name OSV indexes.
 * Note the `.js` suffixes are only stripped where the npm package genuinely lacks it —
 * `chart.js` and `video.js` really are published under those names.
 */
const ALIASES = {
  'angular.js': 'angular',
  'vue.js': 'vue',
  'react.js': 'react',
  'd3.js': 'd3',
  'moment.js': 'moment',
  'lodash.js': 'lodash',
  'underscore.js': 'underscore',
  'backbone.js': 'backbone',
  'ember.js': 'ember-source',
  'handlebars.js': 'handlebars',
  'knockout.js': 'knockout',
  'jquery.js': 'jquery',
  'bootstrap.js': 'bootstrap',
  'dompurify.js': 'dompurify',
  'jquery.min': 'jquery',
  'jquery-ui': 'jquery-ui',
  'jqueryui': 'jquery-ui',
  'angular.min': 'angular',
  'angularjs': 'angular',
  'angular-core': '@angular/core',
  'bootstrap.min': 'bootstrap',
  'lodash.min': 'lodash',
  'underscore.min': 'underscore',
  'moment.min': 'moment',
  'vue.min': 'vue',
  'react.production': 'react',
  'react.development': 'react',
  'react-dom.production': 'react-dom',
  'dompurify': 'dompurify',
  'purify': 'dompurify',
  'handlebars.runtime': 'handlebars',
  'ckeditor': 'ckeditor4',
  'tinymce.min': 'tinymce',
  'axios.min': 'axios',
  'chart': 'chart.js',
  'chart.min': 'chart.js',
  'video': 'video.js',
  'videojs': 'video.js',
  'prototype': 'prototype',
  'mootools': 'mootools',
  'ember': 'ember-source',
  'ember.min': 'ember-source',
  'knockout-min': 'knockout',
  'plotly': 'plotly.js',
  'plotly-latest': 'plotly.js',
};

/**
 * Names too generic to trust from a URL alone — `/app/1.2.3/main.js` is not a library.
 * Without this the URL matcher turns every versioned asset path into a bogus OSV query.
 */
const URL_NAME_DENYLIST = new Set([
  'app', 'main', 'index', 'bundle', 'vendor', 'runtime', 'polyfill', 'polyfills', 'common',
  'chunk', 'script', 'scripts', 'client', 'server', 'assets', 'static', 'dist', 'build',
  'js', 'lib', 'libs', 'min', 'core', 'utils', 'util', 'config', 'analytics', 'gtm', 'ga',
  'widget', 'embed', 'sdk', 'api', 'v1', 'v2', 'v3', 'cdn', 'files', 'page', 'site', 'theme',
]);

function cleanName(raw) {
  let n = String(raw).toLowerCase().replace(/\.(min|slim|production|development|umd|esm|cjs)$/g, '');
  n = ALIASES[n] || n;
  return n;
}

function normalizeVersion(v) {
  const m = String(v).match(/^\d+\.\d+(?:\.\d+)?/);
  if (!m) return null;
  // OSV wants a full semver; `3.4` alone won't range-match reliably.
  const parts = m[0].split('.');
  while (parts.length < 3) parts.push('0');
  return parts.join('.');
}

/** Detect a library from a script URL. Returns null when nothing trustworthy is found. */
export function detectFromUrl(url) {
  let path;
  try {
    path = new URL(url, 'https://x.invalid').pathname;
  } catch {
    path = String(url);
  }
  for (const p of URL_PATTERNS) {
    const m = path.match(p.re);
    if (!m) continue;
    const name = cleanName(m[p.nameFrom]);
    const version = normalizeVersion(m[p.verFrom]);
    if (!version) continue;
    if (URL_NAME_DENYLIST.has(name)) continue;
    if (name.length < 2) continue;
    // A "version" that is really a date or a build hash (2024.10.1) is not a library version.
    if (/^20\d\d\./.test(version)) continue;
    return { name, version, source: 'url', evidence: path };
  }
  return null;
}

const BANNER_PATTERNS = [
  /\/\*!?\s*(?:jQuery(?: JavaScript Library)?)\s+v?(\d+\.\d+\.\d+)/i,
  /\/\*!?\s*(Bootstrap)\s+v(\d+\.\d+\.\d+)/i,
  /\/\*!?\s*(Moment\.js)\s+v?(\d+\.\d+\.\d+)/i,
  /\/\*!?\s*(AngularJS)\s+v(\d+\.\d+\.\d+)/i,
  /\/\*!?\s*(lodash)\s+(?:v|<)?(\d+\.\d+\.\d+)/i,
  /\/\*!?\s*(DOMPurify)\s+(\d+\.\d+\.\d+)/i,
  /\/\*!?\s*(Handlebars)\s+v?(\d+\.\d+\.\d+)/i,
];

const BANNER_NAMES = {
  'jquery': 'jquery', 'bootstrap': 'bootstrap', 'moment.js': 'moment',
  'angularjs': 'angular', 'lodash': 'lodash', 'dompurify': 'dompurify',
  'handlebars': 'handlebars',
};

/** Detect from a source-comment banner in the first few KB of a script. */
export function detectFromBanner(source) {
  const head = String(source).slice(0, 2048);
  for (const re of BANNER_PATTERNS) {
    const m = head.match(re);
    if (!m) continue;
    // The jQuery pattern has no capturing name group; everything else does.
    const isJquery = re.source.includes('jQuery');
    const name = isJquery ? 'jquery' : BANNER_NAMES[String(m[1]).toLowerCase()];
    const version = normalizeVersion(isJquery ? m[1] : m[2]);
    if (name && version) return { name, version, source: 'banner', evidence: m[0].trim() };
  }
  return null;
}

/**
 * Merge detections, keeping the highest-confidence version per package.
 * If a global says jQuery 3.6.0, a URL saying 1.12.4 is a second copy worth keeping —
 * but only if the versions genuinely differ.
 */
export function mergeLibraries(list) {
  const byKey = new Map();
  const rank = { global: 3, banner: 2, url: 1 };
  for (const lib of list) {
    if (!lib || !lib.name || !lib.version) continue;
    const key = `${lib.name}@${lib.version}`;
    const prev = byKey.get(key);
    if (!prev || rank[lib.source] > rank[prev.source]) byKey.set(key, lib);
  }
  return [...byKey.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export { normalizeVersion, cleanName };
