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

/** Globals the content script reads. Kept as strings so the collector can eval them safely. */
export const GLOBAL_PROBES = [
  { pkg: 'jquery', expr: 'window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery' },
  // jQuery UI hangs off jQuery rather than window, and ships its own advisories.
  { pkg: 'jquery-ui', expr: 'window.jQuery && window.jQuery.ui && window.jQuery.ui.version' },
  { pkg: 'angular', expr: 'window.angular && window.angular.version && window.angular.version.full' },
  { pkg: 'react', expr: 'window.React && window.React.version' },
  { pkg: 'react-dom', expr: 'window.ReactDOM && window.ReactDOM.version' },
  { pkg: 'vue', expr: 'window.Vue && window.Vue.version' },
  { pkg: 'lodash', expr: 'window._ && window._.VERSION' },
  { pkg: 'underscore', expr: 'window._ && !window._.chunk && window._.VERSION' },
  { pkg: 'moment', expr: 'window.moment && window.moment.version' },
  { pkg: 'bootstrap', expr: 'window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION' },
  { pkg: 'd3', expr: 'window.d3 && window.d3.version' },
  { pkg: 'handlebars', expr: 'window.Handlebars && window.Handlebars.VERSION' },
  { pkg: 'dompurify', expr: 'window.DOMPurify && window.DOMPurify.version' },
  { pkg: 'axios', expr: 'window.axios && window.axios.VERSION' },
  { pkg: 'core-js', expr: 'window.core && window.core.version' },
  { pkg: 'backbone', expr: 'window.Backbone && window.Backbone.VERSION' },
  { pkg: 'knockout', expr: 'window.ko && window.ko.version' },
  { pkg: 'ember-source', expr: 'window.Ember && window.Ember.VERSION' },
  { pkg: 'video.js', expr: 'window.videojs && window.videojs.VERSION' },
  { pkg: 'chart.js', expr: 'window.Chart && (window.Chart.version || (window.Chart.defaults && window.Chart.defaults.global && "2.x"))' },
  { pkg: 'select2', expr: 'window.jQuery && window.jQuery.fn && window.jQuery.fn.select2 && window.jQuery.fn.select2.amd && "detected"' },
  { pkg: 'three', expr: 'window.THREE && window.THREE.REVISION && ("0." + window.THREE.REVISION + ".0")' },
  { pkg: 'swiper', expr: 'window.Swiper && window.Swiper.version' },
  { pkg: 'marked', expr: 'window.marked && window.marked.defaults && window.marked.version' },
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
