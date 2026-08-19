#!/usr/bin/env node
/**
 * Build browser-specific packages from one shared source tree.
 *
 *   node tools/build.mjs            all targets
 *   node tools/build.mjs firefox    just one
 *
 * The source in src/ is identical for every browser — all engine differences live in the
 * manifest, plus feature detection in src/ext/browser-api.js. This script only assembles
 * manifests and zips; it never rewrites code, so what you test is what ships.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, cpSync, existsSync, readFileSync, writeFileSync, statSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const base = JSON.parse(readFileSync(path.join(root, 'manifest.base.json'), 'utf8'));

export const TARGETS = {
  /**
   * Chrome, Edge, Opera, Brave, Vivaldi — one identical package.
   *
   * Deliberately not split per store. Edge and Opera are Chromium and accept this zip
   * unmodified, so separate targets would emit byte-identical files and invite the two to
   * drift apart for no reason.
   */
  chrome: {
    label: 'Chromium (Chrome, Edge, Opera, Brave, Vivaldi)',
    stores: ['Chrome Web Store', 'Microsoft Edge Add-ons', 'Opera Add-ons'],
    manifest: {
      minimum_chrome_version: '116',
      background: { service_worker: 'src/ext/background.js', type: 'module' },
      // Chromium is the only engine with a downloads API we rely on; Safari falls back.
      permissions: [...base.permissions, 'downloads'],
    },
  },
  /**
   * Firefox does not implement background.service_worker at all — MV3 extensions use a
   * non-persistent event page. ES modules in background scripts need Firefox 128+.
   */
  firefox: {
    label: 'Firefox',
    stores: ['addons.mozilla.org'],
    manifest: {
      background: { scripts: ['src/ext/background.js'], type: 'module' },
      permissions: [...base.permissions, 'downloads'],
      browser_specific_settings: {
        gecko: {
          id: 'quickaudit@babstudios.dev',
          strict_min_version: '128.0',
          data_collection_permissions: { required: ['none'] },
        },
      },
    },
  },
  /**
   * Safari supports MV3 service workers but has no downloads API — the popup falls back to
   * an <a download> click. Packaging requires macOS + Xcode; see BROWSERS.md.
   */
  safari: {
    label: 'Safari (macOS/iOS)',
    stores: ['Apple App Store (via Xcode wrapper)'],
    manifest: {
      background: { service_worker: 'src/ext/background.js', type: 'module' },
      browser_specific_settings: { safari: { strict_min_version: '17.0' } },
    },
  },
};

const INCLUDE = ['icons', 'src', 'LICENSE', 'PRIVACY.md'];

export function build(target) {
  const spec = TARGETS[target];
  if (!spec) throw new Error(`unknown target "${target}" (have: ${Object.keys(TARGETS).join(', ')})`);

  const stage = path.join(root, 'build', target);
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });

  for (const item of INCLUDE) {
    const from = path.join(root, item);
    if (existsSync(from)) cpSync(from, path.join(stage, item), { recursive: true });
  }

  const manifest = { ...base, ...spec.manifest };
  writeFileSync(path.join(stage, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  const staged = walk(stage);
  assertNoSecrets(stage, staged);

  const zipPath = path.join(root, 'build', `quickaudit-${manifest.version}-${target}.zip`);
  rmSync(zipPath, { force: true });
  execFileSync('powershell', ['-NoProfile', '-Command',
    `Compress-Archive -Path '${stage}\\*' -DestinationPath '${zipPath}' -Force`], { stdio: 'pipe' });

  return { target, spec, manifest, zipPath, stage, files: staged.length, size: statSync(zipPath).size };
}

/** A published extension must never carry the licence signing key. */
function assertNoSecrets(stage, staged) {
  for (const f of staged) {
    if (/[\\/]\.keys[\\/]/.test(f) || /private\.pem$/.test(f)) {
      throw new Error(`REFUSING TO BUILD: ${path.relative(stage, f)} would be published.`);
    }
    if (/\.(js|json|html)$/.test(f) && /BEGIN (EC )?PRIVATE KEY/.test(readFileSync(f, 'utf8'))) {
      throw new Error(`REFUSING TO BUILD: a private key is embedded in ${path.relative(stage, f)}.`);
    }
  }
}

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

if (process.argv[1]?.endsWith('build.mjs')) {
  const only = process.argv[2];
  const targets = only ? [only] : Object.keys(TARGETS);
  for (const t of targets) {
    const r = build(t);
    console.log(`${r.target.padEnd(8)} ${(r.size / 1024).toFixed(1).padStart(6)} KB  ${String(r.files).padStart(2)} files  →  ${path.relative(root, r.zipPath)}`);
    console.log(`         ${r.spec.label}`);
    console.log(`         stores: ${r.spec.stores.join(', ')}`);
  }
  console.log('\nLoad unpacked for development from build/<target>/');
  console.log('Nothing uploaded — every store submission is a manual, confirmed step.');
}
