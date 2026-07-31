#!/usr/bin/env node
/**
 * Draw the QuickAudit icon (shield + check) at every size the store needs, with no image
 * dependencies — a tiny rasteriser plus zlib is enough for a flat two-colour glyph.
 */
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';

const OUT = new URL('../icons/', import.meta.url);
mkdirSync(OUT, { recursive: true });

const BLUE = [11, 87, 208];
const WHITE = [255, 255, 255];

/** Shield outline as a function of normalised coordinates, so it scales cleanly. */
function inShield(x, y) {
  // x,y in [0,1]. Shield: rounded top, tapering to a point at the bottom.
  const cx = 0.5;
  const top = 0.10, bottom = 0.92;
  if (y < top || y > bottom) return false;
  const t = (y - top) / (bottom - top);
  // Half-width shrinks from 0.40 to 0 following a curve that stays wide then tapers fast.
  const halfW = 0.40 * Math.sqrt(Math.max(0, 1 - Math.pow(Math.max(0, t - 0.45) / 0.55, 2)));
  if (t < 0.08) {
    // Round the shoulders slightly.
    const r = (0.08 - t) / 0.08;
    return Math.abs(x - cx) <= halfW * (1 - 0.35 * r * r);
  }
  return Math.abs(x - cx) <= halfW;
}

/** Checkmark: two thick strokes. */
function inCheck(x, y) {
  const seg = (ax, ay, bx, by, w) => {
    const dx = bx - ax, dy = by - ay;
    const len2 = dx * dx + dy * dy;
    let t = ((x - ax) * dx + (y - ay) * dy) / len2;
    t = Math.max(0, Math.min(1, t));
    const px = ax + t * dx, py = ay + t * dy;
    return Math.hypot(x - px, y - py) <= w;
  };
  return seg(0.34, 0.50, 0.45, 0.62, 0.055) || seg(0.45, 0.62, 0.68, 0.37, 0.055);
}

function render(size) {
  const px = new Uint8Array(size * size * 4);
  const SS = 3; // supersample for smooth edges at 16px
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let shield = 0, check = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const u = (x + (sx + 0.5) / SS) / size;
          const v = (y + (sy + 0.5) / SS) / size;
          if (inShield(u, v)) {
            shield++;
            if (inCheck(u, v)) check++;
          }
        }
      }
      const n = SS * SS;
      const a = shield / n;
      const c = check / n;
      const i = (y * size + x) * 4;
      // Composite: white check over blue shield, both masked by the shield alpha.
      for (let k = 0; k < 3; k++) {
        px[i + k] = Math.round(BLUE[k] * (1 - c / Math.max(a, 1e-6)) + WHITE[k] * (c / Math.max(a, 1e-6)));
      }
      px[i + 3] = Math.round(a * 255);
    }
  }
  return px;
}

function png(width, height, rgba) {
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    Buffer.from(rgba.buffer, y * stride, stride).copy(raw, y * (stride + 1) + 1);
  }
  const chunks = [
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', (() => {
      const b = Buffer.alloc(13);
      b.writeUInt32BE(width, 0); b.writeUInt32BE(height, 4);
      b[8] = 8; b[9] = 6; b[10] = 0; b[11] = 0; b[12] = 0;
      return b;
    })()),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ];
  return Buffer.concat(chunks);
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body) >>> 0);
  return Buffer.concat([len, body, crc]);
}

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = ~0;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return ~c;
}

for (const size of [16, 32, 48, 128]) {
  const buf = png(size, size, render(size));
  writeFileSync(new URL(`icon${size}.png`, OUT), buf);
  console.log(`icons/icon${size}.png  ${buf.length} bytes  sha256:${createHash('sha256').update(buf).digest('hex').slice(0, 12)}`);
}

// ── store icon ────────────────────────────────────────────────────────────────
/**
 * The Chrome Web Store renders the icon on a light card, so a transparent glyph looks
 * unfinished there. This variant is opaque: white shield on the brand blue, with padding
 * so it reads at small sizes in the store grid.
 */
function renderStore(size) {
  const px = new Uint8Array(size * size * 4);
  const SS = 3;
  const PAD = 0.12; // shrink the glyph so it doesn't touch the tile edge
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let shield = 0, check = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const u = ((x + (sx + 0.5) / SS) / size - PAD) / (1 - 2 * PAD);
          const v = ((y + (sy + 0.5) / SS) / size - PAD) / (1 - 2 * PAD);
          if (u < 0 || u > 1 || v < 0 || v > 1) continue;
          if (inShield(u, v)) { shield++; if (inCheck(u, v)) check++; }
        }
      }
      const n = SS * SS;
      const a = shield / n;
      const c = check / n;
      const i = (y * size + x) * 4;
      // Composite over an opaque near-white tile: blue shield, white tick.
      const bg = [247, 248, 250];
      for (let k = 0; k < 3; k++) {
        const glyph = BLUE[k] * (1 - c / Math.max(a, 1e-6)) + WHITE[k] * (c / Math.max(a, 1e-6));
        px[i + k] = Math.round(bg[k] * (1 - a) + glyph * a);
      }
      px[i + 3] = 255; // fully opaque
    }
  }
  return px;
}

mkdirSync(new URL('../store-assets/', import.meta.url), { recursive: true });
const storeBuf = png(128, 128, renderStore(128));
writeFileSync(new URL('../store-assets/store-icon-128.png', import.meta.url), storeBuf);
console.log(`store-assets/store-icon-128.png  ${storeBuf.length} bytes  (opaque)`);
