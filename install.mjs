#!/usr/bin/env node
// LinkShield Installer — Generates extension icons and validates setup

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import { createRequire } from 'node:module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

console.log(`
  ╔══════════════════════════════════════════════╗
  ║  LinkShield Installer                        ║
  ╚══════════════════════════════════════════════╝
`);

// Generate icons using pure binary PNG generation
generateIcons();

console.log('  [1/3] Icons generated');

// Validate server files
const serverFiles = ['server/server.mjs', 'server/analyze.mjs', 'server/data/lists.json'];
for (const f of serverFiles) {
  if (!fs.existsSync(path.join(__dirname, f))) {
    console.error(`  ERROR: Missing ${f}`);
    process.exit(1);
  }
}
console.log('  [2/3] Server files validated');

// Validate extension files
const extFiles = ['extension/manifest.json', 'extension/service-worker.js', 'extension/content.js',
  'extension/check.html', 'extension/check.js', 'extension/popup.html', 'extension/popup.js'];
for (const f of extFiles) {
  if (!fs.existsSync(path.join(__dirname, f))) {
    console.error(`  ERROR: Missing ${f}`);
    process.exit(1);
  }
}
console.log('  [3/3] Extension files validated');

console.log(`
  Setup complete! Next steps:

  1. Start the analysis server:
     cd ${path.join(__dirname, 'server')}
     node server.mjs

  2. Load the Chrome extension:
     - Open Chrome -> chrome://extensions
     - Enable "Developer mode" (top right)
     - Click "Load unpacked"
     - Select: ${path.join(__dirname, 'extension')}

  3. (Optional) Add API keys for deeper scanning:
     set GOOGLE_SAFE_BROWSING_KEY=your_key
     set VIRUSTOTAL_KEY=your_key

  You're protected!
`);

// ═══════════════════════════════════════════════════════════════
// PNG ICON GENERATOR — Pure binary, zero dependencies
// ═══════════════════════════════════════════════════════════════

function generateIcons() {
  const iconsDir = path.join(__dirname, 'extension', 'icons');
  fs.mkdirSync(iconsDir, { recursive: true });

  for (const size of [16, 48, 128]) {
    const png = createShieldPNG(size);
    fs.writeFileSync(path.join(iconsDir, `shield-${size}.png`), png);
  }
}

function createShieldPNG(size) {
  const pixels = new Uint8Array(size * size * 4);
  const cx = size / 2;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;

      // Normalized coordinates for shield shape
      const nx = (x - cx) / (size * 0.42);
      const ny = (y - size * 0.08) / (size * 0.86);

      let inside = false;
      if (ny >= 0 && ny <= 1) {
        if (ny < 0.5) {
          inside = Math.abs(nx) <= (1.0 - ny * 0.1);
        } else {
          const t = (ny - 0.5) / 0.5;
          inside = Math.abs(nx) <= 0.95 * (1 - t * t);
        }
      }

      if (inside) {
        // Indigo gradient
        const r = Math.round(99 + (79 - 99) * ny);
        const g = Math.round(102 + (70 - 102) * ny);
        const b = Math.round(241 + (229 - 241) * ny);

        // Checkmark in center
        let isCheck = false;
        const checkCy = cx + size * 0.05;
        const checkSize = size * 0.25;

        const lx = x - (cx - checkSize * 0.6);
        const ly = y - checkCy;
        if (Math.abs(lx - ly) < size * 0.08 && lx >= 0 && lx <= checkSize * 0.5) isCheck = true;

        const rx = x - (cx - checkSize * 0.1);
        const ry = -(y - (checkCy + checkSize * 0.15));
        if (Math.abs(rx - ry) < size * 0.08 && rx >= 0 && rx <= checkSize * 0.8) isCheck = true;

        pixels[idx] = isCheck ? 255 : r;
        pixels[idx + 1] = isCheck ? 255 : g;
        pixels[idx + 2] = isCheck ? 255 : b;
        pixels[idx + 3] = 255;
      }
      // else: stays 0,0,0,0 (transparent)
    }
  }

  return encodePNG(size, size, pixels);
}

function encodePNG(width, height, pixels) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  // Raw scanlines with filter byte
  const rowLen = 1 + width * 4;
  const rawData = Buffer.alloc(height * rowLen);
  for (let y = 0; y < height; y++) {
    rawData[y * rowLen] = 0; // No filter
    for (let x = 0; x < width; x++) {
      const srcIdx = (y * width + x) * 4;
      const dstIdx = y * rowLen + 1 + x * 4;
      rawData[dstIdx] = pixels[srcIdx];
      rawData[dstIdx + 1] = pixels[srcIdx + 1];
      rawData[dstIdx + 2] = pixels[srcIdx + 2];
      rawData[dstIdx + 3] = pixels[srcIdx + 3];
    }
  }

  const compressed = deflateSync(rawData);

  return Buffer.concat([
    signature,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', compressed),
    makeChunk('IEND', Buffer.alloc(0)),
  ]);
}

function makeChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuffer = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 0);
  return Buffer.concat([len, typeBuffer, data, crcBuf]);
}

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}
