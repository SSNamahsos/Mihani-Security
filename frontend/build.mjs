// Minimal build script for the MihaniSecurity frontend.
//
// We don't use a JS bundler — the frontend is a single self-contained HTML
// file with inlined CSS and JS (matches the "style to be.html" reference).
// This script just copies index.html → dist/index.html and stashes any
// extra assets under dist/.
//
// Usage:
//   node build.mjs         (production)
//   node build.mjs --dev   (no minification; useful for debugging)
import { promises as fs } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcDir = __dirname;
const distDir = join(__dirname, 'dist');
const isDev = process.argv.includes('--dev');

async function ensureDir(p) { await fs.mkdir(p, { recursive: true }); }

async function copyRecursive(src, dst) {
  await ensureDir(dst);
  const entries = await fs.readdir(src, { withFileTypes: true });
  for (const e of entries) {
    const s = join(src, e.name);
    const d = join(dst, e.name);
    if (e.isDirectory()) await copyRecursive(s, d);
    else await fs.copyFile(s, d);
  }
}

async function build() {
  await ensureDir(distDir);
  // Copy HTML files
  for (const f of ['index.html']) {
    await fs.copyFile(join(srcDir, f), join(distDir, f));
  }
  // Copy any extra asset folders (e.g. icons, fonts)
  for (const sub of ['assets']) {
    try {
      await copyRecursive(join(srcDir, sub), join(distDir, sub));
    } catch (e) {
      // folder optional
    }
  }
  // In dev, leave a console marker so the Wails runtime can show a hint.
  if (isDev) {
    console.log('MihaniSecurity frontend: dev build');
  } else {
    console.log('MihaniSecurity frontend: production build');
  }
}

build().catch((e) => {
  console.error(e);
  process.exit(1);
});
