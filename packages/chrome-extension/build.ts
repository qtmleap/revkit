/**
 * Build script: src/ → dist/
 * Bundles inject (IIFE), background (ESM), bridge (IIFE)
 * dist/ ディレクトリに manifest.json + JS を出力し、Chrome にはそこを読み込ませる
 */

import { copyFileSync, mkdirSync, readdirSync } from "fs";
import { join } from "path";

const watching = process.argv.includes("--watch");
const root = import.meta.dir;
const outdir = join(root, "dist");

async function build() {
  mkdirSync(outdir, { recursive: true });

  const results = await Promise.all([
    // inject.ts → dist/inject.js  (IIFE, runs in page MAIN world)
    Bun.build({
      entrypoints: ["src/inject.ts"],
      outdir,
      target: "browser",
      format: "iife",
      minify: false,
      naming: "[dir]/[name].js",
    }),
    // background.ts → dist/background.js  (Service Worker / ES module)
    Bun.build({
      entrypoints: ["src/background.ts"],
      outdir,
      target: "browser",
      format: "esm",
      minify: false,
      naming: "[dir]/[name].js",
    }),
    // bridge.ts → dist/bridge.js  (IIFE, runs in ISOLATED world)
    Bun.build({
      entrypoints: ["src/bridge.ts"],
      outdir,
      target: "browser",
      format: "iife",
      minify: false,
      naming: "[dir]/[name].js",
    }),
  ]);

  // manifest.json + icons を dist/ にコピー
  copyFileSync(join(root, "manifest.json"), join(outdir, "manifest.json"));
  const iconsDir = join(root, "icons");
  const outIcons = join(outdir, "icons");
  mkdirSync(outIcons, { recursive: true });
  for (const f of readdirSync(iconsDir)) {
    if (f.endsWith(".png")) copyFileSync(join(iconsDir, f), join(outIcons, f));
  }

  for (const result of results) {
    if (!result.success) {
      for (const log of result.logs) {
        console.error(log);
      }
    } else {
      for (const out of result.outputs) {
        console.log(`Built: ${out.path} (${(out.size / 1024).toFixed(1)} KB)`);
      }
    }
  }
}

if (watching) {
  console.log("Watching for changes...");
  const watcher = Bun.file("src").watch ? null : null;
  // Bun には built-in watch がないので interval でポーリング
  let lastMtimes: Record<string, number> = {};
  async function checkChanges() {
    const glob = new Bun.Glob("src/**/*.ts");
    let changed = false;
    for await (const file of glob.scan(".")) {
      const stat = await Bun.file(file).stat?.() ?? null;
      // @ts-ignore
      const mtime = stat?.mtime?.getTime?.() ?? 0;
      if (lastMtimes[file] !== mtime) {
        lastMtimes[file] = mtime;
        changed = true;
      }
    }
    if (changed) {
      console.log(`[${new Date().toISOString()}] Change detected, rebuilding...`);
      await build();
    }
  }
  await build();
  setInterval(checkChanges, 500);
} else {
  await build();
}
