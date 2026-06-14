/**
 * kiou-usi-proxy: WS ⇄ USI engine bridge.
 *
 * Architecture:
 *
 *   [YaneuraOu WASM (Mobility, cfworkers)]
 *               ↑↓ postMessage / addMessageListener
 *      [engine.ts]   — engine wrapper. owns setoption, position→go,
 *                      caps (DepthLimit / NodesLimit / byoyomi).
 *               ↑↓ engine.feed() / engine.onLine()
 *      [socket.ts]   — WS leg. forwards tweak ↔ engine, filters
 *                      engine-internal chatter, writes JSONL game log.
 *               ↑↓ ws://device:port
 *   [tweak]    — pure USI ↔ Kiou translator. sends `position sfen`,
 *                consumes `usiok` / `readyok` / `bestmove`. never `go`.
 *
 * This file does only env-knob parsing and wiring — wakes engine.ts,
 * hands it to socket.ts, waits for one of them to drop.
 *
 * Run:
 *     cd packages/kiou-usi-proxy && bun run dev    # --watch
 *
 * Environment knobs:
 *     KIOU_DEVICE          device IP (default 192.168.0.49)
 *     KIOU_PORT            tweak ws port (default 9527)
 *     KIOU_THREADS         engine threads (default 1 — cfworkers is single-context)
 *     KIOU_USI_HASH_MB     USI_Hash MB (default 32 — cfworkers heap cap)
 *     KIOU_DEPTH_LIMIT     DepthLimit setoption (default 16)
 *     KIOU_NODES_LIMIT     NodesLimit setoption (default 10000000)
 *     KIOU_BYOYOMI_MS      go byoyomi ms per move (default 1000)
 *     KIOU_LOG_FILE        JSONL game log path (default game-log.jsonl, "off" disables)
 *     KIOU_BRIDGE_LOG      Flat trace log path (default bridge.log, "off" disables)
 */

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { exit } from "node:process";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));

// log.ts checks KIOU_BRIDGE_LOG at module-load time; default to a file
// next to the package so unconfigured runs still leave a trace.
// Has to happen BEFORE the first import of engine/socket/log.
if (process.env["KIOU_BRIDGE_LOG"] === undefined) {
  process.env["KIOU_BRIDGE_LOG"] = resolve(__dirname, "../bridge.log");
}

const { startEngine } = await import("./engine.js");
const { connectTweak } = await import("./socket.js");
const { logErr } = await import("./log.js");

function num(env: string, fallback: number): number {
  const v = process.env[env];
  return v === undefined || v === "" ? fallback : Number(v);
}

async function main(): Promise<number> {
  // log.ts is loaded eagerly (it touches the file at module load), so
  // we have to plant a sane default into the environment BEFORE its
  // first import resolves. The wiring below imports it transitively
  // via engine.ts / socket.ts, hence the early assignment.
  if (process.env["KIOU_BRIDGE_LOG"] === undefined) {
    process.env["KIOU_BRIDGE_LOG"] = resolve(__dirname, "../bridge.log");
  }

  const device = process.env["KIOU_DEVICE"] ?? "192.168.0.49";
  const port = num("KIOU_PORT", 9527);
  const threads = num("KIOU_THREADS", 1);
  const usiHashMb = num("KIOU_USI_HASH_MB", 32);
  const depthLimit = num("KIOU_DEPTH_LIMIT", 16);
  const nodesLimit = num("KIOU_NODES_LIMIT", 10_000_000);
  const byoyomiMs = num("KIOU_BYOYOMI_MS", 1000);
  const logFile =
    process.env["KIOU_LOG_FILE"] ??
    resolve(__dirname, "../game-log.jsonl");

  // Resolve the wasm bundle path through the npm subpath export.
  // The mobility cfworkers variant ships weights embedded, so no
  // separate nn.bin needs locating.
  const require = createRequire(import.meta.url);
  const wasmPath = require.resolve(
    "@ultemica/yaneuraou-wasm-mobility-cfworkers/wasm",
  );

  const engine = await startEngine({
    wasmPath,
    threads,
    usiHashMb,
    depthLimit,
    nodesLimit,
    byoyomiMs,
  });

  const socket = connectTweak({ device, port, logFile }, engine);

  const reason = await socket.done;
  logErr(`bridge winding down: ${reason}`);
  socket.close();
  await engine.dispose();
  return 0;
}

main().then(
  (code) => exit(code),
  (err) => {
    logErr(`unhandled: ${(err as Error).stack ?? err}`);
    exit(99);
  },
);
