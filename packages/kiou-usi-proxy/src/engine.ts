/**
 * YaneuraOu WASM (Mobility, cfworkers single-threaded) wrapper.
 *
 * Why Mobility instead of Suisho5 / KP256?
 *   - cfworkers variant has the evaluator weights embedded in the wasm
 *     binary, so no external nn.bin and no MEMFS shuffle.
 *   - Single-threaded: no Worker pool, no SharedArrayBuffer, no
 *     COOP/COEP — runs unmodified in Node.
 *   - Light enough to reach depth 16+ in ~100ms on the bridge host,
 *     which is fine for KIOU's CPU pacing.
 *   - The pthread + HalfKP_256 (Suisho5) variant is browser-only —
 *     Emscripten's worker bootstrap depends on `WorkerGlobalScope` /
 *     `self.name == "em-pthread"`, neither of which Node provides.
 *     We polyfilled both and still hit OOM in the worker pool, so the
 *     cleaner path is to use a variant that's actually built for
 *     single-context environments.
 *
 * Owns:
 *   - Loading the wasm binary
 *   - The USI line stream (postMessage / addMessageListener)
 *   - The position→go convention: when a position is queued, kick a
 *     search with the configured byoyomi
 *   - Caps (DepthLimit / NodesLimit) wired into setoption at boot
 *
 * The outside world is a single contract:
 *   - feed(line) — accept any USI line as if from a stdio engine driver
 *   - onLine(cb) — receive every USI line the engine emits
 *   - dispose() — terminate cleanly
 */

import { readFile } from "node:fs/promises";
import { log, logErr } from "./log.js";

export interface EngineConfig {
  /** Absolute path to the wasm binary (yaneuraou.wasm). */
  wasmPath: string;
  /**
   * Threads USI option. The cfworkers build is single-context but the
   * USI engine still accepts the option (clamped internally). Leave at
   * 1 for the cfworkers variant — bumping doesn't actually parallelize.
   */
  threads: number;
  /**
   * USI_Hash in MB. The cfworkers variant runs inside Emscripten's
   * 128MB heap, so anything above ~32 risks the boot-time
   * `Failed to allocate <N>MB for transposition table` exit. 16-32 is
   * the sweet spot.
   */
  usiHashMb: number;
  /** DepthLimit setoption — engine-side hard depth cap. */
  depthLimit: number;
  /** NodesLimit setoption — engine-side hard node cap. */
  nodesLimit: number;
  /** Per-position byoyomi appended after every `position sfen`. */
  byoyomiMs: number;
}

export interface Engine {
  feed(line: string): void;
  onLine(cb: (line: string) => void): void;
  dispose(): Promise<void>;
}

interface YaneuraOuInstance {
  postMessage(command: string): void;
  addMessageListener(listener: (line: string) => void): void;
  removeMessageListener(listener: (line: string) => void): void;
  terminate(): void;
}

type FactoryOpts = {
  wasmBinary?: ArrayBuffer | Uint8Array;
  print?: (line: string) => void;
  printErr?: (line: string) => void;
  locateFile?: (path: string) => string;
};
type Factory = (opts?: FactoryOpts) => Promise<YaneuraOuInstance>;

// The /engine subpath is the raw Emscripten bundle — no .d.ts ships
// with it, so we cast through `unknown` to grab the factory.
const YaneuraOuFactory = (
  (await import(
    // @ts-ignore — bundled JS, no types
    "@ultemica/yaneuraou-wasm-mobility-cfworkers/engine"
  )) as { default: unknown }
).default as Factory;

/**
 * Spin up the engine and complete `usi`/`isready` setup before returning.
 * The returned Engine starts in `usinewgame`-ready state — feed it any
 * USI line and engine output streams through onLine.
 */
export async function startEngine(cfg: EngineConfig): Promise<Engine> {
  const wasmBinary = await readFile(cfg.wasmPath);
  logErr(`engine: loading mobility wasm (${wasmBinary.length}B)`);

  const listeners: Array<(line: string) => void> = [];
  function dispatch(line: string): void {
    // Single sink for everything the engine emits — id / option / info /
    // bestmove / usiok / readyok all flow through here. Log every line
    // under [engine] so the trace shows what the engine actually said,
    // independent of what socket.ts decides to forward over the WS.
    log("engine", line);
    for (const cb of listeners) cb(line);
  }

  const instance = await YaneuraOuFactory({
    wasmBinary,
    printErr: (line: string) => {
      // Engine stderr is bridge log only. The "loading mobility weights"
      // banner lives here; nothing the tweak needs to see.
      logErr(`engine stderr: ${line}`);
    },
  });
  // The engine wraps the USI output stream through Module.print INTO a
  // listener queue, and only falls back to console.log when the queue
  // is empty — i.e. the factory's `print` option is ignored. We have to
  // attach via addMessageListener() to actually capture lines.
  instance.addMessageListener((line: string) => dispatch(line));

  // Low-level: hand a line to the engine. No logging — callers decide
  // whether the line is bridge-originated, tweak-originated, or auto-
  // generated, and tag it accordingly.
  function rawSend(line: string): void {
    instance.postMessage(line);
  }
  // Bridge-originated commands (setoption / usi / isready / usinewgame /
  // go). Logged under [br>e] so the trace shows who issued each line.
  function bridgeSend(line: string): void {
    log("br>e", line);
    rawSend(line);
  }

  // Hand-rolled handshake. We can't use the package's createEngine
  // because we need the raw USI line stream, but the post-handshake
  // contract is "engine has seen usi + isready + usinewgame".
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("usiok timeout")),
      10_000,
    );
    const wait = (line: string): void => {
      if (line === "usiok") {
        clearTimeout(timer);
        listeners.splice(listeners.indexOf(wait), 1);
        resolve();
      }
    };
    listeners.push(wait);
    bridgeSend("usi");
  });

  // setoption sweep. The package handshakes `usi`/`usiok` but doesn't
  // pre-configure anything — that's our job. The cfworkers variant
  // requires a small Hash; anything above ~32MB fails at allocate
  // time inside the 128MB Emscripten heap. Use bridgeSend so the trace
  // shows these as bridge-originated (= not coming from the tweak).
  bridgeSend(`setoption name USI_Hash value ${cfg.usiHashMb}`);
  bridgeSend(`setoption name Threads value ${cfg.threads}`);
  bridgeSend(`setoption name USI_OwnBook value false`);
  // DepthLimit / NodesLimit are engine-side hard caps. The go line only
  // carries byoyomi; these clip the search inside the engine so neither
  // run-away depth nor run-away nodes are possible.
  bridgeSend(`setoption name DepthLimit value ${cfg.depthLimit}`);
  bridgeSend(`setoption name NodesLimit value ${cfg.nodesLimit}`);

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("readyok timeout")),
      30_000,
    );
    const wait = (line: string): void => {
      if (line === "readyok") {
        clearTimeout(timer);
        listeners.splice(listeners.indexOf(wait), 1);
        resolve();
      }
    };
    listeners.push(wait);
    bridgeSend("isready");
  });

  bridgeSend("usinewgame");
  logErr("engine: ready");

  const goLine = `go byoyomi ${cfg.byoyomiMs}`;
  return {
    feed(line: string): void {
      // Lines flowing in via feed() came from the tweak — socket.ts
      // already logged them as [tw>e]. Use rawSend so we don't double-
      // log them as [br>e] on the way in.
      rawSend(line);
      // position→go is engine-internal. The outside world (= the WS to
      // the tweak) only ever sends `position sfen ...`; we add the go
      // here so neither the tweak nor socket.ts has to think about it.
      // The go itself IS bridge-originated, so it deserves a [br>e]
      // line.
      if (line.startsWith("position sfen ")) {
        bridgeSend(goLine);
      }
    },
    onLine(cb): void {
      listeners.push(cb);
    },
    async dispose(): Promise<void> {
      bridgeSend("quit");
      await new Promise((r) => setTimeout(r, 100));
      try {
        instance.terminate();
      } catch (err) {
        logErr(`engine terminate: ${(err as Error).message}`);
      }
    },
  };
}
