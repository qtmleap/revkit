/**
 * WebSocket leg of the bridge — connects to the tweak's USI port and
 * funnels lines between it and the engine wrapper.
 *
 * Forwarding policy:
 *   - WS → engine    : every line goes through engine.feed() verbatim.
 *                      engine.feed() owns the position→go convention,
 *                      so we don't have to special-case it here.
 *   - engine → WS    : only `usiok` / `readyok` / `bestmove ...` reach
 *                      the tweak. id / option / info / ... stay inside
 *                      the engine wrapper (logged as [engine]).
 *
 * The tweak owns the position; this file owns the transport.
 */

import { appendFileSync } from "node:fs";
import { WebSocket } from "ws";
import type { Engine } from "./engine.js";
import { log, logErr } from "./log.js";

export interface SocketConfig {
  device: string;
  port: number;
  /** JSONL game log path. Empty / "off" disables. */
  logFile: string;
}

/**
 * One round = "we shipped a `position sfen` to the engine and got back a
 * `bestmove`". Kept here (not in engine.ts) because the position arrives
 * on the WS side and the JSONL log is part of the bridge's contract with
 * the operator, not the engine.
 */
interface RoundLog {
  ts: string;
  sfen: string;
  bestmove: string;
}

export interface SocketHandle {
  /** Resolves with a teardown reason when the socket leg dies. */
  done: Promise<string>;
  /** Close the WS cleanly. */
  close(): void;
}

export function connectTweak(cfg: SocketConfig, engine: Engine): SocketHandle {
  let pending: Partial<RoundLog> = {};

  function recordRound(): void {
    if (!cfg.logFile || cfg.logFile === "off") return;
    if (!pending.sfen || !pending.bestmove) return;
    const entry: RoundLog = {
      ts: new Date().toISOString(),
      sfen: pending.sfen,
      bestmove: pending.bestmove,
    };
    try {
      appendFileSync(cfg.logFile, JSON.stringify(entry) + "\n");
    } catch (err) {
      logErr(`failed to append ${cfg.logFile}: ${(err as Error).message}`);
    }
    pending = {};
  }

  const url = `ws://${cfg.device}:${cfg.port}`;
  logErr(`connecting ${url}`);
  // perMessageDeflate=false keeps frames simple to debug. We also disable
  // ws's keepalive ping — earlier Python testing showed the tweak's pong
  // path was async and would race a 20s ping deadline. The tweak is on
  // the LAN so dead-peer detection isn't critical.
  const ws = new WebSocket(url, { perMessageDeflate: false });

  let resolveDone!: (reason: string) => void;
  const done = new Promise<string>((res) => {
    resolveDone = res;
  });

  // Engine → WS. Only USI handshake / result lines actually cross the
  // wire. Everything else is engine-internal and already logged as
  // [engine] inside engine.ts.
  engine.onLine((line) => {
    if (line.startsWith("bestmove ")) {
      const mv = line.slice("bestmove ".length).trim().split(/\s+/)[0] ?? "";
      if (mv) {
        pending.bestmove = mv;
        recordRound();
      }
    }
    const forward =
      line === "usiok" ||
      line === "readyok" ||
      line.startsWith("bestmove ");
    if (!forward) return;
    log("e>tw", line);
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(`${line}\n`);
      } catch (err) {
        logErr(`ws.send failed: ${(err as Error).message}`);
        resolveDone("ws.send threw");
      }
    }
  });

  ws.on("open", () => {
    logErr("ws connected");
  });

  ws.on("message", (data) => {
    // ws hands us either Buffer or string depending on the peer's frame
    // type; the tweak only sends text but coerce defensively.
    const text = data instanceof Buffer ? data.toString("utf8") : String(data);
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line.length === 0) continue;
      log("tw>e", line);

      if (line.startsWith("position sfen ")) {
        pending.sfen = line.slice("position sfen ".length).trim();
      } else if (line === "usinewgame") {
        try {
          appendFileSync(
            cfg.logFile,
            JSON.stringify({
              ts: new Date().toISOString(),
              event: "usinewgame",
            }) + "\n",
          );
        } catch {
          // best-effort
        }
        pending = {};
      }
      // engine.feed() handles the engine side (including auto-appending
      // `go byoyomi N` after each position).
      engine.feed(line);
    }
  });

  ws.on("close", (code, reason) => {
    logErr(`ws closed code=${code} reason=${reason.toString()}`);
    resolveDone("ws closed");
  });

  ws.on("error", (err) => {
    logErr(`ws error: ${err.message}`);
    resolveDone(`ws error: ${err.message}`);
  });

  return {
    done,
    close(): void {
      try {
        if (ws.readyState === WebSocket.OPEN) ws.close();
      } catch {
        // ignore
      }
    },
  };
}
