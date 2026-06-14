/**
 * Shared logger.
 *
 * Every log line carries a single tag so the four message flows (tweak↔
 * engine, engine-internal, bridge wrapper) can be told apart at a
 * glance, and a millisecond timestamp so two adjacent lines can be
 * compared on order. We mirror stdout/stderr to a log file (default
 * bridge.log next to game-log.jsonl) so a long autoplay session leaves
 * a tail of what actually flowed.
 *
 * Tag semantics:
 *   [e>tw]   = engine → tweak (WS で実際に tweak に転送した行)
 *   [tw>e]   = tweak → engine (WS から受けて engine に投げた行)
 *   [br>e]   = bridge → engine (bridge wrapper が自前で engine に投げた行、
 *              setoption / usi / isready / usinewgame / go など)
 *   [engine] = engine の発話 (id / option / info / bestmove / usiok / ...)
 *   [bridge] = bridge wrapper の状態 (起動・接続・終了など)
 *
 * The log file lives at KIOU_BRIDGE_LOG. Empty string or "off" disables
 * file output without affecting stdout/stderr. Existing file is
 * appended, not truncated — pair with `tail -f` for live tracing.
 */

import { appendFileSync, openSync, closeSync } from "node:fs";
import { stderr, stdout } from "node:process";

export type LogTag = "e>tw" | "tw>e" | "br>e" | "engine" | "bridge" | "..";

const LOG_FILE = process.env["KIOU_BRIDGE_LOG"];
const FILE_LOG_ENABLED =
  LOG_FILE !== undefined && LOG_FILE !== "" && LOG_FILE !== "off";

// Best-effort: create / append the file so the first write doesn't race
// with directory permissions in production. Silently skip on error —
// stdout/stderr logging still works.
if (FILE_LOG_ENABLED && LOG_FILE) {
  try {
    const fd = openSync(LOG_FILE, "a");
    closeSync(fd);
  } catch {
    // ignore — we'll just lose file logging
  }
}

function ts(): string {
  // ISO without the Z so the timezone is implicit (= local wall clock).
  // Trim to ms; this is for human eyes, not for sorting across hosts.
  const d = new Date();
  const pad = (n: number, w = 2): string => String(n).padStart(w, "0");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.` +
    `${pad(d.getMilliseconds(), 3)}`
  );
}

function emit(line: string, isErr: boolean): void {
  // Console first; file output failing shouldn't suppress the terminal
  // copy. File appendFileSync is sync because we want every line on
  // disk before the next event fires (the bridge processes maybe a few
  // dozen lines per second, so sync I/O is fine).
  (isErr ? stderr : stdout).write(`${line}\n`);
  if (FILE_LOG_ENABLED && LOG_FILE) {
    try {
      appendFileSync(LOG_FILE, `${line}\n`);
    } catch {
      // ignore — disk full / permission etc.
    }
  }
}

/** Tagged log to stdout + file. Use for any tweak/engine traffic. */
export function log(tag: LogTag, line: string): void {
  emit(`${ts()} [${tag}] ${line}`, false);
}

/** Bridge-side notices (connect / disconnect / spawned / errored). */
export function logErr(line: string): void {
  emit(`${ts()} [bridge] ${line}`, true);
}
