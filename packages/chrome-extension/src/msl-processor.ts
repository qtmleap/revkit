// ── MSL メッセージ処理 ──
// decrypt/encrypt で取得した平文 MSL メッセージのデコード・解析・ログ

import type { CaptureEntry } from "./types";
import { captured, manifestData } from "./state";
import { sendToBridge } from "./bridge-comm";
import { safeStringify, tryDecodeText, tryParseJSON } from "./utils";
import { deepDecodeMSL, extractDecodedPayload } from "./msl-decoder";
import { extractManifestData, createChunkAccumulator } from "./manifest-extractor";
import { extractAleKeys } from "./ale-parser";
import { maybeUpdateEsn } from "./esn";

const PREFIX = "[MSL-Capture]";
const MSL_MSG = "[MSL-Message]";

let _logSeq = 0;
let _onPanelUpdate: (() => void) | null = null;

export function setLogSeq(seq: number): void {
  _logSeq = seq;
}

export function getLogSeq(): number {
  return _logSeq;
}

export function setPanelUpdateCallback(cb: () => void): void {
  _onPanelUpdate = cb;
}

function notifyPanelUpdate(): void {
  _onPanelUpdate?.();
}

export function logCapture(type: string, data: Record<string, unknown>): CaptureEntry {
  _logSeq++;
  const entry: CaptureEntry = { seq: _logSeq, type, ts: new Date().toISOString(), ...data };
  console.groupCollapsed(`${PREFIX} ${type}`);
  console.log(safeStringify(entry));
  console.groupEnd();
  sendToBridge(entry);
  return entry;
}

// Chunk accumulator
const manifestChunkAccum = createChunkAccumulator();

export function logMSLMessage(
  direction: "encrypt" | "decrypt",
  plaintext: ArrayBuffer | Uint8Array,
  algorithm: string,
): void {
  const text = tryDecodeText(plaintext);
  if (!text) return;

  const json = tryParseJSON(text);
  const arrow = direction === "encrypt" ? ">>>" : "<<<";
  const label = direction === "encrypt" ? "SENT" : "RECEIVED";

  if (json && typeof json === "object") {
    const expanded = deepDecodeMSL(json);
    const decodedPayload = extractDecodedPayload(expanded);

    let summary = "";
    if (decodedPayload && typeof decodedPayload === "object") {
      const pd = decodedPayload as Record<string, unknown>;
      if (pd.method) summary = ` method=${pd.method}`;
      else if (pd.url) summary = ` url=${pd.url}`;
      else {
        const keys = Object.keys(pd);
        if (keys.length <= 5) summary = ` keys=[${keys.join(",")}]`;
      }
    }

    const envelope = json as Record<string, unknown>;
    const compressLabel = envelope.compressionalgo ? ` [${envelope.compressionalgo}]` : "";

    console.groupCollapsed(`${MSL_MSG} ${arrow} ${label}${summary} [${algorithm}]${compressLabel} (${text.length} bytes)`);
    console.groupCollapsed("Raw MSL envelope");
    console.log(safeStringify(json));
    console.groupEnd();

    // ESN: envelope.sender or headerdata_decoded.sender
    if (typeof envelope.sender === "string") {
      maybeUpdateEsn(envelope.sender);
    }
    if (expanded._headerdata_decoded) {
      console.groupCollapsed("Header (decoded)");
      console.log(safeStringify(expanded._headerdata_decoded));
      console.groupEnd();
      const hdr = expanded._headerdata_decoded;
      if (typeof hdr.sender === "string") maybeUpdateEsn(hdr.sender);
    }
    if (expanded._useridtoken_decoded) {
      console.groupCollapsed("UserID Token");
      console.log(safeStringify(expanded._useridtoken_decoded));
      console.groupEnd();
    }
    if (expanded._servicetokens_decoded) {
      console.groupCollapsed(`Service Tokens (${expanded._servicetokens_decoded.length})`);
      expanded._servicetokens_decoded.forEach((st, i) => {
        console.groupCollapsed((st.name as string) ?? `token ${i}`);
        console.log(safeStringify(st));
        console.groupEnd();
      });
      console.groupEnd();
    }
    if (decodedPayload) {
      console.group("Payload data (decoded)");
      console.log(typeof decodedPayload === "object" ? safeStringify(decodedPayload) : decodedPayload);
      console.groupEnd();
    }
    console.groupEnd();

    // マニフェスト検出
    if (direction === "decrypt" && decodedPayload && typeof decodedPayload === "object") {
      const pd = decodedPayload as Record<string, unknown>;
      if (pd.result && typeof pd.result === "object") {
        const r = pd.result as Record<string, unknown>;
        if (r.video_tracks || r.audio_tracks) {
          try {
            if (extractManifestData(pd, manifestData)) notifyPanelUpdate();
          } catch (e) {
            console.warn(PREFIX, "extractManifestData error:", e);
          }
        }
      }
      // ALE 鍵の検出
      const aleResult = extractAleKeys(pd.result ?? pd);
      if (aleResult) {
        captured.aleKeys.push(aleResult);
        notifyPanelUpdate();
      }
    }

    if (direction === "decrypt") {
      manifestChunkAccum(envelope, decodedPayload, manifestData, notifyPanelUpdate);
    }

    _logSeq++;
    const entry: CaptureEntry = {
      seq: _logSeq,
      type: "msl.message",
      direction,
      ts: new Date().toISOString(),
      algorithm,
      size: text.length,
      format: "json",
      envelope: json,
      header: expanded._headerdata_decoded ?? null,
      useridtoken: expanded._useridtoken_decoded ?? null,
      servicetokens: expanded._servicetokens_decoded ?? null,
      payload: decodedPayload,
      payloads: expanded._payloads_decoded ?? null,
    };
    captured.mslMessages.push(entry);
    sendToBridge(entry);
  } else {
    console.groupCollapsed(`${MSL_MSG} ${arrow} ${label} [${algorithm}] (text, ${text.length} bytes)`);
    console.log(text);
    console.groupEnd();
    _logSeq++;
    const entry: CaptureEntry = {
      seq: _logSeq,
      type: "msl.message",
      direction,
      ts: new Date().toISOString(),
      algorithm,
      size: text.length,
      format: "text",
      data: text,
    };
    captured.mslMessages.push(entry);
    sendToBridge(entry);
  }
}
