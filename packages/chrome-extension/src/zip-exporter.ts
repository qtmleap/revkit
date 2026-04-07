// ── ZIP 一括エクスポート ──
// キャプチャ済みデータを ZIP にまとめて保存する

import type { CapturedData, ManifestData } from "./types";
import { ZipBuilder } from "./zip-builder";
import { safeStringify } from "./utils";

interface CookieInfo {
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  expirationDate?: number;
  name: string;
  value: string;
}

function buildNetscapeCookieJar(cookies: CookieInfo[]): string {
  const lines = [
    "# Netscape HTTP Cookie File",
    "# https://curl.se/docs/http-cookies.html",
    `# Exported at ${new Date().toISOString()}`,
    "",
  ];
  for (const c of cookies) {
    const domain = c.domain.startsWith(".") ? c.domain : `.${c.domain}`;
    const includeSubdomains = domain.startsWith(".") ? "TRUE" : "FALSE";
    const secure = c.secure ? "TRUE" : "FALSE";
    const expiry = c.expirationDate ? String(Math.floor(c.expirationDate)) : "0";
    lines.push(`${domain}\t${includeSubdomains}\t${c.path}\t${secure}\t${expiry}\t${c.name}\t${c.value}`);
  }
  return lines.join("\n") + "\n";
}

export function buildExportZip(captured: CapturedData, manifestData: ManifestData, cookies?: CookieInfo[]): Uint8Array {
  const zip = new ZipBuilder();
  const mid = manifestData.movieId ?? "unknown";

  // ── Cookies ──
  if (cookies && cookies.length > 0) {
    zip.addFile("cookies.txt", buildNetscapeCookieJar(cookies));
  }

  // ── Manifest ──
  if (manifestData.raw) {
    zip.addJSON(`manifest_${mid}.json`, manifestData.raw);
  }

  // ── EME: License Challenges ──
  for (const [i, req] of captured.eme.licenseRequests.entries()) {
    const idx = String(i + 1).padStart(3, "0");
    const sessionId = req.sessionId ?? "unknown";
    zip.addJSON(`eme/challenges/${idx}_${sessionId}.json`, {
      keySystem: req.keySystem,
      sessionId: req.sessionId,
      messageType: req.messageType,
      messageSize: req.messageSize,
      message_b64: req.message_b64,
      ts: req.ts,
    });
  }

  // ── EME: License Responses ──
  for (const [i, res] of captured.eme.licenseResponses.entries()) {
    const idx = String(i + 1).padStart(3, "0");
    const sessionId = res.sessionId ?? "unknown";
    zip.addJSON(`eme/responses/${idx}_${sessionId}.json`, {
      keySystem: res.keySystem,
      sessionId: res.sessionId,
      responseSize: res.responseSize,
      response_b64: res.response_b64,
      ts: res.ts,
    });
  }

  // ── EME: Sessions (PSSH / initData) ──
  if (captured.eme.sessions.length > 0) {
    zip.addJSON("eme/sessions.json", captured.eme.sessions);
  }

  // ── EME: Key Statuses ──
  if (captured.eme.keyStatuses.length > 0) {
    zip.addJSON("eme/key_statuses.json", captured.eme.keyStatuses);
  }

  // ── ALE Keys ──
  if (captured.aleKeys.length > 0) {
    zip.addJSON("keys/ale_keys.json", captured.aleKeys);
  }

  // ── Crypto Keys ──
  const cryptoKeys = {
    generateKey: captured.generateKey,
    importKey: captured.importKey,
    deriveKey: captured.deriveKey,
  };
  if (captured.generateKey.length + captured.importKey.length + captured.deriveKey.length > 0) {
    zip.addJSON("keys/crypto_keys.json", cryptoKeys);
  }

  // ── ESN ──
  if (captured.esn.prv || captured.esn.pxa) {
    zip.addJSON("esn.json", captured.esn);
  }

  // ── MSL Messages ──
  if (captured.mslMessages.length > 0) {
    const ndjson = captured.mslMessages.map((m) => safeStringify(m)).join("\n") + "\n";
    zip.addFile("msl_messages.jsonl", ndjson);
  }

  // ── HTTP Captures ──
  if (captured.httpCaptures.length > 0) {
    zip.addJSON("http_captures.json", captured.httpCaptures);
  }

  // ── Full capture log (NDJSON) ──
  const allEntries = [
    ...captured.generateKey,
    ...captured.importKey,
    ...captured.deriveKey,
    ...captured.sign,
    ...captured.encrypt,
    ...captured.decrypt,
    ...captured.mslMessages,
    ...captured.httpCaptures,
    ...captured.eme.sessions,
    ...captured.eme.licenseRequests,
    ...captured.eme.licenseResponses,
    ...captured.eme.keyStatuses,
  ].sort((a, b) => a.seq - b.seq);

  if (allEntries.length > 0) {
    const ndjson = allEntries.map((e) => safeStringify(e)).join("\n") + "\n";
    zip.addFile("capture.jsonl", ndjson);
  }

  return zip.build();
}
