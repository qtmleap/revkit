/**
 * Netflix MSL Key Capture + EME Hook — Entry Point
 * inject.ts — runs in MAIN world
 *
 * Bun でバンドルされ、各モジュールがインライン化される。
 */

"use strict";

import "./types"; // declare global の副作用インポート
import { captured, manifestData, profileOverrides } from "./state";
import { safeStringify, formatSize } from "./utils";
import { saveFile, saveZip, saveSettings, requestSaveNow, requestSettings, requestDownloadStream, requestCookies } from "./bridge-comm";
import { buildExportZip } from "./zip-exporter";
import { setEsnUpdateCallback } from "./esn";
import { buildKIDTableRows, buildKIDTableMarkdown } from "./kid-table";
import { setPanelUpdateCallback } from "./msl-processor";
import { installCryptoHooks } from "./crypto-hooks";
import { installEmeHooks } from "./eme-hooks";
import { installHttpHooks } from "./http-hooks";
import { CapturePanel } from "./panel";
import { SettingsLoadMessageSchema, zodParse } from "./schemas";
import type { StreamInfo } from "./types";

const PREFIX = "[MSL-Capture]";
const ALE_PREFIX = "[ALE-Capture]";

// ── Globals ──
window.__MSL_MANIFEST__ = manifestData;
window.__MSL_CAPTURED__ = captured;
window.__MSL_PROFILE_OVERRIDES__ = profileOverrides;
window.__MSL_ALL_PROFILES__ = {
  video: [
    "av1-main-L20-dash-cbcs-prk", "av1-main-L21-dash-cbcs-prk", "av1-main-L30-dash-cbcs-prk",
    "av1-main-L31-dash-cbcs-prk", "av1-main-L40-dash-cbcs-prk", "av1-main-L41-dash-cbcs-prk",
    "av1-main-L50-dash-cbcs-prk", "av1-main-L30-dash-cbcs-live", "av1-main-L31-dash-cbcs-live",
    "av1-main-L40-dash-cbcs-live", "av1-main-L41-dash-cbcs-live",
    "hevc-main10-L30-dash-cenc-prk", "hevc-main10-L31-dash-cenc-prk", "hevc-main10-L40-dash-cenc-prk",
    "hevc-main10-L41-dash-cenc-prk", "hevc-main10-L50-dash-cenc-prk", "hevc-main10-L30-dash-cenc-prk-do",
    "hevc-hdr-main10-L30-dash-cenc-prk", "hevc-hdr-main10-L31-dash-cenc-prk",
    "hevc-hdr-main10-L40-dash-cenc-prk", "hevc-hdr-main10-L41-dash-cenc-prk",
    "hevc-hdr-main10-L30-dash-cenc-prk-do", "hevc-hdr-main10-L30-dash-cenc-live",
    "vp9-profile0-L21-dash-cenc", "vp9-profile0-L30-dash-cenc", "vp9-profile0-L31-dash-cenc",
    "vp9-profile0-L40-dash-cenc", "vp9-profile2-L30-dash-cenc-prk", "vp9-profile2-L31-dash-cenc-prk",
    "vp9-profile2-L40-dash-cenc-prk",
    "playready-h264mpl30-dash", "playready-h264mpl31-dash", "playready-h264mpl40-dash",
    "playready-h264hpl22-dash", "playready-h264hpl30-dash", "playready-h264hpl31-dash",
    "playready-h264hpl40-dash", "none-h264mpl30-dash",
    "h264hpl22-dash-playready-live", "h264hpl30-dash-playready-live",
    "h264hpl31-dash-playready-live", "h264hpl40-dash-playready-live",
  ],
};

// ── Panel ──
let panel: CapturePanel | null = null;

function downloadStream(stream: StreamInfo, type: "video" | "audio", lang?: string): void {
  if (!stream.urls.length) return;
  const urlObj = stream.urls[0];
  const url = typeof urlObj === "string" ? urlObj : urlObj.url;
  if (!url) return;
  const mid = manifestData.movieId ?? "unknown";
  const filename = type === "video"
    ? `netflix_${mid}_${stream.res_w}x${stream.res_h}_${stream.bitrate}kbps.mp4`
    : `netflix_${mid}_audio_${lang ?? "und"}_${stream.bitrate}kbps.mp4`;
  console.log(PREFIX, `[Download] ${type}: ${filename} (${formatSize(stream.size)})`);
  requestDownloadStream(url, filename, stream.size);
}

function updatePanel(): void {
  if (!panel) return;
  panel.update();
}

function initPanel(): void {
  panel = new CapturePanel(
    manifestData,
    captured,
    profileOverrides,
    {
      onSave: () => requestSaveNow(),
      onSaveSettings: () => saveSettings(profileOverrides),
      onDownloadStream: downloadStream,
      onDownloadManifest: () => {
        if (!manifestData.raw) return;
        const mid = manifestData.movieId ?? "unknown";
        const filename = `manifest_${mid}.json`;
        console.log(PREFIX, `[Manifest] Saving: ${filename}`);
        saveFile(filename, safeStringify(manifestData.raw));
      },
      onExportZip: async () => {
        const mid = manifestData.movieId ?? "unknown";
        const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
        const filename = `capture_${mid}_${ts}.zip`;
        console.log(PREFIX, `[Export] Fetching cookies...`);
        const cookies = await requestCookies();
        console.log(PREFIX, `[Export] Got ${cookies.length} cookies, building ZIP: ${filename}`);
        const zipData = buildExportZip(captured, manifestData, cookies);
        console.log(PREFIX, `[Export] ZIP size: ${(zipData.length / 1024).toFixed(1)} KB`);
        saveZip(filename, zipData);
      },
    },
    buildKIDTableRows,
    buildKIDTableMarkdown,
  );
  panel.create();
}

// ── Callbacks ──
setPanelUpdateCallback(updatePanel);
setEsnUpdateCallback(updatePanel);

// ── Install all hooks ──
installCryptoHooks();
installEmeHooks();
installHttpHooks();

// ── Console commands ──
window.__MSL_DUMP__ = () => {
  console.log(PREFIX, "=== CAPTURED KEYS DUMP ===");
  console.log(safeStringify(captured));
  return captured;
};

window.__EME_DUMP__ = () => {
  console.log("[EME-Capture]", "=== CAPTURED EME DATA DUMP ===");
  console.log(safeStringify(captured.eme));
  return captured.eme;
};

window.__HTTP_DUMP__ = () => {
  console.log("[HTTP-Capture]", `=== HTTP HEADERS (${captured.httpCaptures.length}) ===`);
  for (const cap of captured.httpCaptures) {
    console.groupCollapsed(`[HTTP-Capture] ${cap.method ?? ""} ${cap.statusCode ?? ""} ${cap.url}`);
    console.log("Req:", safeStringify(cap.requestHeaders));
    console.log("Res:", safeStringify(cap.responseHeaders));
    console.groupEnd();
  }
  return captured.httpCaptures;
};

window.__MSL_MESSAGES__ = () => {
  console.log("[MSL-Message]", `=== DECRYPTED MSL MESSAGES (${captured.mslMessages.length}) ===`);
  for (const msg of captured.mslMessages) {
    const arrow = msg.direction === "encrypt" ? ">>>" : "<<<";
    console.groupCollapsed(`[MSL-Message] ${arrow} ${msg.direction} [${msg.ts}] (${msg.size} bytes)`);
    if (msg.payload) {
      console.group("Payload");
      console.log(typeof msg.payload === "object" ? safeStringify(msg.payload) : msg.payload);
      console.groupEnd();
    }
    console.groupEnd();
  }
  return captured.mslMessages;
};

window.__MSL_ALE__ = () => {
  console.log(ALE_PREFIX, `=== ALE KEYS (${captured.aleKeys.length}) ===`);
  captured.aleKeys.forEach((ale, i) => {
    console.log(`#${i + 1} KID=${ale.kid} AES=${ale.encryptionKey} HMAC=${ale.hmacKey}`);
  });
  return captured.aleKeys;
};

window.__MSL_KID_TABLE__ = () => {
  const rows = buildKIDTableRows();
  if (!rows.length) {
    console.log(PREFIX, "[KID Table] No manifest data yet.");
    return [];
  }
  console.log(`${PREFIX} [KID Table] movieId=${manifestData.movieId} (${rows.length} streams)`);
  for (const [i, r] of rows.entries()) {
    console.log(`${r.boundary ? "▲" : " "}${String(i + 1).padStart(3)}  ${(r.res_w + "x" + r.res_h).padEnd(12)}  ${r.kid_short.padEnd(18)}  ${r.content_profile}`);
  }
  console.log("\n" + buildKIDTableMarkdown());
  return rows;
};

window.__SAVE_NOW__ = () => {
  requestSaveNow();
  console.log(PREFIX, "Save requested.");
};

window.__SAVE_KEYS__ = () => {
  saveFile("keys/msl_keys.json", safeStringify({
    generateKey: captured.generateKey,
    importKey: captured.importKey,
    deriveKey: captured.deriveKey,
  }));
  saveFile("keys/eme_data.json", safeStringify(captured.eme));
  saveFile("keys/ale_keys.json", safeStringify(captured.aleKeys));
};

window.__MSL_PANEL__ = () => {
  if (panel) {
    panel.show();
  } else {
    initPanel();
  }
};

// ── Settings load listener ──
window.addEventListener("message", (event: MessageEvent) => {
  if (event.source !== window) return;
  const msg = zodParse(SettingsLoadMessageSchema, event.data);
  if (msg) {
    panel?.applySettings(msg.settings);
  }
});

// Settings request
requestSettings();

// Stats interval
setInterval(() => {
  panel?.updateStats();
}, 2000);

// Log
console.log(`${ALE_PREFIX} ALE key extractor active (keyx.scheme=CLEAR)`);
console.log(`${PREFIX} Commands: __MSL_DUMP__() __EME_DUMP__() __MSL_MESSAGES__() __HTTP_DUMP__() __MSL_KID_TABLE__() __MSL_ALE__() __SAVE_NOW__() __SAVE_KEYS__() __MSL_PANEL__()`);

// Panel init
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => initPanel());
} else {
  initPanel();
}
