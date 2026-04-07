// ── Bridge 通信 ──
// MAIN world → ISOLATED world (bridge.ts) への postMessage ラッパー

import type { ProfileOverrides } from "./types";

export function sendToBridge(entry: Record<string, unknown>): void {
  try {
    window.postMessage({ type: "__MSL_CAPTURE_LOG__", payload: entry }, "*");
  } catch { /* ignore */ }
}

export function saveFile(filename: string, content: string, mimeType?: string): void {
  try {
    window.postMessage({
      type: "__MSL_CAPTURE_SAVE_FILE__",
      filename,
      content,
      mimeType: mimeType ?? "application/json",
    }, "*");
  } catch { /* ignore */ }
}

export function saveSettings(overrides: ProfileOverrides): void {
  window.postMessage({
    type: "__MSL_SETTINGS_SAVE__",
    settings: {
      profileOverrideEnabled: overrides.enabled,
      profileOverrideAddProfiles: overrides.addProfiles.slice(),
      profileOverrideReplaceProfiles: overrides.replaceProfiles,
    },
  }, "*");
}

export function requestSettings(): void {
  window.postMessage({ type: "__MSL_SETTINGS_REQUEST__" }, "*");
}

export function requestSaveNow(): void {
  window.postMessage({ type: "__MSL_CAPTURE_SAVE_NOW__" }, "*");
}

export function saveZip(filename: string, data: Uint8Array): void {
  // Uint8Array → base64 に変換して bridge 経由で送る
  let binary = "";
  for (let i = 0; i < data.length; i++) binary += String.fromCharCode(data[i]);
  const b64 = btoa(binary);
  try {
    window.postMessage({
      type: "__MSL_CAPTURE_SAVE_ZIP__",
      filename,
      data_b64: b64,
    }, "*");
  } catch { /* ignore */ }
}

export function requestCookies(): Promise<chrome.cookies.Cookie[]> {
  return new Promise((resolve) => {
    const handler = (event: MessageEvent) => {
      if (event.source !== window) return;
      const data = event.data as Record<string, unknown> | null;
      if (!data || data.type !== "__MSL_COOKIES_RESULT__") return;
      window.removeEventListener("message", handler);
      resolve((data.cookies ?? []) as chrome.cookies.Cookie[]);
    };
    window.addEventListener("message", handler);
    try {
      window.postMessage({ type: "__MSL_GET_COOKIES__" }, "*");
    } catch {
      window.removeEventListener("message", handler);
      resolve([]);
    }
    // タイムアウト
    setTimeout(() => {
      window.removeEventListener("message", handler);
      resolve([]);
    }, 3000);
  });
}

export function requestDownloadStream(url: string, filename: string, size: number | undefined): void {
  window.postMessage({
    type: "__MSL_CAPTURE_DOWNLOAD_STREAM__",
    url,
    filename,
    size,
  }, "*");
}
