/**
 * Bridge Content Script (ISOLATED world)
 *
 * MAIN world の inject.ts は chrome.runtime にアクセスできないため、
 * このスクリプトが window.postMessage 経由でデータを受け取り、
 * chrome.runtime.sendMessage で background.ts に転送する。
 */

// ── 軽量メッセージバリデーション (Zod不要) ──

interface BridgeMessage {
  type: string;
  settings?: unknown;
  payload?: unknown;
  filename?: string;
  content?: unknown;
  mimeType?: string;
  url?: string;
  size?: number;
  data_b64?: string;
}

const VALID_BRIDGE_TYPES = new Set([
  "__MSL_SETTINGS_REQUEST__",
  "__MSL_SETTINGS_SAVE__",
  "__MSL_CAPTURE_LOG__",
  "__MSL_CAPTURE_SAVE_FILE__",
  "__MSL_CAPTURE_SAVE_NOW__",
  "__MSL_CAPTURE_DOWNLOAD_STREAM__",
  "__MSL_CAPTURE_SAVE_ZIP__",
  "__MSL_GET_COOKIES__",
]);

function parseBridgeMessage(data: unknown): BridgeMessage | null {
  if (typeof data !== "object" || data === null) return null;
  const obj = data as Record<string, unknown>;
  if (typeof obj.type !== "string" || !VALID_BRIDGE_TYPES.has(obj.type)) return null;
  return obj as unknown as BridgeMessage;
}

function send(msg: Record<string, unknown>): Promise<unknown> {
  return new Promise((resolve) => {
    try {
      if (!chrome.runtime?.id) {
        resolve(undefined);
        return;
      }
      chrome.runtime.sendMessage(msg, (response: unknown) => {
        try { void chrome.runtime.lastError; } catch { /* invalidated */ }
        resolve(response);
      });
    } catch {
      resolve(undefined);
    }
  });
}

window.addEventListener("message", function (event: MessageEvent) {
  if (event.source !== window) return;

  const data = parseBridgeMessage(event.data);
  if (!data) return;

  switch (data.type) {
    case "__MSL_SETTINGS_REQUEST__":
      send({ type: "msl-get-settings" }).then((response) => {
        const r = response as { settings?: unknown } | null;
        window.postMessage({
          type: "__MSL_SETTINGS_LOAD__",
          settings: r?.settings ?? null,
        }, "*");
      });
      break;

    case "__MSL_SETTINGS_SAVE__":
      send({ type: "msl-set-settings", settings: data.settings });
      break;

    case "__MSL_CAPTURE_LOG__":
      send({ type: "msl-capture-log", data: data.payload });
      break;

    case "__MSL_CAPTURE_SAVE_FILE__":
      send({
        type: "msl-capture-save-file",
        filename: data.filename,
        content: data.content,
        mimeType: data.mimeType,
      });
      break;

    case "__MSL_CAPTURE_SAVE_NOW__":
      send({ type: "msl-capture-save-now" }).then((response) => {
        const r = response as { count?: number } | null;
        window.postMessage({
          type: "__MSL_CAPTURE_SAVE_RESULT__",
          count: r?.count ?? 0,
        });
      });
      break;

    case "__MSL_CAPTURE_SAVE_ZIP__":
      send({
        type: "msl-capture-save-zip",
        filename: data.filename,
        data_b64: data.data_b64,
      });
      break;

    case "__MSL_GET_COOKIES__":
      send({ type: "msl-get-cookies" }).then((response) => {
        const r = response as { cookies?: unknown[] } | null;
        window.postMessage({
          type: "__MSL_COOKIES_RESULT__",
          cookies: r?.cookies ?? [],
        }, "*");
      });
      break;

    case "__MSL_CAPTURE_DOWNLOAD_STREAM__":
      send({
        type: "msl-capture-download-stream",
        url: data.url,
        filename: data.filename,
        size: data.size,
      }).then((response) => {
        const r = response as { ok?: boolean; downloadId?: number; error?: string } | null;
        window.postMessage({
          type: "__MSL_CAPTURE_DOWNLOAD_RESULT__",
          ok: r?.ok ?? false,
          downloadId: r?.downloadId,
          error: r?.error,
        });
      });
      break;
  }
});
