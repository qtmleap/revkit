/**
 * Background Service Worker
 *
 * Content Script (bridge.ts) からメッセージを受け取り、
 * chrome.downloads API でログファイルを自動保存する。
 *
 * Service Worker には DOM がないため Blob / URL.createObjectURL は使えない。
 * data: URL を使ってダウンロードする。
 */

// ── 軽量メッセージバリデーション (Zod不要) ──

interface BackgroundMessage {
  type: string;
  settings?: unknown;
  data?: unknown;
  url?: string;
  filename?: string;
  size?: number;
  content?: unknown;
  mimeType?: string;
  data_b64?: string;
}

const VALID_BG_TYPES = new Set([
  "msl-get-settings",
  "msl-set-settings",
  "msl-capture-log",
  "msl-capture-save-now",
  "msl-capture-download-stream",
  "msl-capture-save-file",
  "msl-capture-save-zip",
  "msl-get-cookies",
]);

function parseBackgroundMessage(data: unknown): BackgroundMessage | null {
  if (typeof data !== "object" || data === null) return null;
  const obj = data as Record<string, unknown>;
  if (typeof obj.type !== "string" || !VALID_BG_TYPES.has(obj.type)) return null;
  return obj as unknown as BackgroundMessage;
}

interface Session {
  startTime: string;
  dirPrefix: string;
  logEntries: unknown[];
  lastSaveCount: number;
}

const sessions = new Map<number, Session>();

function getSession(tabId: number): Session {
  const existing = sessions.get(tabId);
  if (existing) return existing;
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const session: Session = {
    startTime: ts,
    dirPrefix: `netflix-msl-capture/${ts}`,
    logEntries: [],
    lastSaveCount: 0,
  };
  sessions.set(tabId, session);
  return session;
}

function toDataURL(text: string, mimeType: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary);
  return `data:${mimeType};base64,${b64}`;
}

function saveSessionLogs(tabId: number): void {
  const session = sessions.get(tabId);
  if (!session || session.logEntries.length === 0) return;

  const entries = session.logEntries;
  const jsonl = entries.map((e) => JSON.stringify(e)).join("\n") + "\n";
  const url = toDataURL(jsonl, "application/x-ndjson");

  chrome.downloads.download(
    {
      url,
      filename: `${session.dirPrefix}/capture.jsonl`,
      conflictAction: "overwrite",
      saveAs: false,
    },
    (downloadId) => {
      if (chrome.runtime.lastError) {
        console.error("Download error:", chrome.runtime.lastError.message);
        return;
      }
      session.lastSaveCount = entries.length;
      console.log(`Saved ${entries.length} entries (download ${downloadId})`);
    },
  );
}

chrome.runtime.onMessage.addListener(
  (
    message: unknown,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response?: unknown) => void,
  ) => {
    const msg = parseBackgroundMessage(message);
    if (!msg) {
      sendResponse({ ok: false, error: "invalid message" });
      return false;
    }

    // ── 設定の永続化 (tab 不要) ──
    if (msg.type === "msl-get-settings") {
      chrome.storage.local.get("mslSettings", (stored) => {
        sendResponse({ ok: true, settings: stored["mslSettings"] ?? null });
      });
      return true;
    }

    if (msg.type === "msl-set-settings") {
      chrome.storage.local.set({ mslSettings: msg.settings }, () => {
        sendResponse({ ok: true });
      });
      return true;
    }

    if (msg.type === "msl-get-cookies") {
      chrome.cookies.getAll({ domain: ".netflix.com" }, (cookies) => {
        sendResponse({ ok: true, cookies: cookies ?? [] });
      });
      return true;
    }

    // ── tab が必要なメッセージ ──
    const tabId = sender.tab?.id;
    if (!tabId) {
      sendResponse({ ok: false, error: "no tab" });
      return false;
    }

    switch (msg.type) {
      case "msl-capture-log": {
        const session = getSession(tabId);
        session.logEntries.push(msg.data);
        sendResponse({ ok: true, count: session.logEntries.length });
        return false;
      }

      case "msl-capture-save-now": {
        saveSessionLogs(tabId);
        const session = getSession(tabId);
        sendResponse({ ok: true, count: session.logEntries.length });
        return false;
      }

      case "msl-capture-download-stream": {
        const session = getSession(tabId);
        const filename = msg.filename || "stream.mp4";

        chrome.downloads.download(
          {
            url: msg.url!,
            filename: `${session.dirPrefix}/${filename}`,
            conflictAction: "uniquify",
            saveAs: false,
          },
          (downloadId) => {
            if (chrome.runtime.lastError) {
              console.error("Stream download error:", chrome.runtime.lastError.message);
              sendResponse({ ok: false, error: chrome.runtime.lastError.message });
              return;
            }
            console.log(`Stream download started: ${filename} (download ${downloadId})`);
            sendResponse({ ok: true, downloadId });
          },
        );
        return true;
      }

      case "msl-capture-save-zip": {
        const session = getSession(tabId);
        const url = `data:application/zip;base64,${msg.data_b64}`;

        chrome.downloads.download(
          {
            url,
            filename: `${session.dirPrefix}/${msg.filename!}`,
            conflictAction: "uniquify",
            saveAs: false,
          },
          (downloadId) => {
            if (chrome.runtime.lastError) {
              console.error("ZIP download error:", chrome.runtime.lastError.message);
            } else {
              console.log(`ZIP saved: ${msg.filename} (download ${downloadId})`);
            }
          },
        );
        sendResponse({ ok: true });
        return false;
      }

      case "msl-capture-save-file": {
        const session = getSession(tabId);
        const content =
          typeof msg.content === "string"
            ? msg.content
            : JSON.stringify(msg.content, null, 2);
        const url = toDataURL(content, msg.mimeType ?? "application/json");

        chrome.downloads.download(
          {
            url,
            filename: `${session.dirPrefix}/${msg.filename!}`,
            conflictAction: "overwrite",
            saveAs: false,
          },
          (downloadId) => {
            if (chrome.runtime.lastError) {
              console.error("Download error:", chrome.runtime.lastError.message);
            } else {
              console.log(`File saved: ${msg.filename} (download ${downloadId})`);
            }
          },
        );
        sendResponse({ ok: true });
        return false;
      }
    }
  },
);

// タブが閉じられたらセッションをクリーンアップ
chrome.tabs.onRemoved.addListener((tabId: number) => {
  sessions.delete(tabId);
});

console.log("[MSL-Capture] Background service worker started");
