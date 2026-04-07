// ── 型定義 ──
// Zod スキーマから導出 + 内部専用の型

import type { z } from "zod";
import type { SettingsSchema } from "./schemas";

// ── Settings ──

export type Settings = z.infer<typeof SettingsSchema>;

// ── Stream / Track ──

export interface StreamInfo {
  res_w: number;
  res_h: number;
  bitrate: number;
  size: number | undefined;
  vmaf: number | undefined;
  content_profile: string;
  downloadable_id: string;
  kid: string | null;
  urls: Array<string | { url: string }>;
}

export interface VideoTrack {
  trackType: string;
  track_id: string;
  maxWidth: number;
  maxHeight: number;
  drmHeader?: { bytes?: string; keyId?: string };
  streams: StreamInfo[];
}

export interface AudioTrack {
  language: string;
  languageDescription: string;
  channels: string;
  trackType: string;
  track_id: string;
  streams: Array<{
    bitrate: number;
    size: number | undefined;
    content_profile: string;
    downloadable_id: string;
    urls: Array<string | { url: string }>;
  }>;
}

export interface ManifestData {
  movieId: string | null;
  duration: number | null;
  videoTracks: VideoTrack[];
  audioTracks: AudioTrack[];
  textTracks: unknown[];
  servers: unknown[];
  raw: unknown;
}

// ── ALE Keys ──

export interface AleKeys {
  encryptionKey: string;
  hmacKey: string;
  kid: string;
  jweToken: string;
  scheme: string;
  rawKeyHex: string;
  capturedAt: string;
}

// ── KID Table ──

export interface KIDTableRow {
  res_w: number;
  res_h: number;
  bitrate: number;
  kid: string | null;
  kid_short: string;
  content_profile: string;
  boundary: boolean;
}

// ── Profile Override ──

export interface ProfileOverrides {
  enabled: boolean;
  addProfiles: string[];
  replaceProfiles: string[] | null;
}

// ── ESN ──

export interface EsnData {
  prv: string | null;
  pxa: string | null;
  capturedAt: string;
}

// ── Capture Entry ──

export interface CaptureEntry {
  seq: number;
  type: string;
  ts: string;
  [key: string]: unknown;
}

// ── Captured Data (全キャプチャの集約) ──

export interface CapturedData {
  generateKey: CaptureEntry[];
  importKey: CaptureEntry[];
  deriveKey: CaptureEntry[];
  sign: CaptureEntry[];
  encrypt: CaptureEntry[];
  decrypt: CaptureEntry[];
  mslMessages: CaptureEntry[];
  httpCaptures: CaptureEntry[];
  aleKeys: AleKeys[];
  esn: EsnData;
  eme: {
    sessions: CaptureEntry[];
    licenseRequests: CaptureEntry[];
    licenseResponses: CaptureEntry[];
    keyStatuses: CaptureEntry[];
  };
}

// ── MSL Decoder 出力 ──

export interface DecodedMSL {
  headerdata?: string;
  payload?: string;
  payloads?: unknown[];
  data?: string;
  messageid?: number;
  compressionalgo?: string | null;
  endofmsg?: boolean;
  sender?: string;
  servicetokens?: Record<string, unknown>[];
  useridtoken?: Record<string, unknown>;
  _headerdata_decoded?: Record<string, unknown>;
  _payload_decoded?: Record<string, unknown>;
  _payload_data?: unknown;
  _data_decoded?: unknown;
  _payloads_decoded?: unknown[];
  _servicetokens_decoded?: Array<Record<string, unknown>>;
  _useridtoken_decoded?: unknown;
  [key: string]: unknown;
}

// ── Panel コールバック ──

export interface PanelCallbacks {
  onSave: () => void;
  onSaveSettings: () => void;
  onDownloadStream: (stream: StreamInfo, type: "video" | "audio", lang?: string) => void;
  onDownloadManifest: () => void;
  onExportZip: () => void | Promise<void>;
}

// ── Window グローバル拡張 ──

declare global {
  interface Window {
    __MSL_CAPTURED__: CapturedData;
    __MSL_MANIFEST__: ManifestData;
    __MSL_PROFILE_OVERRIDES__: ProfileOverrides;
    __MSL_ALL_PROFILES__: { video: string[] };
    __MSL_DUMP__: () => CapturedData;
    __EME_DUMP__: () => CapturedData["eme"];
    __HTTP_DUMP__: () => CaptureEntry[];
    __MSL_MESSAGES__: () => CaptureEntry[];
    __MSL_ALE__: () => AleKeys[];
    __MSL_KID_TABLE__: () => KIDTableRow[];
    __SAVE_NOW__: () => void;
    __SAVE_KEYS__: () => void;
    __MSL_PANEL__: () => void;
  }
}
