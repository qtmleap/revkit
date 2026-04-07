// ── Zod スキーマ定義 ──
// 外部JSONデータのバリデーションに使用

import { z } from "zod";

// ── Settings ──

export const SettingsSchema = z.object({
  profileOverrideEnabled: z.boolean(),
  profileOverrideAddProfiles: z.array(z.string()),
  profileOverrideReplaceProfiles: z.array(z.string()).nullable(),
});

export type Settings = z.infer<typeof SettingsSchema>;

// ── Netflix Manifest Response ──

export const StreamUrlSchema = z.union([
  z.string(),
  z.object({ url: z.string() }).passthrough(),
]);

export const VideoStreamResponseSchema = z.object({
  res_w: z.number(),
  res_h: z.number(),
  bitrate: z.number(),
  size: z.number().optional(),
  vmaf: z.number().optional(),
  content_profile: z.string(),
  downloadable_id: z.string(),
  drmHeaderId: z.string().default(""),
  urls: z.array(StreamUrlSchema).default([]),
}).passthrough();

export const AudioStreamResponseSchema = z.object({
  bitrate: z.number(),
  size: z.number().optional(),
  content_profile: z.string(),
  downloadable_id: z.string(),
  urls: z.array(StreamUrlSchema).default([]),
}).passthrough();

export const VideoTrackResponseSchema = z.object({
  trackType: z.string(),
  track_id: z.string(),
  maxWidth: z.number(),
  maxHeight: z.number(),
  drmHeader: z.object({
    bytes: z.string().optional(),
    keyId: z.string().optional(),
  }).passthrough().optional(),
  streams: z.array(VideoStreamResponseSchema).default([]),
}).passthrough();

export const AudioTrackResponseSchema = z.object({
  language: z.string(),
  languageDescription: z.string(),
  channels: z.string(),
  trackType: z.string(),
  track_id: z.string(),
  streams: z.array(AudioStreamResponseSchema).default([]),
}).passthrough();

export const TextTrackResponseSchema = z.object({
  language: z.unknown(),
  languageDescription: z.unknown(),
  trackType: z.unknown(),
  downloadableId: z.unknown(),
  isNoneTrack: z.boolean().default(false),
  ttDownloadables: z.unknown().default({}),
}).passthrough();

export const ManifestResultSchema = z.object({
  movieId: z.union([z.string(), z.number()]).transform(String).optional(),
  duration: z.number().optional(),
  video_tracks: z.array(VideoTrackResponseSchema).optional(),
  audio_tracks: z.array(AudioTrackResponseSchema).optional(),
  timedtexttracks: z.array(TextTrackResponseSchema).optional(),
  servers: z.array(z.unknown()).optional(),
}).passthrough();

// payload.result で包まれている場合
export const ManifestPayloadSchema = z.object({
  result: ManifestResultSchema,
}).passthrough();

// ── ALE Provision ──

export const KeyxDataSchema = z.object({
  scheme: z.literal("CLEAR"),
  kid: z.string(),
  data: z.object({
    key: z.string(),
  }).passthrough(),
}).passthrough();

export const ProvisionTokenSchema = z.object({
  keyx: KeyxDataSchema,
  token: z.string().default(""),
}).passthrough();

export const ProvisionResultSchema = z.object({
  provisionResponse: z.string(),
}).passthrough();

// ── MSL Envelope ──

export const MSLPayloadChunkSchema = z.object({
  data: z.string().optional(),
  compressionalgo: z.string().nullable().optional(),
}).passthrough();

export const MSLServiceTokenSchema = z.object({
  tokendata: z.string().optional(),
}).passthrough();

export const MSLUserIdTokenSchema = z.object({
  tokendata: z.string().optional(),
}).passthrough();

export const MSLEnvelopeSchema = z.object({
  headerdata: z.string().optional(),
  payload: z.string().optional(),
  payloads: z.array(z.unknown()).optional(),
  data: z.string().optional(),
  messageid: z.number().optional(),
  compressionalgo: z.string().nullable().optional(),
  endofmsg: z.boolean().optional(),
  sender: z.string().optional(),
  servicetokens: z.array(MSLServiceTokenSchema).optional(),
  useridtoken: MSLUserIdTokenSchema.optional(),
}).passthrough();

export type MSLEnvelope = z.infer<typeof MSLEnvelopeSchema>;

// ── MSL Headerdata (decoded from base64) ──

export const MSLHeaderdataSchema = z.object({
  sender: z.string().optional(),
}).passthrough();

// ── MSL Service Token Data ──

export const MSLTokenDataSchema = z.object({
  name: z.string().optional(),
  servicedata: z.string().optional(),
}).passthrough();

// ── Profile Override リクエストペイロード ──

export const ManifestRequestPayloadSchema = z.object({
  url: z.string(),
  params: z.object({
    profiles: z.array(z.string()),
  }).passthrough(),
}).passthrough();

// LZW 圧縮チャンク
export const LZWChunkSchema = z.object({
  compressionalgo: z.literal("LZW"),
  data: z.string(),
}).passthrough();

// ── Bridge Messages (inject → bridge) ──

export const BridgeMessageSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("__MSL_SETTINGS_REQUEST__") }),
  z.object({ type: z.literal("__MSL_SETTINGS_SAVE__"), settings: SettingsSchema }),
  z.object({ type: z.literal("__MSL_CAPTURE_LOG__"), payload: z.unknown() }),
  z.object({ type: z.literal("__MSL_CAPTURE_SAVE_FILE__"), filename: z.string(), content: z.unknown(), mimeType: z.string().default("application/json") }),
  z.object({ type: z.literal("__MSL_CAPTURE_SAVE_NOW__") }),
  z.object({ type: z.literal("__MSL_CAPTURE_DOWNLOAD_STREAM__"), url: z.string(), filename: z.string(), size: z.number().optional() }),
]);

export type BridgeMessage = z.infer<typeof BridgeMessageSchema>;

// ── Bridge → inject レスポンスメッセージ ──

export const SettingsLoadMessageSchema = z.object({
  type: z.literal("__MSL_SETTINGS_LOAD__"),
  settings: SettingsSchema.nullable(),
});

export const DownloadResultMessageSchema = z.object({
  type: z.literal("__MSL_CAPTURE_DOWNLOAD_RESULT__"),
  ok: z.boolean(),
  downloadId: z.number().optional(),
  error: z.string().optional(),
});

// ── Background Messages (bridge → background) ──

export const BackgroundMessageSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("msl-get-settings") }),
  z.object({ type: z.literal("msl-set-settings"), settings: SettingsSchema }),
  z.object({ type: z.literal("msl-capture-log"), data: z.unknown() }),
  z.object({ type: z.literal("msl-capture-save-now") }),
  z.object({ type: z.literal("msl-capture-download-stream"), url: z.string(), filename: z.string(), size: z.number().optional() }),
  z.object({ type: z.literal("msl-capture-save-file"), filename: z.string(), content: z.unknown(), mimeType: z.string().default("application/json") }),
]);

export type BackgroundMessage = z.infer<typeof BackgroundMessageSchema>;

// ── Background レスポンス ──

export const SettingsGetResponseSchema = z.object({
  ok: z.boolean(),
  settings: SettingsSchema.nullable(),
});

export const DownloadStreamResponseSchema = z.object({
  ok: z.boolean(),
  downloadId: z.number().optional(),
  error: z.string().optional(),
});

// ── JWE Header ──

export const JWEHeaderSchema = z.object({
  alg: z.string().optional(),
  enc: z.string().optional(),
}).passthrough();

// ── Zod パースヘルパー ──

export function zodParse<T>(schema: z.ZodType<T>, data: unknown): T | null {
  const result = schema.safeParse(data);
  return result.success ? result.data : null;
}

export function zodParseJSON<T>(schema: z.ZodType<T>, text: string | null): T | null {
  if (!text) return null;
  try {
    return zodParse(schema, JSON.parse(text));
  } catch {
    return null;
  }
}
