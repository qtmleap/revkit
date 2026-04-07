// ── マニフェストデータ抽出 ──

import type { ManifestData, VideoTrack, AudioTrack, StreamInfo } from "./types";
import { decodeLZW, tryParseJSON, tryDecodeB64 } from "./utils";
import { ManifestResultSchema, zodParse } from "./schemas";

function formatDrmHeaderId(hex: string): string | null {
  if (hex.length !== 32) return hex || null;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function extractManifestData(payload: unknown, manifestData: ManifestData): boolean {
  if (!payload || typeof payload !== "object") return false;

  const p = payload as Record<string, unknown>;
  const rawResult = (p.result ?? p) as unknown;
  const result = zodParse(ManifestResultSchema, rawResult);
  if (!result) return false;
  if (!result.video_tracks && !result.audio_tracks) return false;

  manifestData.movieId = result.movieId != null ? String(result.movieId) : null;
  manifestData.duration = result.duration ?? null;
  manifestData.servers = result.servers ?? [];
  manifestData.raw = rawResult;

  if (result.video_tracks) {
    manifestData.videoTracks = result.video_tracks.map((vt): VideoTrack => ({
      trackType: vt.trackType,
      track_id: vt.track_id,
      maxWidth: vt.maxWidth,
      maxHeight: vt.maxHeight,
      drmHeader: vt.drmHeader
        ? { bytes: vt.drmHeader.bytes, keyId: vt.drmHeader.keyId }
        : undefined,
      streams: (vt.streams ?? []).map((s): StreamInfo => ({
        res_w: s.res_w,
        res_h: s.res_h,
        bitrate: s.bitrate,
        size: s.size,
        vmaf: s.vmaf,
        content_profile: s.content_profile,
        downloadable_id: s.downloadable_id,
        kid: formatDrmHeaderId(s.drmHeaderId ?? ""),
        urls: (s.urls ?? []) as (string | { url: string })[],
      })),
    }));
  }

  if (result.audio_tracks) {
    manifestData.audioTracks = result.audio_tracks.map((at): AudioTrack => ({
      language: at.language,
      languageDescription: at.languageDescription,
      channels: at.channels,
      trackType: at.trackType,
      track_id: at.track_id,
      streams: (at.streams ?? []).map((s) => ({
        bitrate: s.bitrate,
        size: s.size,
        content_profile: s.content_profile,
        downloadable_id: s.downloadable_id,
        urls: (s.urls ?? []) as (string | { url: string })[],
      })),
    }));
  }

  if (result.timedtexttracks) {
    manifestData.textTracks = result.timedtexttracks
      .filter((tt) => !tt.isNoneTrack)
      .map((tt) => ({
        language: tt.language,
        languageDescription: tt.languageDescription,
        trackType: tt.trackType,
        downloadableId: tt.downloadableId,
        urls: tt.ttDownloadables,
      }));
  }

  const totalVideo = manifestData.videoTracks.reduce((n, t) => n + t.streams.length, 0);
  const totalAudio = manifestData.audioTracks.reduce((n, t) => n + t.streams.length, 0);
  console.log(
    `[MSL-Capture] [Manifest] movieId=${manifestData.movieId}`,
    `video=${totalVideo} streams audio=${totalAudio} streams`,
  );
  return true;
}

// ── チャンクアキュムレータ ──

interface ChunkAccumState {
  chunks: string[];
  msgId: number | null;
}

export function createChunkAccumulator() {
  const state: ChunkAccumState = { chunks: [], msgId: null };

  return function accumulate(
    envelope: Record<string, unknown>,
    decodedPayload: unknown,
    manifestData: ManifestData,
    onSuccess: () => void,
  ): void {
    const p = decodedPayload as Record<string, unknown> | null;
    if (p?.result && typeof p.result === "object" && (p.result as Record<string, unknown>).video_tracks) return;

    const msgId = envelope.messageid as number | undefined;
    const data = envelope.data;
    const endofmsg = envelope.endofmsg as boolean | undefined;

    if (!data || typeof data !== "string") return;
    if (msgId !== state.msgId) {
      state.chunks = [];
      state.msgId = msgId ?? null;
    }
    state.chunks.push(data);

    if (endofmsg) {
      try {
        const algo = (envelope.compressionalgo as string) || "LZW";
        const combined = state.chunks
          .map((d) => {
            if (algo === "LZW") return decodeLZW(d) || "";
            const raw = tryDecodeB64(d);
            return raw || "";
          })
          .join("");
        const parsed = tryParseJSON(combined) as Record<string, unknown> | null;
        if (parsed?.result) {
          const r = parsed.result as Record<string, unknown>;
          if (r.video_tracks || r.audio_tracks) {
            if (extractManifestData(parsed, manifestData)) onSuccess();
          }
        }
      } catch (e) {
        console.warn("[MSL-Capture] Manifest chunk reassembly error:", e);
      }
      state.chunks = [];
      state.msgId = null;
    }
  };
}
