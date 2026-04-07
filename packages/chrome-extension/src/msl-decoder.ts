// ── MSL メッセージデコーダー ──

import type { DecodedMSL } from "./types";
import { tryDecodeB64, tryParseJSON, decodeLZW } from "./utils";
import {
  MSLEnvelopeSchema,
  MSLPayloadChunkSchema,
  MSLTokenDataSchema,
  zodParse,
} from "./schemas";

function decodeChunkData(dataStr: string, compressionalgo: string | null): unknown {
  if (!dataStr) return null;
  if (compressionalgo === "LZW") {
    const decompressed = decodeLZW(dataStr);
    if (decompressed) return tryParseJSON(decompressed) ?? decompressed;
  }
  const inner = tryDecodeB64(dataStr);
  if (inner) return tryParseJSON(inner) ?? inner;
  return null;
}

export function deepDecodeMSL(obj: unknown): DecodedMSL {
  if (!obj || typeof obj !== "object") return obj as DecodedMSL;

  const parsed = zodParse(MSLEnvelopeSchema, obj);
  const decoded: DecodedMSL = { ...(obj as Record<string, unknown>) };
  const compress = parsed?.compressionalgo ?? null;

  if (typeof decoded.headerdata === "string") {
    const hdr = tryParseJSON(tryDecodeB64(decoded.headerdata));
    if (hdr && typeof hdr === "object") decoded._headerdata_decoded = hdr as Record<string, unknown>;
  }

  if (typeof decoded.payload === "string") {
    const chunkRaw = tryParseJSON(tryDecodeB64(decoded.payload));
    const chunk = zodParse(MSLPayloadChunkSchema, chunkRaw);
    if (chunk) {
      decoded._payload_decoded = chunkRaw as Record<string, unknown>;
      if (chunk.data) {
        const algo = chunk.compressionalgo ?? compress;
        decoded._payload_data = decodeChunkData(chunk.data, algo);
      }
    }
  }

  if (typeof decoded.data === "string" && decoded.messageid !== undefined) {
    decoded._data_decoded = decodeChunkData(decoded.data, compress);
  }

  if (Array.isArray(decoded.payloads)) {
    decoded._payloads_decoded = decoded.payloads.map((p) => {
      if (typeof p === "string") {
        const chunkRaw = tryParseJSON(tryDecodeB64(p));
        const chunk = zodParse(MSLPayloadChunkSchema, chunkRaw);
        if (chunk?.data) {
          const algo = chunk.compressionalgo ?? compress;
          const inner = decodeChunkData(chunk.data, algo);
          return { _chunk: chunkRaw, _data: inner };
        }
        return chunkRaw ?? p;
      }
      return p;
    });
  }

  if (Array.isArray(decoded.servicetokens)) {
    decoded._servicetokens_decoded = (decoded.servicetokens as Record<string, unknown>[]).map((st) => {
      if (typeof st.tokendata === "string") {
        const tdRaw = tryParseJSON(tryDecodeB64(st.tokendata));
        const td = zodParse(MSLTokenDataSchema, tdRaw);
        if (td) {
          const result: Record<string, unknown> = { ...td };
          if (td.servicedata) {
            const sd = tryDecodeB64(td.servicedata);
            result._servicedata_decoded = sd ? tryParseJSON(sd) ?? sd : null;
          }
          return result;
        }
      }
      return st;
    });
  }

  if (decoded.useridtoken && typeof decoded.useridtoken === "object") {
    const uit = decoded.useridtoken as Record<string, unknown>;
    if (typeof uit.tokendata === "string") {
      decoded._useridtoken_decoded = tryParseJSON(tryDecodeB64(uit.tokendata));
    }
  }

  return decoded;
}

export function extractDecodedPayload(expanded: DecodedMSL): unknown {
  return expanded._data_decoded ?? expanded._payload_data ?? expanded._payload_decoded ?? null;
}
