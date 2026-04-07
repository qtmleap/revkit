// ── MSL メッセージプロセッサー ──
// Chrome extension と同等のログを Frida 環境で出力する
// - MSL エンベロープのデコード (headerdata, payload, servicetokens, useridtoken)
// - ALE 鍵の抽出 (keyx.scheme=CLEAR)
// - ESN の抽出・追跡
// - マニフェストの抽出 (video/audio/text tracks)

import { base64ToString, base64urlToBytes, bytesToHexStr, utf8Decode } from "./base64";
import { decodeLZW } from "./lzw";
import { logData } from "./utils";

// ────────────────────────────────────────────────────────────
// Utility
// ────────────────────────────────────────────────────────────

function tryParseJSON(text: string | null): any {
    if (!text) return null;
    try { return JSON.parse(text); } catch { return null; }
}

function tryDecodeB64(str: string): string | null {
    return base64ToString(str);
}

// ────────────────────────────────────────────────────────────
// ESN Tracking
// ────────────────────────────────────────────────────────────

const IOS_ESN_RE = /^NF[A-Z0-9]+-/i;

interface EsnData {
    esn: string | null;
    capturedAt: string | null;
}

const esnState: EsnData = { esn: null, capturedAt: null };

export function maybeUpdateEsn(value: string): void {
    if (!value || !IOS_ESN_RE.test(value)) return;
    if (esnState.esn === value) return;
    esnState.esn = value;
    esnState.capturedAt = new Date().toISOString();
    logData("esn.detected", {
        esn: value,
    });
}

export function maybeUpdateEsnFromHeader(headers: Record<string, string>): void {
    const esn = headers["x-netflix.esn"] || headers["X-Netflix.esn"] || headers["X-Netflix-ESN"];
    if (esn) maybeUpdateEsn(esn);
}

// ────────────────────────────────────────────────────────────
// MSL Envelope Decoder
// ────────────────────────────────────────────────────────────

function decodeChunkData(dataStr: string, compressionalgo: string | null): any {
    if (!dataStr) return null;
    if (compressionalgo === "LZW") {
        const decompressed = decodeLZW(dataStr);
        if (decompressed) return tryParseJSON(decompressed) ?? decompressed;
    }
    const inner = tryDecodeB64(dataStr);
    if (inner) return tryParseJSON(inner) ?? inner;
    return null;
}

interface DecodedMSL {
    envelope: any;
    header: any;
    useridtoken: any;
    servicetokens: any[];
    payload: any;
    payloads: any[];
    sender: string | null;
}

function deepDecodeMSL(obj: any): DecodedMSL {
    const result: DecodedMSL = {
        envelope: obj,
        header: null,
        useridtoken: null,
        servicetokens: [],
        payload: null,
        payloads: [],
        sender: null,
    };

    if (!obj || typeof obj !== "object") return result;

    const compress = obj.compressionalgo ?? null;

    // sender (ESN)
    if (typeof obj.sender === "string") {
        result.sender = obj.sender;
    }

    // headerdata → base64 decode → JSON parse
    if (typeof obj.headerdata === "string") {
        const hdr = tryParseJSON(tryDecodeB64(obj.headerdata));
        if (hdr && typeof hdr === "object") {
            result.header = hdr;
            if (typeof hdr.sender === "string" && !result.sender) {
                result.sender = hdr.sender;
            }
        }
    }

    // payload → base64 decode → JSON (MSLPayloadChunk) → data decode
    if (typeof obj.payload === "string") {
        const chunkRaw = tryParseJSON(tryDecodeB64(obj.payload));
        if (chunkRaw && typeof chunkRaw === "object") {
            if (chunkRaw.data) {
                const algo = chunkRaw.compressionalgo ?? compress;
                result.payload = decodeChunkData(chunkRaw.data, algo);
            }
        }
    }

    // data field (used in some MSL envelope formats)
    if (typeof obj.data === "string" && obj.messageid !== undefined) {
        result.payload = result.payload ?? decodeChunkData(obj.data, compress);
    }

    // payloads[] → each chunk decoded
    if (Array.isArray(obj.payloads)) {
        result.payloads = obj.payloads.map((p: any) => {
            if (typeof p === "string") {
                const chunkRaw = tryParseJSON(tryDecodeB64(p));
                if (chunkRaw && typeof chunkRaw === "object" && chunkRaw.data) {
                    const algo = chunkRaw.compressionalgo ?? compress;
                    return { _chunk: chunkRaw, _data: decodeChunkData(chunkRaw.data, algo) };
                }
                return chunkRaw ?? p;
            }
            return p;
        });
    }

    // servicetokens[] → tokendata decode → servicedata decode
    if (Array.isArray(obj.servicetokens)) {
        result.servicetokens = obj.servicetokens.map((st: any) => {
            if (st && typeof st.tokendata === "string") {
                const tdRaw = tryParseJSON(tryDecodeB64(st.tokendata));
                if (tdRaw && typeof tdRaw === "object") {
                    const decoded: any = { ...tdRaw };
                    if (tdRaw.servicedata) {
                        const sd = tryDecodeB64(tdRaw.servicedata);
                        decoded._servicedata_decoded = sd ? tryParseJSON(sd) ?? sd : null;
                    }
                    return decoded;
                }
            }
            return st;
        });
    }

    // useridtoken → tokendata decode
    if (obj.useridtoken && typeof obj.useridtoken === "object") {
        if (typeof obj.useridtoken.tokendata === "string") {
            result.useridtoken = tryParseJSON(tryDecodeB64(obj.useridtoken.tokendata));
        }
    }

    return result;
}

// ────────────────────────────────────────────────────────────
// ALE Key Extraction
// ────────────────────────────────────────────────────────────

interface AleKeys {
    encryptionKey: string;
    hmacKey: string;
    kid: string;
    jweToken: string;
    scheme: string;
    rawKeyHex: string;
    capturedAt: string;
}

function extractAleKeys(payload: any): AleKeys | null {
    if (!payload || typeof payload !== "object") return null;

    // provisionResponse field in the result
    const provResponse = payload.provisionResponse;
    if (!provResponse || typeof provResponse !== "string") return null;

    // iOS: base64 エンコード, Android: 直接 JSON
    let tokenObj = tryParseJSON(tryDecodeB64(provResponse));
    if (!tokenObj) tokenObj = tryParseJSON(provResponse);
    if (!tokenObj || typeof tokenObj !== "object") return null;

    const keyx = tokenObj.keyx;
    if (!keyx || !keyx.data) return null;

    // scheme=CLEAR: data.key (平文鍵), scheme=RSA-OAEP-256: data.wrappedkey (ラップ鍵)
    const rawKey = keyx.data.key || keyx.data.wrappedkey;
    if (!rawKey) return null;

    const keyBytes = base64urlToBytes(rawKey);
    if (!keyBytes || keyBytes.length < 16) return null;

    const hmacHex = bytesToHexStr(keyBytes.slice(0, 16));
    const aesHex = bytesToHexStr(keyBytes.slice(16, 32));

    // JWE header info
    const jweToken = tokenObj.token || "";
    let jweAlg = "?";
    let jweEnc = "?";
    if (jweToken) {
        try {
            const parts = jweToken.split(".");
            if (parts.length === 5) {
                const hdrStr = tryDecodeB64(parts[0].replace(/-/g, "+").replace(/_/g, "/"));
                const hdr = tryParseJSON(hdrStr);
                if (hdr) {
                    jweAlg = hdr.alg ?? "?";
                    jweEnc = hdr.enc ?? "?";
                }
            }
        } catch { /* ignore */ }
    }

    logData("ale.keys", {
        hmacKey: hmacHex,
        encryptionKey: aesHex,
        kid: keyx.kid,
        scheme: keyx.scheme,
        jweAlg: jweAlg,
        jweEnc: jweEnc,
        rawKeyHex: bytesToHexStr(keyBytes),
    });

    return {
        encryptionKey: aesHex,
        hmacKey: hmacHex,
        kid: keyx.kid,
        jweToken: jweToken,
        scheme: keyx.scheme,
        rawKeyHex: bytesToHexStr(keyBytes),
        capturedAt: new Date().toISOString(),
    };
}

// ────────────────────────────────────────────────────────────
// Manifest Extraction
// ────────────────────────────────────────────────────────────

function formatKID(hex: string): string | null {
    if (!hex || hex.length !== 32) return hex || null;
    return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
}

function extractManifest(payload: any): void {
    if (!payload || typeof payload !== "object") return;

    const rawResult = payload.result ?? payload;
    if (!rawResult || typeof rawResult !== "object") return;
    if (!rawResult.video_tracks && !rawResult.audio_tracks) return;

    const movieId = rawResult.movieId != null ? String(rawResult.movieId) : null;
    const duration = rawResult.duration ?? null;

    // Video tracks
    const videoTracks: any[] = [];
    if (Array.isArray(rawResult.video_tracks)) {
        for (const vt of rawResult.video_tracks) {
            const streams: any[] = [];
            if (Array.isArray(vt.streams)) {
                for (const s of vt.streams) {
                    streams.push({
                        res_w: s.res_w,
                        res_h: s.res_h,
                        bitrate: s.bitrate,
                        size: s.size,
                        vmaf: s.vmaf,
                        content_profile: s.content_profile,
                        downloadable_id: s.downloadable_id,
                        kid: formatKID(s.drmHeaderId ?? ""),
                    });
                }
            }
            videoTracks.push({
                trackType: vt.trackType,
                track_id: vt.track_id,
                maxWidth: vt.maxWidth,
                maxHeight: vt.maxHeight,
                streams: streams,
            });
        }
    }

    // Audio tracks
    const audioTracks: any[] = [];
    if (Array.isArray(rawResult.audio_tracks)) {
        for (const at of rawResult.audio_tracks) {
            const streams: any[] = [];
            if (Array.isArray(at.streams)) {
                for (const s of at.streams) {
                    streams.push({
                        bitrate: s.bitrate,
                        size: s.size,
                        content_profile: s.content_profile,
                        downloadable_id: s.downloadable_id,
                    });
                }
            }
            audioTracks.push({
                language: at.language,
                languageDescription: at.languageDescription,
                channels: at.channels,
                trackType: at.trackType,
                track_id: at.track_id,
                streams: streams,
            });
        }
    }

    // Text tracks
    const textTracks: any[] = [];
    if (Array.isArray(rawResult.timedtexttracks)) {
        for (const tt of rawResult.timedtexttracks) {
            if (tt.isNoneTrack) continue;
            textTracks.push({
                language: tt.language,
                languageDescription: tt.languageDescription,
                trackType: tt.trackType,
                downloadableId: tt.downloadableId,
            });
        }
    }

    const totalVideo = videoTracks.reduce((n: number, t: any) => n + (t.streams ? t.streams.length : 0), 0);
    const totalAudio = audioTracks.reduce((n: number, t: any) => n + (t.streams ? t.streams.length : 0), 0);

    logData("manifest", {
        movieId: movieId,
        duration: duration,
        videoStreams: totalVideo,
        audioStreams: totalAudio,
        textTracks: textTracks.length,
        videoTracks: videoTracks,
        audioTracks: audioTracks,
        textTracks_detail: textTracks,
    });

    // KID table (video streams grouped by resolution and KID)
    const kidRows: any[] = [];
    for (const vt of videoTracks) {
        let lastKid = "";
        for (const s of vt.streams) {
            const boundary = s.kid !== lastKid && lastKid !== "";
            kidRows.push({
                res: s.res_w + "x" + s.res_h,
                bitrate: s.bitrate,
                kid: s.kid,
                content_profile: s.content_profile,
                boundary: boundary,
            });
            lastKid = s.kid || lastKid;
        }
    }

    if (kidRows.length > 0) {
        logData("manifest.kidTable", {
            movieId: movieId,
            rows: kidRows,
        });
    }
}

// ────────────────────────────────────────────────────────────
// Chunk Accumulator (multi-part manifest reassembly)
// ────────────────────────────────────────────────────────────

let chunkState: { chunks: string[]; msgId: number | null } = { chunks: [], msgId: null };

function accumulateChunks(envelope: any, decodedPayload: any): void {
    // Skip if already a manifest
    if (decodedPayload && typeof decodedPayload === "object") {
        const pd = decodedPayload as Record<string, any>;
        if (pd.result && typeof pd.result === "object" && pd.result.video_tracks) return;
    }

    const msgId = envelope.messageid as number | undefined;
    const data = envelope.data;
    const endofmsg = envelope.endofmsg as boolean | undefined;

    if (!data || typeof data !== "string") return;
    if (msgId !== chunkState.msgId) {
        chunkState.chunks = [];
        chunkState.msgId = msgId ?? null;
    }
    chunkState.chunks.push(data);

    if (endofmsg) {
        try {
            const algo = (envelope.compressionalgo as string) || "LZW";
            const combined = chunkState.chunks
                .map((d: string) => {
                    if (algo === "LZW") return decodeLZW(d) || "";
                    return tryDecodeB64(d) || "";
                })
                .join("");
            const parsed = tryParseJSON(combined);
            if (parsed && parsed.result) {
                if (parsed.result.video_tracks || parsed.result.audio_tracks) {
                    extractManifest(parsed);
                }
            }
        } catch (e) {
            console.log("[-] Manifest chunk reassembly error: " + e);
        }
        chunkState.chunks = [];
        chunkState.msgId = null;
    }
}

// ────────────────────────────────────────────────────────────
// Public API: Process decrypted MSL plaintext
// ────────────────────────────────────────────────────────────

let mslSeq = 0;

export function processMslPlaintext(
    plaintextBytes: ArrayBuffer,
    direction: "encrypt" | "decrypt",
    algorithm: string,
): void {
    const bytes = new Uint8Array(plaintextBytes);

    // バイナリデータ (CBOR 等) を早期にスキップ
    // JSON は '{' (0x7b) または '[' (0x5b) で始まる
    // CBOR MSL エンベロープも内部に JSON を含むことがあるので、
    // JSON 開始文字を探す
    let jsonStart = -1;
    for (let i = 0; i < Math.min(bytes.length, 256); i++) {
        if (bytes[i] === 0x7b || bytes[i] === 0x5b) {
            jsonStart = i;
            break;
        }
    }
    if (jsonStart === -1) return; // JSON が見つからない → バイナリデータ

    let text: string;
    try {
        // JSON 部分のみをデコード (先頭のバイナリヘッダをスキップ)
        text = utf8Decode(bytes.slice(jsonStart));
        // サロゲートペア等の不正文字を除去
        text = text.replace(/[\uD800-\uDFFF]/g, "?");
    } catch {
        return;
    }

    // JSON 末尾以降のゴミを除去 (CBOR フッタ)
    const lastBrace = text.lastIndexOf("}");
    const lastBracket = text.lastIndexOf("]");
    const jsonEnd = Math.max(lastBrace, lastBracket);
    if (jsonEnd > 0) {
        text = text.substring(0, jsonEnd + 1);
    }

    const json = tryParseJSON(text);
    if (!json || typeof json !== "object") {
        // Non-JSON plaintext
        if (text.length > 0 && text.length < 65536) {
            mslSeq++;
            logData("msl.message", {
                seq: mslSeq,
                direction: direction,
                algorithm: algorithm,
                size: text.length,
                format: "text",
                data: text.substring(0, 8192),
            });
        }
        return;
    }

    // Decode MSL envelope
    const decoded = deepDecodeMSL(json);

    // ESN extraction
    if (decoded.sender) maybeUpdateEsn(decoded.sender);

    // Build summary for console
    let summary = "";
    if (decoded.payload && typeof decoded.payload === "object") {
        const pd = decoded.payload;
        if (pd.method) summary = " method=" + pd.method;
        else if (pd.url) summary = " url=" + pd.url;
    }

    // コンソール出力は抑制 (@@LOG@@ でログファイルに記録される)

    // Log decoded MSL message
    mslSeq++;
    logData("msl.message", {
        seq: mslSeq,
        direction: direction,
        algorithm: algorithm,
        size: text.length,
        format: "json",
        envelope: json,
        header: decoded.header,
        useridtoken: decoded.useridtoken,
        servicetokens: decoded.servicetokens.length > 0 ? decoded.servicetokens : null,
        payload: decoded.payload,
        payloads: decoded.payloads.length > 0 ? decoded.payloads : null,
    });

    // Process decrypted payloads
    if (direction === "decrypt" && decoded.payload && typeof decoded.payload === "object") {
        const pd = decoded.payload;
        const result = pd.result ?? pd;

        // Manifest detection
        if (result && typeof result === "object" && (result.video_tracks || result.audio_tracks)) {
            try { extractManifest(pd); } catch (e) {
                console.log("[-] extractManifest error: " + e);
            }
        }

        // ALE key detection
        try {
            extractAleKeys(result);
        } catch (e) {
            console.log("[-] extractAleKeys error: " + e);
        }
    }

    // Chunk accumulation for multi-part manifests
    if (direction === "decrypt") {
        accumulateChunks(json, decoded.payload);
    }
}

// ────────────────────────────────────────────────────────────
// Public API: Process MSL API response (from IosMslClient)
// ────────────────────────────────────────────────────────────

export function processMslApiResponse(url: string, responseStr: string | null): void {
    if (!responseStr) return;

    const json = tryParseJSON(responseStr);
    if (!json || typeof json !== "object") return;

    // If the response itself is an MSL envelope, decode it
    if (json.headerdata || json.payload || json.payloads) {
        const decoded = deepDecodeMSL(json);
        if (decoded.sender) maybeUpdateEsn(decoded.sender);

        if (decoded.payload && typeof decoded.payload === "object") {
            const pd = decoded.payload;
            const result = pd.result ?? pd;

            // Manifest
            if (result && typeof result === "object" && (result.video_tracks || result.audio_tracks)) {
                try { extractManifest(pd); } catch (e) {
                    console.log("[-] extractManifest from API response: " + e);
                }
            }

            // ALE keys
            try { extractAleKeys(result); } catch (e) {
                console.log("[-] extractAleKeys from API response: " + e);
            }
        }
        return;
    }

    // Direct response object (not MSL-wrapped)
    // Check for manifest
    if (json.result && typeof json.result === "object") {
        const result = json.result;
        if (result.video_tracks || result.audio_tracks) {
            try { extractManifest(json); } catch (e) {
                console.log("[-] extractManifest from direct response: " + e);
            }
        }
    }

    // Check for ALE keys
    try { extractAleKeys(json.result ?? json); } catch (e) { /* ignore */ }
}
