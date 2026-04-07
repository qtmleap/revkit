// ── Base64 / Base64URL デコードユーティリティ ──

const B64_LOOKUP: Record<string, number> = {};
const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
for (let i = 0; i < B64_CHARS.length; i++) B64_LOOKUP[B64_CHARS[i]] = i;

export function base64ToBytes(b64: string): Uint8Array | null {
    try {
        const clean = b64.replace(/[\r\n\s]/g, "").replace(/=+$/, "");
        const len = clean.length;
        const outLen = (len * 3) >> 2;
        const out = new Uint8Array(outLen);
        let j = 0;
        for (let i = 0; i < len; i += 4) {
            const a = B64_LOOKUP[clean[i]] ?? 0;
            const b = B64_LOOKUP[clean[i + 1]] ?? 0;
            const c = i + 2 < len ? (B64_LOOKUP[clean[i + 2]] ?? 0) : 0;
            const d = i + 3 < len ? (B64_LOOKUP[clean[i + 3]] ?? 0) : 0;
            out[j++] = (a << 2) | (b >> 4);
            if (i + 2 < len) out[j++] = ((b & 15) << 4) | (c >> 2);
            if (i + 3 < len) out[j++] = ((c & 3) << 6) | d;
        }
        return out.slice(0, j);
    } catch {
        return null;
    }
}

export function base64ToString(b64: string): string | null {
    const bytes = base64ToBytes(b64);
    if (!bytes) return null;
    return utf8Decode(bytes);
}

export function base64urlToBytes(b64url: string): Uint8Array | null {
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (b64.length % 4)) % 4;
    return base64ToBytes(b64 + "=".repeat(pad));
}

export function utf8Decode(bytes: Uint8Array): string {
    let str = "";
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        if (b < 0x80) {
            str += String.fromCharCode(b);
        } else if (b < 0xc0) {
            str += "?";
        } else if (b < 0xe0) {
            const b2 = bytes[++i] & 0x3f;
            str += String.fromCharCode(((b & 0x1f) << 6) | b2);
        } else if (b < 0xf0) {
            const b2 = bytes[++i] & 0x3f;
            const b3 = bytes[++i] & 0x3f;
            str += String.fromCharCode(((b & 0x0f) << 12) | (b2 << 6) | b3);
        } else {
            const b2 = bytes[++i] & 0x3f;
            const b3 = bytes[++i] & 0x3f;
            const b4 = bytes[++i] & 0x3f;
            const cp = ((b & 0x07) << 18) | (b2 << 12) | (b3 << 6) | b4;
            if (cp > 0xffff) {
                str += String.fromCharCode(0xd800 + ((cp - 0x10000) >> 10));
                str += String.fromCharCode(0xdc00 + ((cp - 0x10000) & 0x3ff));
            } else {
                str += String.fromCharCode(cp);
            }
        }
    }
    return str;
}

export function bytesToHexStr(bytes: Uint8Array): string {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i].toString(16);
        hex += (b.length === 1 ? "0" : "") + b;
    }
    return hex;
}
