import { bytesToBase64 } from "../common/utils";

// Java byte[] -> ArrayBuffer
export function jbyteArrayToArrayBuffer(jarray: any): ArrayBuffer | null {
    if (!jarray) return null;
    const len = jarray.length;
    if (len === 0) return new ArrayBuffer(0);
    const buf = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buf[i] = jarray[i] & 0xff;
    }
    return buf.buffer;
}

// Java byte[] -> base64 string
export function jbyteArrayToBase64(jarray: any): string | null {
    if (!jarray) return null;
    const len = jarray.length;
    if (len === 0) return "";
    const buf = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buf[i] = jarray[i] & 0xff;
    }
    return bytesToBase64(buf.buffer);
}

// Java byte[] -> UTF-8 JS string (best effort)
export function jbyteArrayToString(jarray: any): string | null {
    if (!jarray) return null;
    try {
        const String = Java.use("java.lang.String");
        // .toString() converts Java String -> JS string for JSON.stringify
        return String.$new(jarray, "UTF-8").toString();
    } catch (e) { return null; }
}

// Java byte[] から NFANDROID ESN を抽出
export function extractEsnFromBytes(jarray: any): string | null {
    if (!jarray) return null;
    const len = jarray.length;
    let str = "";
    for (let i = 0; i < len; i++) {
        const b = jarray[i] & 0xff;
        if (b >= 0x20 && b <= 0x7e) {
            str += String.fromCharCode(b);
        } else {
            str += "\x00";
        }
    }
    const match = str.match(/NFANDROID1-[A-Z0-9=\-]+/);
    return match ? match[0] : null;
}

// Java byte[] から readable な ASCII 文字列を抽出 (8文字以上)
export function extractStringsFromBytes(jarray: any): string[] {
    if (!jarray) return [];
    const len = jarray.length;
    const results: string[] = [];
    let cur = "";
    for (let i = 0; i < len; i++) {
        const b = jarray[i] & 0xff;
        if (b >= 0x20 && b <= 0x7e) {
            cur += String.fromCharCode(b);
        } else {
            if (cur.length >= 8) results.push(cur);
            cur = "";
        }
    }
    if (cur.length >= 8) results.push(cur);
    return results;
}
