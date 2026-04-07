export const SEP = "======================================================================";
export const SEP2 = "----------------------------------------------------------------------";

export function ts(): string {
    return new Date().toISOString();
}

export function bytesToHex(buf: ArrayBuffer): string {
    const arr = new Uint8Array(buf);
    let hex = "";
    for (let i = 0; i < arr.length; i++) {
        const b = arr[i].toString(16);
        hex += (b.length === 1 ? "0" : "") + b;
    }
    return hex;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function bytesToBase64(buf: ArrayBuffer): string {
    const arr = new Uint8Array(buf);
    const len = arr.length;
    let out = "";
    for (let i = 0; i < len; i += 3) {
        const b0 = arr[i], b1 = i + 1 < len ? arr[i + 1] : 0, b2 = i + 2 < len ? arr[i + 2] : 0;
        out += B64[b0 >> 2] + B64[((b0 & 3) << 4) | (b1 >> 4)];
        out += i + 1 < len ? B64[((b1 & 15) << 2) | (b2 >> 6)] : "=";
        out += i + 2 < len ? B64[b2 & 63] : "=";
    }
    return out;
}

export function logData(event: string, info?: Record<string, any>, data?: ArrayBuffer): void {
    const payload: Record<string, any> = { event: event, ts: ts() };
    if (info) {
        for (const k in info) payload[k] = info[k];
    }
    if (data) {
        payload.data_hex = bytesToHex(data);
        payload.data_size = data.byteLength;
    }
    console.log("@@LOG@@" + JSON.stringify(payload));
}

// ── 共通コンソールロガー ──

export function logMsl(operation: string, detail: string): void {
    console.log("[MSL] " + operation + " " + detail);
}

export function logDrm(detail: string): void {
    console.log("[DRM] " + detail);
}

export function logAle(detail: string): void {
    console.log("[ALE] " + detail);
}

export function logHttpReq(method: string, url: string, bodySize: number, headerCount: number): void {
    console.log("  > " + method + " " + url + " (" + bodySize + "B, " + headerCount + " headers)");
}

export function logHttpResp(status: number, url: string, bodySize: number, headerCount: number): void {
    console.log("  < " + status + " " + url + " (" + bodySize + "B, " + headerCount + " headers)");
}
