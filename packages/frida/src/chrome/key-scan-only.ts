/**
 * RSA Private Key Differential Scanner (Stalker-free)
 *
 * CDM プロセスにアタッチし、Interceptor/Stalker を一切使わず
 * Memory.scan のみで RSA 秘密鍵を検出する。
 *
 * 戦略:
 *   1. アタッチ直後にベースラインスキャン → 既存の鍵を記録
 *   2. Python 側から RPC でスキャンを繰り返し実行
 *   3. ベースラインに無い「新出の鍵」のみを報告
 *
 * これにより TLS セッション鍵等のノイズを排除し、
 * CDM がセッション生成時にデコードした鍵だけを捕捉できる。
 */

const CDM_MODULE = "libwidevinecdm.dylib";
const PKCS8_PATTERN = "30 82 ?? ?? 02 01 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01";
const PKCS1_PATTERN = "30 82 ?? ?? 02 01 00 02 82";

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function bytesToHex(buf: ArrayBuffer): string {
    const arr = new Uint8Array(buf);
    let hex = "";
    for (let i = 0; i < arr.length; i++) {
        const b = arr[i].toString(16);
        hex += (b.length === 1 ? "0" : "") + b;
    }
    return hex;
}

function bytesToBase64(buf: ArrayBuffer): string {
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

// console.log → send()
console.log = function (...args: any[]) {
    const msg = args.map(a => (typeof a === "string" ? a : JSON.stringify(a))).join(" ");
    send(msg);
};

function derSequenceLength(ptr: NativePointer): number {
    const tag = ptr.readU8();
    if (tag !== 0x30) return -1;
    const lenByte = ptr.add(1).readU8();
    if (lenByte === 0x82) {
        return 4 + ((ptr.add(2).readU8() << 8) | ptr.add(3).readU8());
    } else if (lenByte === 0x81) {
        return 2 + ptr.add(2).readU8();
    } else if (lenByte < 0x80) {
        return 2 + lenByte;
    }
    return -1;
}

function validateKey(ptr: NativePointer, format: "pkcs8" | "pkcs1"): { valid: boolean; totalLen: number } {
    try {
        const totalLen = derSequenceLength(ptr);
        if (totalLen < 600 || totalLen > 5000) return { valid: false, totalLen };
        if (ptr.add(4).readU8() !== 0x02 || ptr.add(5).readU8() !== 0x01 || ptr.add(6).readU8() !== 0x00) {
            return { valid: false, totalLen };
        }
        if (format === "pkcs8") {
            if (ptr.add(9).readU8() !== 0x06) return { valid: false, totalLen };
        } else {
            if (ptr.add(7).readU8() !== 0x02) return { valid: false, totalLen };
        }
        return { valid: true, totalLen };
    } catch (_e) {
        return { valid: false, totalLen: -1 };
    }
}

// ─── 状態管理 ───

/** ベースラインの鍵 (ハッシュ的に先頭64バイトの hex を使う) */
const baselineFingerprints: Set<string> = new Set();
let baselineCaptured = false;

/** 全発見鍵のフィンガープリント → 完全データ */
const allKeys: Map<string, { hex: string; b64: string; format: string; location: string; length: number }> = new Map();

/** 新出鍵 (ベースラインに無い) */
const newKeys: Map<string, { hex: string; b64: string; format: string; location: string; length: number }> = new Map();

function fingerprint(ptr: NativePointer, len: number): string {
    const fpLen = Math.min(len, 64);
    return bytesToHex(ptr.readByteArray(fpLen) as ArrayBuffer);
}

interface ScanResult {
    found: number;
    newFound: number;
    totalNew: number;
    keys: Array<{ format: string; location: string; length: number; key_b64: string; key_hex: string }>;
}

function scanAllRanges(): ScanResult {
    const cdmMod = Process.findModuleByName(CDM_MODULE);
    if (!cdmMod) {
        return { found: 0, newFound: 0, totalNew: newKeys.size, keys: [] };
    }

    const currentScanKeys: Array<{ format: string; location: string; length: number; key_b64: string; key_hex: string }> = [];
    let found = 0;
    let newFound = 0;

    function onKeyFound(address: NativePointer, totalLen: number, format: "pkcs8" | "pkcs1", label: string): void {
        const fp = fingerprint(address, totalLen);
        found++;

        if (allKeys.has(fp)) return; // 既知

        const keyHex = bytesToHex(address.readByteArray(totalLen) as ArrayBuffer);
        const keyB64 = bytesToBase64(address.readByteArray(totalLen) as ArrayBuffer);
        const entry = { hex: keyHex, b64: keyB64, format, location: label, length: totalLen };
        allKeys.set(fp, entry);

        if (baselineCaptured && !baselineFingerprints.has(fp)) {
            newFound++;
            newKeys.set(fp, entry);
            currentScanKeys.push({ format, location: label, length: totalLen, key_b64: keyB64, key_hex: keyHex });

            console.log("======================================================================");
            console.log("[!!!] NEW RSA Private Key (" + format.toUpperCase() + ")");
            console.log("  Location: " + label + " @ " + address);
            console.log("  Length: " + totalLen + " bytes");
            console.log("======================================================================");

            send("@@LOG@@" + JSON.stringify({
                event: "cdm.privateKey",
                format, location: label,
                address: address.toString(),
                length: totalLen,
                key_hex: keyHex,
                key_b64: keyB64,
                is_new: true,
            }));
        }
    }

    function scan(base: NativePointer, size: number, pattern: string, format: "pkcs8" | "pkcs1", label: string): void {
        try {
            Memory.scan(base, size, pattern, {
                onMatch(address: NativePointer, _size: number) {
                    const { valid, totalLen } = validateKey(address, format);
                    if (valid) onKeyFound(address, totalLen, format, label);
                },
                onComplete() {},
            });
        } catch (_e) {}
    }

    // CDM モジュール
    scan(cdmMod.base, cdmMod.size, PKCS8_PATTERN, "pkcs8", "cdm_module");
    scan(cdmMod.base, cdmMod.size, PKCS1_PATTERN, "pkcs1", "cdm_module");

    // ヒープ
    const ranges = Process.enumerateRanges("r--");
    const cdmBase = cdmMod.base;
    const cdmEnd = cdmMod.base.add(cdmMod.size);
    for (const range of ranges) {
        if (range.base.compare(cdmBase) >= 0 && range.base.compare(cdmEnd) < 0) continue;
        if (range.size < 1024 || range.size > 100 * 1024 * 1024) continue;
        scan(range.base, range.size, PKCS8_PATTERN, "pkcs8", "heap");
        scan(range.base, range.size, PKCS1_PATTERN, "pkcs1", "heap");
    }

    return { found, newFound, totalNew: newKeys.size, keys: currentScanKeys };
}

// ─── RPC エクスポート ───

rpc.exports = {
    /**
     * ベースラインスキャン: 現時点のメモリ上の鍵を全て記録し、
     * 以降のスキャンではこれらを除外する。
     */
    captureBaseline(): { baselineCount: number } {
        const result = scanAllRanges();
        for (const fp of allKeys.keys()) {
            baselineFingerprints.add(fp);
        }
        baselineCaptured = true;
        console.log("[*] Baseline captured: " + baselineFingerprints.size + " existing key(s)");
        return { baselineCount: baselineFingerprints.size };
    },

    /**
     * 差分スキャン: ベースライン以降に出現した新しい鍵を返す。
     */
    scan(): ScanResult {
        if (!baselineCaptured) {
            console.log("[!] Baseline not captured yet, call captureBaseline() first");
            return { found: 0, newFound: 0, totalNew: 0, keys: [] };
        }
        return scanAllRanges();
    },

    /**
     * 蓄積された全ての新出鍵を返す。
     */
    getNewKeys(): Array<{ format: string; location: string; length: number; key_b64: string; key_hex: string }> {
        const result: Array<{ format: string; location: string; length: number; key_b64: string; key_hex: string }> = [];
        for (const entry of newKeys.values()) {
            result.push({
                format: entry.format,
                location: entry.location,
                length: entry.length,
                key_b64: entry.b64,
                key_hex: entry.hex,
            });
        }
        return result;
    },

    getModuleInfo(): string {
        const cdmMod = Process.findModuleByName(CDM_MODULE);
        if (!cdmMod) return "not loaded";
        return JSON.stringify({
            base: cdmMod.base.toString(),
            size: cdmMod.size,
            path: cdmMod.path,
        });
    },
};

// ─── 起動メッセージ ───

const cdmMod = Process.findModuleByName(CDM_MODULE);
if (cdmMod) {
    console.log("[+] " + CDM_MODULE + " at " + cdmMod.base + " (" + cdmMod.size + " bytes)");
    const vAddr = cdmMod.findExportByName("GetCdmVersion");
    if (vAddr) {
        try {
            const fn = new NativeFunction(vAddr, "pointer", []);
            console.log("[*] CDM Version: " + (fn() as NativePointer).readUtf8String());
        } catch (_e) {}
    }
} else {
    console.log("[-] " + CDM_MODULE + " not loaded yet");
}
