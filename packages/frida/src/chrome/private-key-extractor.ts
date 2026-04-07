/**
 * RSA Private Key Extractor for Widevine CDM (L3)
 *
 * CDM が CreateSessionAndGenerateRequest で challenge を生成する際、
 * RSA 秘密鍵をメモリ上に展開して署名に使用する。
 * このモジュールはメモリ上の DER エンコードされた RSA 秘密鍵を
 * パターンスキャンで検出・ダンプする。
 *
 * 検出パターン:
 *   PKCS#8: 30 82 xx xx 02 01 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01
 *   PKCS#1: 30 82 xx xx 02 01 00 02 82 (version=0, modulus)
 */
import { logData, bytesToHex, bytesToBase64, SEP2 } from "../common/utils";

const CDM_MODULE = "libwidevinecdm.dylib";

/** PKCS#8 RSA 秘密鍵の先頭パターン (RSA OID: 1.2.840.113549.1.1.1) */
const PKCS8_PATTERN = "30 82 ?? ?? 02 01 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01";

/** PKCS#1 RSAPrivateKey の先頭パターン (version=0, modulus follows) */
const PKCS1_PATTERN = "30 82 ?? ?? 02 01 00 02 82";

let extractedKeys: string[] = [];
let scanInProgress = false;

/**
 * DER SEQUENCE の全長を先頭2バイト (length field) から計算する。
 * 30 82 XX YY → total = 4 + (XX << 8 | YY)
 */
function derSequenceLength(ptr: NativePointer): number {
    const tag = ptr.readU8();
    if (tag !== 0x30) return -1;

    const lenByte = ptr.add(1).readU8();
    if (lenByte === 0x82) {
        // 2-byte length
        const hi = ptr.add(2).readU8();
        const lo = ptr.add(3).readU8();
        return 4 + ((hi << 8) | lo);
    } else if (lenByte === 0x81) {
        // 1-byte length
        return 2 + ptr.add(2).readU8();
    } else if (lenByte < 0x80) {
        // short form
        return 2 + lenByte;
    }
    return -1;
}

/**
 * 候補アドレスが有効な RSA 秘密鍵かどうかを簡易検証する。
 * - DER SEQUENCE の長さが妥当 (RSA-2048: ~1200B, RSA-4096: ~2400B)
 * - version フィールドが 0
 */
function validateRSAKey(ptr: NativePointer, format: "pkcs8" | "pkcs1"): { valid: boolean; totalLen: number } {
    try {
        const totalLen = derSequenceLength(ptr);
        // RSA-2048 PKCS#8 ≈ 1218B, RSA-2048 PKCS#1 ≈ 1192B
        // RSA-4096 would be ~2400B
        if (totalLen < 600 || totalLen > 5000) {
            return { valid: false, totalLen };
        }

        if (format === "pkcs8") {
            // Verify: 02 01 00 (version=0), then AlgorithmIdentifier with RSA OID
            const v = ptr.add(4).readU8();  // 02
            const vl = ptr.add(5).readU8(); // 01
            const vv = ptr.add(6).readU8(); // 00
            if (v !== 0x02 || vl !== 0x01 || vv !== 0x00) {
                return { valid: false, totalLen };
            }
            // Check RSA OID at offset 9: 06 09 2a 86 48 86 f7 0d 01 01 01
            const oid = ptr.add(9).readU8();
            if (oid !== 0x06) {
                return { valid: false, totalLen };
            }
        } else {
            // PKCS#1: version=0, then modulus INTEGER
            const v = ptr.add(4).readU8();  // 02
            const vl = ptr.add(5).readU8(); // 01
            const vv = ptr.add(6).readU8(); // 00
            if (v !== 0x02 || vl !== 0x01 || vv !== 0x00) {
                return { valid: false, totalLen };
            }
            // Next should be modulus: 02 82 (for 2048-bit: 02 82 01 01)
            const mTag = ptr.add(7).readU8();
            if (mTag !== 0x02) {
                return { valid: false, totalLen };
            }
        }

        return { valid: true, totalLen };
    } catch (_e) {
        return { valid: false, totalLen: -1 };
    }
}

/**
 * 指定されたメモリ範囲で RSA 秘密鍵をスキャンする。
 */
function scanRange(
    base: NativePointer,
    size: number,
    pattern: string,
    format: "pkcs8" | "pkcs1",
    label: string,
): void {
    try {
        Memory.scan(base, size, pattern, {
            onMatch(address: NativePointer, _size: number) {
                const { valid, totalLen } = validateRSAKey(address, format);
                if (!valid) return;

                const keyHex = bytesToHex(address.readByteArray(totalLen) as ArrayBuffer);
                if (extractedKeys.indexOf(keyHex) !== -1) return; // duplicate
                extractedKeys.push(keyHex);

                const keyB64 = bytesToBase64(address.readByteArray(totalLen) as ArrayBuffer);

                console.log(SEP2);
                console.log("[!!!] RSA Private Key FOUND (" + format.toUpperCase() + ")");
                console.log("  Location: " + label + " @ " + address);
                console.log("  Length: " + totalLen + " bytes");
                console.log("  First 32 bytes: " + bytesToHex(address.readByteArray(32) as ArrayBuffer));
                console.log(SEP2);

                logData("cdm.privateKey", {
                    format: format,
                    location: label,
                    address: address.toString(),
                    length: totalLen,
                    key_hex: keyHex,
                    key_b64: keyB64,
                });
            },
            onComplete() {
                // silent
            },
        });
    } catch (_e) {
        // Access denied or invalid range, skip
    }
}

/**
 * CDM モジュールのメモリ範囲をスキャンする。
 */
function scanCdmModule(): void {
    const cdmMod = Process.findModuleByName(CDM_MODULE);
    if (!cdmMod) return;

    console.log("[*] Scanning CDM module for RSA private keys...");
    console.log("  Base: " + cdmMod.base + " Size: " + cdmMod.size);

    // モジュール全体をスキャン (セクション単位だと漏れる可能性があるため)
    scanRange(cdmMod.base, cdmMod.size, PKCS8_PATTERN, "pkcs8", "cdm_module");
    scanRange(cdmMod.base, cdmMod.size, PKCS1_PATTERN, "pkcs1", "cdm_module");
}

/**
 * プロセスのヒープ領域をスキャンする。
 * CDM が動的にアロケートしたバッファに鍵がある場合に有効。
 */
function scanHeap(): void {
    console.log("[*] Scanning process memory ranges for RSA private keys...");

    const ranges = Process.enumerateRanges("r--");
    let scanned = 0;
    const cdmMod = Process.findModuleByName(CDM_MODULE);
    const cdmBase = cdmMod ? cdmMod.base : ptr(0);
    const cdmEnd = cdmMod ? cdmMod.base.add(cdmMod.size) : ptr(0);

    for (const range of ranges) {
        // CDM モジュール自体は既にスキャン済み
        if (cdmMod &&
            range.base.compare(cdmBase) >= 0 &&
            range.base.compare(cdmEnd) < 0) {
            continue;
        }

        // 小さすぎるレンジはスキップ
        if (range.size < 1024) continue;
        // 大きすぎるレンジもスキップ (効率のため)
        if (range.size > 100 * 1024 * 1024) continue;

        scanRange(range.base, range.size, PKCS8_PATTERN, "pkcs8", "heap");
        scanRange(range.base, range.size, PKCS1_PATTERN, "pkcs1", "heap");
        scanned++;
    }

    console.log("[*] Scanned " + scanned + " memory ranges");
}

/**
 * RSA 秘密鍵のメモリスキャンを実行する。
 * CreateSessionAndGenerateRequest の後に呼び出すことを想定。
 */
export function extractPrivateKey(): void {
    if (scanInProgress) {
        console.log("[*] Scan already in progress, skipping");
        return;
    }
    scanInProgress = true;

    console.log("[*] Starting RSA private key extraction...");

    scanCdmModule();
    scanHeap();

    scanInProgress = false;

    if (extractedKeys.length > 0) {
        console.log("[+] Total unique keys found: " + extractedKeys.length);
    } else {
        console.log("[-] No RSA private keys found in this scan.");
        console.log("[*] Will retry on next CreateSessionAndGenerateRequest call.");
    }
}

/**
 * 定期的にスキャンを行う (CDM が遅延で鍵をロードする場合に対応)。
 */
export function startPeriodicScan(intervalMs: number): void {
    console.log("[*] Starting periodic key scan every " + intervalMs + "ms");
    const timer = setInterval(() => {
        if (extractedKeys.length > 0) {
            console.log("[+] Key already extracted, stopping periodic scan");
            clearInterval(timer);
            return;
        }
        extractPrivateKey();
    }, intervalMs);
}

export function getExtractedKeyCount(): number {
    return extractedKeys.length;
}
