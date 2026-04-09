/**
 * hook_nfwebcrypto_keys.js — NFWebCrypto 署名検証鍵の実行時ダンプ
 *
 * 目的: appboot 署名検証で使用される以下の2鍵をメモリスキャンとフックで捕捉する
 *   1. kAppBootKey     — RSA-4096 公開鍵 (SPKI DER, ~550B)
 *   2. kAppBootEccKey  — ECDSA P-256 公開鍵 (SPKI DER, 91B)
 *
 * 手法:
 *   A. メモリスキャン: NFWebCrypto の .data/.rodata セクションを DER マーカーでスキャン
 *   B. importKey フック: "ABKP" / "ABECCKP" ハンドル名を持つ呼び出しをキャプチャ
 *   C. EVP_PKEY_set1_RSA / d2i_RSAPublicKey / d2i_PUBKEY フック: key import 経路
 *   D. SecKeyCreateWithData / SecItemAdd フック: Keychain 経由の場合
 *
 * 使い方:
 *   frida -H host.docker.internal:27042 -n Argo -l hook_nfwebcrypto_keys.js
 *
 * 注意:
 *   - 鍵は静的に .rodata に埋め込まれている可能性が高い
 *   - メモリスキャンは NFWebCrypto ロード直後に一度だけ実行する
 */

"use strict";

// ===== Utility =====

function ts() {
    return new Date().toISOString();
}

function hex(ptr, len) {
    if (!ptr || ptr.isNull() || len <= 0) return "(null)";
    try {
        return Array.from(new Uint8Array(ptr.readByteArray(len)))
            .map(function (b) { return ("0" + b.toString(16)).slice(-2); })
            .join("");
    } catch (e) {
        return "(unreadable:" + e.message + ")";
    }
}

function banner(title) {
    var line = "=".repeat(60);
    console.log("\n" + line);
    console.log("  " + title);
    console.log("  " + ts());
    console.log(line);
}

// ===== DER marker bytes =====

// RSA-4096 SPKI DER prefix (SubjectPublicKeyInfo wrapping rsaEncryption OID):
//   SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING }
//   30 82 02 22  — SEQUENCE, length 0x0222 = 546 bytes  (for RSA-4096 SPKI)
//   30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00
// The 4-byte outer SEQUENCE tag+len varies for different key sizes;
// we search for the OID bytes which are always present.
var RSA_OID_BYTES = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];

// ECDSA P-256 SPKI DER (91 bytes total, fixed):
//   30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04 ...
var P256_SPKI_PREFIX = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
                        0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
                        0x03, 0x01, 0x07];

// RSA-4096 SPKI full prefix (outer SEQUENCE length for 4096-bit key is 0x0222):
var RSA4096_SPKI_PREFIX = [0x30, 0x82, 0x02, 0x22].concat(RSA_OID_BYTES);

// ===== Captured state =====

var captured = {
    kAppBootKey: null,     // RSA-4096 SPKI hex
    kAppBootEccKey: null,  // ECDSA P-256 SPKI hex
};

// ===== Memory scan helper =====

function findPattern(baseAddr, size, patternBytes) {
    var results = [];
    var patLen = patternBytes.length;

    // Read in 4KB chunks to avoid large allocations
    var CHUNK = 4096;
    var offset = 0;

    while (offset < size) {
        var readLen = Math.min(CHUNK + patLen, size - offset);
        try {
            var chunk = new Uint8Array(baseAddr.add(offset).readByteArray(readLen));
            for (var i = 0; i < chunk.length - patLen; i++) {
                var match = true;
                for (var j = 0; j < patLen; j++) {
                    if (chunk[i + j] !== patternBytes[j]) { match = false; break; }
                }
                if (match) {
                    results.push(baseAddr.add(offset + i));
                }
            }
        } catch (e) {
            // Skip unreadable pages
        }
        offset += CHUNK;
    }
    return results;
}

// Parse DER SEQUENCE length at ptr (may be short or long form)
// Returns { totalLen, headerLen } or null
function parseDerSequenceLen(ptr) {
    try {
        var tag = ptr.readU8();
        if (tag !== 0x30) return null;
        var b1 = ptr.add(1).readU8();
        if (b1 < 0x80) {
            return { totalLen: 2 + b1, headerLen: 2 };
        } else if (b1 === 0x81) {
            var len = ptr.add(2).readU8();
            return { totalLen: 3 + len, headerLen: 3 };
        } else if (b1 === 0x82) {
            var hi = ptr.add(2).readU8();
            var lo = ptr.add(3).readU8();
            var len2 = (hi << 8) | lo;
            return { totalLen: 4 + len2, headerLen: 4 };
        }
        return null;
    } catch (e) {
        return null;
    }
}

// ===== Main scan function =====

function scanNFWebCryptoForKeys(nfwc) {
    banner("Scanning NFWebCrypto memory for RSA-4096 and ECDSA P-256 keys");
    console.log("[*] NFWebCrypto base=" + nfwc.base + " size=" + nfwc.size);

    // ---- Scan for ECDSA P-256 SPKI (91B, exact prefix match) ----
    console.log("[*] Scanning for ECDSA P-256 SPKI prefix...");
    var eccMatches = findPattern(nfwc.base, nfwc.size, P256_SPKI_PREFIX);
    console.log("[*] P-256 prefix hits: " + eccMatches.length);

    eccMatches.forEach(function (addr) {
        var info = parseDerSequenceLen(addr);
        var keyLen = info ? info.totalLen : 91;  // P-256 SPKI is always 91B
        var h = hex(addr, keyLen);
        banner("kAppBootEccKey — ECDSA P-256 SPKI @ " + addr);
        console.log("  address = " + addr);
        console.log("  length  = " + keyLen);
        console.log("  hex     = " + h);
        captured.kAppBootEccKey = h;
    });

    // ---- Scan for RSA-4096 SPKI (search by full prefix including outer SEQUENCE) ----
    console.log("[*] Scanning for RSA-4096 SPKI prefix...");
    var rsaMatches = findPattern(nfwc.base, nfwc.size, RSA4096_SPKI_PREFIX);
    console.log("[*] RSA-4096 prefix hits: " + rsaMatches.length);

    rsaMatches.forEach(function (addr) {
        var info = parseDerSequenceLen(addr);
        if (!info) {
            console.log("[-] Could not parse DER at " + addr);
            return;
        }
        var h = hex(addr, info.totalLen);
        banner("kAppBootKey — RSA-4096 SPKI @ " + addr);
        console.log("  address    = " + addr);
        console.log("  totalLen   = " + info.totalLen);
        console.log("  hex        = " + h);
        captured.kAppBootKey = h;
    });

    // ---- Broader RSA OID scan (catches RSA-2048 or different SEQUENCE length) ----
    if (rsaMatches.length === 0) {
        console.log("[*] Trying broader RSA OID scan...");
        var rsaOidMatches = findPattern(nfwc.base, nfwc.size, RSA_OID_BYTES);
        console.log("[*] RSA OID hits: " + rsaOidMatches.length);

        rsaOidMatches.forEach(function (oidAddr) {
            // Walk back up to 4 bytes to find the outer SEQUENCE tag
            var seqAddr = oidAddr.sub(4);
            var info = parseDerSequenceLen(seqAddr);
            if (!info) {
                seqAddr = oidAddr.sub(2);
                info = parseDerSequenceLen(seqAddr);
            }
            if (!info) return;

            // Sanity: SPKI for RSA-4096 should be 550 bytes or so
            if (info.totalLen < 100 || info.totalLen > 700) return;

            var h = hex(seqAddr, info.totalLen);
            banner("kAppBootKey CANDIDATE (RSA OID scan) @ " + seqAddr);
            console.log("  address    = " + seqAddr);
            console.log("  totalLen   = " + info.totalLen);
            console.log("  hex        = " + h);
            if (!captured.kAppBootKey) captured.kAppBootKey = h;
        });
    }
}

// ===== Hook-based capture =====

function hookNFWebCryptoImportKey(nfwc) {
    // Hook d2i_PUBKEY — parses SubjectPublicKeyInfo DER → EVP_PKEY*
    // EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length)
    var pD2iPubkey = nfwc.findExportByName("d2i_PUBKEY");
    if (pD2iPubkey) {
        Interceptor.attach(pD2iPubkey, {
            onEnter: function (args) {
                this.ppData = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function (retval) {
                if (retval.isNull() || this.len <= 0) return;
                // pp was advanced past the parsed data; read from saved pointer
                try {
                    var dataPtr = this.ppData.readPointer().sub(this.len);
                    var h = hex(dataPtr, this.len);
                    banner("d2i_PUBKEY called — possible kAppBootKey or kAppBootEccKey import");
                    console.log("  length = " + this.len);
                    console.log("  hex    = " + h.slice(0, 256) + (h.length > 256 ? "..." : ""));
                    // Distinguish by size: P-256 = 91B, RSA-4096 ~= 550B
                    if (this.len === 91) {
                        captured.kAppBootEccKey = h;
                    } else if (this.len >= 400 && this.len <= 700) {
                        captured.kAppBootKey = h;
                    }
                } catch (e) {
                    console.log("[-] d2i_PUBKEY data read error: " + e.message);
                }
            }
        });
        console.log("[+] d2i_PUBKEY hooked");
    } else {
        console.log("[-] d2i_PUBKEY not found in NFWebCrypto");
    }

    // Hook d2i_RSAPublicKey / d2i_RSA_PUBKEY
    ["d2i_RSAPublicKey", "d2i_RSA_PUBKEY"].forEach(function (name) {
        var p = nfwc.findExportByName(name);
        if (!p) { console.log("[-] " + name + " not found"); return; }
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.ppData = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function (retval) {
                if (retval.isNull() || this.len <= 0) return;
                try {
                    var dataPtr = this.ppData.readPointer().sub(this.len);
                    var h = hex(dataPtr, this.len);
                    banner(name + " called — kAppBootKey import");
                    console.log("  length = " + this.len);
                    console.log("  hex    = " + h.slice(0, 256) + (h.length > 256 ? "..." : ""));
                    if (this.len >= 400) captured.kAppBootKey = h;
                } catch (e) {}
            }
        });
        console.log("[+] " + name + " hooked");
    });

    // Hook EVP_PKEY_set1_RSA
    var pSetRSA = nfwc.findExportByName("EVP_PKEY_set1_RSA");
    if (pSetRSA) {
        Interceptor.attach(pSetRSA, {
            onEnter: function (args) {
                // args[1] = RSA* — try to serialize it
                this.rsa = args[1];
            },
            onLeave: function (retval) {
                if (retval.toInt32() !== 1) return;
                // Can't easily dump RSA* without i2d_RSAPublicKey — log the pointer
                console.log("[EVP_PKEY_set1_RSA] RSA* = " + this.rsa +
                    " (use i2d_RSAPublicKey to dump if needed)");
            }
        });
        console.log("[+] EVP_PKEY_set1_RSA hooked");
    }

    // Hook EVP_DigestVerifyInit — catches signature verification setup
    // This is called once per verify operation on appboot response
    var pDVI = nfwc.findExportByName("EVP_DigestVerifyInit");
    if (pDVI) {
        Interceptor.attach(pDVI, {
            onEnter: function (args) {
                // args: (EVP_MD_CTX*, EVP_PKEY_CTX**, EVP_MD*, ENGINE*, EVP_PKEY*)
                this.pkey = args[4];
            },
            onLeave: function (retval) {
                if (retval.toInt32() !== 1) return;
                console.log("[EVP_DigestVerifyInit] pkey=" + this.pkey + " (appboot sig verify initiated)");
                // Attempt to dump the public key via i2d_PUBKEY if available
                var pI2d = nfwc.findExportByName("i2d_PUBKEY");
                if (pI2d && this.pkey && !this.pkey.isNull()) {
                    try {
                        var i2dPubkey = new NativeFunction(pI2d, 'int', ['pointer', 'pointer']);
                        var ppOut = Memory.alloc(Process.pointerSize);
                        ppOut.writePointer(ptr(0));
                        var len = i2dPubkey(this.pkey, ppOut);
                        if (len > 0) {
                            var outPtr = ppOut.readPointer();
                            var h = hex(outPtr, len);
                            banner("kAppBootKey/kAppBootEccKey via EVP_DigestVerifyInit + i2d_PUBKEY");
                            console.log("  length = " + len);
                            console.log("  hex    = " + h);
                            if (len === 91) captured.kAppBootEccKey = h;
                            else if (len >= 400) captured.kAppBootKey = h;
                        }
                    } catch (e) {
                        console.log("[-] i2d_PUBKEY dump error: " + e.message);
                    }
                }
            }
        });
        console.log("[+] EVP_DigestVerifyInit hooked");
    }

    // Hook EVP_DigestVerify — the final verify call, pkey already set
    var pDV = nfwc.findExportByName("EVP_DigestVerify");
    if (pDV) {
        Interceptor.attach(pDV, {
            onEnter: function (args) {
                // args: (EVP_MD_CTX*, unsigned char* sig, size_t siglen,
                //        unsigned char* tbs, size_t tbslen)
                this.sigLen = args[2].toUInt32();
                this.tbsLen = args[4].toUInt32();
                this.sig    = args[1];
                this.tbs    = args[3];
            },
            onLeave: function (retval) {
                var result = retval.toInt32();
                console.log("[EVP_DigestVerify] sigLen=" + this.sigLen +
                    " tbsLen=" + this.tbsLen + " result=" + result);
                if (this.sigLen > 0 && this.sigLen <= 512) {
                    console.log("  sig = " + hex(this.sig, this.sigLen));
                }
            }
        });
        console.log("[+] EVP_DigestVerify hooked");
    }
}

// ===== Wait for NFWebCrypto and run =====

function waitForModule(name, cb) {
    var m = Process.findModuleByName(name);
    if (m) { cb(m); return; }
    var iv = setInterval(function () {
        var m2 = Process.findModuleByName(name);
        if (m2) { clearInterval(iv); cb(m2); }
    }, 200);
}

waitForModule("NFWebCrypto", function (nfwc) {
    // Run memory scan first (keys may be in static rodata)
    scanNFWebCryptoForKeys(nfwc);

    // Then install import/verify hooks to catch runtime key loading
    hookNFWebCryptoImportKey(nfwc);

    // Also scan for string "ABKP" / "ABECCKP" handle names in the module
    banner("Scanning for ABKP / ABECCKP handle strings");
    var abkpBytes  = [0x41, 0x42, 0x4b, 0x50, 0x00];   // "ABKP\0"
    var abeccBytes = [0x41, 0x42, 0x45, 0x43, 0x43, 0x4b, 0x50, 0x00]; // "ABECCKP\0"

    var abkpHits  = findPattern(nfwc.base, nfwc.size, abkpBytes);
    var abeccHits = findPattern(nfwc.base, nfwc.size, abeccBytes);

    console.log("[*] \"ABKP\" string hits:    " + abkpHits.length);
    abkpHits.forEach(function (a) { console.log("  @ " + a); });

    console.log("[*] \"ABECCKP\" string hits: " + abeccHits.length);
    abeccHits.forEach(function (a) { console.log("  @ " + a); });
});

// ===== RPC exports =====

rpc.exports = {
    getKeys: function () {
        return JSON.stringify({
            kAppBootKey: captured.kAppBootKey
                ? captured.kAppBootKey.slice(0, 64) + "... (" + (captured.kAppBootKey.length / 2) + "B)"
                : null,
            kAppBootEccKey: captured.kAppBootEccKey || null,
        }, null, 2);
    },
    getKAppBootKey: function () {
        return captured.kAppBootKey || null;
    },
    getKAppBootEccKey: function () {
        return captured.kAppBootEccKey || null;
    },
    rescan: function () {
        var nfwc = Process.findModuleByName("NFWebCrypto");
        if (nfwc) scanNFWebCryptoForKeys(nfwc);
        else console.log("[-] NFWebCrypto not loaded");
    },
};

// REPL shortcuts
var global = this;
global.getKeys = function () { console.log(rpc.exports.getKeys()); };
global.rescan  = function () { rpc.exports.rescan(); };

console.log("\n=== hook_nfwebcrypto_keys.js loaded ===");
console.log("Targets:");
console.log("  kAppBootKey    — RSA-4096 SPKI (ABKP handle)");
console.log("  kAppBootEccKey — ECDSA P-256 SPKI (ABECCKP handle)");
console.log("Actions:");
console.log("  Memory scan runs immediately on NFWebCrypto load");
console.log("  d2i_PUBKEY / EVP_DigestVerifyInit hooks capture runtime import");
console.log("RPC:");
console.log("  getKeys()          — summary of captured keys");
console.log("  getKAppBootKey()   — RSA-4096 hex (full)");
console.log("  getKAppBootEccKey() — P-256 hex (full)");
console.log("  rescan()           — re-run memory scan");
