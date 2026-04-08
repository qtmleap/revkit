/**
 * hook_tfit_table_extract.js — TFIT ホワイトボックス AES テーブル抽出
 *
 * 目的: NFWebCrypto.framework の Irdeto TFIT ホワイトボックス AES チェーンから
 *       AES-256 鍵・AES_encrypt 入出力ペアを全件キャプチャし、
 *       TFIT_KEY (48B) 生成メカニズムを解明する。
 *
 * 使い方:
 *   frida -H host.docker.internal:27042 -n Argo -l hook_tfit_table_extract.js
 *
 * 動作:
 *   1. AES_set_encrypt_key をフック — AES-256 鍵を順序付きで記録
 *      KAT マーカー (000102...1f, 0000...00) でラウンドを区切る
 *   2. AES_encrypt をフック — 単体ブロック ECB の入出力 (各 16B) を記録
 *      TFIT チェーン内のデータフローを可視化する
 *   3. NFWebCrypto の __DATA セグメントを走査して
 *      代替テーブル候補 (256 × 4B = 1KB, 256 × 16B = 4KB) をダンプ
 *   4. TFIT チェーン完了時 (AES-256 呼び出しが 0.5 秒以上途切れた時点) に
 *      全鍵・全 I/O ペアのサマリを出力する
 *
 * 注意:
 *   - AES_cbc_encrypt はクラッシュするためフックしない
 *   - AES_encrypt は void AES_encrypt(const u8 *in, u8 *out, const AES_KEY *key)
 *   - AES-128 呼び出しは KAT / MSL セッション鍵のためノイズが多い — デフォルト無視
 */

"use strict";

// ===== Utility =====

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

function hexShort(ptr, len) {
    if (len <= 32) return hex(ptr, len);
    return hex(ptr, 16) + "..." + hex(ptr.add(len - 8), 8) + " (" + len + "B)";
}

function bytesToHex(arr) {
    return Array.from(arr)
        .map(function (b) { return ("0" + b.toString(16)).slice(-2); })
        .join("");
}

function hexToBytes(hexStr) {
    var bytes = [];
    for (var i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

function safeRead16(ptr) {
    try {
        return new Uint8Array(ptr.readByteArray(16));
    } catch (e) {
        return null;
    }
}

function safeRead32(ptr) {
    try {
        return new Uint8Array(ptr.readByteArray(32));
    } catch (e) {
        return null;
    }
}

// ===== KAT markers =====

// AES-256 Known Answer Test key patterns
var KAT_KEY_INCR = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
var KAT_KEY_ZERO = "0000000000000000000000000000000000000000000000000000000000000000";

// ===== Module =====

var nfwc = Process.findModuleByName("NFWebCrypto");
if (!nfwc) {
    console.log("[-] NFWebCrypto not found. Is Argo running?");
} else {
    console.log("[*] NFWebCrypto base=" + nfwc.base + " size=" + nfwc.size);
}

// ===== Symbol resolution =====

var fn = {};
var fnNames = [
    "AES_set_encrypt_key",
    "AES_set_decrypt_key",
    "AES_encrypt",
];

fnNames.forEach(function (name) {
    var addr = nfwc ? nfwc.findExportByName(name) : null;
    if (addr) {
        fn[name] = addr;
        console.log("[+] " + name + " @ " + addr);
    } else {
        console.log("[-] " + name + " not found in NFWebCrypto exports");
    }
});

// ===== Global state =====

// Ordered list of all AES-256 set_encrypt_key calls
var g_aes256Keys = [];         // { idx, keyHex, ts }

// Ordered list of all AES_encrypt calls
var g_encPairs = [];           // { idx, inHex, outHex, keyHex, ts }

// Current AES_KEY* → key material mapping (address string → keyHex)
// Populated by AES_set_encrypt_key onLeave (AES_KEY* is args[2])
var g_keyMap = {};

// TFIT round counter — incremented each time we see KAT_KEY_INCR
var g_tfitRound = 0;

// Timer for "chain complete" detection
var g_lastAes256Ts = 0;
var g_chainTimer = null;
var g_chainCompleted = false;

// ===== Helpers =====

function isKatIncrKey(keyHex) {
    return keyHex === KAT_KEY_INCR;
}

function isKatZeroKey(keyHex) {
    return keyHex === KAT_KEY_ZERO;
}

function isKatKey(keyHex) {
    return isKatIncrKey(keyHex) || isKatZeroKey(keyHex);
}

// Print a concise summary of a single TFIT chain
function printChainSummary() {
    console.log("\n============================================================");
    console.log("  TFIT CHAIN SUMMARY");
    console.log("============================================================");

    // --- AES-256 keys ---
    console.log("\n[AES_set_encrypt_key] AES-256 calls: " + g_aes256Keys.length);
    var roundIdx = 0;
    g_aes256Keys.forEach(function (entry, i) {
        var marker = "";
        if (isKatIncrKey(entry.keyHex)) {
            roundIdx++;
            marker = "  <<< KAT INCR (round " + roundIdx + " start) >>>";
        } else if (isKatZeroKey(entry.keyHex)) {
            marker = "  <<< KAT ZERO >>>";
        }
        console.log("  [" + i + "] " + entry.keyHex.substring(0, 32) + "..." + marker);
    });

    // --- AES_encrypt I/O pairs ---
    console.log("\n[AES_encrypt] I/O pairs: " + g_encPairs.length);
    g_encPairs.forEach(function (entry, i) {
        console.log("  [" + i + "] in=" + entry.inHex + "  out=" + entry.outHex);
        if (entry.keyHex) {
            console.log("       key=" + entry.keyHex.substring(0, 32) + "...");
        }
    });

    // --- Chain reconstruction attempt ---
    // In a standard TFIT chain the output of AES_encrypt(in, *, key_n) becomes
    // the key for the next round. We try to find that structure.
    if (g_encPairs.length >= 2) {
        console.log("\n[TFIT chain reconstruction]");
        var prev = g_encPairs[0];
        for (var j = 1; j < g_encPairs.length; j++) {
            var cur = g_encPairs[j];
            // Check if prev output is prefix of current key
            if (cur.keyHex && prev.outHex &&
                cur.keyHex.indexOf(prev.outHex) === 0) {
                console.log("  chain[" + (j-1) + "→" + j + "] out=" + prev.outHex + " → key=" + cur.keyHex.substring(0, 32) + "...");
            }
            prev = cur;
        }
    }

    // --- Final candidate TFIT_KEY ---
    // The last three blocks of the final non-KAT AES_encrypt calls form the 48B key
    var nonKatPairs = g_encPairs.filter(function (e) {
        // Filter out KAT plaintext pattern: in=00000000000000000000000000000000
        return e.inHex !== "00000000000000000000000000000000" &&
               e.inHex !== "f34481ec3cc627bacd5dc3fb08f273e6"; // NIST KAT known input
    });
    if (nonKatPairs.length >= 3) {
        var last3 = nonKatPairs.slice(-3);
        var candidate = last3.map(function (e) { return e.outHex; }).join("");
        console.log("\n[TFIT_KEY candidate] last 3 AES_encrypt outputs (48B):");
        console.log("  " + candidate);
    }

    console.log("\n============================================================\n");
}

// Arm a debounce timer: if no new AES-256 call arrives within 1 second,
// consider the chain finished and print the summary.
function armChainTimer() {
    if (g_chainTimer !== null) {
        clearTimeout(g_chainTimer);
    }
    g_chainTimer = setTimeout(function () {
        g_chainTimer = null;
        if (!g_chainCompleted && g_aes256Keys.length > 0) {
            g_chainCompleted = true;
            printChainSummary();
        }
    }, 1000);
}

// ===== Hook: AES_set_encrypt_key =====
// int AES_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key)

if (fn.AES_set_encrypt_key) {
    Interceptor.attach(fn.AES_set_encrypt_key, {
        onEnter: function (args) {
            this.userKey = args[0];
            this.bits    = args[1].toInt32();
            this.aesKey  = args[2];  // AES_KEY* — used to correlate AES_encrypt calls
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 0) return;  // error

            var bits = this.bits;
            var keyLen = bits >> 3;  // bits / 8

            var keyBytes = safeRead32(this.userKey);
            if (!keyBytes) return;

            var keyHex = bytesToHex(
                bits === 256 ? keyBytes : new Uint8Array(keyBytes.buffer, 0, keyLen)
            );

            // Store in address map for AES_encrypt correlation
            var mapKey = this.aesKey.toString();
            g_keyMap[mapKey] = keyHex;

            if (bits === 256) {
                // Reset chain completed flag on new KAT INCR (new session starting)
                if (isKatIncrKey(keyHex)) {
                    if (g_chainCompleted) {
                        // New session: reset state
                        console.log("\n[*] New TFIT session detected — resetting state");
                        g_aes256Keys = [];
                        g_encPairs = [];
                        g_keyMap = {};
                        g_chainCompleted = false;
                        g_tfitRound = 0;
                    }
                    g_tfitRound++;
                    console.log("[AES_set_encrypt_key] AES-256 #" + g_aes256Keys.length +
                                " KAT INCR (round " + g_tfitRound + ")");
                } else if (isKatZeroKey(keyHex)) {
                    console.log("[AES_set_encrypt_key] AES-256 #" + g_aes256Keys.length + " KAT ZERO");
                } else {
                    // Normal TFIT chain key — only log every 10th to reduce noise
                    if (g_aes256Keys.length % 10 === 0) {
                        console.log("[AES_set_encrypt_key] AES-256 #" + g_aes256Keys.length +
                                    " key=" + keyHex.substring(0, 16) + "...");
                    }
                }

                g_aes256Keys.push({
                    idx:    g_aes256Keys.length,
                    keyHex: keyHex,
                    ts:     Date.now()
                });

                g_lastAes256Ts = Date.now();
                armChainTimer();

            } else if (bits === 128) {
                // AES-128: only log if it is a KAT key (useful for sanity checks)
                if (isKatKey(keyHex)) {
                    console.log("[AES_set_encrypt_key] AES-128 KAT key=" + keyHex);
                }
            }
        }
    });
    console.log("[+] AES_set_encrypt_key hooked");
}

// ===== Hook: AES_encrypt =====
// void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
//
// Single-block ECB encrypt. This is the primitive used inside the TFIT chain.
// We capture in/out and correlate to the last AES_KEY* setup.

if (fn.AES_encrypt) {
    Interceptor.attach(fn.AES_encrypt, {
        onEnter: function (args) {
            this.inPtr  = args[0];
            this.outPtr = args[1];
            this.aesKey = args[2];

            // Read input now (before the call overwrites anything)
            var inBytes = safeRead16(this.inPtr);
            this.inHex = inBytes ? bytesToHex(inBytes) : "(unreadable)";

            // Correlate to key material
            var mapKey = this.aesKey ? this.aesKey.toString() : null;
            this.keyHex = (mapKey && g_keyMap[mapKey]) ? g_keyMap[mapKey] : null;
        },
        onLeave: function (retval) {
            var outBytes = safeRead16(this.outPtr);
            if (!outBytes) return;
            var outHex = bytesToHex(outBytes);

            var entry = {
                idx:    g_encPairs.length,
                inHex:  this.inHex,
                outHex: outHex,
                keyHex: this.keyHex,
                ts:     Date.now()
            };

            g_encPairs.push(entry);

            // Only emit a line when we're within an active TFIT chain
            // (i.e. after at least one AES-256 set_encrypt_key and chain not done)
            if (!g_chainCompleted && g_aes256Keys.length > 0) {
                console.log("[AES_encrypt] #" + entry.idx +
                            " in=" + entry.inHex +
                            " out=" + outHex +
                            (entry.keyHex ? " key=" + entry.keyHex.substring(0, 16) + "..." : ""));
            }
        }
    });
    console.log("[+] AES_encrypt hooked");
} else {
    console.log("[!] AES_encrypt not found — will only capture AES_set_encrypt_key calls");
}

// ===== Data segment scan for lookup tables =====
// Irdeto TFIT typically embeds pre-computed S-box / MDS tables in the binary.
// We scan NFWebCrypto's __DATA (read-write) and __RODATA/__TEXT (read-only) segments.
//
// Heuristic: a 4KB block where every 4-byte word is in [0x00000000, 0xffffffff]
// and the byte distribution looks like a permutation table (uniform spread).

function scanForLookupTables() {
    if (!nfwc) {
        console.log("[-] NFWebCrypto not loaded, cannot scan");
        return;
    }

    console.log("\n[*] Scanning NFWebCrypto segments for lookup tables...");

    Process.enumerateRanges({ protection: "r--" }).forEach(function (range) {
        // Only care about ranges inside NFWebCrypto
        if (range.base.compare(nfwc.base) < 0) return;
        if (range.base.compare(nfwc.base.add(nfwc.size)) >= 0) return;

        // Minimum size: 256 × 4 = 1024 bytes
        if (range.size < 1024) return;

        var base = range.base;
        var size = range.size;

        // Walk in 1KB steps, look for patterns consistent with S-box (256 unique bytes)
        var step = 1024;
        for (var offset = 0; offset + 1024 <= size; offset += step) {
            try {
                var buf = new Uint8Array(base.add(offset).readByteArray(1024));

                // Check if this 1KB block looks like 256 × 4-byte table entries
                // where each entry has consistent byte ordering (AES S-box style)
                var lsbSet = new Set();
                var isCandidate = true;
                for (var i = 0; i < 256; i++) {
                    lsbSet.add(buf[i * 4]);
                }
                // A real 256-entry table often has many unique LSB values
                if (lsbSet.size >= 200) {
                    var tableHex = bytesToHex(buf.slice(0, 64)) + "...";
                    console.log("[TABLE CANDIDATE] @ " + base.add(offset) +
                                " (offset 0x" + offset.toString(16) + " in range)");
                    console.log("  first 64B: " + tableHex);
                    console.log("  unique LSBs: " + lsbSet.size + "/256");
                }
            } catch (e) {
                // Skip unreadable pages
            }
        }

        // Also check 4KB blocks for the 256×16 variant (often used for combined MixColumns)
        var step4k = 4096;
        for (var offset4 = 0; offset4 + 4096 <= size; offset4 += step4k) {
            try {
                var buf4 = new Uint8Array(base.add(offset4).readByteArray(4096));
                var lsbSet4 = new Set();
                for (var j = 0; j < 256; j++) {
                    lsbSet4.add(buf4[j * 16]);
                }
                if (lsbSet4.size >= 200) {
                    var tableHex4 = bytesToHex(buf4.slice(0, 64)) + "...";
                    console.log("[TABLE CANDIDATE 4KB] @ " + base.add(offset4) +
                                " (offset 0x" + offset4.toString(16) + " in range)");
                    console.log("  first 64B: " + tableHex4);
                    console.log("  unique 1st-bytes per 16B entry: " + lsbSet4.size + "/256");
                }
            } catch (e) {
                // Skip
            }
        }
    });

    console.log("[*] Segment scan complete");
}

// ===== RPC exports =====

rpc.exports.scanTables = function () {
    scanForLookupTables();
};

rpc.exports.dumpKeys = function () {
    console.log("\n[dumpKeys] AES-256 keys captured: " + g_aes256Keys.length);
    g_aes256Keys.forEach(function (e) {
        var marker = isKatIncrKey(e.keyHex) ? " KAT_INCR" :
                     isKatZeroKey(e.keyHex) ? " KAT_ZERO" : "";
        console.log("  [" + e.idx + "]" + marker + " " + e.keyHex);
    });
};

rpc.exports.dumpPairs = function () {
    console.log("\n[dumpPairs] AES_encrypt pairs captured: " + g_encPairs.length);
    g_encPairs.forEach(function (e) {
        console.log("  [" + e.idx + "] in=" + e.inHex + " out=" + e.outHex);
    });
};

rpc.exports.resetState = function () {
    g_aes256Keys = [];
    g_encPairs = [];
    g_keyMap = {};
    g_chainCompleted = false;
    g_tfitRound = 0;
    console.log("[*] State reset");
};

rpc.exports.printSummary = function () {
    printChainSummary();
};

// ===== REPL convenience aliases =====

var global = this;
global.scanTables   = scanForLookupTables;
global.dumpKeys     = rpc.exports.dumpKeys;
global.dumpPairs    = rpc.exports.dumpPairs;
global.resetState   = rpc.exports.resetState;
global.printSummary = printChainSummary;

// ===== Startup =====

console.log("\n=== TFIT table extractor v1 ===");
console.log("Hooks:");
console.log("  AES_set_encrypt_key — captures all AES-256 keys in TFIT chain");
console.log("  AES_encrypt         — captures single-block ECB in/out pairs");
console.log("Commands:");
console.log("  scanTables()    — scan NFWebCrypto read-only data for S-box candidates");
console.log("  dumpKeys()      — print all captured AES-256 keys");
console.log("  dumpPairs()     — print all AES_encrypt in/out pairs");
console.log("  printSummary()  — force-print current chain summary");
console.log("  resetState()    — clear accumulated state");
console.log("");
console.log("[*] Waiting for TFIT chain... (trigger by opening Netflix or starting playback)");
