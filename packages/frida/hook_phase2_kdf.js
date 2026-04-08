/**
 * hook_phase2_kdf.js — Phase 2 KDF 全暗号操作トレーサー
 *
 * 目的: DH 共有秘密 (128B) → enc_key_0 / sign_key_0 への変換を特定する
 *
 * 使い方:
 *   frida -U -n Netflix -l hook_phase2_kdf.js
 *
 * 動作:
 *   1. NFWebCrypto の暗号関連シンボルを全列挙
 *   2. DH_compute_key 完了時にトレースウィンドウを開く (同一スレッドのみ)
 *   3. OpenSSL HMAC (one-shot / streaming) + CommonCrypto CCHmac をフック
 *   4. SHA256 / SHA1 / SHA384 (OpenSSL + CommonCrypto) をフック
 *   5. AES_set_encrypt_key / AES_set_decrypt_key で鍵バイトを捕捉
 *   6. 最初の AES 鍵設定で "=== DERIVATION COMPLETE ===" を出力
 *   7. DH_compute_key → AES 鍵設定までの全暗号呼び出しシーケンスをサマリ出力
 *   8. rpc.exports.testMslKdf — MSL spec KDF の手動テスト用
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
    if (len <= 64) return hex(ptr, len);
    return hex(ptr, 32) + "..." + hex(ptr.add(len - 16), 16) + " (" + len + "B)";
}

function hexToBytes(hexStr) {
    var bytes = [];
    for (var i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

function bytesToHex(arr) {
    return Array.from(arr)
        .map(function (b) { return ("0" + b.toString(16)).slice(-2); })
        .join("");
}

function bytesEqualPrefix(a, b, len) {
    for (var i = 0; i < len; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

// ===== Known constants =====

var PSK_HEX   = "027617984f6227539a630b897c017d69";
var NONCE_HEX = "809f82a7addf548d3ea9dd067ff9bb91";

// ===== Global trace state =====

var g_traceActive   = false;  // true while between DH_compute_key and first AES key setup
var g_traceThreadId = null;   // thread ID of DH_compute_key — filter all other threads
var g_sharedSecret  = null;   // ArrayBuffer of the 128-byte DH shared secret
var g_sequence      = [];     // ordered log of every crypto call in the window
var g_aesKeyCount   = 0;      // how many AES keys have been set after DH

// Append an entry to the ordered call sequence
function seqPush(tag, obj) {
    obj.tag = tag;
    obj.idx = g_sequence.length;
    g_sequence.push(obj);
}

// ===== Phase 1: Symbol enumeration =====

function enumCryptoSymbols() {
    var nfwc = Process.findModuleByName("NFWebCrypto");
    if (!nfwc) {
        console.log("[-] NFWebCrypto not loaded yet");
        return;
    }

    console.log("\n=== NFWebCrypto crypto symbol enumeration ===");
    console.log("[*] base=" + nfwc.base + " size=" + nfwc.size);

    var patterns = [
        "HMAC", "hmac",
        "SHA", "sha",
        "KDF", "kdf",
        "derive", "Derive",
        "PRF", "prf",
        "expand", "Expand",
        "extract", "Extract",
        "HKDF", "hkdf",
        "key", "Key",
        "dh", "DH",
    ];

    var seen = {};
    var exports = nfwc.enumerateExports();
    exports.forEach(function (exp) {
        if (seen[exp.address]) return;
        var name = exp.name;
        for (var i = 0; i < patterns.length; i++) {
            if (name.indexOf(patterns[i]) !== -1) {
                console.log("[SYM] " + exp.type + " " + name + " @ " + exp.address);
                seen[exp.address] = true;
                break;
            }
        }
    });

    console.log("=== end symbol enumeration ===\n");
}

// ===== Module and function resolution =====

var nfwc = Process.findModuleByName("NFWebCrypto");
if (!nfwc) {
    console.log("[-] NFWebCrypto not found. Attach after Netflix is running.");
} else {
    console.log("[*] NFWebCrypto base=" + nfwc.base + " size=" + nfwc.size);
}

function nfExport(name) {
    return nfwc ? nfwc.findExportByName(name) : null;
}

// Resolve CommonCrypto and libSystem symbols
var libSystem = Process.findModuleByName("libSystem.B.dylib") ||
                Process.findModuleByName("libSystem.B_debug.dylib");
var libCC = Process.findModuleByName("libcommonCrypto.dylib") ||
            Process.findModuleByName("libSystem.B.dylib");  // CC is inside libSystem on iOS

function sysExport(name) {
    // Search in all loaded modules for CommonCrypto symbols
    var addr = null;
    if (libCC) addr = libCC.findExportByName(name);
    if (!addr) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            addr = mods[i].findExportByName(name);
            if (addr) {
                console.log("[CC] " + name + " found in " + mods[i].name + " @ " + addr);
                break;
            }
        }
    }
    return addr;
}

// ===== Phase 2: DH_compute_key — open trace window =====

function hookDHComputeKey() {
    var addr = nfExport("DH_compute_key");
    if (!addr) {
        console.log("[-] DH_compute_key not found in NFWebCrypto");
        return;
    }

    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.outBuf = args[0];
        },
        onLeave: function (retval) {
            var len = retval.toInt32();
            if (len <= 0) {
                console.log("[DH_compute_key] returned " + len + " (failure)");
                return;
            }

            g_sharedSecret  = this.outBuf.readByteArray(len);
            g_traceActive   = true;
            g_traceThreadId = Process.getCurrentThreadId();
            g_sequence      = [];
            g_aesKeyCount   = 0;

            console.log("\n[DH_compute_key] shared_secret (" + len + "B) = " +
                hexShort(this.outBuf, len));
            console.log("[*] Trace window OPEN — thread " + g_traceThreadId);

            seqPush("DH_compute_key", {
                len: len,
                output: hex(this.outBuf, len),
            });
        }
    });
    console.log("[+] DH_compute_key hooked");
}

// ===== Thread guard helper =====

function onTraceThread() {
    if (!g_traceActive) return false;
    if (Process.getCurrentThreadId() !== g_traceThreadId) return false;
    return true;
}

// ===== Phase 3: OpenSSL HMAC — one-shot =====

function hookHMACOneShot() {
    var addr = nfExport("HMAC");
    if (!addr) {
        console.log("[-] HMAC (one-shot) not found");
        return;
    }

    Interceptor.attach(addr, {
        onEnter: function (args) {
            if (!onTraceThread()) return;
            // HMAC(EVP_MD *evp, key, keyLen, data, dataLen, out, outLen*)
            this.keyLen  = args[2].toInt32();
            this.dataLen = args[4].toInt32();
            this.outBuf  = args[5];

            if (this.keyLen > 0 && this.keyLen <= 1024 &&
                this.dataLen >= 0 && this.dataLen <= 65536) {
                this.active = true;
                this.keyHex  = hex(args[1], Math.min(this.keyLen, 64));
                this.dataHex = (this.dataLen <= 256)
                    ? hex(args[3], this.dataLen)
                    : hexShort(args[3], this.dataLen);
                console.log("[HMAC-1shot] key(" + this.keyLen + "B)=" + this.keyHex +
                    " data(" + this.dataLen + "B)=" + this.dataHex);
            }
        },
        onLeave: function (retval) {
            if (!this.active) return;
            var outLen = 32; // HMAC-SHA256 default; HMAC-SHA384=48
            if (!retval.isNull()) {
                // Try to read first 48 bytes conservatively
                var outHex = hex(retval, 48);
                console.log("[HMAC-1shot] output(48B)=" + outHex);
                seqPush("HMAC-1shot", {
                    keyLen:  this.keyLen,
                    keyHex:  this.keyHex,
                    dataLen: this.dataLen,
                    dataHex: this.dataHex,
                    output:  outHex,
                });
            }
        }
    });
    console.log("[+] HMAC (one-shot) hooked");
}

// ===== Phase 3b: OpenSSL HMAC streaming =====

function hookHMACStreaming() {
    var hmacInit   = nfExport("HMAC_Init_ex");
    var hmacUpdate = nfExport("HMAC_Update");
    var hmacFinal  = nfExport("HMAC_Final");

    var ctxMap = {};

    if (hmacInit) {
        Interceptor.attach(hmacInit, {
            onEnter: function (args) {
                if (!onTraceThread()) return;
                var ctxKey = args[0].toString();
                var key    = args[1];
                var keyLen = args[2].toInt32();

                // key/evp may be null on re-init
                if (!key.isNull() && keyLen > 0 && keyLen <= 1024) {
                    ctxMap[ctxKey] = {
                        keyLen:  keyLen,
                        keyHex:  hex(key, Math.min(keyLen, 64)),
                        inputs:  [],
                        totalLen: 0,
                    };
                    console.log("[HMAC_Init_ex] ctx=" + ctxKey +
                        " key(" + keyLen + "B)=" + ctxMap[ctxKey].keyHex);
                }
            }
        });
        console.log("[+] HMAC_Init_ex hooked");
    } else {
        console.log("[-] HMAC_Init_ex not found");
    }

    if (hmacUpdate) {
        Interceptor.attach(hmacUpdate, {
            onEnter: function (args) {
                if (!onTraceThread()) return;
                var ctxKey = args[0].toString();
                var data   = args[1];
                var len    = args[2].toInt32();

                if (!ctxMap[ctxKey]) return;
                if (len > 0 && len <= 65536) {
                    ctxMap[ctxKey].totalLen += len;
                    ctxMap[ctxKey].inputs.push({
                        len: len,
                        hex: (len <= 256) ? hex(data, len) : hexShort(data, len),
                    });
                }
            }
        });
        console.log("[+] HMAC_Update hooked");
    } else {
        console.log("[-] HMAC_Update not found");
    }

    if (hmacFinal) {
        Interceptor.attach(hmacFinal, {
            onEnter: function (args) {
                if (!onTraceThread()) return;
                // HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
                this.md     = args[1];
                this.lenPtr = args[2];
            },
            onLeave: function (retval) {
                if (!onTraceThread()) return;
                if (!this.md || this.md.isNull()) return;
                try {
                    var outLen = (!this.lenPtr || this.lenPtr.isNull()) ? 32 :
                        this.lenPtr.readU32();
                    if (outLen > 0 && outLen <= 64) {
                        var outHex = hex(this.md, outLen);
                        console.log("[HMAC_Final] output(" + outLen + "B)=" + outHex);
                        seqPush("HMAC_Final", { outLen: outLen, output: outHex });
                    }
                } catch (e) {}
            }
        });
        console.log("[+] HMAC_Final hooked");
    } else {
        console.log("[-] HMAC_Final not found");
    }
}

// ===== Phase 3c: CommonCrypto CCHmac =====

function hookCCHmac() {
    // CCHmac(algorithm, key, keyLength, data, dataLength, macOut)
    var ccHmac = sysExport("CCHmac");
    if (ccHmac) {
        Interceptor.attach(ccHmac, {
            onEnter: function (args) {
                if (!onTraceThread()) return;
                var algo    = args[0].toInt32();
                var key     = args[1];
                var keyLen  = args[2].toInt32();
                var data    = args[3];
                var dataLen = args[4].toInt32();
                this.macOut = args[5];
                this.active = true;
                this.algo   = algo;

                var algoName = (algo === 1) ? "SHA1" : (algo === 2) ? "SHA256" :
                               (algo === 6) ? "SHA384" : (algo === 4) ? "SHA224" :
                               (algo === 3) ? "SHA512" : "unknown(" + algo + ")";

                console.log("[CCHmac] algo=" + algoName +
                    " key(" + keyLen + "B)=" + hex(key, Math.min(keyLen, 64)) +
                    " data(" + dataLen + "B)=" +
                    (dataLen <= 256 ? hex(data, dataLen) : hexShort(data, dataLen)));

                this.keyHex  = hex(key, Math.min(keyLen, 64));
                this.keyLen  = keyLen;
                this.dataLen = dataLen;
                this.dataHex = (dataLen <= 256) ? hex(data, dataLen) : hexShort(data, dataLen);
                this.algoName = algoName;
            },
            onLeave: function () {
                if (!this.active) return;
                var outLen = (this.algo === 2) ? 32 : (this.algo === 6) ? 48 :
                             (this.algo === 1) ? 20 : 32;
                var outHex = hex(this.macOut, outLen);
                console.log("[CCHmac] output(" + outLen + "B)=" + outHex);
                seqPush("CCHmac", {
                    algo:    this.algoName,
                    keyLen:  this.keyLen,
                    keyHex:  this.keyHex,
                    dataLen: this.dataLen,
                    dataHex: this.dataHex,
                    output:  outHex,
                });
            }
        });
        console.log("[+] CCHmac hooked");
    } else {
        console.log("[-] CCHmac not found in system libraries");
    }

    // CCHmacInit / CCHmacUpdate / CCHmacFinal (streaming)
    var ccHmacInit   = sysExport("CCHmacInit");
    var ccHmacUpdate = sysExport("CCHmacUpdate");
    var ccHmacFinal  = sysExport("CCHmacFinal");

    var ccHmacCtxMap = {};

    if (ccHmacInit) {
        Interceptor.attach(ccHmacInit, {
            onEnter: function (args) {
                if (!onTraceThread()) return;
                // CCHmacInit(CCHmacContext *ctx, CCHmacAlgorithm algorithm,
                //            const void *key, size_t keyLength)
                var ctxKey  = args[0].toString();
                var algo    = args[1].toInt32();
                var key     = args[2];
                var keyLen  = args[3].toInt32();

                var algoName = (algo === 1) ? "SHA1" : (algo === 2) ? "SHA256" :
                               (algo === 6) ? "SHA384" : "unknown(" + algo + ")";

                ccHmacCtxMap[ctxKey] = {
                    algo:    algoName,
                    keyLen:  keyLen,
                    keyHex:  hex(key, Math.min(keyLen, 64)),
                    inputs:  [],
                    totalLen: 0,
                };
                console.log("[CCHmacInit] ctx=" + ctxKey + " algo=" + algoName +
                    " key(" + keyLen + "B)=" + ccHmacCtxMap[ctxKey].keyHex);
            }
        });
        console.log("[+] CCHmacInit hooked");
    }

    if (ccHmacUpdate) {
        Interceptor.attach(ccHmacUpdate, {
            onEnter: function (args) {
                if (!onTraceThread()) return;
                var ctxKey = args[0].toString();
                var data   = args[1];
                var len    = args[2].toInt32();
                if (!ccHmacCtxMap[ctxKey] || len <= 0) return;
                ccHmacCtxMap[ctxKey].totalLen += len;
                ccHmacCtxMap[ctxKey].inputs.push({
                    len: len,
                    hex: (len <= 256) ? hex(data, len) : hexShort(data, len),
                });
            }
        });
        console.log("[+] CCHmacUpdate hooked");
    }

    if (ccHmacFinal) {
        Interceptor.attach(ccHmacFinal, {
            onEnter: function (args) {
                if (!onTraceThread()) return;
                this.macOut = args[1];
                // Can't look up ctx easily, just capture output
            },
            onLeave: function () {
                if (!onTraceThread()) return;
                if (!this.macOut || this.macOut.isNull()) return;
                // Read up to 48 bytes (max SHA384 HMAC)
                var outHex = hex(this.macOut, 48);
                console.log("[CCHmacFinal] output(48B)=" + outHex);
                seqPush("CCHmacFinal", { output: outHex });
            }
        });
        console.log("[+] CCHmacFinal hooked");
    }
}

// ===== Phase 4: SHA tracking — OpenSSL =====

function hookSHA() {
    var nfwc = Process.findModuleByName("NFWebCrypto");
    if (!nfwc) return;

    var shaVariants = [
        { prefix: "SHA256", digestLen: 32 },
        { prefix: "SHA384", digestLen: 48 },
        { prefix: "SHA1",   digestLen: 20 },
    ];

    shaVariants.forEach(function (v) {
        var shaInit   = nfwc.findExportByName(v.prefix + "_Init");
        var shaUpdate = nfwc.findExportByName(v.prefix + "_Update");
        var shaFinal  = nfwc.findExportByName(v.prefix + "_Final");

        var ctxMap = {};

        if (shaInit) {
            Interceptor.attach(shaInit, {
                onEnter: function (args) {
                    if (!onTraceThread()) return;
                    ctxMap[args[0].toString()] = { inputs: [], totalLen: 0 };
                }
            });
            console.log("[+] " + v.prefix + "_Init hooked");
        }

        if (shaUpdate) {
            Interceptor.attach(shaUpdate, {
                onEnter: function (args) {
                    if (!onTraceThread()) return;
                    var ctxKey = args[0].toString();
                    var data   = args[1];
                    var len    = args[2].toInt32();
                    if (!ctxMap[ctxKey]) ctxMap[ctxKey] = { inputs: [], totalLen: 0 };
                    if (len > 0 && len <= 65536) {
                        ctxMap[ctxKey].totalLen += len;
                        if (len <= 256) {
                            ctxMap[ctxKey].inputs.push({ len: len, hex: hex(data, len) });
                        }
                    }
                }
            });
            console.log("[+] " + v.prefix + "_Update hooked");
        }

        if (shaFinal) {
            (function (digestLen, prefix, ctxMapRef) {
                Interceptor.attach(shaFinal, {
                    onEnter: function (args) {
                        if (!onTraceThread()) return;
                        this.md     = args[0];
                        this.ctxKey = args[1].toString();
                        this.active = true;
                    },
                    onLeave: function (retval) {
                        if (!this.active) return;
                        if (!this.md || this.md.isNull()) return;
                        var ctx = ctxMapRef[this.ctxKey];
                        var totalLen = ctx ? ctx.totalLen : -1;
                        // Only log small inputs (likely KDF not bulk data)
                        if (totalLen < 0 || totalLen <= 512) {
                            var digest = hex(this.md, digestLen);
                            console.log("[" + prefix + "_Final] digest=" + digest +
                                " inputLen=" + totalLen);
                            if (ctx) {
                                ctx.inputs.forEach(function (inp) {
                                    console.log("  input(" + inp.len + "B): " + inp.hex);
                                });
                            }
                            seqPush(prefix + "_Final", {
                                digestLen: digestLen,
                                digest:    digest,
                                totalLen:  totalLen,
                                inputs:    ctx ? ctx.inputs.slice() : [],
                            });
                        }
                        if (ctx) delete ctxMapRef[this.ctxKey];
                    }
                });
            })(v.digestLen, v.prefix, ctxMap);
            console.log("[+] " + v.prefix + "_Final hooked");
        }

        // One-shot variant: SHA256(data, len, md) / SHA384(data, len, md)
        var oneShotAddr = nfwc.findExportByName(v.prefix);
        if (oneShotAddr) {
            (function (digestLen, prefix) {
                Interceptor.attach(oneShotAddr, {
                    onEnter: function (args) {
                        if (!onTraceThread()) return;
                        this.dataLen = args[1].toInt32();
                        this.md      = args[2];
                        this.active  = true;
                        if (this.dataLen <= 512) {
                            this.dataHex = hex(args[0], this.dataLen);
                            console.log("[" + prefix + "-1shot] data(" +
                                this.dataLen + "B)=" + this.dataHex);
                        }
                    },
                    onLeave: function () {
                        if (!this.active) return;
                        if (!this.md || this.md.isNull()) return;
                        var digest = hex(this.md, digestLen);
                        console.log("[" + prefix + "-1shot] digest=" + digest);
                        seqPush(prefix + "-1shot", {
                            dataLen: this.dataLen,
                            dataHex: this.dataHex || "(large)",
                            digest:  digest,
                        });
                    }
                });
            })(v.digestLen, v.prefix);
            console.log("[+] " + v.prefix + " (one-shot) hooked");
        }
    });

    // CommonCrypto: CC_SHA256(data, len, md) / CC_SHA1 / CC_SHA384
    var ccVariants = [
        { name: "CC_SHA256", digestLen: 32 },
        { name: "CC_SHA384", digestLen: 48 },
        { name: "CC_SHA1",   digestLen: 20 },
    ];

    ccVariants.forEach(function (v) {
        var addr = sysExport(v.name);
        if (!addr) {
            console.log("[-] " + v.name + " not found");
            return;
        }
        (function (digestLen, name) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    if (!onTraceThread()) return;
                    this.dataLen = args[1].toInt32();
                    this.md      = args[2];
                    this.active  = true;
                    if (this.dataLen <= 512) {
                        this.dataHex = hex(args[0], this.dataLen);
                        console.log("[" + name + "] data(" + this.dataLen + "B)=" + this.dataHex);
                    }
                },
                onLeave: function () {
                    if (!this.active) return;
                    if (!this.md || this.md.isNull()) return;
                    var digest = hex(this.md, digestLen);
                    console.log("[" + name + "] digest=" + digest);
                    seqPush(name, {
                        dataLen: this.dataLen,
                        dataHex: this.dataHex || "(large)",
                        digest:  digest,
                    });
                }
            });
        })(v.digestLen, v.name);
        console.log("[+] " + v.name + " hooked");
    });
}

// ===== Phase 5 & 6: AES key anchor =====

function hookAESKeys() {
    var aesSetEnc = nfExport("AES_set_encrypt_key");
    var aesSetDec = nfExport("AES_set_decrypt_key");

    function onAESKey(label, args) {
        if (!onTraceThread()) return;
        var bits   = args[1].toInt32();
        var keyLen = bits / 8;
        if (keyLen !== 16 && keyLen !== 24 && keyLen !== 32) return;

        var keyHex = hex(args[0], keyLen);
        console.log("\n[" + label + "] bits=" + bits + " key=" + keyHex);

        // Backtrace to identify the caller
        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 10);
        bt.forEach(function (addr) {
            var sym = DebugSymbol.fromAddress(addr);
            console.log("  " + addr + " " + sym);
        });

        seqPush(label, { bits: bits, keyLen: keyLen, keyHex: keyHex });
        g_aesKeyCount++;

        if (g_aesKeyCount === 1) {
            console.log("\n=== DERIVATION COMPLETE (first AES key after DH) ===");
            console.log("[ANCHOR] " + label + " key=" + keyHex);
            printSummary();
            // Keep trace open for additional AES keys
        }
    }

    if (aesSetEnc) {
        Interceptor.attach(aesSetEnc, {
            onEnter: function (args) { onAESKey.call(this, "AES_set_encrypt_key", args); }
        });
        console.log("[+] AES_set_encrypt_key hooked");
    } else {
        console.log("[-] AES_set_encrypt_key not found");
    }

    if (aesSetDec) {
        Interceptor.attach(aesSetDec, {
            onEnter: function (args) { onAESKey.call(this, "AES_set_decrypt_key", args); }
        });
        console.log("[+] AES_set_decrypt_key hooked");
    } else {
        console.log("[-] AES_set_decrypt_key not found");
    }
}

// ===== Phase 6: Backwards correlation summary =====

function printSummary() {
    console.log("\n========== CRYPTO SEQUENCE SUMMARY ==========");
    console.log("[*] DH thread: " + g_traceThreadId);
    console.log("[*] Total events: " + g_sequence.length);

    if (g_sharedSecret) {
        var ssArr = new Uint8Array(g_sharedSecret);
        console.log("[*] DH shared_secret (" + ssArr.length + "B) = " +
            bytesToHex(ssArr).substring(0, 64) + "...");
    }

    g_sequence.forEach(function (e) {
        var line = "[" + e.idx + "] " + e.tag;

        if (e.tag === "DH_compute_key") {
            line += " -> " + e.output.substring(0, 32) + "... (" + e.len + "B)";
        } else if (e.tag === "HMAC-1shot") {
            line += " key(" + e.keyLen + "B)=" + e.keyHex.substring(0, 32) +
                "... data(" + e.dataLen + "B) -> " + e.output.substring(0, 32) + "...";
        } else if (e.tag === "HMAC_Final" || e.tag === "CCHmacFinal") {
            line += " -> " + e.output.substring(0, 32) + "...";
        } else if (e.tag === "CCHmac") {
            line += "[" + e.algo + "] key(" + e.keyLen + "B)=" +
                e.keyHex.substring(0, 32) + "... data(" + e.dataLen + "B) -> " +
                e.output.substring(0, 32) + "...";
        } else if (e.tag.indexOf("Final") !== -1 || e.tag.indexOf("1shot") !== -1) {
            if (e.digest) {
                line += " digest=" + e.digest.substring(0, 32) + "...";
            }
        } else if (e.tag.indexOf("AES") !== -1) {
            line += " key=" + e.keyHex;
        }

        console.log(line);

        // Print full inputs/outputs for HMAC calls
        if ((e.tag === "HMAC-1shot" || e.tag === "CCHmac") && e.output) {
            console.log("    KEY  = " + e.keyHex);
            console.log("    DATA = " + e.dataHex);
            console.log("    OUT  = " + e.output);
        }
    });

    // Cross-reference: check if DH shared secret appears in any HMAC input
    if (g_sharedSecret) {
        var ssBytes = new Uint8Array(g_sharedSecret);
        var ssHex   = bytesToHex(ssBytes);
        var ssPrefix = ssHex.substring(0, 32); // first 16 bytes as check

        console.log("\n--- Shared secret cross-reference (prefix=" + ssPrefix + ") ---");
        g_sequence.forEach(function (e) {
            var fields = ["keyHex", "dataHex", "output", "digest", "inputs"];
            fields.forEach(function (f) {
                if (typeof e[f] === "string" && e[f].indexOf(ssPrefix) !== -1) {
                    console.log("[XREF] event[" + e.idx + "]." + f + " contains shared_secret prefix");
                }
                if (Array.isArray(e[f])) {
                    e[f].forEach(function (inp) {
                        if (inp.hex && inp.hex.indexOf(ssPrefix) !== -1) {
                            console.log("[XREF] event[" + e.idx + "].inputs[" + inp.len + "B] contains shared_secret prefix");
                        }
                    });
                }
            });
        });
    }

    console.log("========== END SUMMARY ==========\n");
}

// ===== Phase 7: RPC export for MSL spec KDF test =====

rpc.exports.testMslKdf = function (sharedSecretHex, pskHex, nonceHex) {
    // Compute HMAC-SHA384(sharedSecret, "MASTER_SECRET" || psk || nonce)
    var hmacFn = nfwc ? nfwc.findExportByName("HMAC") : null;
    var evpSha384 = nfwc ? nfwc.findExportByName("EVP_sha384") : null;

    if (!hmacFn || !evpSha384) {
        return { error: "HMAC or EVP_sha384 not found in NFWebCrypto" };
    }

    var HMAC_native = new NativeFunction(hmacFn,
        'pointer', ['pointer', 'pointer', 'int', 'pointer', 'size_t', 'pointer', 'pointer']);
    var EVP_sha384_native = new NativeFunction(evpSha384, 'pointer', []);

    var ssBytes    = hexToBytes(sharedSecretHex);
    var pskBytes   = hexToBytes(pskHex);
    var nonceBytes = hexToBytes(nonceHex);

    var label    = "MASTER_SECRET";
    var labelBuf = Memory.allocUtf8String(label);

    // data = label || psk || nonce
    var dataLen = label.length + pskBytes.length + nonceBytes.length;
    var dataBuf = Memory.alloc(dataLen);
    Memory.copy(dataBuf, labelBuf, label.length);
    dataBuf.add(label.length).writeByteArray(pskBytes.buffer);
    dataBuf.add(label.length + pskBytes.length).writeByteArray(nonceBytes.buffer);

    var keyBuf = Memory.alloc(ssBytes.length);
    keyBuf.writeByteArray(ssBytes.buffer);

    var outBuf = Memory.alloc(48);
    var outLen = Memory.alloc(4);
    outLen.writeU32(48);

    var md  = EVP_sha384_native();
    var res = HMAC_native(md, keyBuf, ssBytes.length, dataBuf, dataLen, outBuf, outLen);

    if (res.isNull()) {
        return { error: "HMAC returned null" };
    }

    var actualLen = outLen.readU32();
    var outHex    = hex(outBuf, actualLen);

    console.log("[testMslKdf] HMAC-SHA384(ss, MASTER_SECRET||psk||nonce)=" + outHex);
    return { result: outHex, len: actualLen };
};

// Also expose getSequence for external inspection
rpc.exports.getSequence = function () {
    return JSON.stringify(g_sequence);
};

rpc.exports.getSummary = function () {
    printSummary();
    return "done";
};

rpc.exports.resetTrace = function () {
    g_traceActive   = false;
    g_traceThreadId = null;
    g_sharedSecret  = null;
    g_sequence      = [];
    g_aesKeyCount   = 0;
    console.log("[*] Trace state reset");
    return "reset";
};

// ===== REPL convenience aliases =====

var global = this;
global.getSummary  = printSummary;
global.resetTrace  = rpc.exports.resetTrace;
global.getSequence = function () { console.log(JSON.stringify(g_sequence, null, 2)); };

// ===== Main =====

console.log("\n=== hook_phase2_kdf.js v1 ===");
console.log("[*] Phase 2 KDF tracer — DH shared_secret → enc_key_0/sign_key_0");
console.log("");

enumCryptoSymbols();
hookDHComputeKey();
hookHMACOneShot();
hookHMACStreaming();
hookCCHmac();
hookSHA();
hookAESKeys();

console.log("");
console.log("[*] All hooks installed. Clear app data and restart Netflix to trigger DH exchange.");
console.log("[*] Trace window opens on DH_compute_key call and closes after first AES key setup.");
console.log("[*] Thread filter: only events on the DH thread are recorded.");
console.log("");
console.log("RPC commands:");
console.log("  rpc.exports.testMslKdf(ss_hex, psk_hex, nonce_hex)");
console.log("  rpc.exports.getSummary()");
console.log("  rpc.exports.getSequence()");
console.log("  rpc.exports.resetTrace()");
console.log("");
console.log("REPL commands:");
console.log("  getSummary()   — print ordered crypto call sequence");
console.log("  getSequence()  — dump raw JSON sequence");
console.log("  resetTrace()   — clear state for a fresh run");
console.log("=== ready ===");
