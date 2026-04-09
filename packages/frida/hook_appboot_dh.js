/**
 * hook_appboot_dh.js — appboot DH 共有秘密の手動計算と初期鍵復号試行
 *
 * 目的: DH_generate_key で得た秘密鍵と appboot レスポンスのサーバー公開鍵から
 *       DH_compute_key を手動呼び出しして共有秘密を取得し、
 *       key 33.6 (96B 暗号文) の復号を試行する
 *
 * 使い方:
 *   frida -U -n Netflix -l hook_appboot_dh.js
 *
 *   1. アプリデータを削除して Netflix を起動 (appboot を発生させる)
 *   2. DH_generate_key が発火したら DH ハンドルが自動保存される
 *   3. appboot レスポンスから key 33 のサーバー公開鍵・暗号文を手動で設定:
 *        setServerPubKey("hex...")
 *        setKey336("hex...")   // 96 bytes
 *        setKey339("hex...")   // 16 bytes nonce
 *   4. computeAndDecrypt() で共有秘密の計算 → 復号試行を実行
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
        return "(unreadable)";
    }
}

function hexToBytes(hexStr) {
    var bytes = [];
    for (var i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

function bytesToHex(arr) {
    return Array.from(arr).map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
}

// ===== NFWebCrypto module & function pointers =====

var nfwc = Process.findModuleByName("NFWebCrypto");
if (!nfwc) {
    console.log("[-] NFWebCrypto not found. Is Netflix running?");
} else {
    console.log("[*] NFWebCrypto base=" + nfwc.base + " size=" + nfwc.size);
}

// OpenSSL function pointers from NFWebCrypto
var fn = {};
var fnNames = [
    "DH_generate_key", "DH_compute_key", "DH_new", "DH_free",
    "DH_get0_key", "DH_get0_pqg", "DH_set0_pqg", "DH_set0_key",
    "BN_new", "BN_free", "BN_bin2bn", "BN_bn2bin", "BN_num_bits", "BN_dup",
    "BN_mod_exp", "BN_CTX_new", "BN_CTX_free",
    "SHA256", "SHA384",
    "AES_set_decrypt_key", "AES_cbc_encrypt",
    "HMAC",
    "EVP_sha256",
];

fnNames.forEach(function (name) {
    var addr = nfwc ? nfwc.findExportByName(name) : null;
    if (addr) {
        fn[name] = addr;
        console.log("[+] " + name + " @ " + addr);
    } else {
        console.log("[-] " + name + " not found");
    }
});

// ===== NativeFunction wrappers =====

var DH_compute_key = fn.DH_compute_key ? new NativeFunction(fn.DH_compute_key,
    'int', ['pointer', 'pointer', 'pointer']) : null;

var BN_bin2bn = fn.BN_bin2bn ? new NativeFunction(fn.BN_bin2bn,
    'pointer', ['pointer', 'int', 'pointer']) : null;

var BN_bn2bin = fn.BN_bn2bin ? new NativeFunction(fn.BN_bn2bin,
    'int', ['pointer', 'pointer']) : null;

var BN_num_bits = fn.BN_num_bits ? new NativeFunction(fn.BN_num_bits,
    'int', ['pointer']) : null;

var BN_free = fn.BN_free ? new NativeFunction(fn.BN_free,
    'void', ['pointer']) : null;

var SHA256 = fn.SHA256 ? new NativeFunction(fn.SHA256,
    'pointer', ['pointer', 'size_t', 'pointer']) : null;

var SHA384 = fn.SHA384 ? new NativeFunction(fn.SHA384,
    'pointer', ['pointer', 'size_t', 'pointer']) : null;

var AES_set_decrypt_key = fn.AES_set_decrypt_key ? new NativeFunction(fn.AES_set_decrypt_key,
    'int', ['pointer', 'int', 'pointer']) : null;

var AES_cbc_encrypt = fn.AES_cbc_encrypt ? new NativeFunction(fn.AES_cbc_encrypt,
    'void', ['pointer', 'pointer', 'size_t', 'pointer', 'pointer', 'int']) : null;

var HMAC_fn = fn.HMAC ? new NativeFunction(fn.HMAC,
    'pointer', ['pointer', 'pointer', 'int', 'pointer', 'size_t', 'pointer', 'pointer']) : null;

var EVP_sha256 = fn.EVP_sha256 ? new NativeFunction(fn.EVP_sha256,
    'pointer', []) : null;

// ===== State =====

var g_dhHandle = null;        // DH* from DH_generate_key
var g_dhPubKey = null;        // client public key (hex)
var g_dhPrivKey = null;       // client private key (hex)
var g_dhP = null;             // DH p parameter (hex)
var g_dhG = null;             // DH g parameter (hex)
var g_serverPubKey = null;    // server DH public key (hex) — set manually
var g_key336 = null;          // key 33.6 ciphertext 96 bytes (hex)
var g_key339 = null;          // key 33.9 nonce 16 bytes (hex)

// Known PSK and nonce from binary
var PSK_HEX = "027617984f6227539a630b897c017d69";
var NONCE_HEX = "809f82a7addf548d3ea9dd067ff9bb91";

// ===== Hook DH_generate_key to capture DH handle =====

if (fn.DH_generate_key) {
    var DH_get0_key = fn.DH_get0_key ? new NativeFunction(fn.DH_get0_key,
        'void', ['pointer', 'pointer', 'pointer']) : null;
    var DH_get0_pqg = fn.DH_get0_pqg ? new NativeFunction(fn.DH_get0_pqg,
        'void', ['pointer', 'pointer', 'pointer', 'pointer']) : null;

    Interceptor.attach(fn.DH_generate_key, {
        onEnter: function (args) {
            this.dh = args[0];
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 1) {
                console.log("[-] DH_generate_key failed");
                return;
            }

            g_dhHandle = this.dh;
            console.log("\n[DH_generate_key] DH handle saved: " + this.dh);

            // Extract pub/priv keys
            if (DH_get0_key) {
                var pubPtr = Memory.alloc(Process.pointerSize);
                var privPtr = Memory.alloc(Process.pointerSize);
                DH_get0_key(this.dh, pubPtr, privPtr);

                var pub = pubPtr.readPointer();
                var priv = privPtr.readPointer();

                if (!pub.isNull() && BN_num_bits && BN_bn2bin) {
                    var pubBits = BN_num_bits(pub);
                    var pubBytes = (pubBits + 7) >> 3;
                    var pubBuf = Memory.alloc(pubBytes);
                    BN_bn2bin(pub, pubBuf);
                    g_dhPubKey = hex(pubBuf, pubBytes);
                    console.log("[DH] pub_key (" + pubBytes + "B) = " + g_dhPubKey.substring(0, 32) + "...");
                }

                if (!priv.isNull() && BN_num_bits && BN_bn2bin) {
                    var privBits = BN_num_bits(priv);
                    var privBytes = (privBits + 7) >> 3;
                    var privBuf = Memory.alloc(privBytes);
                    BN_bn2bin(priv, privBuf);
                    g_dhPrivKey = hex(privBuf, privBytes);
                    console.log("[DH] priv_key (" + privBytes + "B) = " + g_dhPrivKey.substring(0, 32) + "...");
                }
            }

            // Extract DH parameters (p, g)
            if (DH_get0_pqg) {
                var pPtr = Memory.alloc(Process.pointerSize);
                var qPtr = Memory.alloc(Process.pointerSize);
                var gPtr = Memory.alloc(Process.pointerSize);
                DH_get0_pqg(this.dh, pPtr, qPtr, gPtr);

                var p = pPtr.readPointer();
                var g = gPtr.readPointer();

                if (!p.isNull() && BN_num_bits && BN_bn2bin) {
                    var pBits = BN_num_bits(p);
                    var pBytes = (pBits + 7) >> 3;
                    var pBuf = Memory.alloc(pBytes);
                    BN_bn2bin(p, pBuf);
                    g_dhP = hex(pBuf, pBytes);
                    // Log the full DH prime p (128B = 1024-bit)
                    console.log("[DH] p (" + pBytes + "B) = " + g_dhP);
                }

                if (!g.isNull() && BN_num_bits && BN_bn2bin) {
                    var gBits = BN_num_bits(g);
                    var gBytes = (gBits + 7) >> 3;
                    var gBuf = Memory.alloc(gBytes);
                    BN_bn2bin(g, gBuf);
                    g_dhG = hex(gBuf, gBytes);
                    console.log("[DH] g = " + g_dhG);
                }
            }

            console.log("\n[*] DH handle captured. Now set server public key with:");
            console.log('    setServerPubKey("hex...")');
        }
    });
    console.log("[+] DH_generate_key hooked");
}

// ===== Also hook DH_compute_key to see if Netflix calls it =====

if (fn.DH_compute_key) {
    Interceptor.attach(fn.DH_compute_key, {
        onEnter: function (args) {
            this.outBuf = args[0];
            console.log("[!] DH_compute_key CALLED by Netflix! (not expected)");
        },
        onLeave: function (retval) {
            var len = retval.toInt32();
            if (len > 0) {
                console.log("[DH_compute_key] shared_secret (" + len + "B) = " + hex(this.outBuf, Math.min(len, 64)) + "...");
            }
        }
    });
    console.log("[+] DH_compute_key hooked (observer)");
}

// ===== Hook BN_mod_exp to catch manual DH computation =====
// DH_compute_key internally does: shared_secret = server_pub ^ priv mod p
// Netflix may call BN_mod_exp directly instead of DH_compute_key

var g_dhGenerateTime = 0;  // timestamp when DH_generate_key fired

if (fn.BN_mod_exp) {
    // BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p_exp, const BIGNUM *m, BN_CTX *ctx)
    Interceptor.attach(fn.BN_mod_exp, {
        onEnter: function (args) {
            this.r = args[0];
            this.a = args[1];      // base
            this.p_exp = args[2];  // exponent
            this.m = args[3];      // modulus

            // Only log if BN sizes suggest DH (1024-bit modulus)
            if (BN_num_bits) {
                var mBits = BN_num_bits(this.m);
                var aBits = BN_num_bits(this.a);
                var expBits = BN_num_bits(this.p_exp);

                // DH: base^exp mod p where p is 1024-bit
                if (mBits >= 1020 && mBits <= 1030) {
                    this.isDH = true;
                    console.log("\n[BN_mod_exp] DH-sized operation detected!");
                    console.log("  base: " + aBits + " bits");
                    console.log("  exp:  " + expBits + " bits");
                    console.log("  mod:  " + mBits + " bits");

                    // Dump base and exponent (full bytes)
                    if (BN_bn2bin) {
                        var aBytes = (aBits + 7) >> 3;
                        var aBuf = Memory.alloc(aBytes);
                        BN_bn2bin(this.a, aBuf);
                        console.log("  base hex: " + hex(aBuf, aBytes));

                        var expBytes = (expBits + 7) >> 3;
                        var expBuf = Memory.alloc(expBytes);
                        BN_bn2bin(this.p_exp, expBuf);
                        console.log("  exp hex:  " + hex(expBuf, expBytes));

                        // Also dump the full modulus (DH prime p, 128B)
                        var mBytes = (mBits + 7) >> 3;
                        var mBuf = Memory.alloc(mBytes);
                        BN_bn2bin(this.m, mBuf);
                        console.log("  mod hex:  " + hex(mBuf, mBytes));
                    }
                }
            }
        },
        onLeave: function (retval) {
            if (this.isDH && retval.toInt32() === 1 && BN_num_bits && BN_bn2bin) {
                var rBits = BN_num_bits(this.r);
                var rBytes = (rBits + 7) >> 3;
                var rBuf = Memory.alloc(rBytes);
                BN_bn2bin(this.r, rBuf);
                var resultHex = hex(rBuf, rBytes);
                console.log("[BN_mod_exp] result (" + rBytes + "B) = " + resultHex);

                // Store as potential DH shared secret
                g_dhSharedSecret = resultHex;
                console.log("[*] Stored as potential DH shared secret");

                // Print backtrace to identify caller
                console.log("  backtrace:");
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 6);
                bt.forEach(function (addr) {
                    var sym = DebugSymbol.fromAddress(addr);
                    console.log("    " + addr + " " + sym);
                });
            }
        }
    });
    console.log("[+] BN_mod_exp hooked (DH-sized filter)");
}

var g_dhSharedSecret = null;  // hex string from BN_mod_exp

// ===== RPC functions callable from Frida console =====

// Set server's DH public key (from appboot response)
rpc.exports.setServerPubKey = function (hexStr) {
    g_serverPubKey = hexStr;
    console.log("[*] Server pub key set (" + (hexStr.length / 2) + " bytes)");
};

// Set key 33.6 (96 bytes ciphertext)
rpc.exports.setKey336 = function (hexStr) {
    g_key336 = hexStr;
    console.log("[*] key 33.6 set (" + (hexStr.length / 2) + " bytes)");
};

// Set key 33.9 (16 bytes nonce)
rpc.exports.setKey339 = function (hexStr) {
    g_key339 = hexStr;
    console.log("[*] key 33.9 set (" + (hexStr.length / 2) + " bytes)");
};

// Helper: AES-128-CBC decrypt
function aesCbcDecrypt(keyBytes, ivBytes, ctBytes) {
    if (!AES_set_decrypt_key || !AES_cbc_encrypt) {
        console.log("[-] AES functions not available");
        return null;
    }

    var keyBuf = Memory.alloc(keyBytes.length);
    keyBuf.writeByteArray(keyBytes.buffer);

    // AES_KEY struct is ~256 bytes
    var aesKey = Memory.alloc(256);
    var ret = AES_set_decrypt_key(keyBuf, keyBytes.length * 8, aesKey);
    if (ret !== 0) {
        console.log("[-] AES_set_decrypt_key failed: " + ret);
        return null;
    }

    var ivBuf = Memory.alloc(16);
    ivBuf.writeByteArray(ivBytes.buffer);

    var ctBuf = Memory.alloc(ctBytes.length);
    ctBuf.writeByteArray(ctBytes.buffer);

    var ptBuf = Memory.alloc(ctBytes.length);

    // enc=0 means decrypt
    AES_cbc_encrypt(ctBuf, ptBuf, ctBytes.length, aesKey, ivBuf, 0);

    return new Uint8Array(ptBuf.readByteArray(ctBytes.length));
}

// Helper: HMAC-SHA256
function hmacSha256(keyBytes, dataBytes) {
    if (!HMAC_fn || !EVP_sha256) {
        console.log("[-] HMAC functions not available");
        return null;
    }

    var md = EVP_sha256();

    var keyBuf = Memory.alloc(keyBytes.length);
    keyBuf.writeByteArray(keyBytes.buffer);

    var dataBuf = Memory.alloc(dataBytes.length);
    dataBuf.writeByteArray(dataBytes.buffer);

    var outBuf = Memory.alloc(32);
    var outLen = Memory.alloc(4);
    outLen.writeU32(32);

    var result = HMAC_fn(md, keyBuf, keyBytes.length, dataBuf, dataBytes.length, outBuf, outLen);
    if (result.isNull()) {
        console.log("[-] HMAC failed");
        return null;
    }

    return new Uint8Array(outBuf.readByteArray(32));
}

// Helper: compute DH shared secret manually via BN_mod_exp
// shared_secret = server_pub ^ priv mod p
function computeViaBnModExp() {
    if (!g_dhPrivKey || !g_serverPubKey || !g_dhP || !fn.BN_mod_exp) {
        console.log("[-] Missing data for BN_mod_exp (need priv, server_pub, p)");
        return null;
    }

    var BN_mod_exp_fn = new NativeFunction(fn.BN_mod_exp,
        'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
    var BN_CTX_new_fn = fn.BN_CTX_new ? new NativeFunction(fn.BN_CTX_new,
        'pointer', []) : null;
    var BN_CTX_free_fn = fn.BN_CTX_free ? new NativeFunction(fn.BN_CTX_free,
        'void', ['pointer']) : null;
    var BN_new_fn = fn.BN_new ? new NativeFunction(fn.BN_new, 'pointer', []) : null;

    // Create BIGNUMs
    var privBytes = hexToBytes(g_dhPrivKey);
    var privBuf = Memory.alloc(privBytes.length);
    privBuf.writeByteArray(privBytes.buffer);
    var privBN = BN_bin2bn(privBuf, privBytes.length, ptr(0));

    var pubBytes = hexToBytes(g_serverPubKey);
    var pubBuf = Memory.alloc(pubBytes.length);
    pubBuf.writeByteArray(pubBytes.buffer);
    var pubBN = BN_bin2bn(pubBuf, pubBytes.length, ptr(0));

    var pBytes = hexToBytes(g_dhP);
    var pBuf = Memory.alloc(pBytes.length);
    pBuf.writeByteArray(pBytes.buffer);
    var pBN = BN_bin2bn(pBuf, pBytes.length, ptr(0));

    var rBN = BN_new_fn ? BN_new_fn() : BN_bin2bn(ptr(0), 0, ptr(0));
    var ctx = BN_CTX_new_fn ? BN_CTX_new_fn() : ptr(0);

    console.log("[BN_mod_exp] Computing server_pub ^ priv mod p ...");
    var ret = BN_mod_exp_fn(rBN, pubBN, privBN, pBN, ctx);

    if (ret !== 1) {
        console.log("[-] BN_mod_exp failed");
        BN_free(privBN); BN_free(pubBN); BN_free(pBN); BN_free(rBN);
        if (BN_CTX_free_fn && !ctx.isNull()) BN_CTX_free_fn(ctx);
        return null;
    }

    var rBits = BN_num_bits(rBN);
    var rLen = (rBits + 7) >> 3;
    var rBuf = Memory.alloc(rLen);
    BN_bn2bin(rBN, rBuf);
    var result = new Uint8Array(rBuf.readByteArray(rLen));

    console.log("[+] BN_mod_exp result (" + rLen + "B) = " + bytesToHex(result));

    BN_free(privBN); BN_free(pubBN); BN_free(pBN); BN_free(rBN);
    if (BN_CTX_free_fn && !ctx.isNull()) BN_CTX_free_fn(ctx);

    return result;
}

// Main: compute shared secret and try to decrypt key 33.6
rpc.exports.computeAndDecrypt = function () {
    return computeAndDecryptImpl();
};

function computeAndDecryptImpl() {
    console.log("\n========== computeAndDecrypt ==========");

    var sharedSecret = null;
    var sharedHex = null;

    // --- Strategy 1: Use BN_mod_exp captured shared secret ---
    if (g_dhSharedSecret) {
        console.log("[*] Using BN_mod_exp captured shared secret");
        sharedSecret = hexToBytes(g_dhSharedSecret);
        sharedHex = g_dhSharedSecret;
        console.log("[+] shared_secret (" + sharedSecret.length + "B) = " + sharedHex.substring(0, 64) + "...");
    }
    // --- Strategy 2: Compute via DH_compute_key ---
    else if (g_dhHandle && g_serverPubKey && DH_compute_key) {
        console.log("[*] Computing via DH_compute_key");

        var serverPubBytes = hexToBytes(g_serverPubKey);
        var serverPubBuf = Memory.alloc(serverPubBytes.length);
        serverPubBuf.writeByteArray(serverPubBytes.buffer);

        var serverPubBN = BN_bin2bn(serverPubBuf, serverPubBytes.length, ptr(0));
        if (serverPubBN.isNull()) {
            console.log("[-] BN_bin2bn failed for server pub key");
            return;
        }

        var outBuf = Memory.alloc(256);
        var sharedLen = DH_compute_key(outBuf, serverPubBN, g_dhHandle);
        BN_free(serverPubBN);

        if (sharedLen <= 0) {
            console.log("[-] DH_compute_key failed: " + sharedLen);
            console.log("[*] Trying BN_mod_exp fallback...");
            sharedSecret = computeViaBnModExp();
            if (!sharedSecret) return;
            sharedHex = bytesToHex(sharedSecret);
        } else {
            sharedSecret = new Uint8Array(outBuf.readByteArray(sharedLen));
            sharedHex = bytesToHex(sharedSecret);
        }
    }
    // --- Strategy 3: Manual BN_mod_exp ---
    else if (g_dhPrivKey && g_serverPubKey && g_dhP && fn.BN_mod_exp) {
        console.log("[*] Computing via manual BN_mod_exp");
        sharedSecret = computeViaBnModExp();
        if (!sharedSecret) return;
        sharedHex = bytesToHex(sharedSecret);
    } else {
        console.log("[-] Need either: BN_mod_exp captured data, or DH handle + server pub key, or priv+pub+p for manual BN_mod_exp");
        console.log("    DH handle: " + (g_dhHandle ? "yes" : "no"));
        console.log("    Server pub: " + (g_serverPubKey ? "yes" : "no"));
        console.log("    Priv key: " + (g_dhPrivKey ? "yes" : "no"));
        console.log("    DH p: " + (g_dhP ? "yes" : "no"));
        return;
    }

    console.log("[+] DH shared_secret (" + sharedSecret.length + "B) = " + sharedHex.substring(0, 64) + "...");

    // --- Step 3: Derive candidate keys from shared_secret ---
    console.log("\n--- Candidate key derivation ---");

    // 3a. SHA-384(shared_secret)
    var sha384Out = Memory.alloc(48);
    var sha384In = Memory.alloc(sharedSecret.length);
    sha384In.writeByteArray(sharedSecret.buffer);
    SHA384(sha384In, sharedSecret.length, sha384Out);
    var sha384 = new Uint8Array(sha384Out.readByteArray(48));
    console.log("[SHA384] " + bytesToHex(sha384));
    console.log("  enc_candidate = " + bytesToHex(sha384.slice(0, 16)));
    console.log("  sign_candidate = " + bytesToHex(sha384.slice(16, 48)));

    // 3b. SHA-384(0x00 || shared_secret) — MSL Java reference style
    var padded1 = new Uint8Array(1 + sharedSecret.length);
    padded1[0] = 0x00;
    padded1.set(sharedSecret, 1);
    var padded1Buf = Memory.alloc(padded1.length);
    padded1Buf.writeByteArray(padded1.buffer);
    SHA384(padded1Buf, 1 + sharedSecret.length, sha384Out);
    var sha384null = new Uint8Array(sha384Out.readByteArray(48));
    console.log("[SHA384(0x00||ss)] " + bytesToHex(sha384null));
    console.log("  enc_candidate = " + bytesToHex(sha384null.slice(0, 16)));
    console.log("  sign_candidate = " + bytesToHex(sha384null.slice(16, 48)));

    // 3c. SHA-256(shared_secret)
    var sha256Out = Memory.alloc(32);
    SHA256(sha384In, sharedSecret.length, sha256Out);
    var sha256 = new Uint8Array(sha256Out.readByteArray(32));
    console.log("[SHA256] " + bytesToHex(sha256));
    console.log("  enc_candidate = " + bytesToHex(sha256.slice(0, 16)));

    // 3d. Shared secret first 16 bytes as raw key
    console.log("[RAW] first 16B = " + bytesToHex(sharedSecret.slice(0, 16)));

    // --- Step 4: Try to decrypt key 33.6 if available ---
    if (g_key336) {
        console.log("\n--- key 33.6 decryption attempts ---");
        var key336Bytes = hexToBytes(g_key336);

        if (key336Bytes.length !== 96) {
            console.log("[!] key 33.6 is " + key336Bytes.length + " bytes (expected 96)");
        }

        // Structure: IV(16) + CT(48) + HMAC(32)
        var iv = key336Bytes.slice(0, 16);
        var ct = key336Bytes.slice(16, 64);
        var hmacTag = key336Bytes.slice(64, 96);

        console.log("  IV   = " + bytesToHex(iv));
        console.log("  CT   = " + bytesToHex(ct));
        console.log("  HMAC = " + bytesToHex(hmacTag));

        // Try each candidate key
        var candidates = [
            { name: "SHA384[:16]", key: sha384.slice(0, 16) },
            { name: "SHA384(0x00||ss)[:16]", key: sha384null.slice(0, 16) },
            { name: "SHA256[:16]", key: sha256.slice(0, 16) },
            { name: "raw_ss[:16]", key: sharedSecret.slice(0, 16) },
            { name: "PSK", key: hexToBytes(PSK_HEX) },
        ];

        // Also try HMAC-based derivations
        var pskBytes = hexToBytes(PSK_HEX);

        // HMAC-SHA256(PSK, shared_secret)[:16]
        var hmacPskSs = hmacSha256(pskBytes, sharedSecret);
        if (hmacPskSs) {
            candidates.push({ name: "HMAC(PSK,ss)[:16]", key: hmacPskSs.slice(0, 16) });
        }

        // HMAC-SHA256(shared_secret[:16], PSK)
        var hmacSsPsk = hmacSha256(sharedSecret.slice(0, 16), pskBytes);
        if (hmacSsPsk) {
            candidates.push({ name: "HMAC(ss[:16],PSK)[:16]", key: hmacSsPsk.slice(0, 16) });
        }

        // HMAC-SHA256(shared_secret, PSK)[:16]
        var hmacFullSsPsk = hmacSha256(sharedSecret, pskBytes);
        if (hmacFullSsPsk) {
            candidates.push({ name: "HMAC(ss,PSK)[:16]", key: hmacFullSsPsk.slice(0, 16) });
        }

        candidates.forEach(function (c) {
            var pt = aesCbcDecrypt(c.key, iv, ct);
            if (pt) {
                console.log("\n  [" + c.name + "] decrypt key = " + bytesToHex(c.key));
                console.log("    plaintext (48B) = " + bytesToHex(pt));
                console.log("    enc_key_0? = " + bytesToHex(pt.slice(0, 16)));
                console.log("    sign_key_0? = " + bytesToHex(pt.slice(16, 48)));

                // Verify: run KDF with this candidate enc_key_0/sign_key_0
                // and check if it produces known enc_key_1
                var nonceBytes = g_key339 ? hexToBytes(g_key339) : hexToBytes(NONCE_HEX);
                var encKey0 = pt.slice(0, 16);
                var signKey0 = pt.slice(16, 48);

                // KDF Step 3: enc_temp = HMAC(PSK, enc_key_0)
                var encTemp = hmacSha256(pskBytes, encKey0);
                if (encTemp) {
                    // KDF Step 4: new_enc = HMAC(enc_temp, nonce)[:16]
                    var newEnc = hmacSha256(encTemp, nonceBytes);
                    if (newEnc) {
                        console.log("    KDF → enc_key_1 = " + bytesToHex(newEnc.slice(0, 16)));
                    }
                }

                // KDF Step 5: sign_temp = HMAC(PSK, sign_key_0)
                var signTemp = hmacSha256(pskBytes, signKey0);
                if (signTemp) {
                    // KDF Step 6: new_sign = HMAC(sign_temp, nonce)
                    var newSign = hmacSha256(signTemp, nonceBytes);
                    if (newSign) {
                        console.log("    KDF → sign_key_1 = " + bytesToHex(newSign));
                    }
                }
            }
        });
    } else {
        console.log("\n[*] key 33.6 not set. Call setKey336(hex) to try decryption.");
    }

    console.log("\n========== done ==========");
}

// ===== Convenience: also hook AES_set_encrypt_key / AES_set_decrypt_key to capture session keys =====

if (fn.AES_set_decrypt_key) {
    Interceptor.attach(fn.AES_set_decrypt_key, {
        onEnter: function (args) {
            var bits = args[1].toInt32();
            var keyLen = bits / 8;
            if (keyLen === 16) {
                console.log("[AES_set_decrypt_key] bits=" + bits + " key=" + hex(args[0], keyLen));
            }
        }
    });
}

// Make functions callable from Frida REPL
// Usage: setServerPubKey("abcd..."), computeAndDecrypt()
var global = this;
global.setServerPubKey = function (h) { g_serverPubKey = h; console.log("[*] Server pub key set (" + (h.length / 2) + "B)"); };
global.setKey336 = function (h) { g_key336 = h; console.log("[*] key 33.6 set (" + (h.length / 2) + "B)"); };
global.setKey339 = function (h) { g_key339 = h; console.log("[*] key 33.9 set (" + (h.length / 2) + "B)"); };
global.computeAndDecrypt = computeAndDecryptImpl;
global.getState = function () {
    console.log("DH handle: " + (g_dhHandle ? g_dhHandle : "null"));
    console.log("Client pub: " + (g_dhPubKey ? g_dhPubKey.substring(0, 32) + "..." : "null"));
    console.log("Client priv: " + (g_dhPrivKey ? g_dhPrivKey.substring(0, 32) + "..." : "null"));
    console.log("Server pub: " + (g_serverPubKey ? g_serverPubKey.substring(0, 32) + "..." : "null"));
    console.log("BN_mod_exp captured: " + (g_dhSharedSecret ? g_dhSharedSecret.substring(0, 32) + "..." : "null"));
    console.log("key 33.6: " + (g_key336 ? g_key336.substring(0, 32) + "... (" + (g_key336.length / 2) + "B)" : "null"));
    console.log("key 33.9: " + (g_key339 || "null"));
};

console.log("\n=== appboot DH hook v1 ===");
console.log("Commands:");
console.log("  getState()                  — show current state");
console.log("  setServerPubKey('hex...')    — set server DH public key");
console.log("  setKey336('hex...')          — set key 33.6 ciphertext (96B)");
console.log("  setKey339('hex...')          — set key 33.9 nonce (16B)");
console.log("  computeAndDecrypt()         — compute shared secret & try decrypt");
console.log("");
console.log("[*] Waiting for DH_generate_key... (clear app data & restart Netflix)");
