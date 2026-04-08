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
                    console.log("[DH] p (" + pBytes + "B) = " + g_dhP.substring(0, 16) + "...");
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

// Main: compute shared secret and try to decrypt key 33.6
rpc.exports.computeAndDecrypt = function () {
    return computeAndDecryptImpl();
};

function computeAndDecryptImpl() {
    console.log("\n========== computeAndDecrypt ==========");

    if (!g_dhHandle) {
        console.log("[-] No DH handle. Wait for DH_generate_key to fire.");
        return;
    }
    if (!g_serverPubKey) {
        console.log("[-] No server pub key. Call setServerPubKey(hex)");
        return;
    }

    // --- Step 1: Convert server pub key hex to BIGNUM ---
    var serverPubBytes = hexToBytes(g_serverPubKey);
    var serverPubBuf = Memory.alloc(serverPubBytes.length);
    serverPubBuf.writeByteArray(serverPubBytes.buffer);

    var serverPubBN = BN_bin2bn(serverPubBuf, serverPubBytes.length, ptr(0));
    if (serverPubBN.isNull()) {
        console.log("[-] BN_bin2bn failed for server pub key");
        return;
    }
    console.log("[+] Server pub key BIGNUM created (" + serverPubBytes.length + " bytes)");

    // --- Step 2: Call DH_compute_key ---
    var outBuf = Memory.alloc(256);
    var sharedLen = DH_compute_key(outBuf, serverPubBN, g_dhHandle);
    BN_free(serverPubBN);

    if (sharedLen <= 0) {
        console.log("[-] DH_compute_key failed: " + sharedLen);
        return;
    }

    var sharedSecret = new Uint8Array(outBuf.readByteArray(sharedLen));
    var sharedHex = bytesToHex(sharedSecret);
    console.log("[+] DH shared_secret (" + sharedLen + "B) = " + sharedHex);

    // --- Step 3: Derive candidate keys from shared_secret ---
    console.log("\n--- Candidate key derivation ---");

    // 3a. SHA-384(shared_secret)
    var sha384Out = Memory.alloc(48);
    var sha384In = Memory.alloc(sharedLen);
    sha384In.writeByteArray(sharedSecret.buffer);
    SHA384(sha384In, sharedLen, sha384Out);
    var sha384 = new Uint8Array(sha384Out.readByteArray(48));
    console.log("[SHA384] " + bytesToHex(sha384));
    console.log("  enc_candidate = " + bytesToHex(sha384.slice(0, 16)));
    console.log("  sign_candidate = " + bytesToHex(sha384.slice(16, 48)));

    // 3b. SHA-384(0x00 || shared_secret) — MSL Java reference style
    var padded1 = new Uint8Array(1 + sharedLen);
    padded1[0] = 0x00;
    padded1.set(sharedSecret, 1);
    var padded1Buf = Memory.alloc(padded1.length);
    padded1Buf.writeByteArray(padded1.buffer);
    SHA384(padded1Buf, padded1.length, sha384Out);
    var sha384null = new Uint8Array(sha384Out.readByteArray(48));
    console.log("[SHA384(0x00||ss)] " + bytesToHex(sha384null));
    console.log("  enc_candidate = " + bytesToHex(sha384null.slice(0, 16)));
    console.log("  sign_candidate = " + bytesToHex(sha384null.slice(16, 48)));

    // 3c. SHA-256(shared_secret)
    var sha256Out = Memory.alloc(32);
    SHA256(sha384In, sharedLen, sha256Out);
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
