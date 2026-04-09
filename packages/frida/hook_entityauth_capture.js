/**
 * hook_entityauth_capture.js — entity_auth_data 未知値の実行時キャプチャ
 *
 * 目的: MSL entity_auth_data に含まれる以下の3値を実行時にキャプチャする
 *   1. devicetoken  (216B protobuf) — Nbp.framework 生成
 *   2. apphmac      (32B HMAC-SHA256) — NFWebCrypto.framework HMAC
 *   3. device_key_data (~6576B) — ファイル / NSUserDefaults / SQLite から読み込み
 *
 * 使い方:
 *   frida -H host.docker.internal:27042 -n Argo -l hook_entityauth_capture.js
 *
 * 注意:
 *   - Netflix は standalone spawn で JB 検知して落ちるため、必ず attach で使うこと
 *   - appboot 発生後に entity_auth_data が組み立てられるタイミングでキャプチャされる
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

function hexShort(ptr, len) {
    if (len <= 64) return hex(ptr, len);
    return hex(ptr, 32) + "..." + hex(ptr.add(len - 16), 16) + " (" + len + "B)";
}

function hexArr(arr) {
    return Array.from(arr)
        .map(function (b) { return ("0" + b.toString(16)).slice(-2); })
        .join("");
}

function banner(title) {
    var line = "=".repeat(60);
    console.log("\n" + line);
    console.log("  " + title);
    console.log("  " + ts());
    console.log(line);
}

// ===== Module wait helper =====

function waitForModule(name, cb) {
    var m = Process.findModuleByName(name);
    if (m) { cb(m); return; }
    var iv = setInterval(function () {
        var m2 = Process.findModuleByName(name);
        if (m2) { clearInterval(iv); cb(m2); }
    }, 200);
}

// ===== Captured state (accessible via RPC) =====

var captured = {
    devicetoken: null,       // hex string (216B protobuf)
    apphmac: null,           // hex string (32B HMAC-SHA256)
    deviceKeyData: null,     // hex string (~6576B)
    hmacCandidates: [],      // all 32B HMAC outputs seen near entity_auth assembly
    fileReads: [],           // large file reads (>= 1KB)
};

// ===== 1. devicetoken capture — Nbp.framework =====
//
// Strategy:
//   a. Enumerate all exports/symbols in Nbp that match token/credential/Device
//   b. Hook promising candidates and log 216B-sized return buffers
//   c. Hook ObjC methods on NflxPinnedCertEvaluator / IosMslClient that return NSData

waitForModule("Nbp", function (nbp) {
    banner("Nbp.framework loaded — scanning for devicetoken symbols");
    console.log("[*] Nbp base=" + nbp.base + " size=" + nbp.size);

    // ---- Enumerate exports matching token/credential/device patterns ----
    var tokenPatterns = ["token", "Token", "credential", "Credential", "DeviceToken",
        "device", "Device", "attestation", "Attestation", "regist", "Register"];

    var candidateExports = [];
    var candidateSymbols = [];

    try {
        nbp.enumerateExports().forEach(function (exp) {
            for (var i = 0; i < tokenPatterns.length; i++) {
                if (exp.name.indexOf(tokenPatterns[i]) !== -1) {
                    candidateExports.push(exp);
                    console.log("[NBP-EXP] " + exp.type + " " + exp.name + " @ " + exp.address);
                    break;
                }
            }
        });
    } catch (e) {
        console.log("[-] enumerateExports error: " + e.message);
    }

    try {
        nbp.enumerateSymbols().forEach(function (sym) {
            if (sym.type !== "function") return;
            for (var i = 0; i < tokenPatterns.length; i++) {
                if (sym.name.indexOf(tokenPatterns[i]) !== -1) {
                    candidateSymbols.push(sym);
                    console.log("[NBP-SYM] " + sym.type + " " + sym.name + " @ " + sym.address);
                    break;
                }
            }
        });
    } catch (e) {
        console.log("[-] enumerateSymbols error: " + e.message);
    }

    // ---- Hook all candidates: watch for 216B buffer returns ----
    var TARGET_TOKEN_LEN = 216;

    function tryHookTokenCandidate(name, addr) {
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    // Common pattern: output buffer pointer as first or second arg
                    this.arg0 = args[0];
                    this.arg1 = args[1];
                    this.arg2 = args[2];
                },
                onLeave: function (retval) {
                    // Check if retval looks like a pointer to NSData or raw buffer
                    if (!retval || retval.isNull()) return;

                    // Try reading as length-prefixed buffer (NSData: [ptr isa][ptr bytes][size_t length])
                    try {
                        var lenOffset = 2 * Process.pointerSize;
                        var dataLen = retval.add(lenOffset).readUSize();
                        if (dataLen === TARGET_TOKEN_LEN) {
                            var bytesPtr = retval.add(Process.pointerSize).readPointer();
                            if (!bytesPtr.isNull()) {
                                var h = hex(bytesPtr, TARGET_TOKEN_LEN);
                                banner("devicetoken CANDIDATE (NSData path) — " + name);
                                console.log("[+] length = " + dataLen);
                                console.log("[+] bytes  = " + h);
                                captured.devicetoken = h;
                            }
                        }
                    } catch (e2) {}

                    // Try reading retval directly as 216B buffer
                    try {
                        var h2 = hex(retval, TARGET_TOKEN_LEN);
                        // Sanity: first byte should be 0x0a (protobuf field 1 type 2)
                        var first = retval.readU8();
                        if (first === 0x0a || first === 0x08 || first === 0x12) {
                            banner("devicetoken CANDIDATE (raw ptr path) — " + name);
                            console.log("[+] bytes = " + h2);
                            if (!captured.devicetoken) captured.devicetoken = h2;
                        }
                    } catch (e3) {}
                }
            });
            console.log("[+] Hooked NBP: " + name);
        } catch (e) {
            console.log("[-] Failed to hook NBP " + name + ": " + e.message);
        }
    }

    candidateExports.forEach(function (exp) {
        if (exp.type === "function") tryHookTokenCandidate(exp.name, exp.address);
    });
    candidateSymbols.forEach(function (sym) {
        tryHookTokenCandidate(sym.name, sym.address);
    });

    // Also dump ALL exports so we can review them offline
    console.log("\n[NBP] Full export list:");
    try {
        nbp.enumerateExports().forEach(function (exp) {
            console.log("  [NBP-ALL] " + exp.type + " " + exp.name);
        });
    } catch (e) {
        console.log("[-] " + e.message);
    }
});

// ===== ObjC hooks for devicetoken via IosMslClient / NflxPinnedCertEvaluator =====

setTimeout(function () {
    if (!ObjC.available) {
        console.log("[-] ObjC runtime not available");
        return;
    }

    banner("ObjC scan for devicetoken / device_key_data methods");

    var TARGET_TOKEN_LEN = 216;
    var TARGET_DKD_LEN_MIN = 6000;
    var TARGET_DKD_LEN_MAX = 7200;

    // Scan all loaded ObjC classes for methods that return NSData and match our patterns
    var classPatterns = ["Nflx", "Netflix", "Msl", "MSL", "Device", "Token",
        "Credential", "Auth", "Attestation", "Boot", "Key"];
    var methodPatterns = ["token", "Token", "credential", "Credential", "deviceKey",
        "DeviceKey", "keyData", "KeyData", "attestation", "deviceData"];

    ObjC.enumerateLoadedClasses(function (name) {
        var matchClass = false;
        for (var i = 0; i < classPatterns.length; i++) {
            if (name.indexOf(classPatterns[i]) !== -1) { matchClass = true; break; }
        }
        if (!matchClass) return;

        try {
            var cls = ObjC.classes[name];
            if (!cls) return;

            cls.$ownMethods.forEach(function (method) {
                var matchMethod = false;
                for (var j = 0; j < methodPatterns.length; j++) {
                    if (method.indexOf(methodPatterns[j]) !== -1) { matchMethod = true; break; }
                }
                if (!matchMethod) return;

                console.log("[OBJC-CAND] " + name + " " + method);

                try {
                    var impl = cls[method];
                    if (!impl) return;

                    Interceptor.attach(impl.implementation, {
                        onLeave: function (retval) {
                            if (!retval || retval.isNull()) return;
                            try {
                                // Check if it's NSData
                                var isData = retval.isKindOfClass_
                                    ? retval.isKindOfClass_(ObjC.classes.NSData)
                                    : false;

                                // Try ObjC API
                                var obj = new ObjC.Object(retval);
                                var className = obj.$className;

                                if (className === "NSData" || className === "__NSCFData" ||
                                    className === "NSMutableData" || className === "_NSInlineData") {

                                    var dataLen = obj.length();
                                    if (dataLen === TARGET_TOKEN_LEN) {
                                        var bytesPtr = obj.bytes();
                                        var h = hex(bytesPtr, TARGET_TOKEN_LEN);
                                        banner("devicetoken via ObjC: " + name + " " + method);
                                        console.log("[+] length = " + dataLen);
                                        console.log("[+] bytes  = " + h);
                                        captured.devicetoken = h;

                                    } else if (dataLen >= TARGET_DKD_LEN_MIN && dataLen <= TARGET_DKD_LEN_MAX) {
                                        var bytesPtr2 = obj.bytes();
                                        var h2 = hex(bytesPtr2, dataLen);
                                        banner("device_key_data via ObjC: " + name + " " + method);
                                        console.log("[+] length = " + dataLen);
                                        console.log("[+] bytes  = " + h2);
                                        captured.deviceKeyData = h2;
                                    }
                                }
                            } catch (e) {}
                        }
                    });
                    console.log("[+] ObjC hooked: " + name + " " + method);
                } catch (e) {
                    console.log("[-] ObjC hook failed: " + name + " " + method + ": " + e.message);
                }
            });
        } catch (e) {}
    });
}, 500);

// ===== 2. apphmac capture — NFWebCrypto.framework HMAC =====
//
// Hook NFWebCrypto HMAC function. Filter for 32B outputs that occur in the
// timeframe when entity_auth_data is being assembled (near MslClient calls).
// Log: key bytes, data bytes, output hash for all candidates.
//
// Known candidates:
//   HMAC(PSK, devicetoken)
//   HMAC(enc_key_0, ESN)
//   HMAC(sign_key, payload)

waitForModule("NFWebCrypto", function (nfwc) {
    banner("NFWebCrypto.framework loaded — hooking HMAC for apphmac capture");
    console.log("[*] NFWebCrypto base=" + nfwc.base + " size=" + nfwc.size);

    var pHMAC = nfwc.findExportByName("HMAC");
    if (!pHMAC) {
        console.log("[-] HMAC not found in NFWebCrypto");
        return;
    }
    console.log("[+] HMAC @ " + pHMAC);

    // HMAC(const EVP_MD *evp_md,
    //      const void *key, int key_len,
    //      const unsigned char *data, size_t data_len,
    //      unsigned char *md, unsigned int *md_len)
    Interceptor.attach(pHMAC, {
        onEnter: function (args) {
            this.evp_md  = args[0];
            this.key     = args[1];
            this.keyLen  = args[2].toInt32();
            this.data    = args[3];
            this.dataLen = args[4].toUInt32();
            this.md      = args[5];
            this.mdLenPtr = args[6];
        },
        onLeave: function (retval) {
            if (retval.isNull()) return;

            var outLen = (this.mdLenPtr && !this.mdLenPtr.isNull())
                ? this.mdLenPtr.readU32() : 32;

            // Only care about HMAC-SHA256 (32B output) for apphmac
            if (outLen !== 32) return;

            var keyHex  = hex(this.key, Math.min(this.keyLen, 64));
            var dataHex = hexShort(this.data, Math.min(this.dataLen, 256));
            var outHex  = hex(retval, 32);

            var entry = {
                ts: ts(),
                keyLen: this.keyLen,
                key: keyHex,
                dataLen: this.dataLen,
                data: dataHex,
                out: outHex,
            };
            captured.hmacCandidates.push(entry);

            // Check if output matches 32B and data size matches devicetoken (216B)
            var isTokenHmac = (this.dataLen === 216);
            // Check if data size matches ESN-like (variable, usually 20-40B)
            var isEsnHmac = (this.dataLen >= 20 && this.dataLen <= 50);

            var label = "HMAC-SHA256";
            if (isTokenHmac) label += " [DEVICETOKEN-SIZE DATA]";
            if (isEsnHmac)   label += " [ESN-SIZE DATA]";

            console.log("\n[" + ts() + "] " + label);
            console.log("  key    (" + this.keyLen + "B) = " + keyHex);
            console.log("  data   (" + this.dataLen + "B) = " + dataHex);
            console.log("  output (32B) = " + outHex);

            // Heuristic: if dataLen == 216 this is likely HMAC(PSK, devicetoken) = apphmac
            if (isTokenHmac) {
                banner("apphmac CANDIDATE — HMAC(key, 216B_data)");
                console.log("  [CANDIDATE] key   = " + keyHex);
                console.log("  [CANDIDATE] data  = " + dataHex);
                console.log("  [CANDIDATE] hmac  = " + outHex);
                captured.apphmac = outHex;
            }

            // Backtrace to identify caller context
            var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 5);
            console.log("  backtrace:");
            bt.forEach(function (addr) {
                var sym = DebugSymbol.fromAddress(addr);
                console.log("    " + addr + " " + sym);
            });
        }
    });
    console.log("[+] HMAC hooked in NFWebCrypto");
});

// ===== 3. device_key_data capture =====
//
// Strategy A: NSData dataWithContentsOfFile: — watch all file reads >= 1KB
// Strategy B: NSUserDefaults objectForKey: — watch large NSData values
// Strategy C: sqlite3_step — watch for large BLOB column reads

setTimeout(function () {
    if (!ObjC.available) return;

    banner("device_key_data capture — file / NSUserDefaults / SQLite hooks");

    var TARGET_DKD_LEN_MIN = 4000;   // be generous — might be base64 or padded
    var TARGET_DKD_LEN_MAX = 10000;

    // ---- Strategy A: NSData dataWithContentsOfFile: ----
    try {
        var NSData = ObjC.classes.NSData;
        if (NSData) {
            var dataWithContents = NSData["+ dataWithContentsOfFile:"];
            if (dataWithContents) {
                Interceptor.attach(dataWithContents.implementation, {
                    onEnter: function (args) {
                        // args[2] is the NSString path (index 0=self, 1=sel, 2=path)
                        try {
                            this.path = new ObjC.Object(args[2]).toString();
                        } catch (e) {
                            this.path = "(unknown)";
                        }
                    },
                    onLeave: function (retval) {
                        if (!retval || retval.isNull()) return;
                        try {
                            var obj = new ObjC.Object(retval);
                            var dataLen = obj.length();
                            var entry = { ts: ts(), path: this.path, size: dataLen };
                            captured.fileReads.push(entry);
                            console.log("[FILE] " + ts() + " dataWithContentsOfFile: " + this.path + " → " + dataLen + "B");

                            if (dataLen >= TARGET_DKD_LEN_MIN && dataLen <= TARGET_DKD_LEN_MAX) {
                                var bytesPtr = obj.bytes();
                                var h = hex(bytesPtr, dataLen);
                                banner("device_key_data CANDIDATE — file read");
                                console.log("  path   = " + this.path);
                                console.log("  length = " + dataLen);
                                console.log("  bytes  = " + h.slice(0, 128) + "...");
                                captured.deviceKeyData = h;
                            }
                        } catch (e) {}
                    }
                });
                console.log("[+] NSData dataWithContentsOfFile: hooked");
            }

            // Also hook dataWithContentsOfFile:options:error:
            var dataWithContentsOpts = NSData["+ dataWithContentsOfFile:options:error:"];
            if (dataWithContentsOpts) {
                Interceptor.attach(dataWithContentsOpts.implementation, {
                    onEnter: function (args) {
                        try {
                            this.path = new ObjC.Object(args[2]).toString();
                        } catch (e) {
                            this.path = "(unknown)";
                        }
                    },
                    onLeave: function (retval) {
                        if (!retval || retval.isNull()) return;
                        try {
                            var obj = new ObjC.Object(retval);
                            var dataLen = obj.length();
                            console.log("[FILE] " + ts() + " dataWithContentsOfFile:options:error: " + this.path + " → " + dataLen + "B");
                            if (dataLen >= TARGET_DKD_LEN_MIN && dataLen <= TARGET_DKD_LEN_MAX) {
                                var bytesPtr = obj.bytes();
                                var h = hex(bytesPtr, dataLen);
                                banner("device_key_data CANDIDATE — file read (options:error:)");
                                console.log("  path   = " + this.path);
                                console.log("  length = " + dataLen);
                                console.log("  bytes  = " + h.slice(0, 128) + "...");
                                captured.deviceKeyData = h;
                            }
                        } catch (e) {}
                    }
                });
                console.log("[+] NSData dataWithContentsOfFile:options:error: hooked");
            }
        }
    } catch (e) {
        console.log("[-] NSData file hook error: " + e.message);
    }

    // ---- Strategy B: NSUserDefaults objectForKey: ----
    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;
        if (NSUserDefaults) {
            var objectForKey = NSUserDefaults["- objectForKey:"];
            if (objectForKey) {
                Interceptor.attach(objectForKey.implementation, {
                    onEnter: function (args) {
                        try {
                            this.key = new ObjC.Object(args[2]).toString();
                        } catch (e) {
                            this.key = "(unknown)";
                        }
                    },
                    onLeave: function (retval) {
                        if (!retval || retval.isNull()) return;
                        try {
                            var obj = new ObjC.Object(retval);
                            var className = obj.$className;
                            if (className === "NSData" || className === "__NSCFData" ||
                                className === "NSMutableData" || className === "_NSInlineData") {
                                var dataLen = obj.length();
                                console.log("[DEFAULTS] " + ts() + " objectForKey: " + this.key + " → NSData " + dataLen + "B");
                                if (dataLen >= TARGET_DKD_LEN_MIN && dataLen <= TARGET_DKD_LEN_MAX) {
                                    var bytesPtr = obj.bytes();
                                    var h = hex(bytesPtr, dataLen);
                                    banner("device_key_data CANDIDATE — NSUserDefaults");
                                    console.log("  key    = " + this.key);
                                    console.log("  length = " + dataLen);
                                    console.log("  bytes  = " + h.slice(0, 128) + "...");
                                    captured.deviceKeyData = h;
                                }
                            }
                        } catch (e) {}
                    }
                });
                console.log("[+] NSUserDefaults objectForKey: hooked");
            }
        }
    } catch (e) {
        console.log("[-] NSUserDefaults hook error: " + e.message);
    }

    // ---- Strategy C: sqlite3_step — watch for large BLOB column reads ----
    // We hook sqlite3_column_blob + sqlite3_column_bytes after sqlite3_step
    var sqlite3Mods = ["libsqlite3.dylib", "libsqlite3.0.dylib"];
    var sqlite3 = null;
    Process.enumerateModules().forEach(function (m) {
        if (m.name.indexOf("sqlite3") !== -1) sqlite3 = m;
    });

    if (sqlite3) {
        var pStep     = sqlite3.findExportByName("sqlite3_step");
        var pColBlob  = sqlite3.findExportByName("sqlite3_column_blob");
        var pColBytes = sqlite3.findExportByName("sqlite3_column_bytes");

        if (pStep && pColBlob && pColBytes) {
            var colBlob  = new NativeFunction(pColBlob,  'pointer', ['pointer', 'int']);
            var colBytes = new NativeFunction(pColBytes, 'int',     ['pointer', 'int']);

            Interceptor.attach(pStep, {
                onLeave: function (retval) {
                    // SQLITE_ROW = 100
                    if (retval.toInt32() !== 100) return;
                    var stmt = this.context.x0; // arm64: first arg stays in x0
                    // Scan first 10 columns
                    for (var col = 0; col < 10; col++) {
                        try {
                            var blobLen = colBytes(stmt, col);
                            if (blobLen >= TARGET_DKD_LEN_MIN && blobLen <= TARGET_DKD_LEN_MAX) {
                                var blobPtr = colBlob(stmt, col);
                                if (blobPtr && !blobPtr.isNull()) {
                                    var h = hex(blobPtr, blobLen);
                                    banner("device_key_data CANDIDATE — SQLite BLOB");
                                    console.log("  column = " + col);
                                    console.log("  length = " + blobLen);
                                    console.log("  bytes  = " + h.slice(0, 128) + "...");
                                    captured.deviceKeyData = h;
                                }
                            }
                        } catch (e) {}
                    }
                }
            });
            console.log("[+] sqlite3_step hooked (BLOB size filter " +
                TARGET_DKD_LEN_MIN + "-" + TARGET_DKD_LEN_MAX + "B)");
        } else {
            console.log("[-] sqlite3 step/column functions not found");
        }
    } else {
        console.log("[-] libsqlite3 not found");
    }
}, 300);

// ===== RPC exports =====

rpc.exports = {
    getCaptured: function () {
        return JSON.stringify({
            devicetoken: captured.devicetoken,
            apphmac:     captured.apphmac,
            deviceKeyData: captured.deviceKeyData
                ? captured.deviceKeyData.slice(0, 64) + "... (" + (captured.deviceKeyData.length / 2) + "B)"
                : null,
            hmacCandidates: captured.hmacCandidates.length,
            fileReads: captured.fileReads.length,
        }, null, 2);
    },
    getHmacCandidates: function () {
        return JSON.stringify(captured.hmacCandidates, null, 2);
    },
    getDeviceKeyData: function () {
        return captured.deviceKeyData || null;
    },
    getDeviceToken: function () {
        return captured.devicetoken || null;
    },
    getAppHmac: function () {
        return captured.apphmac || null;
    },
    getFileReads: function () {
        return JSON.stringify(captured.fileReads, null, 2);
    },
};

// Make callable from REPL
var global = this;
global.getCaptured = function () {
    console.log(rpc.exports.getCaptured());
};
global.getHmacCandidates = function () {
    console.log(rpc.exports.getHmacCandidates());
};
global.getDeviceToken = function () {
    console.log(rpc.exports.getDeviceToken());
};
global.getDeviceKeyData = function () {
    var d = rpc.exports.getDeviceKeyData();
    if (d) console.log(d.slice(0, 256) + "... (" + (d.length / 2) + "B)");
    else console.log("(not captured yet)");
};

console.log("\n=== hook_entityauth_capture.js loaded ===");
console.log("Targets:");
console.log("  1. devicetoken (216B) — Nbp.framework token symbols");
console.log("  2. apphmac     (32B)  — NFWebCrypto HMAC (dataLen==216 filter)");
console.log("  3. device_key_data    — file / NSUserDefaults / SQLite (4-10KB filter)");
console.log("RPC commands:");
console.log("  getCaptured()         — summary of all captured values");
console.log("  getHmacCandidates()   — all 32B HMAC calls seen");
console.log("  getDeviceToken()      — devicetoken hex");
console.log("  getDeviceKeyData()    — device_key_data hex");
console.log("");
console.log("[*] Navigate to Netflix homescreen to trigger entity_auth_data assembly");
