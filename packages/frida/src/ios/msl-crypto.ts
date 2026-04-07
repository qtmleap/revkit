import { bytesToBase64, logData, logMsl } from "../common/utils";
import { processMslPlaintext } from "../common/msl-processor";

// ── Apple ARM64 ABI for C++ shared_ptr ──
// shared_ptr は non-trivial type なので間接渡し:
//   args[N] = shared_ptr* (スタック上の shared_ptr へのポインタ)
//   [args[N]+0] = __ptr_ (T* = vector<uint8_t>*)
//   [args[N]+8] = __cntrl_ (control block*)
//
// 戻り値 (shared_ptr) は x8 レジスタの sret で返される:
//   x8 = sret バッファへのポインタ
//   [x8+0] = __ptr_, [x8+8] = __cntrl_
//
// vector<uint8_t> layout: [begin_ptr, end_ptr, capacity_ptr]

function readVecFromSharedPtrPtr(sharedPtrPtr: NativePointer): { ptr: NativePointer; size: number; bytes: ArrayBuffer } | null {
    try {
        if (sharedPtrPtr.isNull()) return null;
        const vecPtr = sharedPtrPtr.readPointer(); // __ptr_ = vector*
        if (vecPtr.isNull()) return null;
        const begin = vecPtr.readPointer();
        const end = vecPtr.add(Process.pointerSize).readPointer();
        if (begin.isNull()) return null;
        const size = end.sub(begin).toInt32();
        if (size <= 0 || size > 4 * 1024 * 1024) return null;
        return { ptr: begin, size, bytes: begin.readByteArray(size)! };
    } catch (e) { return null; }
}

// 生の vector ポインタから読む (低レベル関数用)
function readVecDirect(vecPtr: NativePointer): { ptr: NativePointer; size: number; bytes: ArrayBuffer } | null {
    try {
        if (vecPtr.isNull()) return null;
        const begin = vecPtr.readPointer();
        const end = vecPtr.add(Process.pointerSize).readPointer();
        if (begin.isNull()) return null;
        const size = end.sub(begin).toInt32();
        if (size <= 0 || size > 4 * 1024 * 1024) return null;
        return { ptr: begin, size, bytes: begin.readByteArray(size)! };
    } catch (e) { return null; }
}

export function hookMslCrypto(): void {
    const mod = Process.findModuleByName("MslClient");
    if (!mod) {
        console.log("[-] MslClient module not loaded");
        return;
    }

    console.log("[*] MslClient module: " + mod.name + " base=" + mod.base + " size=" + mod.size);

    let exports = mod.enumerateExports();
    console.log("[*] MslClient exports: " + exports.length);
    if (exports.length === 0) {
        exports = mod.enumerateSymbols() as ModuleExportDetails[];
        console.log("[*] MslClient symbols: " + exports.length);
    }

    let hooked = 0;

    exports.forEach(function (sym) {
        if (sym.type !== 'function') return;
        const name = sym.name;

        // ============================================================
        // IosSessionCryptoContext (薄いラッパー)
        // ABI: x0=this, x1=shared_ptr* data (間接), x2=shared_ptr* encoder (間接)
        //      x8=sret (戻り値バッファ, IosCryptoContext に透過的に渡される)
        //      戻り値: sret に shared_ptr が書かれる
        // ============================================================

        if (name.indexOf("IosSessionCryptoContext") !== -1) {

            // encrypt
            if (name.indexOf("encrypt") !== -1 && name.indexOf("decrypt") === -1) {
                Interceptor.attach(sym.address, {
                    onEnter: function (args) {
                        this._sret = (this.context as any).x8;
                        this._input = readVecFromSharedPtrPtr(args[1]);
                    },
                    onLeave: function (_retval) {
                        const output = readVecFromSharedPtrPtr(this._sret);
                        const input = this._input;
                        logMsl("SessionCryptoContext.encrypt", "plain:" + (input ? input.size : 0) + "B -> cipher:" + (output ? output.size : 0) + "B");
                        logData("msl.aesCbcEncrypt", {
                            plaintext_b64: input ? bytesToBase64(input.bytes) : null,
                            ciphertext_b64: output ? bytesToBase64(output.bytes) : null,
                            plaintext_size: input ? input.size : 0,
                            ciphertext_size: output ? output.size : 0,
                        });
                        if (input && input.size > 0) {
                            try { processMslPlaintext(input.bytes, "encrypt", "AES-CBC"); } catch (e) { }
                        }
                    }
                });
                console.log("[+] Hooked (Session) " + sym.name);
                hooked++;
            }

            // decrypt
            if (name.indexOf("decrypt") !== -1) {
                Interceptor.attach(sym.address, {
                    onEnter: function (args) {
                        this._sret = (this.context as any).x8;
                        this._input = readVecFromSharedPtrPtr(args[1]);
                    },
                    onLeave: function (_retval) {
                        const output = readVecFromSharedPtrPtr(this._sret);
                        const input = this._input;
                        logMsl("SessionCryptoContext.decrypt", "cipher:" + (input ? input.size : 0) + "B -> plain:" + (output ? output.size : 0) + "B");
                        logData("msl.aesCbcDecrypt", {
                            ciphertext_b64: input ? bytesToBase64(input.bytes) : null,
                            plaintext_b64: output ? bytesToBase64(output.bytes) : null,
                            ciphertext_size: input ? input.size : 0,
                            plaintext_size: output ? output.size : 0,
                        });
                        if (output && output.size > 0) {
                            try { processMslPlaintext(output.bytes, "decrypt", "AES-CBC"); } catch (e) { }
                        }
                    }
                });
                console.log("[+] Hooked (Session) " + sym.name);
                hooked++;
            }

            // sign
            if (name.indexOf("sign") !== -1 && name.indexOf("Signature") === -1) {
                Interceptor.attach(sym.address, {
                    onEnter: function (args) {
                        this._sret = (this.context as any).x8;
                        this._data = readVecFromSharedPtrPtr(args[1]);
                    },
                    onLeave: function (_retval) {
                        const sig = readVecFromSharedPtrPtr(this._sret);
                        logMsl("SessionCryptoContext.sign", "data:" + (this._data ? this._data.size : 0) + "B -> sig:" + (sig ? sig.size : 0) + "B");
                        logData("msl.hmacSha256", {
                            data_b64: this._data ? bytesToBase64(this._data.bytes) : null,
                            signature_b64: sig ? bytesToBase64(sig.bytes) : null,
                            data_size: this._data ? this._data.size : 0,
                        });
                    }
                });
                console.log("[+] Hooked (Session) " + sym.name);
                hooked++;
            }

            // verify — returns bool, no sret
            if (name.indexOf("verify") !== -1) {
                Interceptor.attach(sym.address, {
                    onEnter: function (args) {
                        this._data = readVecFromSharedPtrPtr(args[1]);
                        this._sig = readVecFromSharedPtrPtr(args[2]);
                    },
                    onLeave: function (retval) {
                        const result = retval.toInt32() !== 0;
                        logMsl("SessionCryptoContext.verify", "data:" + (this._data ? this._data.size : 0) + "B -> " + result);
                        logData("msl.hmacVerify", {
                            data_b64: this._data ? bytesToBase64(this._data.bytes) : null,
                            signature_b64: this._sig ? bytesToBase64(this._sig.bytes) : null,
                            data_size: this._data ? this._data.size : 0,
                            result: result,
                        });
                    }
                });
                console.log("[+] Hooked (Session) " + sym.name);
                hooked++;
            }

            return;
        }

        // ── 低レベル関数 (生 const vector& ポインタ) ──

        if (name.indexOf('aesKwUnwrap') !== -1) {
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this._out = args[2];
                    this._kek = readVecDirect(args[0]);
                    this._wrapped = readVecDirect(args[1]);
                },
                onLeave: function (_retval) {
                    const unwrapped = readVecDirect(this._out);
                    logMsl("aesKwUnwrap", "wrapped:" + (this._wrapped ? this._wrapped.size : 0) + "B -> unwrapped:" + (unwrapped ? unwrapped.size : 0) + "B");
                    logData("msl.aesKwUnwrap", {
                        kek_b64: this._kek ? bytesToBase64(this._kek.bytes) : null,
                        wrapped_key_b64: this._wrapped ? bytesToBase64(this._wrapped.bytes) : null,
                        unwrapped_key_b64: unwrapped ? bytesToBase64(unwrapped.bytes) : null,
                    });
                }
            });
            console.log("[+] Hooked " + sym.name);
            hooked++;
        }

        if (name.indexOf('dhComputeSharedSecret') !== -1) {
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this._out = args[3];
                    this._pub = readVecDirect(args[1]);
                },
                onLeave: function (_retval) {
                    const shared = readVecDirect(this._out);
                    logMsl("dhComputeSharedSecret", "pub:" + (this._pub ? this._pub.size : 0) + "B -> shared:" + (shared ? shared.size : 0) + "B");
                    logData("msl.dhSharedSecret", {
                        pub_key_b64: this._pub ? bytesToBase64(this._pub.bytes) : null,
                        shared_secret_b64: shared ? bytesToBase64(shared.bytes) : null,
                    });
                }
            });
            console.log("[+] Hooked " + sym.name);
            hooked++;
        }

        if (name.indexOf('rsaEncrypt') !== -1 || name.indexOf('rsaDecrypt') !== -1) {
            const fnName = name.indexOf('rsaEncrypt') !== -1 ? "rsaEncrypt" : "rsaDecrypt";
            Interceptor.attach(sym.address, {
                onEnter: function (args) {
                    this._fnName = fnName;
                    this._out = args[3];
                    this._input = readVecDirect(args[1]);
                },
                onLeave: function (_retval) {
                    const output = readVecDirect(this._out);
                    logMsl(this._fnName, "input:" + (this._input ? this._input.size : 0) + "B -> output:" + (output ? output.size : 0) + "B");
                    logData("msl." + this._fnName, {
                        input_b64: this._input ? bytesToBase64(this._input.bytes) : null,
                        output_b64: output ? bytesToBase64(output.bytes) : null,
                    });
                }
            });
            console.log("[+] Hooked " + sym.name);
            hooked++;
        }
    });

    console.log("[+] Hooked " + hooked + " MSL crypto functions");
}
