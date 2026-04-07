import { logData, logMsl } from "../common/utils";
import { processMslPlaintext } from "../common/msl-processor";
import { jbyteArrayToBase64, jbyteArrayToString, jbyteArrayToArrayBuffer, extractEsnFromBytes, extractStringsFromBytes } from "./utils";
import { mslCurrentUrl, mslCurrentDomain } from "./msl-state";

export function hookMSLCrypto(): void {
    // -------------------------------------------------------
    // AesCbcEncryptor -- AES-CBC 暗号化/復号
    // Obfuscated: encrypt -> b or d (3-arg, returns MslCiphertextEnvelope)
    //             decrypt -> e (1-arg, returns byte[])
    // -------------------------------------------------------
    try {
        const AesCbc = Java.use("com.netflix.msl.crypto.AesCbcEncryptor");

        // Dynamic encrypt method detection: 3-arg method returning non-byte[]
        let encryptHooked = false;
        const encryptNames = ["d", "b"];
        for (let ei = 0; ei < encryptNames.length && !encryptHooked; ei++) {
            const eName = encryptNames[ei];
            try {
                AesCbc[eName].implementation = function (data: any, version: any, keyId: any) {
                    const result = this[eName](data, version, keyId);
                    logMsl("AesCbcEncryptor.encrypt", "plain:" + data.length + "B keyId=" + keyId);
                    logData("msl.aesCbcEncrypt", {
                        plaintext_b64: jbyteArrayToBase64(data),
                        plaintext_size: data.length,
                        keyId: keyId ? ("" + keyId) : null
                    });
                    const ab = jbyteArrayToArrayBuffer(data);
                    if (ab && ab.byteLength > 0) {
                        try { processMslPlaintext(ab, "encrypt", "AES-CBC"); } catch (e) { }
                    }
                    return result;
                };
                console.log("[+] Hooked AesCbcEncryptor." + eName + " (encrypt)");
                encryptHooked = true;
            } catch (e2) {
                // try next name
            }
        }
        if (!encryptHooked) {
            // Fallback: enumerate methods
            const methods = AesCbc.class.getDeclaredMethods();
            methods.forEach(function (m: any) {
                if (m.getParameterTypes().length === 3 && !encryptHooked) {
                    const name = m.getName();
                    console.log("[*] AesCbcEncryptor candidate encrypt: " + name + "(" + m.getParameterTypes().length + ")");
                }
            });
            console.log("[-] AesCbcEncryptor encrypt: could not hook");
        }

        // e() = decrypt: (MslCiphertextEnvelope) -> byte[]
        try {
            AesCbc.e.implementation = function (envelope: any) {
                const result = this.e(envelope);
                const plainStr = jbyteArrayToString(result);
                const preview = plainStr && plainStr.length > 300 ? plainStr.substring(0, 300) + "..." : plainStr;
                logMsl("AesCbcEncryptor.decrypt", "-> " + result.length + "B");
                if (preview) console.log("  " + preview);
                logData("msl.aesCbcDecrypt", {
                    plaintext_b64: jbyteArrayToBase64(result),
                    plaintext_size: result.length
                });
                const ab = jbyteArrayToArrayBuffer(result);
                if (ab && ab.byteLength > 0) {
                    try { processMslPlaintext(ab, "decrypt", "AES-CBC"); } catch (e) { }
                }
                return result;
            };
            console.log("[+] Hooked AesCbcEncryptor.e (decrypt)");
        } catch (e2) {
            console.log("[-] AesCbcEncryptor.e: " + e2);
        }
    } catch (e) {
        console.log("[-] AesCbcEncryptor: " + e);
    }

    // -------------------------------------------------------
    // HmacSha256Signer -- HMAC-SHA256 署名
    // Obfuscated: sign -> a(byte[]) -> MslSignatureEnvelope
    //             verify -> e(byte[], MslSignatureEnvelope) -> boolean
    // -------------------------------------------------------
    try {
        const HmacSigner = Java.use("com.netflix.msl.crypto.HmacSha256Signer");

        // a() = sign
        try {
            HmacSigner.a.implementation = function (data: any) {
                const result = this.a(data);
                logMsl("HmacSha256Signer.sign", "data:" + data.length + "B");
                logData("msl.hmacSha256.sign", {
                    data_b64: jbyteArrayToBase64(data),
                    data_size: data.length
                });
                return result;
            };
            console.log("[+] Hooked HmacSha256Signer.a (sign)");
        } catch (e2) {
            console.log("[-] HmacSha256Signer.a: " + e2);
        }

        // verify -- try e(), then enumerate methods returning boolean with 2 args
        let verifyHooked = false;
        try {
            HmacSigner.e.implementation = function (data: any, sigEnvelope: any) {
                const result = this.e(data, sigEnvelope);
                logMsl("HmacSha256Signer.verify", "data:" + data.length + "B -> " + result);
                return result;
            };
            console.log("[+] Hooked HmacSha256Signer.e (verify)");
            verifyHooked = true;
        } catch (e2) {
            console.log("[-] HmacSha256Signer.e: " + e2);
        }
        if (!verifyHooked) {
            // Enumerate methods to find verify (boolean return, 2 args: byte[], envelope)
            const methods = HmacSigner.class.getDeclaredMethods();
            methods.forEach(function (m: any) {
                const params = m.getParameterTypes();
                const ret = m.getReturnType().getName();
                if (params.length === 2 && ret === "boolean" && !verifyHooked) {
                    const name = m.getName();
                    console.log("[*] HmacSha256Signer candidate verify: " + name + "(" + params[0].getName() + ", " + params[1].getName() + ") -> boolean");
                    try {
                        HmacSigner[name].implementation = function (data: any, sigEnvelope: any) {
                            const result = this[name](data, sigEnvelope);
                            logMsl("HmacSha256Signer.verify", "data:" + data.length + "B -> " + result);
                            return result;
                        };
                        console.log("[+] Hooked HmacSha256Signer." + name + " (verify)");
                        verifyHooked = true;
                    } catch (ex) {
                        console.log("[-] HmacSha256Signer." + name + " hook failed: " + ex);
                    }
                }
            });
        }
    } catch (e) {
        console.log("[-] HmacSha256Signer: " + e);
    }

    // -------------------------------------------------------
    // WidevineCryptoContext -- Widevine暗号
    // encrypt(byte[], MslEncoderFactory, jOK) -> byte[]
    // c(byte[], MslEncoderFactory) -> byte[] (decrypt)
    // b(byte[], MslEncoderFactory, jOK) -> byte[] (sign)
    // c(byte[], byte[], MslEncoderFactory) -> boolean (verify)
    // -------------------------------------------------------
    try {
        const WvCrypto = Java.use("com.netflix.msl.client.impl.WidevineCryptoContext");

        // encrypt (kept as encrypt)
        try {
            WvCrypto.encrypt.implementation = function (data: any, encoder: any, format: any) {
                const result = this.encrypt(data, encoder, format);
                const esn = extractEsnFromBytes(data);
                const strings = extractStringsFromBytes(data);
                logMsl("WidevineCryptoContext.encrypt", "data:" + data.length + "B" + (esn ? " sender=" + esn : ""));
                logData("msl.widevine.encrypt", {
                    domain: mslCurrentDomain,
                    url: mslCurrentUrl,
                    sender: esn,
                    plaintext_size: data.length,
                    strings: strings
                });
                return result;
            };
            console.log("[+] Hooked WidevineCryptoContext.encrypt");
        } catch (e2) {
            console.log("[-] WidevineCryptoContext.encrypt: " + e2);
        }

        // c(byte[], MslEncoderFactory) = decrypt (2-arg overload)
        let decryptHooked = false;
        const methods = WvCrypto.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            const paramCount = m.getParameterTypes().length;
            const retType = m.getReturnType().getName();
            if (name === "c" || name === "b" || name === "d") {
                console.log("[*] WidevineCryptoContext." + name + "(" + paramCount + ") -> " + retType);
            }
        });

        // decrypt: 'c' with 2 args returning byte[]
        try {
            WvCrypto.c.overload('[B', 'com.netflix.msl.io.MslEncoderFactory').implementation = function (data: any, encoder: any) {
                const result = this.c(data, encoder);
                const esn = extractEsnFromBytes(result);
                const strings = extractStringsFromBytes(result);
                logMsl("WidevineCryptoContext.decrypt", data.length + "B -> " + result.length + "B" + (esn ? " sender=" + esn : ""));
                logData("msl.widevine.decrypt", {
                    domain: mslCurrentDomain,
                    url: mslCurrentUrl,
                    sender: esn,
                    plaintext_b64: jbyteArrayToBase64(result),
                    ciphertext_size: data.length,
                    plaintext_size: result.length,
                    strings: strings
                });
                return result;
            };
            console.log("[+] Hooked WidevineCryptoContext.c (decrypt, 2-arg)");
            decryptHooked = true;
        } catch (e2) {
            console.log("[-] WidevineCryptoContext.c(2): " + e2);
        }
        // Fallback: try method name enumeration for decrypt
        if (!decryptHooked) {
            methods.forEach(function (m: any) {
                const name = m.getName();
                const params = m.getParameterTypes();
                const retType = m.getReturnType().getName();
                if (params.length === 2 && retType === "[B" && name !== "encrypt" && !decryptHooked) {
                    try {
                        WvCrypto[name].overload(params[0].getName(), params[1].getName()).implementation = function (data: any, encoder: any) {
                            const result = this[name](data, encoder);
                            const esn = extractEsnFromBytes(result);
                            const strings = extractStringsFromBytes(result);
                            logMsl("WidevineCryptoContext.decrypt", data.length + "B -> " + result.length + "B" + (esn ? " sender=" + esn : ""));
                            logData("msl.widevine.decrypt", {
                                domain: mslCurrentDomain,
                                url: mslCurrentUrl,
                                sender: esn,
                                plaintext_b64: jbyteArrayToBase64(result),
                                ciphertext_size: data.length,
                                plaintext_size: result.length,
                                strings: strings
                            });
                            return result;
                        };
                        console.log("[+] Hooked WidevineCryptoContext." + name + " (decrypt fallback)");
                        decryptHooked = true;
                    } catch (ex) {
                        console.log("[-] WidevineCryptoContext." + name + " decrypt hook failed: " + ex);
                    }
                }
            });
        }

        // sign: 'b' with 3 args returning byte[]
        try {
            WvCrypto.b.overload('[B', 'com.netflix.msl.io.MslEncoderFactory', 'com.netflix.msl.io.jOK').implementation = function (data: any, encoder: any, format: any) {
                const result = this.b(data, encoder, format);
                logMsl("WidevineCryptoContext.sign", "data:" + data.length + "B -> sig:" + result.length + "B");
                logData("msl.widevine.sign", {
                    domain: mslCurrentDomain,
                    url: mslCurrentUrl,
                    data_b64: jbyteArrayToBase64(data),
                    data_size: data.length,
                    signature_b64: jbyteArrayToBase64(result),
                    signature_size: result.length
                });
                return result;
            };
            console.log("[+] Hooked WidevineCryptoContext.b (sign, 3-arg)");
        } catch (e2) {
            console.log("[-] WidevineCryptoContext.b(3) sign: " + e2);
            // Fallback: enumerate 3-arg methods returning byte[]
            methods.forEach(function (m: any) {
                const name = m.getName();
                const params = m.getParameterTypes();
                const retType = m.getReturnType().getName();
                if (params.length === 3 && retType === "[B" && name !== "encrypt") {
                    try {
                        WvCrypto[name].overload(params[0].getName(), params[1].getName(), params[2].getName()).implementation = function (data: any, encoder: any, format: any) {
                            const result = this[name](data, encoder, format);
                            logMsl("WidevineCryptoContext.sign", "data:" + data.length + "B -> sig:" + result.length + "B");
                            logData("msl.widevine.sign", {
                                data_b64: jbyteArrayToBase64(data),
                                data_size: data.length,
                                signature_b64: jbyteArrayToBase64(result),
                                signature_size: result.length
                            });
                            return result;
                        };
                        console.log("[+] Hooked WidevineCryptoContext." + name + " (sign fallback)");
                    } catch (ex) {
                        console.log("[-] WidevineCryptoContext." + name + " sign hook failed: " + ex);
                    }
                }
            });
        }

        // verify: 'c' with 3 args returning boolean
        try {
            WvCrypto.c.overload('[B', '[B', 'com.netflix.msl.io.MslEncoderFactory').implementation = function (data: any, sig: any, encoder: any) {
                const result = this.c(data, sig, encoder);
                logMsl("WidevineCryptoContext.verify", "data:" + data.length + "B -> " + result);
                logData("msl.widevine.verify", {
                    data_b64: jbyteArrayToBase64(data),
                    data_size: data.length,
                    verified: result
                });
                return result;
            };
            console.log("[+] Hooked WidevineCryptoContext.c (verify, 3-arg)");
        } catch (e2) {
            console.log("[-] WidevineCryptoContext.c(3) verify: " + e2);
        }
    } catch (e) {
        console.log("[-] WidevineCryptoContext: " + e);
    }

    // -------------------------------------------------------
    // SymmetricCryptoContext -- 汎用対称暗号
    // Same obfuscation: encrypt, c(decrypt), b(sign), c(verify)
    // -------------------------------------------------------
    try {
        const SymCrypto = Java.use("com.netflix.msl.crypto.SymmetricCryptoContext");

        SymCrypto.encrypt.implementation = function (data: any, encoder: any, format: any) {
            const result = this.encrypt(data, encoder, format);
            const esn = extractEsnFromBytes(data);
            logMsl("SymmetricCryptoContext.encrypt", "data:" + data.length + "B" + (esn ? " sender=" + esn : ""));
            logData("msl.symmetric.encrypt", {
                sender: esn,
                plaintext_size: data.length,
                strings: extractStringsFromBytes(data)
            });
            return result;
        };
        console.log("[+] Hooked SymmetricCryptoContext.encrypt");

        // Enumerate methods to find decrypt/sign/verify
        const symMethods = SymCrypto.class.getDeclaredMethods();
        symMethods.forEach(function (m: any) {
            const name = m.getName();
            const paramCount = m.getParameterTypes().length;
            const retType = m.getReturnType().getName();
            if (name !== "encrypt") {
                console.log("[*] SymmetricCryptoContext." + name + "(" + paramCount + ") -> " + retType);
            }
        });

        // decrypt: 'c' with 2 args (byte[], MslEncoderFactory) -> byte[]
        let symDecryptHooked = false;
        try {
            SymCrypto.c.overload('[B', 'com.netflix.msl.io.MslEncoderFactory').implementation = function (data: any, encoder: any) {
                const result = this.c(data, encoder);
                const esn = extractEsnFromBytes(result);
                logMsl("SymmetricCryptoContext.decrypt", data.length + "B -> " + result.length + "B" + (esn ? " sender=" + esn : ""));
                logData("msl.symmetric.decrypt", {
                    sender: esn,
                    ciphertext_size: data.length,
                    plaintext_size: result.length,
                    strings: extractStringsFromBytes(result)
                });
                return result;
            };
            console.log("[+] Hooked SymmetricCryptoContext.c (decrypt)");
            symDecryptHooked = true;
        } catch (e2) {
            console.log("[-] SymmetricCryptoContext.c(2): " + e2);
        }
        if (!symDecryptHooked) {
            symMethods.forEach(function (m: any) {
                const name = m.getName();
                const params = m.getParameterTypes();
                const retType = m.getReturnType().getName();
                if (params.length === 2 && retType === "[B" && name !== "encrypt" && !symDecryptHooked) {
                    try {
                        SymCrypto[name].overload(params[0].getName(), params[1].getName()).implementation = function (data: any, encoder: any) {
                            const result = this[name](data, encoder);
                            const esn = extractEsnFromBytes(result);
                            logMsl("SymmetricCryptoContext.decrypt", data.length + "B -> " + result.length + "B" + (esn ? " sender=" + esn : ""));
                            logData("msl.symmetric.decrypt", {
                                sender: esn,
                                ciphertext_size: data.length,
                                plaintext_size: result.length,
                                strings: extractStringsFromBytes(result)
                            });
                            const ab = jbyteArrayToArrayBuffer(result);
                            if (ab && ab.byteLength > 0) {
                                try { processMslPlaintext(ab, "decrypt", "Symmetric"); } catch (e) { }
                            }
                            return result;
                        };
                        console.log("[+] Hooked SymmetricCryptoContext." + name + " (decrypt fallback)");
                        symDecryptHooked = true;
                    } catch (ex) {
                        console.log("[-] SymmetricCryptoContext." + name + " decrypt hook failed: " + ex);
                    }
                }
            });
        }

        // sign: 'b' with 3 args (byte[], MslEncoderFactory, jOK) -> byte[]
        try {
            SymCrypto.b.overload('[B', 'com.netflix.msl.io.MslEncoderFactory', 'com.netflix.msl.io.jOK').implementation = function (data: any, encoder: any, format: any) {
                const result = this.b(data, encoder, format);
                logMsl("SymmetricCryptoContext.sign", "data:" + data.length + "B -> sig:" + result.length + "B");
                logData("msl.symmetric.sign", {
                    data_size: data.length,
                    signature_size: result.length
                });
                return result;
            };
            console.log("[+] Hooked SymmetricCryptoContext.b (sign)");
        } catch (e2) {
            console.log("[-] SymmetricCryptoContext.b(3) sign: " + e2);
        }

        // verify: 'c' with 3 args (byte[], byte[], MslEncoderFactory) -> boolean
        try {
            SymCrypto.c.overload('[B', '[B', 'com.netflix.msl.io.MslEncoderFactory').implementation = function (data: any, sig: any, encoder: any) {
                const result = this.c(data, sig, encoder);
                logMsl("SymmetricCryptoContext.verify", "data:" + data.length + "B -> " + result);
                logData("msl.symmetric.verify", {
                    data_size: data.length,
                    verified: result
                });
                return result;
            };
            console.log("[+] Hooked SymmetricCryptoContext.c (verify)");
        } catch (e2) {
            console.log("[-] SymmetricCryptoContext.c(3) verify: " + e2);
        }
    } catch (e) {
        console.log("[-] SymmetricCryptoContext: " + e);
    }

    // -------------------------------------------------------
    // JsonWebEncryptionCryptoContext -- JWE暗号
    // wrap -> c(byte[], MslEncoderFactory, jOK)
    // unwrap -> d(byte[], MslEncoderFactory)
    // -------------------------------------------------------
    try {
        const JweCrypto = Java.use("com.netflix.msl.crypto.JsonWebEncryptionCryptoContext");
        const jweMethods = JweCrypto.class.getDeclaredMethods();
        jweMethods.forEach(function (m: any) {
            const name = m.getName();
            const paramCount = m.getParameterTypes().length;
            const retType = m.getReturnType().getName();
            console.log("[*] JWECryptoContext." + name + "(" + paramCount + ") -> " + retType);
        });

        // wrap (encrypt): 3 args (byte[], MslEncoderFactory, jOK) -> byte[]
        try {
            JweCrypto.encrypt.implementation = function (data: any, encoder: any, format: any) {
                const result = this.encrypt(data, encoder, format);
                logMsl("JWECryptoContext.wrap", "data:" + data.length + "B -> " + result.length + "B");
                logData("msl.jwe.wrap", {
                    plaintext_size: data.length,
                    wrapped_size: result.length
                });
                return result;
            };
            console.log("[+] Hooked JWECryptoContext.encrypt (wrap)");
        } catch (e2) {
            console.log("[-] JWECryptoContext.encrypt: " + e2);
            // Fallback: try 'c' with 3 args -> byte[]
            jweMethods.forEach(function (m: any) {
                const name = m.getName();
                const params = m.getParameterTypes();
                const retType = m.getReturnType().getName();
                if (params.length === 3 && retType === "[B") {
                    try {
                        JweCrypto[name].overload(params[0].getName(), params[1].getName(), params[2].getName()).implementation = function (data: any, encoder: any, format: any) {
                            const result = this[name](data, encoder, format);
                            logMsl("JWECryptoContext.wrap", "data:" + data.length + "B -> " + result.length + "B");
                            logData("msl.jwe.wrap", {
                                plaintext_size: data.length,
                                wrapped_size: result.length
                            });
                            return result;
                        };
                        console.log("[+] Hooked JWECryptoContext." + name + " (wrap fallback)");
                    } catch (ex) {
                        console.log("[-] JWECryptoContext." + name + " wrap hook failed: " + ex);
                    }
                }
            });
        }

        // unwrap (decrypt): 2 args (byte[], MslEncoderFactory) -> byte[]
        let jweDecryptHooked = false;
        try {
            JweCrypto.c.overload('[B', 'com.netflix.msl.io.MslEncoderFactory').implementation = function (data: any, encoder: any) {
                const result = this.c(data, encoder);
                logMsl("JWECryptoContext.unwrap", data.length + "B -> " + result.length + "B");
                logData("msl.jwe.unwrap", {
                    ciphertext_size: data.length,
                    plaintext_size: result.length
                });
                return result;
            };
            console.log("[+] Hooked JWECryptoContext.c (unwrap)");
            jweDecryptHooked = true;
        } catch (e2) {
            console.log("[-] JWECryptoContext.c(2): " + e2);
        }
        if (!jweDecryptHooked) {
            // Fallback: try 'd' with 2 args, or enumerate
            try {
                JweCrypto.d.overload('[B', 'com.netflix.msl.io.MslEncoderFactory').implementation = function (data: any, encoder: any) {
                    const result = this.d(data, encoder);
                    logMsl("JWECryptoContext.unwrap", data.length + "B -> " + result.length + "B");
                    logData("msl.jwe.unwrap", {
                        ciphertext_size: data.length,
                        plaintext_size: result.length
                    });
                    return result;
                };
                console.log("[+] Hooked JWECryptoContext.d (unwrap fallback)");
                jweDecryptHooked = true;
            } catch (e3) {
                console.log("[-] JWECryptoContext.d(2): " + e3);
            }
        }
        if (!jweDecryptHooked) {
            jweMethods.forEach(function (m: any) {
                const name = m.getName();
                const params = m.getParameterTypes();
                const retType = m.getReturnType().getName();
                if (params.length === 2 && retType === "[B" && name !== "encrypt" && !jweDecryptHooked) {
                    try {
                        JweCrypto[name].overload(params[0].getName(), params[1].getName()).implementation = function (data: any, encoder: any) {
                            const result = this[name](data, encoder);
                            logMsl("JWECryptoContext.unwrap", data.length + "B -> " + result.length + "B");
                            logData("msl.jwe.unwrap", {
                                ciphertext_size: data.length,
                                plaintext_size: result.length
                            });
                            return result;
                        };
                        console.log("[+] Hooked JWECryptoContext." + name + " (unwrap enum fallback)");
                        jweDecryptHooked = true;
                    } catch (ex) {
                        console.log("[-] JWECryptoContext." + name + " unwrap hook failed: " + ex);
                    }
                }
            });
        }

        console.log("[+] JsonWebEncryptionCryptoContext hooks complete");
    } catch (e) {
        console.log("[-] JWE: " + e);
    }
}
