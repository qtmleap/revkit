import { logData, logAle } from "../common/utils";
import { jbyteArrayToBase64, jbyteArrayToString } from "./utils";

export function hookALE(): void {
    // -------------------------------------------------------
    // AleService -- ALE暗号サービス
    // createSession(String) -> AleSession
    // getProvisioningRequest() -> String (JSON)
    // -------------------------------------------------------
    try {
        const AleService = Java.use("com.netflix.ale.AleService");

        AleService.createSession.implementation = function (responseStr: any) {
            const session = this.createSession(responseStr);
            const s = responseStr ? responseStr.toString() : null;
            logAle("AleService.createSession: response=" + (s ? s.substring(0, 200) : "null"));
            logData("ale.createSession", {
                response: s ? s.substring(0, 65536) : null
            });
            return session;
        };
        console.log("[+] Hooked AleService.createSession");

        AleService.getProvisioningRequest.implementation = function () {
            const req = this.getProvisioningRequest();
            const s = req ? req.toString() : null;
            logAle("AleService.getProvisioningRequest: " + (s ? s.substring(0, 200) : "null"));
            logData("ale.provisionRequest", {
                request: s ? s.substring(0, 65536) : null
            });
            return req;
        };
        console.log("[+] Hooked AleService.getProvisioningRequest");
    } catch (e) {
        console.log("[-] AleService: " + e);
    }

    // -------------------------------------------------------
    // AleSession -- ALEセッション
    // encrypt(byte[]) -> String, encrypt(String) -> String
    // decrypt(String) -> byte[]
    // decryptString(String) -> String
    // -------------------------------------------------------
    try {
        const AleSession = Java.use("com.netflix.ale.AleSession");

        // encrypt(String)
        try {
            AleSession.encrypt.overload("java.lang.String").implementation = function (plaintext: any) {
                const result = this.encrypt(plaintext);
                const pt = plaintext.toString();
                logAle("AleSession.encrypt str:" + pt.length + "->" + result.toString().length + " chars");
                logData("ale.encrypt", {
                    plaintext: pt.substring(0, 8192),
                    plaintext_size: pt.length
                });
                return result;
            };
            console.log("[+] Hooked AleSession.encrypt(String)");
        } catch (e2) {
            console.log("[-] AleSession.encrypt(String): " + e2);
        }

        // encrypt(byte[])
        try {
            AleSession.encrypt.overload("[B").implementation = function (data: any) {
                const result = this.encrypt(data);
                logAle("AleSession.encrypt bytes:" + data.length + "B");
                logData("ale.encrypt", {
                    plaintext_size: data.length
                });
                return result;
            };
            console.log("[+] Hooked AleSession.encrypt(byte[])");
        } catch (e2) { }

        // decrypt(String) -> byte[]
        try {
            AleSession.decrypt.implementation = function (jweStr: any) {
                const result = this.decrypt(jweStr);
                const plainStr = jbyteArrayToString(result);
                const preview = plainStr && plainStr.length > 300 ? plainStr.substring(0, 300) + "..." : plainStr;
                logAle("AleSession.decrypt -> " + result.length + "B");
                if (preview) console.log("  " + preview);
                logData("ale.decrypt", {
                    plaintext_size: result.length,
                    body: plainStr ? plainStr.substring(0, 65536) : null
                });
                return result;
            };
            console.log("[+] Hooked AleSession.decrypt");
        } catch (e2) { }

        // decryptString(String) -> String
        try {
            AleSession.decryptString.implementation = function (jweStr: any) {
                const result = this.decryptString(jweStr);
                const s = result.toString();
                const preview = s.length > 300 ? s.substring(0, 300) + "..." : s;
                logAle("AleSession.decryptString -> " + s.length + " chars");
                console.log("  " + preview);
                logData("ale.decryptString", {
                    plaintext: s.substring(0, 65536),
                    plaintext_size: s.length
                });
                return result;
            };
            console.log("[+] Hooked AleSession.decryptString");
        } catch (e2) { }
    } catch (e) {
        console.log("[-] AleSession: " + e);
    }

    // -------------------------------------------------------
    // AleCryptoBouncyCastle -- ALE低レベル暗号
    // aesCbcEncrypt(AleKey, iv, plaintext) -> byte[]
    // aesCbcDecrypt(AleKey, iv, ciphertext) -> byte[]
    // aesGcmEncrypt(AleKey, iv, aad, plaintext) -> byte[]
    // hmacSha256(AleKey, data) -> byte[]
    // rsaOaepEncrypt(AleKey, data) -> byte[]
    // -------------------------------------------------------
    try {
        const AleCrypto = Java.use("com.netflix.ale.AleCryptoBouncyCastle");

        try {
            AleCrypto.aesCbcEncrypt.implementation = function (key: any, iv: any, plaintext: any) {
                const result = this.aesCbcEncrypt(key, iv, plaintext);
                logAle("AleCrypto.aesCbcEncrypt plain:" + plaintext.length + "B -> cipher:" + result.length + "B");
                logData("ale.aesCbcEncrypt", {
                    plaintext_size: plaintext.length,
                    ciphertext_size: result.length
                });
                return result;
            };
            console.log("[+] Hooked AleCrypto.aesCbcEncrypt");
        } catch (e2) { }

        try {
            AleCrypto.aesCbcDecrypt.implementation = function (key: any, iv: any, ciphertext: any) {
                const result = this.aesCbcDecrypt(key, iv, ciphertext);
                logAle("AleCrypto.aesCbcDecrypt cipher:" + ciphertext.length + "B -> plain:" + result.length + "B");
                logData("ale.aesCbcDecrypt", {
                    plaintext_size: result.length,
                    ciphertext_size: ciphertext.length
                });
                return result;
            };
            console.log("[+] Hooked AleCrypto.aesCbcDecrypt");
        } catch (e2) { }

        try {
            AleCrypto.aesGcmEncrypt.implementation = function (key: any, iv: any, aad: any, plaintext: any) {
                const result = this.aesGcmEncrypt(key, iv, aad, plaintext);
                logAle("AleCrypto.aesGcmEncrypt plain:" + plaintext.length + "B -> cipher:" + result.length + "B");
                logData("ale.aesGcmEncrypt", {
                    plaintext_size: plaintext.length
                });
                return result;
            };
            console.log("[+] Hooked AleCrypto.aesGcmEncrypt");
        } catch (e2) { }

        try {
            AleCrypto.aesGcmDecrypt.implementation = function (key: any, iv: any, aad: any, ciphertext: any) {
                const result = this.aesGcmDecrypt(key, iv, aad, ciphertext);
                logAle("AleCrypto.aesGcmDecrypt cipher:" + ciphertext.length + "B -> plain:" + result.length + "B");
                logData("ale.aesGcmDecrypt", {
                    plaintext_size: result.length
                });
                return result;
            };
            console.log("[+] Hooked AleCrypto.aesGcmDecrypt");
        } catch (e2) { }

        try {
            AleCrypto.hmacSha256.implementation = function (key: any, data: any) {
                const result = this.hmacSha256(key, data);
                logAle("AleCrypto.hmacSha256 data:" + data.length + "B -> mac:" + result.length + "B");
                return result;
            };
            console.log("[+] Hooked AleCrypto.hmacSha256");
        } catch (e2) { }

        try {
            AleCrypto.rsaOaepEncrypt.implementation = function (key: any, data: any) {
                const result = this.rsaOaepEncrypt(key, data);
                logAle("AleCrypto.rsaOaepEncrypt data:" + data.length + "B -> cipher:" + result.length + "B");
                logData("ale.rsaOaepEncrypt", {
                    plaintext_size: data.length
                });
                return result;
            };
            console.log("[+] Hooked AleCrypto.rsaOaepEncrypt");
        } catch (e2) { }
    } catch (e) {
        console.log("[-] AleCryptoBouncyCastle: " + e);
    }

    // -------------------------------------------------------
    // JweBase -- JWE encrypt/decrypt (親クラス)
    // encrypt(byte[]) -> String (JWE compact serialization)
    // decrypt(String) -> byte[]
    // -------------------------------------------------------
    try {
        const JweBase = Java.use("com.netflix.ale.JweBase");

        try {
            JweBase.encrypt.implementation = function (plaintext: any) {
                const result = this.encrypt(plaintext);
                logAle("JweBase.encrypt " + plaintext.length + "B -> JWE");
                logData("ale.jwe.encrypt", {
                    plaintext_size: plaintext.length
                });
                return result;
            };
            console.log("[+] Hooked JweBase.encrypt");
        } catch (e2) { }

        try {
            JweBase.decrypt.implementation = function (jweStr: any) {
                const result = this.decrypt(jweStr);
                const plainStr = jbyteArrayToString(result);
                logAle("JweBase.decrypt JWE -> " + result.length + "B");
                logData("ale.jwe.decrypt", {
                    plaintext_size: result.length,
                    body: plainStr ? plainStr.substring(0, 65536) : null
                });
                return result;
            };
            console.log("[+] Hooked JweBase.decrypt");
        } catch (e2) { }
    } catch (e) {
        console.log("[-] JweBase: " + e);
    }
}
