import { logData, logDrm } from "../common/utils";
import { jbyteArrayToBase64 } from "./utils";

export function hookWidevineDRM(): void {
    // -------------------------------------------------------
    // NetflixMediaDrm -- Widevine MediaDrm ラッパー
    // -------------------------------------------------------
    try {
        const NfMediaDrm = Java.use("com.netflix.mediaclient.drm.NetflixMediaDrm");

        // openSession
        try {
            const openMethods = NfMediaDrm.class.getDeclaredMethods();
            openMethods.forEach(function (m: any) {
                const name = m.getName();
                if (name === "openSession" || name === "closeSession" ||
                    name === "getKeyRequest" || name === "provideKeyResponse" ||
                    name === "getPropertyByteArray" || name === "getPropertyString") {
                    console.log("[*] NetflixMediaDrm." + name + "(" + m.getParameterTypes().length + ")");
                }
            });
        } catch (e) { }
    } catch (e) {
        console.log("[-] NetflixMediaDrm: " + e);
    }

    // -------------------------------------------------------
    // MediaDrm API -- Android標準 DRM API
    // -------------------------------------------------------
    try {
        const MediaDrm = Java.use("android.media.MediaDrm");

        // getKeyRequest -- DRMライセンスリクエスト
        MediaDrm.getKeyRequest.overload("[B", "[B", "java.lang.String", "int", "java.util.HashMap").implementation = function (scope: any, init: any, mimeType: any, keyType: any, optParams: any) {
            const result = this.getKeyRequest(scope, init, mimeType, keyType, optParams);
            const reqData = result.getData();
            logDrm("MediaDrm.getKeyRequest type=" + keyType + " mime=" + mimeType + " reqSize=" + reqData.length);
            logData("drm.keyRequest", {
                keyType: keyType,
                mimeType: mimeType,
                request_b64: jbyteArrayToBase64(reqData),
                request_size: reqData.length
            });
            return result;
        };
        console.log("[+] Hooked MediaDrm.getKeyRequest");

        // provideKeyResponse -- DRMライセンスレスポンス
        MediaDrm.provideKeyResponse.implementation = function (scope: any, response: any) {
            logDrm("MediaDrm.provideKeyResponse scope=" + scope.length + "B response=" + response.length + "B");
            logData("drm.keyResponse", {
                scope_b64: jbyteArrayToBase64(scope),
                response_b64: jbyteArrayToBase64(response),
                response_size: response.length
            });
            return this.provideKeyResponse(scope, response);
        };
        console.log("[+] Hooked MediaDrm.provideKeyResponse");

        // openSession
        MediaDrm.openSession.overload().implementation = function () {
            const sessionId = this.openSession();
            logDrm("MediaDrm.openSession -> sessionId=" + sessionId.length + "B");
            logData("drm.openSession", {
                sessionId_b64: jbyteArrayToBase64(sessionId)
            });
            return sessionId;
        };
        console.log("[+] Hooked MediaDrm.openSession");

        // getPropertyByteArray -- デバイスID等
        MediaDrm.getPropertyByteArray.implementation = function (name: any) {
            const result = this.getPropertyByteArray(name);
            logDrm("MediaDrm.getPropertyByteArray('" + name + "') -> " + result.length + "B");
            logData("drm.property", {
                name: name,
                value_b64: jbyteArrayToBase64(result),
                size: result.length
            });
            return result;
        };
        console.log("[+] Hooked MediaDrm.getPropertyByteArray");

        // getPropertyString
        MediaDrm.getPropertyString.implementation = function (name: any) {
            const result = this.getPropertyString(name);
            logDrm("MediaDrm.getPropertyString('" + name + "') -> '" + result + "'");
            logData("drm.propertyString", { name: name, value: result });
            return result;
        };
        console.log("[+] Hooked MediaDrm.getPropertyString");
    } catch (e) {
        console.log("[-] MediaDrm: " + e);
    }

    // -------------------------------------------------------
    // MSLWidevineL3CryptoManagerImpl -- L3暗号マネージャ
    // -------------------------------------------------------
    try {
        const L3Mgr = Java.use("com.netflix.mediaclient.cryptomanager.impl.MSLWidevineL3CryptoManagerImpl");
        const methods = L3Mgr.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            if (name.indexOf("encrypt") !== -1 || name.indexOf("decrypt") !== -1 ||
                name.indexOf("sign") !== -1 || name.indexOf("verify") !== -1 ||
                name.indexOf("wrap") !== -1 || name.indexOf("unwrap") !== -1 ||
                name.indexOf("provision") !== -1 || name.indexOf("Session") !== -1) {
                console.log("[*] MSLWidevineL3CryptoManager." + name);
            }
        });
    } catch (e) {
        console.log("[-] MSLWidevineL3CryptoManager: " + e);
    }

    // -------------------------------------------------------
    // MSLWidevineL1CryptoManagerImpl -- L1暗号マネージャ
    // -------------------------------------------------------
    try {
        const L1Mgr = Java.use("com.netflix.mediaclient.cryptomanager.impl.MSLWidevineL1CryptoManagerImpl");
        const methods = L1Mgr.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            if (name.indexOf("encrypt") !== -1 || name.indexOf("decrypt") !== -1 ||
                name.indexOf("sign") !== -1 || name.indexOf("verify") !== -1 ||
                name.indexOf("wrap") !== -1 || name.indexOf("unwrap") !== -1 ||
                name.indexOf("provision") !== -1 || name.indexOf("Session") !== -1) {
                console.log("[*] MSLWidevineL1CryptoManager." + name);
            }
        });
    } catch (e) {
        console.log("[-] MSLWidevineL1CryptoManager: " + e);
    }

    // -------------------------------------------------------
    // BaseCryptoManager -- 共通暗号マネージャ (aesCbcEncrypt/Decrypt, hmacSha256)
    // -------------------------------------------------------
    try {
        const BaseCM = Java.use("com.netflix.mediaclient.cryptomanager.impl.BaseCryptoManager");
        const methods = BaseCM.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            if (name === "aesCbcEncrypt" || name === "aesCbcDecrypt" ||
                name === "hmacSha256" || name === "hmacSha256Verify") {
                console.log("[*] BaseCryptoManager." + name + "(" + m.getParameterTypes().length + ")");
                // フック: aesCbcEncrypt
                if (name === "aesCbcEncrypt") {
                    try {
                        m.setAccessible(true);
                        // Dynamic hook via overload
                    } catch (e2) { }
                }
            }
        });
    } catch (e) {
        console.log("[-] BaseCryptoManager: " + e);
    }

    // -------------------------------------------------------
    // CryptoProvider -- DRM暗号プロバイダ
    // -------------------------------------------------------
    try {
        const CryptoProvider = Java.use("com.netflix.mediaclient.crypto.api.CryptoProvider");
        const methods = CryptoProvider.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            console.log("[*] CryptoProvider." + m.getName());
        });
    } catch (e) { }
}
