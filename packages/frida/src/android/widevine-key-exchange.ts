export function hookWidevineKeyExchange(): void {
    // -------------------------------------------------------
    // WidevineKeyExchange -- MSLキー交換の実装
    // -------------------------------------------------------
    try {
        const WvKeyEx = Java.use("com.netflix.msl.client.impl.WidevineKeyExchange");
        const methods = WvKeyEx.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            console.log("[*] WidevineKeyExchange." + name + "(" + m.getParameterTypes().length + ")");
        });
    } catch (e) {
        console.log("[-] WidevineKeyExchange: " + e);
    }

    // -------------------------------------------------------
    // WidevineKeyRequestData / WidevineKeyResponseData
    // -------------------------------------------------------
    try {
        const WvKeyReq = Java.use("com.netflix.msl.keyx.WidevineKeyRequestData");
        const methods = WvKeyReq.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            console.log("[*] WidevineKeyRequestData." + m.getName());
        });
    } catch (e) { }

    try {
        const WvKeyResp = Java.use("com.netflix.msl.keyx.WidevineKeyResponseData");
        const methods = WvKeyResp.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            console.log("[*] WidevineKeyResponseData." + m.getName());
        });
    } catch (e) { }

    // -------------------------------------------------------
    // DiffieHellmanExchange -- DHキー交換
    // -------------------------------------------------------
    try {
        const DHExchange = Java.use("com.netflix.msl.keyx.DiffieHellmanExchange");
        const methods = DHExchange.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            if (name.indexOf("generate") !== -1 || name.indexOf("derive") !== -1 || name.indexOf("Request") !== -1 || name.indexOf("Response") !== -1) {
                console.log("[*] DiffieHellmanExchange." + name);
            }
        });
    } catch (e) {
        console.log("[-] DiffieHellmanExchange: " + e);
    }

    // -------------------------------------------------------
    // JsonWebEncryptionLadderExchange -- JWE ラダーキー交換
    // -------------------------------------------------------
    try {
        const JweLadder = Java.use("com.netflix.msl.keyx.JsonWebEncryptionLadderExchange");
        const methods = JweLadder.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            console.log("[*] JWELadderExchange." + m.getName());
        });
    } catch (e) {
        console.log("[-] JWELadderExchange: " + e);
    }

    // -------------------------------------------------------
    // AsymmetricWrappedExchange -- RSA/ECC ラップキー交換
    // -------------------------------------------------------
    try {
        const AsymExchange = Java.use("com.netflix.msl.keyx.AsymmetricWrappedExchange");
        const methods = AsymExchange.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            console.log("[*] AsymmetricWrappedExchange." + m.getName());
        });
    } catch (e) {
        console.log("[-] AsymmetricWrappedExchange: " + e);
    }
}
