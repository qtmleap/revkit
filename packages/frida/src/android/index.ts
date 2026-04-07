import { hookSSLPinning } from "./ssl-pinning";
import { hookSSL } from "./ssl-capture";
import { hookEsnOverride, forceProxyEsnRefetch } from "./esn-override";
import { hookMSL } from "./msl";
import { hookMSLCrypto } from "./msl-crypto";
import { hookHTTP } from "./http";
import { hookWidevineKeyExchange } from "./widevine-key-exchange";
import { hookALE } from "./ale";
import { hookWidevineDRM } from "./widevine-drm";
import { dumpStorage } from "./storage-dump";

console.log("[*] Netflix Android Hook starting...");
Java.perform(() => {
    console.log("[*] Java.perform started");
    hookSSLPinning();
    forceProxyEsnRefetch();
    hookEsnOverride();
    hookMSL();
    hookMSLCrypto();
    hookHTTP();
    hookWidevineKeyExchange();
    hookALE();
    hookWidevineDRM();
    console.log("[*] Java hooks installed");

    // ストレージダンプは遅延実行 (Application コンテキスト初期化待ち)
    setTimeout(() => {
        Java.perform(() => {
            try { dumpStorage(); } catch (e) { console.log("[-] dumpStorage: " + e); }
        });
    }, 3000);
});
hookSSL();
console.log("[*] All hooks installed");
