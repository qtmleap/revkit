import { hookSSLPinning } from "./ssl-pinning";
import { hookMSL } from "./msl";
import { hookObjCTrace } from "./http";
import { hookMslCrypto } from "./msl-crypto";
import { hookALE } from "./ale";
import { dumpStorage, forceAleProvision } from "./storage-dump";
import { traceMslModule } from "./msl-trace";

console.log("[*] Netflix iOS Hook starting...");

// ── Hook 有効化フラグ ──
const ENABLE_SSL_PINNING = false;
const ENABLE_MSL = true;
const ENABLE_HTTP = true;
const ENABLE_MSL_CRYPTO = true;
const ENABLE_ALE = true;

// Phase 1: ObjC ランタイム初期化を待ってからフック
setTimeout(function () {
    try { dumpStorage(); } catch (e) { console.log("[-] dumpStorage: " + e); }
    if (ENABLE_SSL_PINNING) try { hookSSLPinning(); } catch (e) { console.log("[-] hookSSLPinning: " + e); }
    if (ENABLE_HTTP) try { hookObjCTrace(); } catch (e) { console.log("[-] hookObjCTrace: " + e); }
    if (ENABLE_MSL) try { hookMSL(); } catch (e) { console.log("[-] hookMSL: " + e); }
    console.log("[*] Phase 1 done (storage dump + ObjC hooks)");

    // Phase 2: MslClient + Nbp のロードを待ってフック
    function tryHookNative(): boolean {
        const mslMod = Process.findModuleByName("MslClient");
        if (!mslMod) return false;
        console.log("[*] MslClient loaded, installing hooks...");
        if (ENABLE_MSL_CRYPTO) try { hookMslCrypto(); } catch (e) { console.log("[-] hookMslCrypto: " + e); }
        if (ENABLE_ALE) try { hookALE(); } catch (e) { console.log("[-] hookALE: " + e); }
        console.log("[*] Netflix Helper Ready.");

        // 全フック完了後に aleProvision を強制トリガー
        setTimeout(function () {
            try { forceAleProvision(); } catch (e) { console.log("[-] forceAleProvision: " + e); }
        }, 2000);

        return true;
    }

    if (!tryHookNative()) {
        console.log("[*] Waiting for MslClient module...");
        const interval = setInterval(function () {
            if (tryHookNative()) {
                clearInterval(interval);
            }
        }, 500);
        setTimeout(function () {
            clearInterval(interval);
            if (!Process.findModuleByName("MslClient")) {
                console.log("[-] MslClient not loaded after 30s");
            }
        }, 30000);
    }
}, 1000);
