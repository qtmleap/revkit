/**
 * CDM Host Callback Hook
 *
 * CDM がライセンスリクエストを生成すると、Host::OnSessionMessage コールバックで
 * Chrome に challenge データが渡される。このコールバックをフックして
 * challenge (SignedLicenseRequest protobuf) をキャプチャする。
 *
 * Host_10 vtable layout:
 *   ...
 *   OnInitialized
 *   OnResolveKeyStatusPromise
 *   OnResolveNewSessionPromise
 *   OnResolvePromise
 *   OnRejectPromise
 *   OnSessionMessage        ← ★ challenge がここで渡される
 *   OnSessionKeysChange     ← ★ キーステータス変更通知
 *   OnExpirationChange
 *   OnSessionClosed
 *   ...
 *
 * Note: Host vtable のオフセットは Chrome のバージョンによって変わる可能性がある。
 * ここでは heuristic に基づいてフックする。
 */
import { logData, bytesToHex, bytesToBase64, SEP2, ts } from "../common/utils";

const MESSAGE_TYPE: Record<number, string> = {
    0: "kLicenseRequest",
    1: "kLicenseRenewal",
    2: "kLicenseRelease",
    3: "kIndividualizationRequest",
};

const KEY_STATUS: Record<number, string> = {
    0: "kUsable",
    1: "kInternalError",
    2: "kExpired",
    3: "kOutputRestricted",
    4: "kOutputDownscaled",
    5: "kStatusPending",
    6: "kReleased",
};

/**
 * Chrome Helper の CDM Host コールバックをフックする代替手法。
 * CreateCdmInstance の第4引数 (GetCdmHostFunc) から Host ポインタを辿る
 * のは複雑なので、代わりに CDM 内部の関数をパターンスキャンする。
 *
 * ここではより実用的なアプローチとして、Chrome プロセスの
 * OnSessionMessage 等のシンボルを探す。
 */
export function hookHostCallbacks(): void {
    // Chrome Framework 内のシンボルを探す
    const chromeMod = Process.findModuleByName("Google Chrome Framework");
    if (!chromeMod) {
        console.log("[-] Google Chrome Framework not found in this process");
        return;
    }

    console.log("[*] Google Chrome Framework at " + chromeMod.base + " size=" + chromeMod.size);

    // CdmAdapter や MojoCdmService のシンボルを探す
    const resolver = new ApiResolver("module");
    const patterns = [
        "exports:*!*OnSessionMessage*",
        "exports:*!*OnSessionKeysChange*",
        "exports:*!*CdmAdapter*",
    ];

    for (const pattern of patterns) {
        try {
            const matches = resolver.enumerateMatches(pattern);
            for (const m of matches) {
                console.log("[*] Found: " + m.name + " at " + m.address);
            }
        } catch (e) {
            // stripped symbols, expected
        }
    }
}
