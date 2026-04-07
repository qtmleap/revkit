/**
 * Chrome Widevine CDM L3 Hook - macOS
 *
 * Chrome のマルチプロセスアーキテクチャでは、CDM は Utility プロセス
 * (Chrome Helper) 内で libwidevinecdm.dylib としてロードされる。
 *
 * このスクリプトは CDM Interface v10 の以下をフックする:
 *   - CreateCdmInstance: CDM インスタンス生成 → vtable 取得
 *   - SetServerCertificate: サービス証明書の設定
 *   - CreateSessionAndGenerateRequest: ライセンスリクエスト (Challenge) 生成
 *   - UpdateSession: ライセンスレスポンス処理 (キー取得)
 *   - CloseSession: セッション終了
 *   - Decrypt: コンテンツ復号
 */
import { SEP, ts } from "../common/utils";
import { hookCreateCdmInstance } from "./widevine-cdm";
import { extractPrivateKey, startPeriodicScan } from "./private-key-extractor";

// Python API 経由の場合、console.log の出力は on('message') に届かないことがある。
// send() を使って全出力を Python ランナーに転送する。
// _origLog は呼ばない (重複出力を防ぐ)。
console.log = function (...args: any[]) {
    const msg = args.map(a => (typeof a === "string" ? a : JSON.stringify(a))).join(" ");
    send(msg);
};

function main(): void {
    console.log(SEP);
    console.log("[*] Chrome Widevine CDM L3 Hook - macOS (with Key Extraction)");
    console.log("[*] " + ts());
    console.log(SEP);

    hookCreateCdmInstance();

    // CDM 初期化直後のスキャン (鍵が既にロード済みの場合に対応)
    setTimeout(() => {
        console.log("[*] Running initial memory scan for pre-loaded keys...");
        extractPrivateKey();
    }, 3000);

    // 定期スキャン (5秒間隔、鍵が見つかったら自動停止)
    startPeriodicScan(5000);
}

main();
