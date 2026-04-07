import { logData } from "../common/utils";
import { ORIGINAL_ESN, OVERRIDE_ESN } from "./config";

export function forceProxyEsnRefetch(): void {
    // -------------------------------------------------------
    // ProxyEsn.$init で expired フラグを強制 true にする
    // → getProxyEsn が発火 → aleProvision も自動実行
    // -------------------------------------------------------
    try {
        const ProxyEsn = Java.use("com.netflix.mediaclient.esn.impl.ProxyEsn");
        ProxyEsn.$init.overloads.forEach(function (overload: any) {
            overload.implementation = function () {
                overload.apply(this, arguments);
                // expired フラグ (boolean フィールド) を強制 true
                try {
                    const fields = this.getClass().getDeclaredFields();
                    for (let i = 0; i < fields.length; i++) {
                        const f = fields[i];
                        if (f.getType().getName() === "boolean") {
                            f.setAccessible(true);
                            const original = f.getBoolean(this);
                            f.setBoolean(this, true);
                            console.log("[ESN] ProxyEsn." + f.getName() + " = " + original + " -> true (force expired)");
                            logData("proxyEsn.forceExpired", {
                                field: f.getName(),
                                original: original,
                            });
                        }
                    }
                } catch (e) {
                    console.log("[-] ProxyEsn expired override: " + e);
                }
            };
        });
        console.log("[+] Hooked ProxyEsn.$init (force expired)");
    } catch (e) {
        console.log("[-] ProxyEsn: " + e);
    }
}

export function hookEsnOverride(): void {
    // -------------------------------------------------------
    // 1. MslContext.getEntityAuthenticationData -> sender (ESN) の提供元
    //    MessageHeader 構築時に MslContext から ESN を取得するため、
    //    ここで差し替えれば MSL 層全体に反映される
    // -------------------------------------------------------
    try {
        const MslContext = Java.use("com.netflix.msl.util.MslContext");
        const methods = MslContext.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            const paramCount = m.getParameterTypes().length;
            const retType = m.getReturnType().getName();
            console.log("[*] MslContext." + name + "(" + paramCount + ") -> " + retType);
        });
    } catch (e) {
        console.log("[-] MslContext enumeration: " + e);
    }

    // -------------------------------------------------------
    // 2. EntityAuthenticationData -- ESN を含む認証データ
    //    Netflix Android では UnauthenticatedAuthenticationData が使われ、
    //    identity フィールドが ESN を保持する
    // -------------------------------------------------------
    try {
        const UnauthData = Java.use("com.netflix.msl.entityauth.UnauthenticatedAuthenticationData");
        // getIdentity() をフックして ESN を差し替え
        try {
            UnauthData.getIdentity.implementation = function () {
                const original = this.getIdentity();
                const esn = original ? original.toString() : null;
                if (esn) {
                    logData("msl.sender", { esn: esn });
                }
                if (esn === ORIGINAL_ESN) {
                    console.log("[ESN] UnauthenticatedAuthenticationData.getIdentity -> override");
                    return Java.use("java.lang.String").$new(OVERRIDE_ESN);
                }
                return original;
            };
            console.log("[+] Hooked UnauthenticatedAuthenticationData.getIdentity (ESN capture + override)");
        } catch (e2) {
            console.log("[-] UnauthenticatedAuthenticationData.getIdentity: " + e2);
            // ProGuard: identity フィールドを直接書き換え
            // コンストラクタをフックして identity を差し替え
            try {
                const constructors = UnauthData.class.getDeclaredConstructors();
                constructors.forEach(function (c: any) {
                    console.log("[*] UnauthenticatedAuthenticationData.<init>(" + c.getParameterTypes().length + ")");
                });
                UnauthData.$init.overload("java.lang.String").implementation = function (identity: any) {
                    if (identity && identity.toString() === ORIGINAL_ESN) {
                        console.log("[ESN] UnauthenticatedAuthenticationData constructor -> override");
                        this.$init(OVERRIDE_ESN);
                    } else {
                        this.$init(identity);
                    }
                };
                console.log("[+] Hooked UnauthenticatedAuthenticationData constructor (ESN override)");
            } catch (e3) {
                console.log("[-] UnauthenticatedAuthenticationData constructor: " + e3);
            }
        }
    } catch (e) {
        console.log("[-] UnauthenticatedAuthenticationData: " + e);
    }

    // -------------------------------------------------------
    // 3. MessageHeader.sender -- CBOR key 20 に書き込まれる ESN
    //    MessageHeader 構築時にフックして sender を差し替え
    // -------------------------------------------------------
    try {
        const MessageHeader = Java.use("com.netflix.msl.msg.MessageHeader");
        const mhMethods = MessageHeader.class.getDeclaredMethods();
        mhMethods.forEach(function (m: any) {
            const name = m.getName();
            const retType = m.getReturnType().getName();
            // getSender / sender 系メソッドを探す
            if (name.toLowerCase().indexOf("sender") !== -1 || name.toLowerCase().indexOf("identity") !== -1) {
                console.log("[*] MessageHeader." + name + "(" + m.getParameterTypes().length + ") -> " + retType);
            }
        });
        // getSender() をフック
        try {
            MessageHeader.getSender.implementation = function () {
                const original = this.getSender();
                if (original && original.toString() === ORIGINAL_ESN) {
                    console.log("[ESN] MessageHeader.getSender -> override");
                    return Java.use("java.lang.String").$new(OVERRIDE_ESN);
                }
                return original;
            };
            console.log("[+] Hooked MessageHeader.getSender (ESN override)");
        } catch (e2) {
            console.log("[-] MessageHeader.getSender: " + e2);
        }
    } catch (e) {
        console.log("[-] MessageHeader ESN override: " + e);
    }

    // -------------------------------------------------------
    // 4. 汎用 ESN 文字列置換 -- SharedPreferences / DeviceInfo
    //    アプリ内でESNを保持する SharedPreferences や DeviceInfo を探索
    // -------------------------------------------------------
    try {
        // SharedPreferences.getString をフックして ESN 値を差し替え
        // SharedPreferences はインターフェースなので実装クラスをフック
        const SharedPrefsImpl = Java.use("android.app.SharedPreferencesImpl");
        SharedPrefsImpl.getString.implementation = function (key: any, defValue: any) {
            const result = this.getString(key, defValue);
            if (result && result.toString() === ORIGINAL_ESN) {
                console.log("[ESN] SharedPreferences.getString('" + key + "') -> override");
                return Java.use("java.lang.String").$new(OVERRIDE_ESN);
            }
            return result;
        };
        console.log("[+] Hooked SharedPreferences.getString (ESN override)");
    } catch (e) {
        console.log("[-] SharedPreferences ESN override: " + e);
    }

    console.log("[*] ESN Override hooks installed: " + OVERRIDE_ESN.substring(0, 40) + "...");
}
