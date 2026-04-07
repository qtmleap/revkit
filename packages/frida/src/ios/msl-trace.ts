// ── MslClient モジュール内の暗号関連関数を網羅的にトレースする ──
// どの関数が実際に呼ばれているか調査用

export function traceMslModule(): void {
    const mod = Process.findModuleByName("MslClient");
    if (!mod) {
        console.log("[-] MslClient module not loaded");
        return;
    }

    console.log("[*] MslClient: base=" + mod.base + " size=" + mod.size);

    const keywords = [
        "encrypt", "decrypt", "Encrypt", "Decrypt",
        "cipher", "Cipher",
        "aes", "Aes", "AES",
        "hmac", "Hmac", "HMAC",
        "sign", "Sign",
        "wrap", "Wrap",
        "key", "Key",
        "rsa", "Rsa", "RSA",
        "dh", "DH",
        "provision", "Provision",
        "session", "Session",
        "token", "Token",
    ];

    let exports = mod.enumerateExports();
    if (exports.length === 0) {
        exports = mod.enumerateSymbols() as ModuleExportDetails[];
    }

    const traced: string[] = [];

    exports.forEach(function (sym) {
        if (sym.type !== 'function') return;
        const name = sym.name;

        // キーワードに一致する関数をトレース
        const match = keywords.some(kw => name.indexOf(kw) !== -1);
        if (!match) return;

        // 既知の大量呼び出し関数はスキップ
        if (name.indexOf("__cxa_") !== -1 || name.indexOf("operator") !== -1) return;

        try {
            Interceptor.attach(sym.address, {
                onEnter: function (_args) {
                    console.log("[TRACE] " + name);
                }
            });
            traced.push(name);
        } catch (e) {
            // attach 失敗は無視
        }
    });

    console.log("[*] Tracing " + traced.length + " crypto-related functions in MslClient");

    // ObjC クラスも調査
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        const cryptoClasses = [
            "IosMslCryptoContext",
            "IosMdxCryptoContext",
            "IosCryptoContext",
            "MslCryptoContext",
            "NfCryptoContext",
            "NFCryptoContext",
            "AesCbcCryptoContext",
            "SymmetricCryptoContext",
        ];

        cryptoClasses.forEach(function (clsName) {
            try {
                const cls = ObjC.classes[clsName];
                if (cls) {
                    const methods = cls.$ownMethods;
                    console.log("[*] Found ObjC class: " + clsName + " (" + methods.length + " methods)");
                    methods.forEach(function (m: string) {
                        console.log("    " + m);
                    });
                }
            } catch (e) { }
        });

        // "Crypto" を含むクラスを広く検索
        try {
            const resolver = new ApiResolver("objc");
            const matches = resolver.enumerateMatches("-[*Crypto* encrypt*]");
            matches.forEach(function (match) {
                console.log("[*] ObjC encrypt method: " + match.name);
                try {
                    Interceptor.attach(match.address, {
                        onEnter: function (_args) {
                            console.log("[TRACE-OBJC] " + match.name);
                        }
                    });
                } catch (e) { }
            });

            const decMatches = resolver.enumerateMatches("-[*Crypto* decrypt*]");
            decMatches.forEach(function (match) {
                console.log("[*] ObjC decrypt method: " + match.name);
                try {
                    Interceptor.attach(match.address, {
                        onEnter: function (_args) {
                            console.log("[TRACE-OBJC] " + match.name);
                        }
                    });
                } catch (e) { }
            });
        } catch (e) {
            console.log("[-] ObjC crypto search: " + e);
        }
    }
}
