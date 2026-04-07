import { bytesToBase64, logData, logAle } from "../common/utils";

// ── iOS ALE フック ──
// Nbp.framework の AleManager / ALE モジュールの ObjC/Swift クラスをフック
// MslClient ネイティブではなく Nbp の Swift 実装

export function hookALE(): void {
    if (typeof ObjC === 'undefined' || !ObjC.available) return;

    hookAleManager();
    hookAleService();
    hookPBOClient();
}

// ── AleManager (Nbp) ──

function hookAleManager(): void {
    // Swift クラスの ObjC 名: _TtC3Nbp10AleManager
    const clsName = "_TtC3Nbp10AleManager";
    try {
        const cls = ObjC.classes[clsName];
        if (!cls) {
            console.log("[-] " + clsName + " not found");
            return;
        }

        const methods = cls.$ownMethods;
        console.log("[*] AleManager methods (" + methods.length + "):");
        methods.forEach(function (m: string) {
            console.log("    " + m);
        });

        // 全メソッドをフック
        methods.forEach(function (m: string) {
            try {
                const impl = cls[m];
                if (!impl) return;
                Interceptor.attach(impl.implementation, {
                    onEnter: function (args) {
                        logAle("AleManager" + m);
                    }
                });
            } catch (e) { }
        });

        console.log("[+] Hooked AleManager (" + methods.length + " methods)");
    } catch (e) {
        console.log("[-] AleManager: " + e);
    }
}

// ── AleService / AleSession (ALE module) ──

function hookAleService(): void {
    const classNames = [
        "_TtC3ALE10AleService",
        "_TtC3ALE10AleSession",
        "_TtC3ALE7AleAuto",
        "_TtC3ALE16KeyExchangeClear",
        "_TtC3ALE18KeyExchangeRsaOaep",
    ];

    for (const clsName of classNames) {
        try {
            const cls = ObjC.classes[clsName];
            if (!cls) continue;

            const shortName = clsName.replace("_TtC3ALE", "ALE.").replace("_TtC3Nbp", "Nbp.");
            const methods = cls.$ownMethods;
            console.log("[*] " + shortName + " methods (" + methods.length + "):");
            methods.forEach(function (m: string) {
                console.log("    " + m);
            });

            methods.forEach(function (m: string) {
                try {
                    const impl = cls[m];
                    if (!impl) return;
                    Interceptor.attach(impl.implementation, {
                        onEnter: function (args) {
                            logAle(shortName + m);
                            // createSession / getProvisioningRequest の引数/戻り値をキャプチャ
                            if (m.indexOf("createSession") !== -1 || m.indexOf("provisionResponse") !== -1) {
                                try {
                                    // Swift String 引数は args[2] (self=args[0], _cmd=args[1])
                                    if (args[2] && !args[2].isNull()) {
                                        const str = new ObjC.Object(args[2]).toString();
                                        if (str && str.length > 0) {
                                            const preview = str.length > 300 ? str.substring(0, 300) + "..." : str;
                                            logAle(shortName + ".createSession response: " + preview);
                                            logData("ale.createSession", {
                                                response: str.substring(0, 65536)
                                            });
                                        }
                                    }
                                } catch (e) { }
                            }
                            if (m.indexOf("getProvisioningRequest") !== -1) {
                                logData("ale.provisionRequest", {});
                            }
                        },
                        onLeave: function (retval) {
                            if (m.indexOf("getProvisioningRequest") !== -1) {
                                try {
                                    if (retval && !retval.isNull()) {
                                        const str = new ObjC.Object(retval).toString();
                                        if (str && str.length > 0) {
                                            const preview = str.length > 300 ? str.substring(0, 300) + "..." : str;
                                            logAle(shortName + ".getProvisioningRequest -> " + preview);
                                            logData("ale.provisionRequest", {
                                                request: str.substring(0, 65536)
                                            });
                                        }
                                    }
                                } catch (e) { }
                            }
                        }
                    });
                } catch (e) { }
            });

            if (methods.length > 0) {
                console.log("[+] Hooked " + shortName + " (" + methods.length + " methods)");
            }
        } catch (e) { }
    }
}

// ── PBOClient (PlayapiClient) — aleProvision ルーティング監視 ──

function hookPBOClient(): void {
    try {
        const PBORequest = ObjC.classes.PBORequest;
        if (!PBORequest) {
            console.log("[-] PBORequest not found");
            return;
        }

        // +[PBORequest stringForAction:] をフック
        try {
            const resolver = new ApiResolver("objc");
            resolver.enumerateMatches("+[PBORequest stringForAction:]").forEach(function (match) {
                Interceptor.attach(match.address, {
                    onLeave: function (retval) {
                        if (retval && !retval.isNull()) {
                            const actionStr = new ObjC.Object(retval).toString();
                            if (actionStr === "aleProvision") {
                                logAle("PBORequest.stringForAction -> aleProvision");
                            }
                        }
                    }
                });
            });
            console.log("[+] Hooked PBORequest.stringForAction:");
        } catch (e) { }

        // PBOClient.sendRequest:callback: をフック
        try {
            const PBOClient = ObjC.classes.PBOClient;
            if (PBOClient) {
                const resolver = new ApiResolver("objc");
                resolver.enumerateMatches("-[PBOClient sendRequest:callback:]").forEach(function (match) {
                    Interceptor.attach(match.address, {
                        onEnter: function (args) {
                            try {
                                const request = new ObjC.Object(args[2]);
                                const desc = request.toString();
                                if (desc.indexOf("aleProvision") !== -1 || desc.indexOf("Provision") !== -1) {
                                    logAle("PBOClient.sendRequest: " + desc.substring(0, 200));
                                }
                            } catch (e) { }
                        }
                    });
                });
                console.log("[+] Hooked PBOClient.sendRequest:callback:");
            }
        } catch (e) { }
    } catch (e) {
        console.log("[-] PBOClient hooks: " + e);
    }
}
