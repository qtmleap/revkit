export function hookSSLPinning(): void {
    if (typeof ObjC === 'undefined' || !ObjC.available) {
        console.log("[-] ObjC not available, skipping SSL pinning bypass");
        return;
    }

    // ── 1. SecTrustEvaluateWithError (iOS 12+) ──
    // bool SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error)
    // error に NULL を書き込まないと呼び出し元が不正なエラーを参照してクラッシュする
    try {
        const SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onEnter: function (args) {
                    this._errorPtr = args[1]; // CFErrorRef *error
                },
                onLeave: function (retval) {
                    // error ポインタが渡されていれば NULL をセット (エラーなし)
                    if (this._errorPtr && !this._errorPtr.isNull()) {
                        this._errorPtr.writePointer(ptr(0));
                    }
                    retval.replace(ptr(1)); // true = 検証成功
                }
            });
            console.log("[+] Hooked SecTrustEvaluateWithError (always returns true)");
        }
    } catch (e) {
        console.log("[-] SecTrustEvaluateWithError: " + e);
    }

    // ── 2. SecTrustEvaluate (legacy) ──
    // OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
    try {
        const SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onEnter: function (args) {
                    this._resultPtr = args[1];
                },
                onLeave: function (retval) {
                    // kSecTrustResultProceed = 1
                    if (this._resultPtr && !this._resultPtr.isNull()) {
                        this._resultPtr.writeU32(1);
                    }
                    retval.replace(ptr(0)); // errSecSuccess
                }
            });
            console.log("[+] Hooked SecTrustEvaluate (always succeeds)");
        }
    } catch (e) {
        console.log("[-] SecTrustEvaluate: " + e);
    }

    // ── 3. SecTrustGetTrustResult ──
    try {
        const SecTrustGetTrustResult = Module.findExportByName("Security", "SecTrustGetTrustResult");
        if (SecTrustGetTrustResult) {
            Interceptor.attach(SecTrustGetTrustResult, {
                onEnter: function (args) {
                    this._resultPtr = args[1];
                },
                onLeave: function (retval) {
                    if (this._resultPtr && !this._resultPtr.isNull()) {
                        // kSecTrustResultProceed = 1
                        this._resultPtr.writeU32(1);
                    }
                    retval.replace(ptr(0)); // errSecSuccess
                }
            });
            console.log("[+] Hooked SecTrustGetTrustResult");
        }
    } catch (e) {
        console.log("[-] SecTrustGetTrustResult: " + e);
    }

    // ── 4. NSURLSession delegate (completionHandler block) ──
    // NF/Netflix/Osprey 以外のクラスも対象にする
    try {
        const resolver = new ApiResolver("objc");
        const matches = resolver.enumerateMatches("-[* URLSession:didReceiveChallenge:completionHandler:]");
        let count = 0;
        matches.forEach(function (match) {
            // Netflix 関連クラスのみ (システムクラスを除外)
            const name = match.name;
            if (name.indexOf("NF") === -1 && name.indexOf("Netflix") === -1 &&
                name.indexOf("Osprey") === -1 && name.indexOf("Argo") === -1) return;

            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const challenge = new ObjC.Object(args[3]);
                        const serverTrust = challenge.protectionSpace().serverTrust();
                        const cred = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);

                        // ObjC.Block で型シグネチャを明示
                        const handler = new ObjC.Block(args[4], {
                            retType: 'void',
                            argTypes: ['int', 'object']
                        });
                        // NSURLSessionAuthChallengeUseCredential = 0
                        handler(0, cred);
                        console.log("[*] SSL pinning bypassed: " + name);
                    } catch (e) {
                        // フォールバック: invoke pointer を直接呼ぶ
                        try {
                            const challenge = new ObjC.Object(args[3]);
                            const serverTrust = challenge.protectionSpace().serverTrust();
                            const cred = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                            const blockPtr = args[4];
                            // Block layout: isa, flags, reserved, invoke, descriptor
                            const invokePtr = blockPtr.add(Process.pointerSize * 2).readPointer();
                            const invoke = new NativeFunction(invokePtr, 'void', ['pointer', 'int', 'pointer']);
                            invoke(blockPtr, 0, cred.handle);
                            console.log("[*] SSL pinning bypassed (invoke): " + name);
                        } catch (e2) {
                            console.log("[-] SSL pinning bypass failed: " + name + " " + e2);
                        }
                    }
                }
            });
            count++;
        });
        console.log("[+] Hooked " + count + " didReceiveChallenge delegates");
    } catch (e) {
        console.log("[-] didReceiveChallenge: " + e);
    }

    // ── 5. URLSession:task:didReceiveChallenge:completionHandler: (per-task) ──
    try {
        const resolver = new ApiResolver("objc");
        const matches = resolver.enumerateMatches("-[* URLSession:task:didReceiveChallenge:completionHandler:]");
        let count = 0;
        matches.forEach(function (match) {
            const name = match.name;
            if (name.indexOf("NF") === -1 && name.indexOf("Netflix") === -1 &&
                name.indexOf("Osprey") === -1 && name.indexOf("Argo") === -1) return;

            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const challenge = new ObjC.Object(args[4]);
                        const serverTrust = challenge.protectionSpace().serverTrust();
                        const cred = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                        const handler = new ObjC.Block(args[5], {
                            retType: 'void',
                            argTypes: ['int', 'object']
                        });
                        handler(0, cred);
                        console.log("[*] SSL pinning bypassed (per-task): " + name);
                    } catch (e) {
                        try {
                            const challenge = new ObjC.Object(args[4]);
                            const serverTrust = challenge.protectionSpace().serverTrust();
                            const cred = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                            const blockPtr = args[5];
                            const invokePtr = blockPtr.add(Process.pointerSize * 2).readPointer();
                            const invoke = new NativeFunction(invokePtr, 'void', ['pointer', 'int', 'pointer']);
                            invoke(blockPtr, 0, cred.handle);
                            console.log("[*] SSL pinning bypassed (per-task invoke): " + name);
                        } catch (e2) {
                            console.log("[-] SSL pinning bypass (per-task) failed: " + name + " " + e2);
                        }
                    }
                }
            });
            count++;
        });
        if (count > 0) console.log("[+] Hooked " + count + " per-task didReceiveChallenge delegates");
    } catch (e) {
        console.log("[-] per-task didReceiveChallenge: " + e);
    }
}
