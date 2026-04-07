// ── Netflix iOS アンチ検出バイパス ──
// spawn モードで動作させるために、以下を無効化:
// 1. objc_setHook_getClass (NFNetworkState) — ObjC ランタイムフックの競合回避
// 2. task_set_exception_ports (Nbp) — Mach 例外ポート奪取の阻止
// 3. __dyld_register_func_for_add_image — frida-agent.dylib 検出の抑制
//
// これらは全て __mod_init_func / +load で実行されるため、
// スクリプトロード直後（コンストラクタ実行前）に Interceptor.replace で NOP 化する

export function installAntiDetectionBypass(): void {
    console.log("[*] Installing anti-detection bypass...");

    bypassObjcSetHookGetClass();
    bypassTaskSetExceptionPorts();
    bypassDyldRegisterAddImage();
    bypassTermination();

    console.log("[+] Anti-detection bypass installed");
}

// ── 1. objc_setHook_getClass NOP 化 ──
// NFNetworkState が installGetClassHook_untrusted() で ObjC クラス解決をフック
// Frida の ObjC ブリッジと競合するため、フック登録自体を無効化

function bypassObjcSetHookGetClass(): void {
    try {
        const addr = findExport("libobjc.A.dylib", "objc_setHook_getClass");
        if (!addr) {
            console.log("[-] objc_setHook_getClass not found");
            return;
        }
        // replace ではなく attach で監視のみ (NOP 化すると依存する初期化が壊れる)
        Interceptor.attach(addr, {
            onEnter: function (_args) {
                console.log("[MONITOR] objc_setHook_getClass called");
            }
        });
        console.log("[+] Monitoring objc_setHook_getClass");
    } catch (e) {
        console.log("[-] objc_setHook_getClass bypass: " + e);
    }
}

// ── 2. task_set_exception_ports ──
// 監視のみ (NOP 化すると他に影響する可能性)

function bypassTaskSetExceptionPorts(): void {
    try {
        const addr = findExport("libsystem_kernel.dylib", "task_set_exception_ports");
        if (!addr) {
            console.log("[-] task_set_exception_ports not found");
            return;
        }
        Interceptor.attach(addr, {
            onEnter: function (args) {
                console.log("[MONITOR] task_set_exception_ports(mask=" + args[1] + ", behavior=" + args[3] + ")");
            }
        });
        console.log("[+] Monitoring task_set_exception_ports");
    } catch (e) {
        console.log("[-] task_set_exception_ports bypass: " + e);
    }
}

// ── 3. __dyld_register_func_for_add_image コールバック抑制 ──
// NFRCW, NFNetworkState, Nbp が dylib ロード通知を受け取り、
// frida-agent.dylib を検出する
// コールバック登録自体を NOP 化

function bypassDyldRegisterAddImage(): void {
    // attach 時の Interceptor.attach で登録をログしつつ通す
    // spawn 時はフレームワーク初期化で呼ばれるが、frida-agent は既にロード済みなので
    // 新規 dylib ロード通知は問題にならないはず
    // → replace ではなく attach にして副作用を最小化
    const targets = ["_dyld_register_func_for_add_image", "_dyld_register_func_for_remove_image"];

    for (const symName of targets) {
        try {
            const addr = findExport("libdyld.dylib", symName)
                || findExport("libSystem.B.dylib", symName);
            if (!addr) continue;

            Interceptor.attach(addr, {
                onEnter: function (_args) {
                    console.log("[MONITOR] " + symName + " called");
                }
            });
            console.log("[+] Monitoring " + symName);
        } catch (e) {
            console.log("[-] " + symName + " monitor: " + e);
        }
    }
}

// ── 4. 終了関数フック — クラッシュ原因の特定 ──

function bypassTermination(): void {
    const funcs = ["abort", "_exit", "exit"];
    for (const name of funcs) {
        try {
            const addr = findExport(null, name);
            if (!addr) continue;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    const code = name === "abort" ? "" : " code=" + args[0].toInt32();
                    console.log("[CRASH] " + name + "()" + code + " called!");
                    console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            });
            console.log("[+] Monitoring " + name + "()");
        } catch (e) { }
    }

    // kill (self)
    try {
        const addr = findExport(null, "kill");
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    const pid = args[0].toInt32();
                    const sig = args[1].toInt32();
                    if (pid === Process.id || pid === 0) {
                        console.log("[CRASH] kill(self, " + sig + ")!");
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                }
            });
        }
    } catch (e) { }

    // raise
    try {
        const addr = findExport(null, "raise");
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    console.log("[CRASH] raise(" + args[0].toInt32() + ")!");
                    console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            });
        }
    } catch (e) { }

    // __pthread_kill
    try {
        const addr = findExport(null, "__pthread_kill");
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    const sig = args[1].toInt32();
                    if (sig === 6 || sig === 9) { // SIGABRT or SIGKILL
                        console.log("[CRASH] __pthread_kill(sig=" + sig + ")!");
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                }
            });
        }
    } catch (e) { }
}

// ── ヘルパー ──

function findExport(moduleName: string | null, symbolName: string): NativePointer | null {
    try {
        if (moduleName) {
            const mod = Process.findModuleByName(moduleName);
            if (!mod) return null;
            for (const exp of mod.enumerateExports()) {
                if (exp.name === symbolName) return exp.address;
            }
        } else {
            // 全モジュールから検索
            for (const mod of Process.enumerateModules()) {
                for (const exp of mod.enumerateExports()) {
                    if (exp.name === symbolName) return exp.address;
                }
            }
        }
    } catch (e) { }
    return null;
}
