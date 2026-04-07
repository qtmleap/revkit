// ── Netflix iOS の Frida / Jailbreak 検出メカニズム調査 ──
// attach モードで実行し、検出・終了処理を特定する

export function investigateDetection(): void {
    // ObjC が使えなくても C 関数フックは可能 (spawn 直後対応)

    // 最優先: ptrace ブロック (spawn 直後に呼ばれる可能性)
    hookPtrace();

    // 終了系関数 (exit, abort, kill, raise, pthread_kill)
    hookTerminationFunctions();

    // sysctl (デバッガ検出)
    hookSysctl();

    // dlopen / dyld (Frida 検出)
    hookDynamicLoading();

    // ObjC が使える場合のみ
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        hookFileExistenceChecks();
    }
}

function hookTerminationFunctions(): void {
    // exit
    try {
        const exitPtr = Module.findExportByName(null, "exit");
        if (exitPtr) {
            Interceptor.attach(exitPtr, {
                onEnter: function (args) {
                    const code = args[0].toInt32();
                    console.log("[DETECT] exit(" + code + ") called!");
                    console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            });
        }
    } catch (e) { }

    // _exit
    try {
        const _exitPtr = Module.findExportByName(null, "_exit");
        if (_exitPtr) {
            Interceptor.attach(_exitPtr, {
                onEnter: function (args) {
                    console.log("[DETECT] _exit(" + args[0].toInt32() + ") called!");
                    console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            });
        }
    } catch (e) { }

    // abort
    try {
        const abortPtr = Module.findExportByName(null, "abort");
        if (abortPtr) {
            Interceptor.attach(abortPtr, {
                onEnter: function () {
                    console.log("[DETECT] abort() called!");
                    console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            });
        }
    } catch (e) { }

    // kill (自プロセスへの SIGKILL)
    try {
        const killPtr = Module.findExportByName(null, "kill");
        if (killPtr) {
            Interceptor.attach(killPtr, {
                onEnter: function (args) {
                    const pid = args[0].toInt32();
                    const sig = args[1].toInt32();
                    if (pid === Process.id || pid === 0) {
                        console.log("[DETECT] kill(" + pid + ", " + sig + ") self-kill!");
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                }
            });
        }
    } catch (e) { }

    // raise (SIGKILL / SIGABRT)
    try {
        const raisePtr = Module.findExportByName(null, "raise");
        if (raisePtr) {
            Interceptor.attach(raisePtr, {
                onEnter: function (args) {
                    const sig = args[0].toInt32();
                    console.log("[DETECT] raise(" + sig + ")!");
                    console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n"));
                }
            });
        }
    } catch (e) { }

    // pthread_kill
    try {
        const pthreadKillPtr = Module.findExportByName(null, "pthread_kill");
        if (pthreadKillPtr) {
            Interceptor.attach(pthreadKillPtr, {
                onEnter: function (args) {
                    const sig = args[1].toInt32();
                    if (sig === 9 || sig === 6) { // SIGKILL or SIGABRT
                        console.log("[DETECT] pthread_kill(thread, " + sig + ")!");
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                }
            });
        }
    } catch (e) { }

    // __pthread_kill (低レベル)
    try {
        const __pthreadKillPtr = Module.findExportByName(null, "__pthread_kill");
        if (__pthreadKillPtr) {
            Interceptor.attach(__pthreadKillPtr, {
                onEnter: function (args) {
                    const sig = args[1].toInt32();
                    console.log("[DETECT] __pthread_kill(thread, " + sig + ")");
                    if (sig === 9 || sig === 6) {
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                }
            });
        }
    } catch (e) { }

    // signal handler registration
    try {
        const signalPtr = Module.findExportByName(null, "signal");
        if (signalPtr) {
            Interceptor.attach(signalPtr, {
                onEnter: function (args) {
                    const sig = args[0].toInt32();
                    console.log("[DETECT] signal(" + sig + ", handler)");
                }
            });
        }
    } catch (e) { }

    // NSException raise (ObjC 例外)
    try {
        if (typeof ObjC !== 'undefined' && ObjC.available) {
            const resolver = new ApiResolver("objc");
            resolver.enumerateMatches("+[NSException raise:format:]").forEach(function (match) {
                Interceptor.attach(match.address, {
                    onEnter: function (args) {
                        const name = new ObjC.Object(args[2]).toString();
                        const reason = new ObjC.Object(args[3]).toString();
                        console.log("[DETECT] NSException raise: " + name + " reason: " + reason);
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                });
            });
        }
    } catch (e) { }

    console.log("[+] Hooked termination functions (exit, _exit, abort, kill, raise, pthread_kill, signal)");
}

function hookFileExistenceChecks(): void {
    // Jailbreak 検出でよく使われるファイルパス
    const jbPaths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/usr/bin/ssh",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/tmp/cydia.log",
        "/usr/libexec/sftp-server",
        "/var/jb",
        "/var/LIB",
        "frida",
        "substrate",
        "cycript",
    ];

    // NSFileManager fileExistsAtPath:
    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[NSFileManager fileExistsAtPath:]").forEach(function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    const path = new ObjC.Object(args[2]).toString();
                    const pathLower = path.toLowerCase();
                    if (jbPaths.some(jb => pathLower.indexOf(jb.toLowerCase()) !== -1)) {
                        console.log("[DETECT] fileExistsAtPath: " + path);
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                }
            });
        });
        console.log("[+] Hooked NSFileManager fileExistsAtPath:");
    } catch (e) { }

    // access() C function
    try {
        const accessPtr = Module.findExportByName(null, "access");
        if (accessPtr) {
            Interceptor.attach(accessPtr, {
                onEnter: function (args) {
                    const path = args[0].readUtf8String();
                    if (path) {
                        const pathLower = path.toLowerCase();
                        if (jbPaths.some(jb => pathLower.indexOf(jb.toLowerCase()) !== -1)) {
                            console.log("[DETECT] access('" + path + "')");
                        }
                    }
                }
            });
        }
    } catch (e) { }

    // stat()
    try {
        const statPtr = Module.findExportByName(null, "stat");
        if (statPtr) {
            Interceptor.attach(statPtr, {
                onEnter: function (args) {
                    const path = args[0].readUtf8String();
                    if (path) {
                        const pathLower = path.toLowerCase();
                        if (jbPaths.some(jb => pathLower.indexOf(jb.toLowerCase()) !== -1)) {
                            console.log("[DETECT] stat('" + path + "')");
                        }
                    }
                }
            });
        }
    } catch (e) { }

    // open() for reading jailbreak files
    try {
        const openPtr = Module.findExportByName(null, "open");
        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter: function (args) {
                    const path = args[0].readUtf8String();
                    if (path) {
                        const pathLower = path.toLowerCase();
                        if (jbPaths.some(jb => pathLower.indexOf(jb.toLowerCase()) !== -1)) {
                            console.log("[DETECT] open('" + path + "')");
                        }
                    }
                }
            });
        }
    } catch (e) { }
}

function hookDynamicLoading(): void {
    // dlopen - Frida ライブラリ検出
    try {
        const dlopenPtr = Module.findExportByName(null, "dlopen");
        if (dlopenPtr) {
            Interceptor.attach(dlopenPtr, {
                onEnter: function (args) {
                    const path = args[0].readUtf8String();
                    if (path && (path.toLowerCase().indexOf("frida") !== -1 ||
                        path.toLowerCase().indexOf("substrate") !== -1 ||
                        path.toLowerCase().indexOf("cycript") !== -1)) {
                        console.log("[DETECT] dlopen('" + path + "')");
                    }
                }
            });
        }
    } catch (e) { }

    // _dyld_get_image_name - モジュール列挙
    try {
        const getImageNamePtr = Module.findExportByName(null, "_dyld_get_image_name");
        if (getImageNamePtr) {
            Interceptor.attach(getImageNamePtr, {
                onEnter: function (args) {
                    this._idx = args[0].toInt32();
                },
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        const name = retval.readUtf8String();
                        if (name && name.toLowerCase().indexOf("frida") !== -1) {
                            console.log("[DETECT] _dyld_get_image_name(" + this._idx + ") -> " + name);
                            console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join("\n"));
                        }
                    }
                }
            });
        }
    } catch (e) { }
}

function hookSysctl(): void {
    // sysctl - デバッガ検出 (P_TRACED flag)
    try {
        const sysctlPtr = Module.findExportByName(null, "sysctl");
        if (sysctlPtr) {
            Interceptor.attach(sysctlPtr, {
                onEnter: function (args) {
                    // CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1
                    const mib = args[0];
                    const name0 = mib.readInt();
                    const name1 = mib.add(4).readInt();
                    if (name0 === 1 && name1 === 14) {
                        console.log("[DETECT] sysctl(KERN_PROC) - debugger check");
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                    }
                }
            });
        }
    } catch (e) { }
}

function hookPtrace(): void {
    // ptrace(PT_DENY_ATTACH, ...) - アンチデバッグ
    try {
        const ptracePtr = Module.findExportByName(null, "ptrace");
        if (ptracePtr) {
            Interceptor.attach(ptracePtr, {
                onEnter: function (args) {
                    const request = args[0].toInt32();
                    if (request === 31) { // PT_DENY_ATTACH
                        console.log("[DETECT] ptrace(PT_DENY_ATTACH) blocked!");
                        console.log("  backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\n"));
                        // ブロック: 何もせず return 0
                        args[0] = ptr(0);
                    }
                }
            });
            console.log("[+] Hooked ptrace (PT_DENY_ATTACH bypass)");
        }
    } catch (e) { }
}
