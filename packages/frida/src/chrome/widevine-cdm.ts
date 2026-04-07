/**
 * Widevine CDM Interface v10/v11 Hook - Stalker ベース
 *
 * ★ Stalker を使う理由:
 *   Interceptor.attach/replace は対象関数のコードを書き換えるため、
 *   CDM の VerifyCdmHost_0 コード整合性検証に失敗する。
 *   Stalker はオリジナルコードを一切変更せず、JIT コンパイルした
 *   コピー上でスレッドを実行しながら callout でデータをキャプチャする。
 *
 * 戦略:
 *   1. CDM エクスポート関数のアドレスを取得 (読み取りのみ)
 *   2. 全スレッドを Stalker.follow して、CDM 関数への call を監視
 *   3. CreateCdmInstance の呼び出しと戻り値をキャプチャ
 *   4. 戻り値から CDM インスタンスの vtable を読み取り
 *   5. vtable 内の各メソッドアドレスも Stalker で監視
 */
import { logData, bytesToHex, bytesToBase64, SEP, SEP2, ts } from "../common/utils";
import { extractPrivateKey, startPeriodicScan, getExtractedKeyCount } from "./private-key-extractor";

const CDM_MODULE = "libwidevinecdm.dylib";

function findExport(moduleName: string, exportName: string): NativePointer | null {
    const mod = Process.findModuleByName(moduleName);
    if (!mod) return null;
    return mod.findExportByName(exportName);
}

const INIT_DATA_TYPE: Record<number, string> = { 0: "Cenc", 1: "Keyids", 2: "WebM" };
const SESSION_TYPE: Record<number, string> = { 0: "Temporary", 1: "PersistentLicense" };
const CDM_STATUS: Record<number, string> = {
    0: "kSuccess", 1: "kNeedMoreData", 2: "kNoKey",
    3: "kInitializationError", 4: "kDecryptError", 5: "kDecodeError",
    6: "kDeferredInitialization", 7: "kInvalidState", 8: "kSessionNotFound",
};

function readBuf(ptr: NativePointer, size: number): ArrayBuffer {
    return ptr.readByteArray(size) as ArrayBuffer;
}

function getVtableEntry(vt: NativePointer, index: number): NativePointer {
    return vt.add(index * Process.pointerSize).readPointer();
}

// 監視対象アドレス
let createCdmAddr: NativePointer | null = null;
let verifyCdmAddr: NativePointer | null = null;
let initModuleAddr: NativePointer | null = null;

// vtable メソッドアドレス (CreateCdmInstance 完了後に設定)
let vtableAddrs: Record<string, NativePointer> = {};
let vtableInstalled = false;

// Stalker で follow 中のスレッド
const followedThreads: Set<number> = new Set();

// Decrypt カウンタ
let decryptCount = 0;

export function hookCreateCdmInstance(): void {
    const cdmMod = Process.findModuleByName(CDM_MODULE);
    if (!cdmMod) {
        console.log("[-] " + CDM_MODULE + " not loaded. Waiting...");
        const wait = setInterval(() => {
            if (Process.findModuleByName(CDM_MODULE)) {
                clearInterval(wait);
                console.log("[+] " + CDM_MODULE + " loaded");
                setup();
            }
        }, 500);
        return;
    }
    console.log("[+] " + CDM_MODULE + " at " + cdmMod.base);
    setup();
}

function setup(): void {
    // バージョン取得 (副作用なし)
    const versionAddr = findExport(CDM_MODULE, "GetCdmVersion");
    if (versionAddr) {
        try {
            const fn = new NativeFunction(versionAddr, "pointer", []);
            const ver = (fn() as NativePointer).readUtf8String();
            console.log("[*] CDM Version: " + ver);
            logData("cdm.version", { version: ver });
        } catch (_e) { /* ignore */ }
    }

    // エクスポートアドレスを記録
    createCdmAddr = findExport(CDM_MODULE, "CreateCdmInstance");
    verifyCdmAddr = findExport(CDM_MODULE, "VerifyCdmHost_0");
    initModuleAddr = findExport(CDM_MODULE, "InitializeCdmModule_4");

    console.log("[*] Targets:");
    console.log("  CreateCdmInstance: " + createCdmAddr);
    console.log("  VerifyCdmHost_0: " + verifyCdmAddr);
    console.log("  InitializeCdmModule_4: " + initModuleAddr);

    if (!createCdmAddr) {
        console.log("[-] CreateCdmInstance not found");
        return;
    }

    // 全スレッドを Stalker で follow
    followAllThreads();

    console.log("[+] Stalker active. Open DRM content in Chrome.");
}

function followAllThreads(): void {
    const threads = Process.enumerateThreads();
    console.log("[*] Following " + threads.length + " threads with Stalker...");

    for (const thread of threads) {
        followThread(thread.id);
    }

    // 新しいスレッドもキャッチするためにポーリング
    setInterval(() => {
        const current = Process.enumerateThreads();
        for (const t of current) {
            if (!followedThreads.has(t.id)) {
                followThread(t.id);
            }
        }
    }, 1000);
}

function followThread(threadId: number): void {
    if (followedThreads.has(threadId)) return;
    followedThreads.add(threadId);

    try {
        Stalker.follow(threadId, {
            transform: function (iterator: StalkerArm64Iterator) {
                let instruction = iterator.next();
                while (instruction !== null) {
                    const addr = instruction.address;

                    // CreateCdmInstance の先頭をヒット
                    if (createCdmAddr && addr.equals(createCdmAddr)) {
                        iterator.putCallout(onCreateCdmInstanceEntry);
                    }

                    // VerifyCdmHost_0 の先頭
                    if (verifyCdmAddr && addr.equals(verifyCdmAddr)) {
                        iterator.putCallout(onVerifyCdmHostEntry);
                    }

                    // InitializeCdmModule_4 の先頭
                    if (initModuleAddr && addr.equals(initModuleAddr)) {
                        iterator.putCallout(onInitModuleEntry);
                    }

                    // vtable メソッドの先頭
                    if (vtableInstalled) {
                        for (const name in vtableAddrs) {
                            if (addr.equals(vtableAddrs[name])) {
                                // クロージャで name をキャプチャ
                                const methodName = name;
                                iterator.putCallout(function (ctx: CpuContext) {
                                    onVtableMethodEntry(methodName, ctx);
                                });
                                break;
                            }
                        }
                    }

                    iterator.keep();
                    instruction = iterator.next();
                }
            }
        });
    } catch (_e) {
        followedThreads.delete(threadId);
    }
}

// ─── Stalker callout ハンドラ ───

function onInitModuleEntry(ctx: CpuContext): void {
    console.log("[CDM] InitializeCdmModule_4()");
    logData("cdm.initModule", {});
}

function onVerifyCdmHostEntry(ctx: CpuContext): void {
    console.log("[CDM] VerifyCdmHost_0()");
    logData("cdm.verifyHost", { note: "entry detected via Stalker" });
}

function onCreateCdmInstanceEntry(ctx: CpuContext): void {
    // arm64: x0=interface_version, x1=key_system, x2=key_system_len
    const arm64ctx = ctx as Arm64CpuContext;
    const ifVer = arm64ctx.x0.toInt32();

    let keySys = "";
    try {
        keySys = arm64ctx.x1.readUtf8String() || "";
    } catch (_e) { keySys = "(unreadable)"; }

    console.log(SEP);
    console.log("[CDM] CreateCdmInstance");
    console.log("  interface_version: " + ifVer);
    console.log("  key_system: " + keySys);
    logData("cdm.createInstance", { interface_version: ifVer, key_system: keySys });

    // CreateCdmInstance の ret 命令にもコールアウトを仕掛けたいが、
    // Stalker の transform は関数全体に及ぶので、
    // 代わりに短いポーリングで戻り値 (x0) を監視する。
    // → 実用的な方法: CreateCdmInstance の呼び出し後、
    //   呼び出し元に戻ったタイミングで x0 を読む。
    //
    // Stalker では ret のアドレスを特定するのが難しいため、
    // 別スレッドでポーリングして CDM インスタンスを探す。
    if (!vtableInstalled) {
        console.log("[*] Waiting for CreateCdmInstance to return...");
        setTimeout(function () {
            scanForVtable();
        }, 500);
    }
}

function onVtableMethodEntry(name: string, ctx: CpuContext): void {
    const arm64ctx = ctx as Arm64CpuContext;

    if (name === "Initialize") {
        // x1=allow_distinctive, x2=allow_persistent, x3=use_hw_secure
        const hwSecure = arm64ctx.x3.toInt32() !== 0;
        console.log("[CDM] Initialize hw_secure=" + hwSecure + (hwSecure ? " (L1)" : " (L3)"));
        logData("cdm.initialize", {
            use_hw_secure_codecs: hwSecure,
            drm_level: hwSecure ? "L1" : "L3",
        });
    } else if (name === "SetServerCertificate") {
        // x1=promise_id, x2=cert_data, x3=cert_size
        const certSize = arm64ctx.x3.toInt32();
        console.log("[CDM] SetServerCertificate cert_size=" + certSize);
        if (certSize > 0 && certSize < 65536) {
            try {
                logData("cdm.setServerCertificate", {
                    cert_size: certSize,
                    cert_b64: bytesToBase64(readBuf(arm64ctx.x2, certSize)),
                });
            } catch (_e) { /* ignore */ }
        }
    } else if (name === "CreateSessionAndGenerateRequest") {
        // x1=promise_id, x2=session_type, x3=init_data_type, x4=init_data, x5=init_data_size
        const sessType = arm64ctx.x2.toInt32();
        const initType = arm64ctx.x3.toInt32();
        const initSize = arm64ctx.x5.toInt32();
        console.log(SEP);
        console.log("[CDM] CreateSessionAndGenerateRequest");
        console.log("  session=" + (SESSION_TYPE[sessType] || sessType) +
            " type=" + (INIT_DATA_TYPE[initType] || initType) + " size=" + initSize);
        if (initSize > 0 && initSize < 65536) {
            try {
                const buf = readBuf(arm64ctx.x4, initSize);
                console.log("  PSSH: " + bytesToHex(buf));
                logData("cdm.createSession", {
                    session_type: SESSION_TYPE[sessType] || sessType,
                    init_data_type: INIT_DATA_TYPE[initType] || initType,
                    init_data_size: initSize,
                    init_data_b64: bytesToBase64(buf),
                    init_data_hex: bytesToHex(buf),
                });
            } catch (_e) { /* ignore */ }
        }
        // セッション生成後に RSA 秘密鍵をスキャン
        if (getExtractedKeyCount() === 0) {
            setTimeout(() => {
                console.log("[*] Triggering RSA private key scan after CreateSession...");
                extractPrivateKey();
            }, 1000);
        }
    } else if (name === "UpdateSession") {
        // x1=promise_id, x2=session_id, x3=session_id_size, x4=response, x5=response_size
        const sidSize = arm64ctx.x3.toInt32();
        const respSize = arm64ctx.x5.toInt32();
        let sid = "";
        if (sidSize > 0 && sidSize < 256) {
            try { sid = arm64ctx.x2.readUtf8String(sidSize) || ""; } catch (_e) { }
        }
        console.log(SEP);
        console.log("[CDM] UpdateSession session=" + sid + " response_size=" + respSize);
        if (respSize > 0 && respSize < 1048576) {
            try {
                const b64 = bytesToBase64(readBuf(arm64ctx.x4, respSize));
                console.log("  response: " + b64.substring(0, 200) + (b64.length > 200 ? "..." : ""));
                logData("cdm.updateSession", {
                    session_id: sid, response_size: respSize, response_b64: b64,
                });
            } catch (_e) { /* ignore */ }
        }
    } else if (name === "CloseSession") {
        const sidSize = arm64ctx.x3.toInt32();
        let sid = "";
        if (sidSize > 0 && sidSize < 256) {
            try { sid = arm64ctx.x2.readUtf8String(sidSize) || ""; } catch (_e) { }
        }
        console.log("[CDM] CloseSession session=" + sid);
        logData("cdm.closeSession", { session_id: sid });
    } else if (name === "Decrypt") {
        decryptCount++;
        if (decryptCount <= 5 || decryptCount % 500 === 0) {
            // x1=InputBuffer*, x2=DecryptedBlock*
            try {
                const inBuf = arm64ctx.x1;
                const dataSize = inBuf.add(8).readU32();
                const encScheme = inBuf.add(12).readU32();
                const keyIdPtr = inBuf.add(16).readPointer();
                const keyIdSize = inBuf.add(24).readU32();
                const schemes = ["Unencrypted", "Cenc", "Cbcs"];
                const keyId = (keyIdSize > 0 && keyIdSize <= 32)
                    ? bytesToHex(readBuf(keyIdPtr, keyIdSize)) : "";
                console.log("[CDM] Decrypt #" + decryptCount + " " +
                    (schemes[encScheme] || encScheme) +
                    " size=" + dataSize + " key=" + keyId);
                logData("cdm.decrypt", {
                    count: decryptCount, data_size: dataSize,
                    encryption_scheme: schemes[encScheme] || encScheme,
                    key_id: keyId || null,
                });
            } catch (_e) {
                console.log("[CDM] Decrypt #" + decryptCount);
            }
        }
    }
}

// ─── vtable スキャン (CreateCdmInstance 後に実行) ───

function scanForVtable(): void {
    const cdmMod = Process.findModuleByName(CDM_MODULE);
    if (!cdmMod) return;

    const modStart = cdmMod.base;
    const modEnd = cdmMod.base.add(cdmMod.size);
    const step = Process.pointerSize;
    const sections = cdmMod.enumerateSections();

    for (const section of sections) {
        const sid = (section as any).id || "";
        if (!sid.includes("__const") && !sid.includes("__data")) continue;

        const base = (section as any).address as NativePointer;
        const size = (section as any).size as number;
        if (!base || size < step * 20) continue;

        for (let off = 0; off < size - step * 20; off += step) {
            const cand = base.add(off);
            let count = 0;
            for (let i = 0; i < 20; i++) {
                const e = cand.add(i * step).readPointer();
                if (e.compare(modStart) >= 0 && e.compare(modEnd) < 0) count++;
                else break;
            }
            // CDM Interface v10=20 entries, v11 もおそらく20前後
            if (count < 15) continue;

            // vtable として登録
            console.log("[+] CDM vtable at " + cand + " (" + count + " entries)");
            registerVtableMethods(cand);

            // Stalker を再 follow して新しいアドレスを監視
            refollowAllThreads();
            return;
        }
    }
    console.log("[-] vtable not found after CreateCdmInstance");
}

function registerVtableMethods(vt: NativePointer): void {
    const names = [
        "Destructor", "Initialize", "GetStatusForPolicy",
        "SetServerCertificate", "CreateSessionAndGenerateRequest",
        "LoadSession", "UpdateSession", "CloseSession",
        "RemoveSession", "TimerExpired", "Decrypt",
    ];
    const cdmMod = Process.findModuleByName(CDM_MODULE);
    console.log(SEP2);
    for (let i = 0; i < names.length; i++) {
        const entry = getVtableEntry(vt, i);
        const off = cdmMod ? "+" + entry.sub(cdmMod.base).toString(16) : "?";
        console.log("  [" + i + "] " + names[i] + " (" + off + ")");

        // Stalker で監視する対象を登録
        if (i >= 1 && i <= 10 && i !== 2 && i !== 5 && i !== 8 && i !== 9) {
            vtableAddrs[names[i]] = entry;
        }
    }
    console.log(SEP2);
    vtableInstalled = true;
    console.log("[+] Registered " + Object.keys(vtableAddrs).length + " vtable methods for Stalker");
}

function refollowAllThreads(): void {
    // 既存の follow を解除して再 follow (新しい transform で)
    for (const tid of followedThreads) {
        try { Stalker.unfollow(tid); } catch (_e) { }
    }
    followedThreads.clear();
    followAllThreads();
}

export function hookCdmVtable(_a: NativePointer, _b: NativePointer): void {}
