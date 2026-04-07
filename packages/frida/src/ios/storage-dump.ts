// ── iOS UserDefaults + Keychain ダンプ ──
// 起動時に Netflix 関連のストレージ内容を表示

import { logData } from "../common/utils";

export function dumpStorage(): void {
    if (typeof ObjC === 'undefined' || !ObjC.available) return;

    dumpUserDefaults();
    dumpKeychain();
    dumpSandbox();
}

// ── aleProvision 強制トリガー ──
// IosMslClient のインスタンスを探して _retrieveProxyESN を呼び出す
// これにより getProxyEsn → aleProvision が発火する

export function forceAleProvision(): void {
    if (typeof ObjC === 'undefined' || !ObjC.available) return;

    try {
        // IosMslClient のインスタンスを ObjC ヒープから検索
        ObjC.choose(ObjC.classes.IosMslClient, {
            onMatch: function (instance) {
                console.log("[*] Found IosMslClient instance: " + instance);

                // didAppboot を false にリセット → appboot が再実行される
                try {
                    instance.setDidAppboot_(false);
                    console.log("[+] Reset didAppboot = false");
                } catch (e) {
                    console.log("[-] setDidAppboot: " + e);
                }

                // _retrieveProxyESN を呼び出し → getProxyEsn → aleProvision
                try {
                    // ObjC メッセージ送信
                    const sel = ObjC.selector("_retrieveProxyESN");
                    const method = instance.methodForSelector_(sel);
                    if (method && !method.isNull()) {
                        const fn = new NativeFunction(method, "void", ["pointer", "pointer"]);
                        fn(instance.handle, sel);
                        console.log("[+] Called _retrieveProxyESN via msgSend");
                        logData("proxyEsn.forceExpired", { method: "_retrieveProxyESN" });
                    } else {
                        console.log("[-] _retrieveProxyESN method not found");
                    }
                } catch (e) {
                    console.log("[-] _retrieveProxyESN: " + e);
                }

                // appboot も再実行
                try {
                    const sel2 = ObjC.selector("checkOnAppboot:");
                    const method2 = instance.methodForSelector_(sel2);
                    if (method2 && !method2.isNull()) {
                        const fn2 = new NativeFunction(method2, "void", ["pointer", "pointer", "pointer"]);
                        fn2(instance.handle, sel2, NULL);
                        console.log("[+] Called checkOnAppboot:");
                    }
                } catch (e) {
                    console.log("[-] checkOnAppboot: " + e);
                }
            },
            onComplete: function () {
                console.log("[*] IosMslClient search complete");
            }
        });
    } catch (e) {
        console.log("[-] forceAleProvision: " + e);
    }
}

// ── ストレージ全消去 ──
// UserDefaults + Keychain の Netflix 関連データを全削除
// → アプリ初回起動と同じ状態 → getProxyEsn → aleProvision が強制発火

function forceProxyEsnExpired(): void {
    clearUserDefaults();
    clearKeychain();
}

function clearUserDefaults(): void {
    try {
        const defaults = ObjC.classes.NSUserDefaults.standardUserDefaults();
        const dict = defaults.dictionaryRepresentation();
        const keys = dict.allKeys();
        const count = keys.count();

        // Netflix 関連のキーを全削除
        const keywords = ["netflix", "nf", "esn", "cdm", "msl", "ale", "drm", "provision", "token", "bf"];
        let removed = 0;

        for (let i = 0; i < count; i++) {
            const key = keys.objectAtIndex_(i).toString();
            const keyLower = key.toLowerCase();
            if (keywords.some(kw => keyLower.indexOf(kw) !== -1)) {
                defaults.removeObjectForKey_(keys.objectAtIndex_(i));
                removed++;
            }
        }

        defaults.synchronize();
        console.log("[+] UserDefaults: removed " + removed + " Netflix-related keys");
        logData("storage.clear.userDefaults", { removed: removed });
    } catch (e) {
        console.log("[-] clearUserDefaults: " + e);
    }
}

function clearKeychain(): void {
    try {
        // SecItemCopyMatching と SecItemDelete を取得
        const secMod = Process.findModuleByName("Security");
        if (!secMod) { console.log("[-] Security module not found"); return; }

        let copyAddr: NativePointer | null = null;
        let deleteAddr: NativePointer | null = null;
        for (const exp of secMod.enumerateExports()) {
            if (exp.name === "SecItemCopyMatching") copyAddr = exp.address;
            if (exp.name === "SecItemDelete") deleteAddr = exp.address;
        }
        if (!copyAddr || !deleteAddr) { console.log("[-] SecItem functions not found"); return; }

        const SecItemCopyMatching = new NativeFunction(copyAddr, "int32", ["pointer", "pointer"]);
        const SecItemDelete = new NativeFunction(deleteAddr, "int32", ["pointer"]);

        const nsStr = ObjC.classes.NSString;
        const nsNum = ObjC.classes.NSNumber;
        const secClasses = ["genp", "inet"];
        let totalRemoved = 0;

        for (const cls of secClasses) {
            // まず全アイテムを取得
            const query = ObjC.classes.NSMutableDictionary.alloc().init();
            query.setObject_forKey_(nsStr.stringWithString_(cls), nsStr.stringWithString_("class"));
            query.setObject_forKey_(nsNum.numberWithBool_(1), nsStr.stringWithString_("r_Attributes"));
            query.setObject_forKey_(nsStr.stringWithString_("m_LimitAll"), nsStr.stringWithString_("m_Limit"));

            const resultPtr = Memory.alloc(Process.pointerSize);
            resultPtr.writePointer(ptr(0));
            const status = SecItemCopyMatching(query.handle, resultPtr);
            if (status !== 0) continue;

            const items = new ObjC.Object(resultPtr.readPointer());
            if (!items || items.isNull()) continue;

            const count = items.count();
            for (let i = 0; i < count; i++) {
                try {
                    const item = items.objectAtIndex_(i);
                    const agrp = item.objectForKey_(nsStr.stringWithString_("agrp"));
                    if (!agrp) continue;
                    const agrpStr = agrp.toString().toLowerCase();
                    if (agrpStr.indexOf("netflix") === -1) continue;

                    // このアイテムを削除
                    const delQuery = ObjC.classes.NSMutableDictionary.alloc().init();
                    delQuery.setObject_forKey_(nsStr.stringWithString_(cls), nsStr.stringWithString_("class"));
                    // service + account で特定
                    const svc = item.objectForKey_(nsStr.stringWithString_("svce"));
                    const acct = item.objectForKey_(nsStr.stringWithString_("acct"));
                    if (svc) delQuery.setObject_forKey_(svc, nsStr.stringWithString_("svce"));
                    if (acct) delQuery.setObject_forKey_(acct, nsStr.stringWithString_("acct"));

                    const delStatus = SecItemDelete(delQuery.handle);
                    if (delStatus === 0) {
                        totalRemoved++;
                        const acctStr = acct ? acct.toString() : "?";
                        console.log("[KC:DEL] " + cls + " acct=" + acctStr);
                    }
                } catch (_) { }
            }
        }

        console.log("[+] Keychain: deleted " + totalRemoved + " Netflix items");
        logData("storage.clear.keychain", { removed: totalRemoved });
    } catch (e) {
        console.log("[-] clearKeychain: " + e);
    }
}

// ── UserDefaults ──

function dumpUserDefaults(): void {
    try {
        const NSUserDefaults = ObjC.classes.NSUserDefaults;
        const defaults = NSUserDefaults.standardUserDefaults();
        const dict = defaults.dictionaryRepresentation();
        const keys = dict.allKeys();
        const count = keys.count();

        console.log("[*] UserDefaults: " + count + " keys");

        const allEntries: Record<string, any> = {};
        const keywords = ["netflix", "nf", "ale", "msl", "esn", "drm", "provision", "token", "session", "crypto", "key", "auth", "cookie", "profile", "user"];
        let matchCount = 0;

        for (let i = 0; i < count; i++) {
            const key = keys.objectAtIndex_(i).toString();

            try {
                const val = dict.objectForKey_(keys.objectAtIndex_(i));
                if (!val || val.isNull()) continue;

                let valStr: string;
                const className = val.$className || "";

                if (className === "NSData" || className === "__NSCFData") {
                    const len = val.length();
                    const str = ObjC.classes.NSString.alloc().initWithData_encoding_(val, 4);
                    if (str && !str.isNull()) {
                        valStr = str.toString();
                    } else {
                        // base64 で保存
                        const b64 = val.base64EncodedStringWithOptions_(0);
                        valStr = b64 && !b64.isNull() ? "b64:" + b64.toString() : "<NSData " + len + " bytes>";
                    }
                } else {
                    valStr = val.toString();
                }

                allEntries[key] = valStr;

                // コンソールにはフィルタ済みのみ表示
                const keyLower = key.toLowerCase();
                if (keywords.some(kw => keyLower.indexOf(kw) !== -1)) {
                    matchCount++;
                    const display = valStr.length > 200 ? valStr.substring(0, 200) + "..." : valStr;
                    console.log("  [UD] " + key + " = " + display);
                }
            } catch (e) {
                allEntries[key] = "<error: " + e + ">";
            }
        }

        logData("storage.userDefaults", {
            total: count,
            matchCount: matchCount,
            entries: allEntries
        });

        console.log("[+] UserDefaults: " + matchCount + " Netflix-related / " + count + " total keys");
    } catch (e) {
        console.log("[-] UserDefaults dump: " + e);
    }
}

// ── Keychain ──

function dumpKeychain(): void {
    try {
        console.log("[*] Keychain dump starting...");
        console.log("[*] NSMutableDictionary: " + !!ObjC.classes.NSMutableDictionary);
        console.log("[*] NSString: " + !!ObjC.classes.NSString);
        console.log("[*] NSNumber: " + !!ObjC.classes.NSNumber);
        console.log("[*] numberWithBool_: " + typeof ObjC.classes.NSNumber.numberWithBool_);
        console.log("[*] numberWithInt_: " + typeof ObjC.classes.NSNumber.numberWithInt_);
        // Security framework から SecItemCopyMatching を探す
        let secAddr: NativePointer | null = null;
        const secMod = Process.findModuleByName("Security");
        if (secMod) {
            const exports = secMod.enumerateExports();
            for (let i = 0; i < exports.length; i++) {
                if (exports[i].name === "SecItemCopyMatching") {
                    secAddr = exports[i].address;
                    break;
                }
            }
        }
        console.log("[*] SecItemCopyMatching addr: " + secAddr);
        if (!secAddr || secAddr.isNull()) {
            console.log("[-] SecItemCopyMatching not found");
            return;
        }
        const SecItemCopyMatching = new NativeFunction(secAddr, "int32", ["pointer", "pointer"]);

        const secClasses = ["genp", "inet"];
        const classNames = ["GenericPassword", "InternetPassword"];

        let totalFound = 0;

        for (let ci = 0; ci < secClasses.length; ci++) {
            try {
                const query = ObjC.classes.NSMutableDictionary.alloc().init();
                const nsStr = ObjC.classes.NSString;
                const nsNum = ObjC.classes.NSNumber;

                query.setObject_forKey_(nsStr.stringWithString_(secClasses[ci]), nsStr.stringWithString_("class"));
                query.setObject_forKey_(nsNum.numberWithBool_(1), nsStr.stringWithString_("r_Attributes"));
                query.setObject_forKey_(nsNum.numberWithBool_(1), nsStr.stringWithString_("r_Data"));
                query.setObject_forKey_(nsStr.stringWithString_("m_LimitAll"), nsStr.stringWithString_("m_Limit"));

                console.log("[*] KC query " + classNames[ci] + ": " + query.toString().substring(0, 200));

                const resultPtr = Memory.alloc(Process.pointerSize);
                resultPtr.writePointer(ptr(0));
                const status = SecItemCopyMatching(query.handle, resultPtr);

                if (status !== 0) {
                    if (status !== -25300) {
                        console.log("  [KC] " + classNames[ci] + ": status=" + status);
                    }
                    continue;
                }

                const resultObj = new ObjC.Object(resultPtr.readPointer());
                if (!resultObj || resultObj.isNull()) continue;

                // NSArray of NSDictionary
                const itemCount = resultObj.count();

                for (let i = 0; i < itemCount; i++) {
                    try {
                        const item = resultObj.objectAtIndex_(i);
                        const service = safeStr(item, "svce");
                        const account = safeStr(item, "acct");
                        const label = safeStr(item, "labl");
                        const accessGroup = safeStr(item, "agrp");

                        const combined = (service + " " + account + " " + label + " " + accessGroup).toLowerCase();
                        const keywords = ["netflix", "nf", "ale", "msl", "esn", "drm", "provision", "com.netflix"];
                        if (!keywords.some(kw => combined.indexOf(kw) !== -1)) continue;

                        totalFound++;

                        let dataStr = "";
                        let dataB64 = "";
                        let dataSize = 0;
                        try {
                            const vData = item.objectForKey_(ObjC.classes.NSString.stringWithString_("v_Data"));
                            if (vData && !vData.isNull()) {
                                dataSize = vData.length();
                                // UTF-8 で読めるか試す
                                const str = ObjC.classes.NSString.alloc().initWithData_encoding_(vData, 4);
                                if (str && !str.isNull()) {
                                    dataStr = str.toString();
                                }
                                // base64 エンコード (全データ保存)
                                if (dataSize > 0) {
                                    const b64 = vData.base64EncodedStringWithOptions_(0);
                                    if (b64 && !b64.isNull()) {
                                        dataB64 = b64.toString();
                                    }
                                }
                            }
                        } catch (_) { }

                        const display = dataStr || ("<" + dataSize + " bytes>");
                        console.log("  [KC:" + classNames[ci] + "] svc=" + service + "  acct=" + account + "  " + dataSize + "B");
                        console.log("    " + (dataStr ? dataStr.substring(0, 200) : "b64=" + dataB64.substring(0, 80) + "..."));

                        logData("storage.keychain", {
                            class: classNames[ci],
                            service: service,
                            account: account,
                            label: label,
                            accessGroup: accessGroup,
                            size: dataSize,
                            data: dataStr || null,
                            data_b64: dataB64,
                        });
                    } catch (_) { }
                }
            } catch (ce) {
                console.log("  [KC] " + classNames[ci] + ": " + ce);
            }
        }

        console.log("[+] Keychain: " + totalFound + " Netflix-related items");
    } catch (e) {
        console.log("[-] Keychain dump: " + e);
    }
}

// ── サンドボックスファイル探索 ──

function dumpSandbox(): void {
    try {
        const NSFileManager = ObjC.classes.NSFileManager;
        const fm = NSFileManager.defaultManager();

        // ホームディレクトリ: NSTemporaryDirectory の親から推定、または既知パス
        let homeDir = "";
        try {
            // Library/Preferences のパスから逆算
            const paths = ObjC.classes.NSSearchPathForDirectoriesInDomains
                ? null  // これは C 関数なので使えない
                : null;
            // NSBundle.mainBundle.bundlePath → /var/containers/Bundle/Application/UUID/Netflix.app
            // データは /var/containers/Data/Application/UUID/ にある
            // fm.URLsForDirectory_inDomains_(5, 1) = NSDocumentDirectory, NSUserDomainMask
            // NSLibraryDirectory = 5 in some versions, NSDocumentDirectory = 9
            // Try multiple directory types
            for (const dirType of [9, 5]) { // NSDocumentDirectory, NSLibraryDirectory
                try {
                    const urls = fm.URLsForDirectory_inDomains_(dirType, 1);
                    if (urls && urls.count() > 0) {
                        const p = urls.objectAtIndex_(0).path().toString();
                        // Strip trailing /Documents or /Library
                        homeDir = p.replace(/\/(Documents|Library)$/, "");
                        if (homeDir) break;
                    }
                } catch (_) { }
            }
        } catch (e) {
            console.log("[-] Home dir detection: " + e);
        }
        if (!homeDir) {
            console.log("[-] Could not determine home directory");
            return;
        }
        console.log("[*] App home: " + homeDir);

        const searchDirs = [
            homeDir + "/Documents",
            homeDir + "/Library",
            homeDir + "/Library/Caches",
            homeDir + "/Library/Application Support",
            homeDir + "/Library/Preferences",
            homeDir + "/tmp",
        ];

        const allFiles: { path: string; size: number; isDir: boolean }[] = [];

        for (const dir of searchDirs) {
            try {
                listDirRecursive(fm, dir, allFiles, 2);
            } catch (_) { }
        }

        // 結果表示
        console.log("[*] Sandbox: " + allFiles.length + " relevant files/dirs");
        for (const f of allFiles) {
            const type = f.isDir ? "DIR " : "FILE";
            const sizeStr = f.isDir ? "" : " (" + f.size + "B)";
            console.log("  [FS:" + type + "] " + f.path + sizeStr);
        }

        // 小さいファイル (< 4KB) の中身を読む
        for (const f of allFiles) {
            if (f.isDir || f.size === 0 || f.size > 4096) continue;
            try {
                const nsPath = ObjC.classes.NSString.stringWithString_(f.path);
                const data = ObjC.classes.NSData.dataWithContentsOfFile_(nsPath);
                if (!data || data.isNull()) continue;

                let content = "";
                const str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                if (str && !str.isNull()) {
                    content = str.toString();
                } else {
                    // plist 試行
                    try {
                        const plist = ObjC.classes.NSPropertyListSerialization.propertyListWithData_options_format_error_(data, 0, NULL, NULL);
                        if (plist && !plist.isNull()) content = plist.toString();
                    } catch (_) { }
                }
                if (content) {
                    const preview = content.length > 300 ? content.substring(0, 300) + "..." : content;
                    console.log("  [FS:CONTENT] " + f.path + ": " + preview);
                    logData("storage.file", { path: f.path, size: f.size, content: content.substring(0, 8192) });
                }
            } catch (_) { }
        }

        logData("storage.sandbox", {
            home: homeDir,
            files: allFiles,
        });
    } catch (e) {
        console.log("[-] Sandbox dump: " + e);
    }
}

function listDirRecursive(
    fm: ObjC.Object, dir: string,
    result: { path: string; size: number; isDir: boolean }[],
    maxDepth: number
): void {
    if (maxDepth <= 0) return;
    try {
        const nsDir = ObjC.classes.NSString.stringWithString_(dir);
        const contents = fm.contentsOfDirectoryAtPath_error_(nsDir, NULL);
        if (!contents || contents.isNull()) return;
        const count = contents.count();
        for (let i = 0; i < count; i++) {
            const name = contents.objectAtIndex_(i).toString();
            const fullPath = dir + "/" + name;
            let size = 0;
            let isDir = false;
            try {
                const attrs = fm.attributesOfItemAtPath_error_(ObjC.classes.NSString.stringWithString_(fullPath), NULL);
                if (attrs && !attrs.isNull()) {
                    const ft = safeStr(attrs, "NSFileType");
                    isDir = ft === "NSFileTypeDirectory";
                    if (!isDir) {
                        const s = attrs.objectForKey_(ObjC.classes.NSString.stringWithString_("NSFileSize"));
                        if (s) size = parseInt(s.toString()) || 0;
                    }
                }
            } catch (_) { }
            result.push({ path: fullPath, size, isDir });
            if (isDir) listDirRecursive(fm, fullPath, result, maxDepth - 1);
        }
    } catch (_) { }
}

function safeStr(dict: ObjC.Object, key: string): string {
    try {
        const val = dict.objectForKey_(ObjC.classes.NSString.stringWithString_(key));
        if (val && !val.isNull()) return val.toString();
    } catch (e) { }
    return "";
}
