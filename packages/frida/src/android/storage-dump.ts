// ── Android SharedPreferences + アプリストレージダンプ ──

import { logData } from "../common/utils";

export function dumpStorage(): void {
    dumpSharedPreferences();
    dumpAppFiles();
}

// ── SharedPreferences ──

function dumpSharedPreferences(): void {
    try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const app = ActivityThread.currentApplication();
        const ctx = app.getApplicationContext();
        const appInfo = ctx.getApplicationInfo();
        const dataDir = appInfo.dataDir.value;

        console.log("[*] App dataDir: " + dataDir);

        // SharedPreferences XML ファイルを列挙
        const prefsDir = dataDir + "/shared_prefs";
        const File = Java.use("java.io.File");
        const prefsFile = File.$new(prefsDir);

        if (!prefsFile.exists()) {
            console.log("[-] shared_prefs dir not found");
            return;
        }

        const files = prefsFile.listFiles();
        if (!files) {
            console.log("[-] No SharedPreferences files");
            return;
        }

        console.log("[*] SharedPreferences: " + files.length + " files");

        const keywords = ["netflix", "nf", "ale", "msl", "esn", "drm", "provision", "token", "session", "crypto", "key", "auth", "cookie", "profile", "cdm", "widevine"];

        for (let i = 0; i < files.length; i++) {
            const f = files[i];
            const fname = f.getName();
            console.log("  [SP:FILE] " + fname + " (" + f.length() + "B)");

            // XML を直接読んでパース
            try {
                const filePath = prefsDir + "/" + fname;
                const FileInputStream = Java.use("java.io.FileInputStream");
                const BufferedReader = Java.use("java.io.BufferedReader");
                const InputStreamReader = Java.use("java.io.InputStreamReader");

                const fis = FileInputStream.$new(filePath);
                const isr = InputStreamReader.$new(fis, "UTF-8");
                const br = BufferedReader.$new(isr);
                let xmlContent = "";
                let line = br.readLine();
                while (line !== null) {
                    xmlContent += line.toString() + "\n";
                    line = br.readLine();
                }
                br.close();

                // XML からキー/値を抽出 (行ベースパーサ)
                const allEntries: Record<string, any> = {};
                let matchCount = 0;
                const lines = xmlContent.split("\n");
                let pendingTag = "";
                let pendingKey = "";
                let pendingVal = "";

                for (let li = 0; li < lines.length; li++) {
                    const ln = lines[li];

                    // <string name="key">value</string> (1行)
                    let m = ln.match(/<(string)\s+name="([^"]+)">(.*?)<\/\1>/);
                    if (m) {
                        allEntries[m[2]] = m[3].replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
                        continue;
                    }

                    // <string name="key"> (複数行開始)
                    m = ln.match(/<(string)\s+name="([^"]+)">/);
                    if (m) {
                        pendingTag = m[1];
                        pendingKey = m[2];
                        pendingVal = "";
                        continue;
                    }

                    // </string> (複数行終了)
                    if (pendingKey && ln.indexOf("</" + pendingTag + ">") !== -1) {
                        const endIdx = ln.indexOf("</" + pendingTag + ">");
                        pendingVal += ln.substring(0, endIdx);
                        allEntries[pendingKey] = pendingVal.replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
                        pendingKey = "";
                        pendingTag = "";
                        continue;
                    }

                    // 複数行の途中
                    if (pendingKey) {
                        pendingVal += ln + "\n";
                        continue;
                    }

                    // <int name="key" value="123" />
                    m = ln.match(/<(int|long|float)\s+name="([^"]+)"\s+value="([^"]*)"\s*\/>/);
                    if (m) { allEntries[m[2]] = m[3]; continue; }

                    // <boolean name="key" value="true" />
                    m = ln.match(/<boolean\s+name="([^"]+)"\s+value="([^"]*)"\s*\/>/);
                    if (m) { allEntries[m[1]] = m[2]; continue; }
                }

                for (const key of Object.keys(allEntries)) {
                    const val = allEntries[key] || "";
                    const keyLower = key.toLowerCase();
                    const valLower = val.toLowerCase();
                    if (keywords.some(kw => keyLower.indexOf(kw) !== -1 || valLower.indexOf(kw) !== -1)) {
                        matchCount++;
                        const display = val.length > 200 ? val.substring(0, 200) + "..." : val;
                        console.log("    [SP] " + key + " = " + display);
                    }
                }

                logData("storage.sharedPreferences", {
                    file: fname,
                    total: Object.keys(allEntries).length,
                    matchCount: matchCount,
                    entries: allEntries,
                });
            } catch (pe) {
                console.log("    [-] Failed to read: " + pe);
            }
        }
    } catch (e) {
        console.log("[-] SharedPreferences dump: " + e);
    }
}

// ── アプリファイル探索 ──

function dumpAppFiles(): void {
    try {
        const ActivityThread = Java.use("android.app.ActivityThread");
        const app = ActivityThread.currentApplication();
        const ctx = app.getApplicationContext();
        const appInfo = ctx.getApplicationInfo();
        const dataDir = appInfo.dataDir.value;

        const File = Java.use("java.io.File");
        const keywords = ["msl", "ale", "drm", "provision", "token", "session", "crypto", "key", "esn", "netflix", "widevine", "cdm"];

        const searchDirs = [
            dataDir + "/files",
            dataDir + "/cache",
            dataDir + "/databases",
            dataDir + "/app_webview",
            dataDir + "/no_backup",
        ];

        const allFiles: { path: string; size: number; isDir: boolean }[] = [];

        for (const dir of searchDirs) {
            try {
                const dirFile = File.$new(dir);
                if (!dirFile.exists() || !dirFile.isDirectory()) continue;

                listFilesRecursive(dirFile, keywords, allFiles, 2);
            } catch (_) { }
        }

        console.log("[*] App files: " + allFiles.length + " relevant files/dirs");
        for (const f of allFiles) {
            const type = f.isDir ? "DIR " : "FILE";
            const sizeStr = f.isDir ? "" : " (" + f.size + "B)";
            console.log("  [FS:" + type + "] " + f.path + sizeStr);
        }

        // 小さいテキストファイル (< 4KB) の中身を読む
        const BufferedReader = Java.use("java.io.BufferedReader");
        const InputStreamReader = Java.use("java.io.InputStreamReader");
        const FileInputStream = Java.use("java.io.FileInputStream");

        for (const f of allFiles) {
            if (f.isDir || f.size === 0 || f.size > 4096) continue;
            try {
                const fis = FileInputStream.$new(f.path);
                const isr = InputStreamReader.$new(fis, "UTF-8");
                const br = BufferedReader.$new(isr);
                let content = "";
                let line = br.readLine();
                while (line !== null) {
                    content += line + "\n";
                    line = br.readLine();
                }
                br.close();

                if (content.length > 0) {
                    const preview = content.length > 300 ? content.substring(0, 300) + "..." : content;
                    console.log("  [FS:CONTENT] " + f.path + ": " + preview);
                    logData("storage.file", { path: f.path, size: f.size, content: content.substring(0, 8192) });
                }
            } catch (_) { }
        }

        logData("storage.appFiles", {
            dataDir: dataDir,
            files: allFiles,
        });
    } catch (e) {
        console.log("[-] App files dump: " + e);
    }
}

function listFilesRecursive(
    dir: any,
    keywords: string[],
    result: { path: string; size: number; isDir: boolean }[],
    maxDepth: number,
): void {
    if (maxDepth <= 0) return;
    try {
        const files = dir.listFiles();
        if (!files) return;

        for (let i = 0; i < files.length; i++) {
            const f = files[i];
            const name = f.getName().toLowerCase();
            const isDir = f.isDirectory();
            const size = isDir ? 0 : f.length();
            const match = keywords.some(kw => name.indexOf(kw) !== -1);

            if (match) {
                result.push({ path: f.getAbsolutePath(), size, isDir });
            }

            if (isDir) {
                listFilesRecursive(f, keywords, result, maxDepth - 1);
            }
        }
    } catch (_) { }
}
