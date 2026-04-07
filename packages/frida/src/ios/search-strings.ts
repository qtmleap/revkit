// Netflix バイナリ内の ALE/provision 関連文字列を検索

function searchModuleStrings(modName: string | null, keywords: string[]): void {
    let mod: Module | null = null;
    if (modName) {
        mod = Process.findModuleByName(modName);
        if (!mod) {
            console.log("[-] Module not found: " + modName);
            return;
        }
    } else {
        mod = Process.enumerateModules()[0]; // main binary
    }

    console.log("[*] Searching " + mod.name + " (base=" + mod.base + " size=" + mod.size + ")");

    const base = mod.base;
    const size = mod.size;

    for (const kw of keywords) {
        const kwBytes = [];
        for (let i = 0; i < kw.length; i++) {
            kwBytes.push(kw.charCodeAt(i));
        }

        // Memory.scan for the keyword
        const pattern = kwBytes.map(b => b.toString(16).padStart(2, '0')).join(" ");
        const results: NativePointer[] = [];

        Memory.scan(base, size, pattern, {
            onMatch: function (address, _size) {
                results.push(address);
            },
            onComplete: function () {
                if (results.length > 0) {
                    console.log("  [FOUND] \"" + kw + "\" x" + results.length + " in " + mod!.name);
                    for (let i = 0; i < Math.min(results.length, 5); i++) {
                        // Read surrounding context
                        try {
                            const str = results[i].readUtf8String(200);
                            const preview = str ? str.substring(0, 100) : "";
                            const offset = results[i].sub(base);
                            console.log("    @" + offset + ": " + preview);
                        } catch (e) {
                            console.log("    @" + results[i].sub(base));
                        }
                    }
                }
            }
        });
    }
}

const keywords = [
    "aleProvision",
    "AleProvision",
    "getProxyEsn",
    "ProxyEsn",
    "proxyEsn",
    "provisionResponse",
    "AleService",
    "AleSession",
    "AleCrypto",
    "/aleProvision",
    "ale.provision",
    "CLEAR",
    "RSA-OAEP",
    "keyx",
];

console.log("[*] String search starting...");

// Main binary
searchModuleStrings(null, keywords);

// MslClient
searchModuleStrings("MslClient", keywords);

// Netflix framework
const modules = Process.enumerateModules();
for (const m of modules) {
    if (m.name.indexOf("Netflix") !== -1 && m.name !== "Netflix") {
        searchModuleStrings(m.name, keywords);
    }
}

console.log("[*] String search complete.");
