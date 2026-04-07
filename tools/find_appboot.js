// appboot.netflix.com 関連のシンボル・文字列・フレームワークを調査
//
// objection 経由で spawn (pause 状態で起動):
//   objection -N -h 192.168.0.49 -n com.netflix.Netflix -s start
//
// objection プロンプトで:
//   import tools/find_appboot.js
//   %resume

// 即時実行 (pause 状態で実行するため遅延不要)
console.log("[*] Searching for appboot references...\n");

var modules = Process.enumerateModules();
console.log("[*] Loaded modules: " + modules.length);

// Netflix 関連モジュールのみ
var nfModules = modules.filter(function (m) {
    var n = m.name;
    return n.indexOf("Netflix") !== -1 ||
        n.indexOf("NF") !== -1 ||
        n.indexOf("Argo") !== -1 ||
        n.indexOf("Osprey") !== -1 ||
        n.indexOf("Gibbon") !== -1 ||
        n.indexOf("Nbp") !== -1 ||
        n.indexOf("Msl") !== -1 ||
        n.indexOf("Bolt") !== -1;
});

console.log("\n[*] Netflix-related modules (" + nfModules.length + "):");
nfModules.forEach(function (m) {
    console.log("  " + m.name + " @ " + m.base + " (" + m.size + " bytes)");
});

// Netflix モジュール内のみで "appboot" を検索
console.log("\n[*] Scanning Netflix modules for 'appboot'...");
nfModules.forEach(function (m) {
    try {
        var ranges = m.enumerateRanges("r--");
        ranges.forEach(function (range) {
            try {
                var results = Memory.scanSync(range.base, range.size, "61 70 70 62 6f 6f 74"); // "appboot"
                results.forEach(function (match) {
                    try {
                        var str = match.address.readUtf8String(200);
                        console.log("  [" + m.name + "] @ " + match.address + ": " + str.split("\0")[0]);
                    } catch (e) {}
                });
            } catch (e) {}
        });
    } catch (e) {}
});

// ObjC クラスで appboot 関連を検索
if (ObjC.available) {
    console.log("\n[*] ObjC classes matching 'appboot' or 'boot'...");
    var classNames = Object.keys(ObjC.classes);
    classNames.forEach(function (name) {
        var lower = name.toLowerCase();
        if (lower.indexOf("appboot") !== -1 ||
            (lower.indexOf("boot") !== -1 &&
                (name.indexOf("NF") !== -1 || name.indexOf("Netflix") !== -1 || name.indexOf("Argo") !== -1))) {
            console.log("  Class: " + name);
            try {
                ObjC.classes[name].$ownMethods.forEach(function (method) {
                    console.log("    " + method);
                });
            } catch (e) {}
        }
    });

    // SSL pinning / certificate 関連クラス
    console.log("\n[*] ObjC classes matching pinning/cert/trust/ssl...");
    classNames.forEach(function (name) {
        if ((name.indexOf("NF") === 0 || name.indexOf("Netflix") !== -1 || name.indexOf("Argo") !== -1) &&
            (name.toLowerCase().indexOf("pin") !== -1 ||
             name.toLowerCase().indexOf("cert") !== -1 ||
             name.toLowerCase().indexOf("trust") !== -1 ||
             name.toLowerCase().indexOf("ssl") !== -1 ||
             name.toLowerCase().indexOf("tls") !== -1 ||
             name.toLowerCase().indexOf("security") !== -1)) {
            console.log("  Class: " + name);
            try {
                ObjC.classes[name].$ownMethods.forEach(function (method) {
                    console.log("    " + method);
                });
            } catch (e) {}
        }
    });
}

console.log("\n[*] Done.");
