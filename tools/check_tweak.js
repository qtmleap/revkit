// tweak がロードされているか確認
// frida -H <host> -n com.netflix.Netflix -l tools/check_tweak.js

console.log("[*] Checking if NetflixSSLBypass tweak is loaded...\n");

// ロード済みモジュールから tweak を検索
var modules = Process.enumerateModules();
var found = modules.filter(function (m) {
    return m.name.toLowerCase().indexOf("netflixssl") !== -1 ||
        m.name.toLowerCase().indexOf("sslbypass") !== -1 ||
        m.name.toLowerCase().indexOf("sslkill") !== -1 ||
        m.name.toLowerCase().indexOf("orion") !== -1;
});

if (found.length > 0) {
    console.log("[+] Found tweak modules:");
    found.forEach(function (m) {
        console.log("  " + m.name + " @ " + m.base);
    });
} else {
    console.log("[-] No tweak modules found.");
}

// Substrate/Substitute/ElleKit がロードされているか
var hooking = modules.filter(function (m) {
    return m.name.indexOf("substrate") !== -1 ||
        m.name.indexOf("Substitute") !== -1 ||
        m.name.indexOf("substitute") !== -1 ||
        m.name.indexOf("ElleKit") !== -1 ||
        m.name.indexOf("ellekit") !== -1 ||
        m.name.indexOf("CydiaSubstrate") !== -1;
});

console.log("\n[*] Hooking frameworks loaded:");
if (hooking.length > 0) {
    hooking.forEach(function (m) {
        console.log("  " + m.name + " @ " + m.base);
    });
} else {
    console.log("  [-] None found — Substrate/Substitute/ElleKit not loaded!");
}

console.log("\n[*] Done.");
