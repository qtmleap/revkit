export function hookSSLPinning(): void {
    // --- TrustManager 回避 ---
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        const TrustManager = Java.registerClass({
            name: "com.netflix.frida.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain: any, authType: any) { },
                checkServerTrusted: function (chain: any, authType: any) { },
                getAcceptedIssuers: function () { return []; }
            }
        });
        const ctx = SSLContext.getInstance("TLS");
        ctx.init(null, [TrustManager.$new()], null);
        SSLContext.setDefault(ctx);
        console.log("[+] Bypassed TrustManager (global SSLContext)");
    } catch (e) {
        console.log("[-] TrustManager bypass: " + e);
    }

    // --- OkHttp CertificatePinner 回避 ---
    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname: any, peerCertificates: any) {
            // do nothing
        };
        console.log("[+] Bypassed OkHttp CertificatePinner.check(String, List)");
    } catch (e) {
        console.log("[-] CertificatePinner List: " + e);
    }
    try {
        const CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function (hostname: any, peerCertificates: any) {
            // do nothing
        };
        console.log("[+] Bypassed OkHttp CertificatePinner.check$okhttp");
    } catch (e) {
        console.log("[-] CertificatePinner okhttp: " + e);
    }

    // --- Android WebViewClient SSL error 回避 ---
    try {
        const WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view: any, handler: any, error: any) {
            handler.proceed();
        };
        console.log("[+] Bypassed WebViewClient SSL error");
    } catch (e) { }
}
