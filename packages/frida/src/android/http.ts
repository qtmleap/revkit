import { logData, logHttpReq, logHttpResp } from "../common/utils";
import { ORIGINAL_ESN, OVERRIDE_ESN } from "./config";

// URL -> domain
function domainOf(urlStr: string): string {
    const m = urlStr.match(/^https?:\/\/([^\/\?:]+)/);
    return m ? m[1] : "unknown";
}

function isLocal(urlStr: string): boolean {
    return /^https?:\/\/(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.|localhost|0\.0\.0\.0)/.test(urlStr);
}

// 不要なアセット系リクエストをスキップ
const SKIP_EXTENSIONS = /\.(png|jpg|jpeg|gif|webp|svg|ico|bmp|tiff|avif|woff|woff2|ttf|otf|eot|css|js|map|mp4|webm|ts|m4s|m4v|m4a|aac|mp3|vtt|ttml|dfxp)(\?|$)/i;
const SKIP_DOMAINS = /\b(assets\.nflxext\.com|codex\.nflxext\.com|image\.tmdb\.org|art-[a-z]+\.nflximg\.net|occ-\d+-\d+\.nflxso\.net|lottie\.netflix\.com)\b/;

function isSkippableUrl(urlStr: string): boolean {
    if (SKIP_EXTENSIONS.test(urlStr)) return true;
    if (SKIP_DOMAINS.test(urlStr)) return true;
    return false;
}

export function hookHTTP(): void {
    // -------------------------------------------------------
    // OkHttp Interceptor -- リクエスト/レスポンス
    // -------------------------------------------------------
    try {
        // OkHttp の RealCall.execute / enqueue をフック
        const RealCall = Java.use("okhttp3.internal.connection.RealCall");
        const Buffer = Java.use("okio.Buffer");

        RealCall.getResponseWithInterceptorChain.implementation = function () {
            let request = this.getOriginalRequest();
            const url = request.url().toString();
            if (isLocal(url) || url.indexOf("netflix") === -1 || isSkippableUrl(url)) {
                return this.getResponseWithInterceptorChain();
            }

            // --- ESN Override: X-Netflix-ProxyEsn ヘッダーを書き換え ---
            try {
                const proxyEsn = request.header("X-Netflix-ProxyEsn");
                if (proxyEsn && proxyEsn.indexOf(ORIGINAL_ESN) !== -1) {
                    const newRequest = request.newBuilder()
                        .removeHeader("X-Netflix-ProxyEsn")
                        .addHeader("X-Netflix-ProxyEsn", OVERRIDE_ESN)
                        .build();
                    // RealCall の originalRequest フィールドを差し替え
                    const origField = this.getClass().getDeclaredField("originalRequest");
                    origField.setAccessible(true);
                    origField.set(this, newRequest);
                    request = newRequest;
                    console.log("[ESN] Replaced ProxyEsn header: " + OVERRIDE_ESN.substring(0, 40) + "...");
                }
            } catch (esnErr) {
                console.log("[-] ESN header replace: " + esnErr);
            }

            const domain = domainOf(url);
            const method = request.method();
            let bodyStr: string | null = null;
            let bodySize = 0;

            // リクエストヘッダー取得
            const reqHeaders: Record<string, string> = {};
            try {
                const headers = request.headers();
                const namesArr = headers.names().toArray();
                for (let hi = 0; hi < namesArr.length; hi++) {
                    const hname = namesArr[hi].toString();
                    reqHeaders[hname] = headers.get(hname);
                }
            } catch (e2) { }

            try {
                const body = request.body();
                if (body) {
                    const buf = Buffer.$new();
                    body.writeTo(buf);
                    bodySize = buf.size();
                    bodyStr = buf.readUtf8();
                }
            } catch (e) { }

            const reqInfo: Record<string, any> = {
                domain: domain,
                method: method,
                url: url,
                headers: reqHeaders
            };
            if (bodyStr) {
                reqInfo.size = bodySize;
                reqInfo.body = bodyStr.substring(0, 8192);
            }
            logData("http.request", reqInfo);
            logHttpReq(method, url, bodySize || 0, Object.keys(reqHeaders).length);

            const response = this.getResponseWithInterceptorChain();

            try {
                // レスポンスヘッダー取得
                const respHeaders: Record<string, string> = {};
                try {
                    const rh = response.headers();
                    const rnamesArr = rh.names().toArray();
                    for (let ri = 0; ri < rnamesArr.length; ri++) {
                        const rname = rnamesArr[ri].toString();
                        respHeaders[rname] = rh.get(rname);
                    }
                } catch (e3) { }

                const respBody = response.body();
                if (respBody) {
                    const source = respBody.source();
                    source.request(Java.use("java.lang.Long").MAX_VALUE.value);
                    const respBuf = source.getBuffer().clone();
                    const respStr = respBuf.readUtf8();
                    const status = response.code();

                    logData("http.response", {
                        domain: domain,
                        url: url,
                        status: status,
                        headers: respHeaders,
                        size: respStr.length,
                        body: respStr.substring(0, 65536)
                    });
                    logHttpResp(status, url, respStr.length, Object.keys(respHeaders).length);
                }
            } catch (e) { }

            return response;
        };
        console.log("[+] Hooked OkHttp RealCall");
    } catch (e) {
        console.log("[-] OkHttp RealCall: " + e);
    }

    // -------------------------------------------------------
    // HttpURLConnection -- MSL HTTP通信 (Cronet/system)
    // -------------------------------------------------------
    try {
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            const conn = this.openConnection();
            const url = this.toString();
            if (url.indexOf("netflix") !== -1 && !isLocal(url)) {
                console.log("[*] URL.openConnection: " + url);
                logData("url", { domain: domainOf(url), url: url });
            }
            return conn;
        };
        console.log("[+] Hooked URL.openConnection");
    } catch (e) {
        console.log("[-] URL.openConnection: " + e);
    }
}
