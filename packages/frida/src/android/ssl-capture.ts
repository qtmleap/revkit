import { logData } from "../common/utils";

// Parse HTTP/1.1 request line + Host header from text data
function parseHttpRequest(text: string): { method: string; url: string; host: string } | null {
    const m = text.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/\d/);
    if (!m) return null;
    const method = m[1];
    const path = m[2];
    const hostMatch = text.match(/\r?\nHost:\s*(\S+)/i);
    const host = hostMatch ? hostMatch[1] : "unknown";
    const url = "https://" + host + path;
    return { method: method, url: url, host: host };
}

// Parse HTTP/1.1 response status line
function parseHttpResponse(text: string): { status: number; statusText: string } | null {
    const m = text.match(/^HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
    if (!m) return null;
    return { status: parseInt(m[1]), statusText: m[2] };
}

// Extract body from HTTP text (after blank line)
function extractBody(text: string): string | null {
    let idx = text.indexOf("\r\n\r\n");
    if (idx === -1) idx = text.indexOf("\n\n");
    if (idx === -1) return null;
    const body = text.substring(idx + (text[idx + 1] === '\n' ? 2 : 4));
    return body.length > 0 ? body : null;
}

// Extract all HTTP headers from raw HTTP text
function extractHeaders(text: string): Record<string, string> {
    const headers: Record<string, string> = {};
    let idx = text.indexOf("\r\n\r\n");
    if (idx === -1) idx = text.indexOf("\n\n");
    const headerBlock = idx !== -1 ? text.substring(0, idx) : text;
    const lines = headerBlock.split(/\r?\n/);
    // Skip first line (request/status line)
    for (let i = 1; i < lines.length; i++) {
        const colon = lines[i].indexOf(":");
        if (colon > 0) {
            const key = lines[i].substring(0, colon).trim();
            const val = lines[i].substring(colon + 1).trim();
            headers[key] = val;
        }
    }
    return headers;
}

export function hookSSL(): void {
    let connId = 0;
    const sslConnMap: Record<string, string> = {};
    // Track per-connection state: last request URL for matching responses
    const connLastUrl: Record<string, string> = {};
    const connLastMethod: Record<string, string> = {};

    // Android uses BoringSSL in libssl.so (or via Conscrypt/Cronet)
    // Netflix may bundle its own SSL in a renamed or embedded library
    let ssl_write: NativePointer | null = null;
    const sslLibs = ["libssl.so", "libsscronet.so", "libcronet.so", "libconscrypt_jni.so", "libgmscore.so"];
    for (let i = 0; i < sslLibs.length && !ssl_write; i++) {
        try { ssl_write = Module.findExportByName(sslLibs[i], "SSL_write"); } catch (e) { }
    }
    if (!ssl_write) {
        try { ssl_write = Module.findExportByName(null, "SSL_write"); } catch (e) { }
    }
    if (!ssl_write) {
        // Search all loaded modules for SSL_write
        Process.enumerateModules().forEach(function (m) {
            if (ssl_write) return;
            try {
                const exp = m.findExportByName("SSL_write");
                if (exp) {
                    console.log("[*] Found SSL_write in " + m.name);
                    ssl_write = exp;
                }
            } catch (e) { }
        });
    }

    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function (args) {
                const ssl = args[0].toString();
                const buf = args[1];
                const len = args[2].toInt32();

                if (!sslConnMap[ssl]) sslConnMap[ssl] = "conn_" + (connId++);
                const connName = sslConnMap[ssl];

                try {
                    const data = buf.readUtf8String(len);
                    const req = parseHttpRequest(data!);
                    if (req) {
                        connLastUrl[connName] = req.url;
                        connLastMethod[connName] = req.method;
                        const body = extractBody(data!);
                        const hdrs = extractHeaders(data!);
                        logData("http.request", {
                            domain: req.host,
                            method: req.method,
                            url: req.url,
                            headers: hdrs,
                            size: len,
                            body: body ? body.substring(0, 65536) : null
                        });
                    }
                } catch (e) {
                    // binary data -- log raw for non-HTTP/2 preface
                    const bytes = buf.readByteArray(Math.min(len, 4));
                    const b = new Uint8Array(bytes!);
                    // Skip HTTP/2 binary frames (type byte at offset 3)
                    if (len > 9 && !(b[0] === 0x50 && b[1] === 0x52 && b[2] === 0x49)) {
                        logData("ssl.write", {
                            conn: connName,
                            size: len
                        }, buf.readByteArray(Math.min(len, 8192))!);
                    }
                }
            }
        });
        console.log("[+] Hooked SSL_write");
    } else {
        console.log("[-] SSL_write not found");
    }

    let ssl_read: NativePointer | null = null;
    for (let j = 0; j < sslLibs.length && !ssl_read; j++) {
        try { ssl_read = Module.findExportByName(sslLibs[j], "SSL_read"); } catch (e) { }
    }
    if (!ssl_read) {
        try { ssl_read = Module.findExportByName(null, "SSL_read"); } catch (e) { }
    }
    if (!ssl_read) {
        Process.enumerateModules().forEach(function (m) {
            if (ssl_read) return;
            try {
                const exp = m.findExportByName("SSL_read");
                if (exp) {
                    console.log("[*] Found SSL_read in " + m.name);
                    ssl_read = exp;
                }
            } catch (e) { }
        });
    }

    if (ssl_read) {
        Interceptor.attach(ssl_read, {
            onEnter: function (args) {
                this.ssl = args[0].toString();
                this.buf = args[1];
            },
            onLeave: function (retval) {
                const len = retval.toInt32();
                if (len <= 0) return;

                if (!sslConnMap[this.ssl]) sslConnMap[this.ssl] = "conn_" + (connId++);
                const connName = sslConnMap[this.ssl];

                try {
                    const data = this.buf.readUtf8String(len);
                    const resp = parseHttpResponse(data!);
                    if (resp) {
                        const body = extractBody(data!);
                        const hdrs = extractHeaders(data!);
                        const url = connLastUrl[connName] || "";
                        const domain = url.match(/^https?:\/\/([^\/\?:]+)/) ? url.match(/^https?:\/\/([^\/\?:]+)/)![1] : "unknown";
                        logData("http.response", {
                            domain: domain,
                            url: url,
                            status: resp.status,
                            headers: hdrs,
                            size: len,
                            body: body ? body.substring(0, 65536) : null
                        });
                    }
                } catch (e) {
                    // binary response -- skip logging individual HTTP/2 frames
                }
            }
        });
        console.log("[+] Hooked SSL_read");
    } else {
        console.log("[-] SSL_read not found");
    }
}
