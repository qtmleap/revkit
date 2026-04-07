import { SEP, SEP2, ts } from "../common/utils";

export function hookSSL(): void {
    let connId = 0;
    const sslConnMap: Record<string, string> = {};

    let ssl_write: NativePointer | null = null;
    try {
        ssl_write = Module.findExportByName("libboringssl.dylib", "SSL_write");
    } catch (e) { }
    if (!ssl_write) {
        try { ssl_write = Module.findExportByName(null, "SSL_write"); } catch (e) { }
    }

    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function (args) {
                const ssl = args[0].toString();
                const buf = args[1];
                const len = args[2].toInt32();

                if (!sslConnMap[ssl]) sslConnMap[ssl] = "conn_" + (connId++);

                try {
                    const data = buf.readUtf8String(len);
                    console.log("\n" + SEP);
                    console.log("[" + ts() + "] >>> WRITE " + sslConnMap[ssl] + " (" + len + " bytes)");
                    console.log(SEP);
                    console.log(data);
                } catch (e) {
                    console.log("\n[" + ts() + "] >>> WRITE " + sslConnMap[ssl] + " (" + len + " bytes, binary)");
                    console.log(hexdump(buf, { length: Math.min(len, 512), ansi: false }));
                }
            }
        });
        console.log("[+] Hooked SSL_write");
    } else {
        console.log("[-] SSL_write not found");
    }

    let ssl_read: NativePointer | null = null;
    try {
        ssl_read = Module.findExportByName("libboringssl.dylib", "SSL_read");
    } catch (e) { }
    if (!ssl_read) {
        try { ssl_read = Module.findExportByName(null, "SSL_read"); } catch (e) { }
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

                try {
                    const data = this.buf.readUtf8String(len);
                    console.log("\n" + SEP2);
                    console.log("[" + ts() + "] <<< READ  " + sslConnMap[this.ssl] + " (" + len + " bytes)");
                    console.log(SEP2);
                    console.log(data);
                } catch (e) {
                    console.log("\n[" + ts() + "] <<< READ  " + sslConnMap[this.ssl] + " (" + len + " bytes, binary)");
                    console.log(hexdump(this.buf, { length: Math.min(len, 512), ansi: false }));
                }
            }
        });
        console.log("[+] Hooked SSL_read");
    } else {
        console.log("[-] SSL_read not found");
    }
}
