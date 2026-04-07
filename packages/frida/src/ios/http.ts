import { logData, logHttpReq, logHttpResp } from "../common/utils";
import { maybeUpdateEsnFromHeader } from "../common/msl-processor";

function domainOf(urlStr: string): string {
    const m = urlStr.match(/^https?:\/\/([^\/\?:]+)/);
    return m ? m[1] : "unknown";
}

function isLocal(urlStr: string): boolean {
    return /^https?:\/\/(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.|localhost|0\.0\.0\.0)/.test(urlStr);
}

export function hookObjCTrace(): void {
    if (typeof ObjC === 'undefined' || !ObjC.available) return;

    const lastUrlByThread: Record<number, string> = {};

    // +[NSURL URLWithString:]
    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("+[NSURL URLWithString:]").forEach(function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    const url = new ObjC.Object(args[2]).toString();
                    lastUrlByThread[this.threadId] = url;
                    if (isLocal(url)) return;
                    const domain = domainOf(url);
                    logData("url", { domain: domain, url: url });
                }
            });
        });
        console.log("[+] Hooked +[NSURL URLWithString:]");
    } catch (e) { console.log("[-] NSURL: " + e); }

    // -[NSMutableURLRequest setHTTPBody:]
    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[NSMutableURLRequest setHTTPBody:]").forEach(function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const req = new ObjC.Object(args[0]);
                        let url = "";
                        try {
                            const reqUrl = req.URL();
                            if (reqUrl && !reqUrl.isNull()) url = reqUrl.absoluteString().toString();
                        } catch (e) { }
                        if (!url) url = lastUrlByThread[this.threadId] || "";
                        if (isLocal(url)) return;
                        const data = new ObjC.Object(args[2]);
                        const domain = domainOf(url);
                        let bodyStr: string | null = null;
                        let bodySize = 0;

                        let method = "POST";
                        try { method = req.HTTPMethod().toString(); } catch (e) { }

                        try { bodySize = data.length(); } catch (e) { }

                        const str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                        if (str && !str.isNull()) {
                            bodyStr = str.toString();
                        }

                        let contentType: string | null = null;
                        try {
                            const ct = req.valueForHTTPHeaderField_("Content-Type");
                            if (ct && !ct.isNull()) contentType = ct.toString();
                        } catch (e) { }

                        // Extract all headers for ESN detection
                        const headers: Record<string, string> = {};
                        try {
                            const allHeaders = req.allHTTPHeaderFields();
                            if (allHeaders && !allHeaders.isNull()) {
                                const keys = allHeaders.allKeys();
                                const count = keys.count();
                                for (let i = 0; i < count; i++) {
                                    const k = keys.objectAtIndex_(i).toString();
                                    const v = allHeaders.objectForKey_(keys.objectAtIndex_(i)).toString();
                                    headers[k] = v;
                                }
                            }
                        } catch (e) { }

                        maybeUpdateEsnFromHeader(headers);

                        logData("http.request", {
                            domain: domain,
                            method: method,
                            url: url,
                            content_type: contentType,
                            size: bodySize,
                            body: bodyStr ? bodyStr.substring(0, 8192) : null,
                            headers: Object.keys(headers).length > 0 ? headers : undefined
                        });
                        logHttpReq(method, url, bodySize, Object.keys(headers).length);
                    } catch (e) { }
                }
            });
        });
        console.log("[+] Hooked -[NSMutableURLRequest setHTTPBody:]");
    } catch (e) { console.log("[-] setHTTPBody: " + e); }

    // -[NSMutableURLRequest setHTTPBodyStream:]
    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[NSMutableURLRequest setHTTPBodyStream:]").forEach(function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const req = new ObjC.Object(args[0]);
                        const stream = new ObjC.Object(args[2]);
                        let url = "";
                        try {
                            const reqUrl = req.URL();
                            if (reqUrl && !reqUrl.isNull()) url = reqUrl.absoluteString().toString();
                        } catch (e) { }
                        if (!url) url = lastUrlByThread[this.threadId] || "";
                        if (isLocal(url)) return;
                        const domain = domainOf(url);

                        let bodyStr: string | null = null;
                        let bodySize = 0;
                        try {
                            const data = stream.valueForKey_("_data");
                            if (data && !data.isNull()) {
                                bodySize = data.length();
                                const str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                if (str && !str.isNull()) bodyStr = str.toString();
                            }
                        } catch (e) { }

                        if (!bodyStr) {
                            try {
                                stream.open();
                                const bufSize = 65536;
                                const buf = Memory.alloc(bufSize);
                                const bytesRead = stream.read_maxLength_(buf, bufSize);
                                if (bytesRead > 0) {
                                    bodySize = bytesRead;
                                    const nsData = ObjC.classes.NSData.dataWithBytes_length_(buf, bytesRead);
                                    const str = ObjC.classes.NSString.alloc().initWithData_encoding_(nsData, 4);
                                    if (str && !str.isNull()) bodyStr = str.toString();
                                }
                                stream.close();
                            } catch (e) { }
                        }

                        let method = "POST";
                        try { method = req.HTTPMethod().toString(); } catch (e) { }
                        let contentType: string | null = null;
                        try {
                            const ct = req.valueForHTTPHeaderField_("Content-Type");
                            if (ct && !ct.isNull()) contentType = ct.toString();
                        } catch (e) { }

                        logData("http.request", {
                            domain: domain,
                            method: method,
                            url: url,
                            content_type: contentType,
                            size: bodySize,
                            body: bodyStr ? bodyStr.substring(0, 8192) : null,
                            via: "bodyStream"
                        });
                    } catch (e) { }
                }
            });
        });
        console.log("[+] Hooked -[NSMutableURLRequest setHTTPBodyStream:]");
    } catch (e) { console.log("[-] setHTTPBodyStream: " + e); }

    // uploadTaskWithRequest:fromData:completionHandler:
    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[NSURLSession uploadTaskWithRequest:fromData:completionHandler:]").forEach(function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const req = new ObjC.Object(args[2]);
                        const data = new ObjC.Object(args[3]);
                        let url = "";
                        try {
                            const reqUrl = req.URL();
                            if (reqUrl && !reqUrl.isNull()) url = reqUrl.absoluteString().toString();
                        } catch (e) { }
                        if (isLocal(url)) return;
                        const domain = domainOf(url);

                        let bodyStr: string | null = null;
                        let bodySize = 0;
                        if (data && !data.isNull()) {
                            try { bodySize = data.length(); } catch (e) { }
                            try {
                                const str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                                if (str && !str.isNull()) bodyStr = str.toString();
                            } catch (e) { }
                        }

                        let method = "POST";
                        try { method = req.HTTPMethod().toString(); } catch (e) { }
                        let contentType: string | null = null;
                        try {
                            const ct = req.valueForHTTPHeaderField_("Content-Type");
                            if (ct && !ct.isNull()) contentType = ct.toString();
                        } catch (e) { }

                        logData("http.request", {
                            domain: domain,
                            method: method,
                            url: url,
                            content_type: contentType,
                            size: bodySize,
                            body: bodyStr ? bodyStr.substring(0, 8192) : null,
                            via: "uploadTask"
                        });
                    } catch (e) { }
                }
            });
        });
        console.log("[+] Hooked uploadTaskWithRequest:fromData:completionHandler:");
    } catch (e) { console.log("[-] uploadTask: " + e); }

    // dataTaskWithRequest:completionHandler: (request + response)
    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[NSURLSession dataTaskWithRequest:completionHandler:]").forEach(function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const req = new ObjC.Object(args[2]);
                        let url = "";
                        try {
                            const reqUrl = req.URL();
                            if (reqUrl && !reqUrl.isNull()) url = reqUrl.absoluteString().toString();
                        } catch (e) { }
                        if (isLocal(url)) return;
                        const domain = domainOf(url);
                        if (url.indexOf("netflix") === -1) return;

                        let reqBodyStr: string | null = null;
                        let reqBodySize = 0;
                        try {
                            const httpBody = req.HTTPBody();
                            if (httpBody && !httpBody.isNull()) {
                                reqBodySize = httpBody.length();
                                const str = ObjC.classes.NSString.alloc().initWithData_encoding_(httpBody, 4);
                                if (str && !str.isNull()) reqBodyStr = str.toString();
                            }
                        } catch (e) { }

                        if (!reqBodyStr) {
                            try {
                                const bodyStream = req.HTTPBodyStream();
                                if (bodyStream && !bodyStream.isNull()) {
                                    try {
                                        const sData = bodyStream.valueForKey_("_data");
                                        if (sData && !sData.isNull()) {
                                            reqBodySize = sData.length();
                                            const str = ObjC.classes.NSString.alloc().initWithData_encoding_(sData, 4);
                                            if (str && !str.isNull()) reqBodyStr = str.toString();
                                        }
                                    } catch (e) { }
                                }
                            } catch (e) { }
                        }

                        let method = "GET";
                        try { method = req.HTTPMethod().toString(); } catch (e) { }
                        let contentType: string | null = null;
                        try {
                            const ct = req.valueForHTTPHeaderField_("Content-Type");
                            if (ct && !ct.isNull()) contentType = ct.toString();
                        } catch (e) { }

                        // Extract headers for ESN detection
                        const reqHeaders: Record<string, string> = {};
                        try {
                            const allHeaders = req.allHTTPHeaderFields();
                            if (allHeaders && !allHeaders.isNull()) {
                                const keys = allHeaders.allKeys();
                                const count = keys.count();
                                for (let i = 0; i < count; i++) {
                                    const k = keys.objectAtIndex_(i).toString();
                                    const v = allHeaders.objectForKey_(keys.objectAtIndex_(i)).toString();
                                    reqHeaders[k] = v;
                                }
                            }
                        } catch (e) { }

                        maybeUpdateEsnFromHeader(reqHeaders);

                        if (reqBodyStr && (method === "POST" || method === "PUT" || method === "PATCH")) {
                            logData("http.request", {
                                domain: domain,
                                method: method,
                                url: url,
                                content_type: contentType,
                                size: reqBodySize,
                                body: reqBodyStr.substring(0, 8192),
                                headers: Object.keys(reqHeaders).length > 0 ? reqHeaders : undefined,
                                via: "dataTask"
                            });
                            logHttpReq(method, url, reqBodySize, Object.keys(reqHeaders).length);
                        }

                        const cb = new ObjC.Block(args[3]);
                        const origImpl = cb.implementation;
                        const capturedUrl = url;
                        const capturedDomain = domain;

                        cb.implementation = function (data: any, response: any, error: any) {
                            try {
                                let bodyStr: string | null = null;
                                if (data && !data.isNull()) {
                                    const nsData = ObjC.Object(data);
                                    try {
                                        const str = ObjC.classes.NSString.alloc().initWithData_encoding_(nsData, 4);
                                        if (str && !str.isNull()) bodyStr = str.toString();
                                    } catch (e) { }
                                }

                                let statusCode = 0;
                                const respHeaders: Record<string, string> = {};
                                if (response && !response.isNull()) {
                                    try { statusCode = ObjC.Object(response).statusCode(); } catch (e) { }
                                    try {
                                        const hdrs = ObjC.Object(response).allHeaderFields();
                                        if (hdrs && !hdrs.isNull()) {
                                            const keys = hdrs.allKeys();
                                            const count = keys.count();
                                            for (let i = 0; i < count; i++) {
                                                const k = keys.objectAtIndex_(i).toString();
                                                const v = hdrs.objectForKey_(keys.objectAtIndex_(i)).toString();
                                                respHeaders[k] = v;
                                            }
                                        }
                                    } catch (e) { }
                                }

                                maybeUpdateEsnFromHeader(respHeaders);

                                let errStr: string | null = null;
                                if (error && !error.isNull()) {
                                    try { errStr = ObjC.Object(error).toString(); } catch (e) { }
                                }

                                logData("http.response", {
                                    domain: capturedDomain,
                                    url: capturedUrl,
                                    status: statusCode,
                                    size: bodyStr ? bodyStr.length : 0,
                                    body: bodyStr ? bodyStr.substring(0, 65536) : null,
                                    responseHeaders: Object.keys(respHeaders).length > 0 ? respHeaders : undefined,
                                    error: errStr
                                });
                                logHttpResp(statusCode, capturedUrl, bodyStr ? bodyStr.length : 0, Object.keys(respHeaders).length);
                            } catch (e) { }
                            origImpl(data, response, error);
                        };
                    } catch (e) { }
                }
            });
        });
        console.log("[+] Hooked dataTaskWithRequest:completionHandler: (request+response)");
    } catch (e) { console.log("[-] dataTask: " + e); }

    // uploadTaskWithStreamedRequest:
    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[NSURLSession uploadTaskWithStreamedRequest:]").forEach(function (match) {
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const req = new ObjC.Object(args[2]);
                        let url = "";
                        try {
                            const reqUrl = req.URL();
                            if (reqUrl && !reqUrl.isNull()) url = reqUrl.absoluteString().toString();
                        } catch (e) { }
                        if (isLocal(url)) return;
                        if (url.indexOf("netflix") === -1) return;
                        const domain = domainOf(url);

                        let method = "POST";
                        try { method = req.HTTPMethod().toString(); } catch (e) { }
                        let contentType: string | null = null;
                        try {
                            const ct = req.valueForHTTPHeaderField_("Content-Type");
                            if (ct && !ct.isNull()) contentType = ct.toString();
                        } catch (e) { }

                        let reqBodyStr: string | null = null;
                        let reqBodySize = 0;
                        try {
                            const httpBody = req.HTTPBody();
                            if (httpBody && !httpBody.isNull()) {
                                reqBodySize = httpBody.length();
                                const str = ObjC.classes.NSString.alloc().initWithData_encoding_(httpBody, 4);
                                if (str && !str.isNull()) reqBodyStr = str.toString();
                            }
                        } catch (e) { }

                        logData("http.request", {
                            domain: domain,
                            method: method,
                            url: url,
                            content_type: contentType,
                            size: reqBodySize,
                            body: reqBodyStr ? reqBodyStr.substring(0, 8192) : null,
                            via: "streamedUpload"
                        });
                    } catch (e) { }
                }
            });
        });
        console.log("[+] Hooked uploadTaskWithStreamedRequest:");
    } catch (e) { console.log("[-] streamedUpload: " + e); }

    // NSURLSession delegate: didReceiveData + didCompleteWithError
    const mslResponseBuffers: Record<string, ObjC.Object> = {};
    const mslResponseUrls: Record<string, string> = {};

    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[* URLSession:dataTask:didReceiveData:]").forEach(function (match) {
            if (match.name.indexOf("NF") === -1 && match.name.indexOf("Netflix") === -1 && match.name.indexOf("Msl") === -1 && match.name.indexOf("Osprey") === -1) return;
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const task = new ObjC.Object(args[3]);
                        const data = new ObjC.Object(args[4]);
                        let url = "";
                        try {
                            const req = task.originalRequest();
                            if (req && !req.isNull()) {
                                const reqUrl = req.URL();
                                if (reqUrl && !reqUrl.isNull()) url = reqUrl.absoluteString().toString();
                            }
                        } catch (e) { }
                        if (!url || url.indexOf("netflix") === -1) return;

                        const taskId = task.taskIdentifier();
                        const key = url + "#" + taskId;

                        if (url.indexOf("/msl/") !== -1 || url.indexOf("/license") !== -1 || url.indexOf("/manifest") !== -1) {
                            if (!mslResponseBuffers[key]) {
                                mslResponseBuffers[key] = ObjC.classes.NSMutableData.alloc().init();
                                mslResponseUrls[key] = url;
                            }
                            mslResponseBuffers[key].appendData_(data);
                        }
                    } catch (e) { }
                }
            });
            console.log("[+] didReceiveData: " + match.name);
        });
    } catch (e) { console.log("[-] didReceiveData: " + e); }

    try {
        const resolver = new ApiResolver("objc");
        resolver.enumerateMatches("-[* URLSession:task:didCompleteWithError:]").forEach(function (match) {
            if (match.name.indexOf("NF") === -1 && match.name.indexOf("Netflix") === -1 && match.name.indexOf("Msl") === -1 && match.name.indexOf("Osprey") === -1) return;
            Interceptor.attach(match.address, {
                onEnter: function (args) {
                    try {
                        const task = new ObjC.Object(args[3]);
                        const error = args[4];
                        let url = "";
                        try {
                            const req = task.originalRequest();
                            if (req && !req.isNull()) {
                                const reqUrl = req.URL();
                                if (reqUrl && !reqUrl.isNull()) url = reqUrl.absoluteString().toString();
                            }
                        } catch (e) { }
                        if (!url) return;

                        const taskId = task.taskIdentifier();
                        const key = url + "#" + taskId;
                        const buf = mslResponseBuffers[key];
                        if (!buf) return;

                        let statusCode = 0;
                        const delegateRespHeaders: Record<string, string> = {};
                        try {
                            const resp = task.response();
                            if (resp && !resp.isNull()) {
                                statusCode = resp.statusCode();
                                try {
                                    const hdrs = resp.allHeaderFields();
                                    if (hdrs && !hdrs.isNull()) {
                                        const keys = hdrs.allKeys();
                                        const count = keys.count();
                                        for (let i = 0; i < count; i++) {
                                            const k = keys.objectAtIndex_(i).toString();
                                            const v = hdrs.objectForKey_(keys.objectAtIndex_(i)).toString();
                                            delegateRespHeaders[k] = v;
                                        }
                                    }
                                } catch (e) { }
                            }
                        } catch (e) { }

                        maybeUpdateEsnFromHeader(delegateRespHeaders);

                        let errStr: string | null = null;
                        if (error && !error.isNull()) {
                            try { errStr = ObjC.Object(error).toString(); } catch (e) { }
                        }

                        let bodyStr: string | null = null;
                        const bodySize = buf.length();
                        try {
                            const str = ObjC.classes.NSString.alloc().initWithData_encoding_(buf, 4);
                            if (str && !str.isNull()) bodyStr = str.toString();
                        } catch (e) { }

                        const domain = domainOf(url);

                        logData("http.response", {
                            domain: domain,
                            url: url,
                            status: statusCode,
                            size: bodyStr ? bodyStr.length : bodySize,
                            body: bodyStr ? bodyStr.substring(0, 65536) : null,
                            responseHeaders: Object.keys(delegateRespHeaders).length > 0 ? delegateRespHeaders : undefined,
                            error: errStr,
                            via: "delegate"
                        });
                        logHttpResp(statusCode, url, bodyStr ? bodyStr.length : bodySize, Object.keys(delegateRespHeaders).length);

                        delete mslResponseBuffers[key];
                        delete mslResponseUrls[key];
                    } catch (e) { }
                }
            });
            console.log("[+] didCompleteWithError: " + match.name);
        });
    } catch (e) { console.log("[-] didCompleteWithError: " + e); }
}
