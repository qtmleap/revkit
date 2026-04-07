import { logData, logMsl } from "../common/utils";
import { processMslApiResponse, maybeUpdateEsn } from "../common/msl-processor";

function objcToJsonStr(obj: ObjC.Object | NativePointer, maxLen?: number): string | null {
    if (!obj || (obj as NativePointer).isNull()) return null;
    if (maxLen === undefined || maxLen === null) maxLen = 65536;
    const respObj = ObjC.Object(obj);

    function truncate(s: string): string {
        if (maxLen! > 0 && s.length > maxLen!) return s.substring(0, maxLen!);
        return s;
    }

    try {
        if (respObj.isKindOfClass_(ObjC.classes.NSDictionary) ||
            respObj.isKindOfClass_(ObjC.classes.NSArray)) {
            const jsonData = ObjC.classes.NSJSONSerialization.dataWithJSONObject_options_error_(respObj, 1, NULL);
            if (jsonData) {
                const jsonStr = ObjC.classes.NSString.alloc().initWithData_encoding_(jsonData, 4);
                if (jsonStr && !jsonStr.isNull()) return truncate(jsonStr.toString());
            }
        }
    } catch (e) { }

    try {
        if (respObj.isKindOfClass_(ObjC.classes.NSData)) {
            const str = ObjC.classes.NSString.alloc().initWithData_encoding_(respObj, 4);
            if (str && !str.isNull()) return truncate(str.toString());
        }
    } catch (e) { }

    try {
        return truncate(respObj.toString());
    } catch (e) { }
    return null;
}

export function hookMSL(): void {
    if (typeof ObjC === 'undefined' || !ObjC.available) return;

    // IosMslClient sendAPIRequest (リクエストのみキャプチャ、コールバック書き換えなし)
    // レスポンスは http.ts (HTTP層) と msl-crypto.ts (復号後平文) で取得する
    try {
        const sendAPI = ObjC.classes.IosMslClient["- sendAPIRequest:extraHeaders:params:userAuthData:requestOptions:callback:"];
        if (sendAPI) {
            Interceptor.attach(sendAPI.implementation, {
                onEnter: function (args) {
                    try {
                        const apiPath = ObjC.Object(args[2]).toString();
                        const params = ObjC.Object(args[4]);

                        let paramsStr: string | null = null;
                        if (params && !params.isNull()) {
                            try {
                                const jsonData = ObjC.classes.NSJSONSerialization.dataWithJSONObject_options_error_(params, 1, NULL);
                                if (jsonData) {
                                    const jsonStr = ObjC.classes.NSString.alloc().initWithData_encoding_(jsonData, 4);
                                    paramsStr = jsonStr.toString();
                                }
                            } catch (e) {
                                paramsStr = params.toString();
                            }
                        }

                        const m = apiPath.match(/^https?:\/\/([^\/\?:]+)/);
                        const domain = m ? m[1] : "msl.netflix.com";

                        // ESN extraction from userAuthData
                        try {
                            const userAuthData = ObjC.Object(args[5]);
                            if (userAuthData && !userAuthData.isNull()) {
                                const authStr = objcToJsonStr(userAuthData, 4096);
                                if (authStr) {
                                    const parsed = JSON.parse(authStr);
                                    if (parsed && typeof parsed.sender === "string") maybeUpdateEsn(parsed.sender);
                                }
                            }
                        } catch (e) { }

                        logData("msl.api", {
                            domain: domain,
                            url: apiPath,
                            params: paramsStr
                        });
                        logMsl("IosMslClient.sendAPIRequest", apiPath + " (" + (paramsStr ? paramsStr.length : 0) + "B)");
                    } catch (e) {
                        console.log("[-] sendAPIRequest onEnter: " + e);
                    }
                }
            });
            console.log("[+] Hooked IosMslClient sendAPIRequest (request only)");
        }
    } catch (e) {
        console.log("[-] IosMslClient: " + e);
    }

    // _handleAppbootResponse
    try {
        const handleAppboot = ObjC.classes.IosMslClient["- _handleAppbootResponse:error:timeoutMS:"];
        if (handleAppboot) {
            Interceptor.attach(handleAppboot.implementation, {
                onEnter: function (args) {
                    try {
                        const respStr = objcToJsonStr(args[2]);
                        let errStr: string | null = null;
                        if (args[3] && !args[3].isNull()) {
                            try { errStr = ObjC.Object(args[3]).toString(); } catch (e) { }
                        }

                        logData("appboot.response", {
                            domain: "appboot.netflix.com",
                            response: respStr,
                            error: errStr
                        });
                        logMsl("appboot.response", "(" + (respStr ? respStr.length : 0) + "B)" + (errStr ? " error=" + errStr : ""));
                    } catch (e) {
                        console.log("[-] appboot response capture: " + e);
                    }
                }
            });
            console.log("[+] Hooked _handleAppbootResponse");
        }
    } catch (e) {
        console.log("[-] _handleAppbootResponse: " + e);
    }

    // IosMdxCryptoContext
    try {
        const cls = ObjC.classes.IosMdxCryptoContext;
        if (cls) {
            const enc = cls["- encrypt:"];
            if (enc) {
                Interceptor.attach(enc.implementation, {
                    onEnter: function (args) {
                        try {
                            const data = ObjC.Object(args[2]);
                            const dataStr = data.toString().substring(0, 8192);
                            logData("msl.encrypt.input", {
                                domain: "msl.netflix.com",
                                data: dataStr
                            });
                            // Try to extract ESN from encrypt input
                            try {
                                const parsed = JSON.parse(dataStr);
                                if (parsed && typeof parsed.sender === "string") maybeUpdateEsn(parsed.sender);
                            } catch (e) { }
                        } catch (e) { }
                    }
                });
                console.log("[+] Hooked MdxCrypto encrypt");
            }

            const dec = cls["- decrypt:"];
            if (dec) {
                Interceptor.attach(dec.implementation, {
                    onLeave: function (retval) {
                        try {
                            const data = ObjC.Object(retval);
                            const dataStr = data.toString().substring(0, 8192);
                            logData("msl.decrypt.output", {
                                domain: "msl.netflix.com",
                                data: dataStr
                            });
                            // Process decrypted output for manifest/ALE/ESN
                            try { processMslApiResponse("msl.decrypt", dataStr); } catch (e) { }
                        } catch (e) { }
                    }
                });
                console.log("[+] Hooked MdxCrypto decrypt");
            }
        }
    } catch (e) { }
}
