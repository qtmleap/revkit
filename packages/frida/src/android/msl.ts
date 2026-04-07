import { logData, logMsl } from "../common/utils";
import { jbyteArrayToString, jbyteArrayToBase64 } from "./utils";
import { setMslContext } from "./msl-state";

export function hookMSL(): void {
    // -------------------------------------------------------
    // ApiHandlerImpl.apiRequest -- MSL APIリクエストのエントリポイント
    // Signature: apiRequest(String url, byte[] body, Map headers,
    //   String userId, UserAuthenticationData auth, boolean, Object, List, boolean)
    // -------------------------------------------------------
    try {
        const ApiHandler = Java.use("com.netflix.msl.client.impl.handler.ApiHandlerImpl");
        // apiRequest は9引数メソッド
        const methods = ApiHandler.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            const paramCount = m.getParameterTypes().length;
            console.log("[*] ApiHandlerImpl." + name + "(" + paramCount + ")");

            // apiRequest (9 params) をフック
            if (name === "apiRequest" && paramCount >= 5) {
                try {
                    ApiHandler[name].implementation = function () {
                        const url = arguments[0] ? arguments[0].toString() : "?";
                        const domainMatch = url.match(/^https?:\/\/([^\/\?:]+)/);
                        const domain = domainMatch ? domainMatch[1] : "msl.netflix.com";
                        setMslContext(url, domain);

                        // logblob / cl ログはノイズなのでスキップ
                        if (url.indexOf("/logblob/") !== -1 || url.indexOf("/log/android/cl/") !== -1) {
                            return this[name].apply(this, arguments);
                        }
                        const bodyBytes = arguments[1];
                        const bodyStr = bodyBytes ? jbyteArrayToString(bodyBytes) : null;
                        const bodySize = bodyBytes ? bodyBytes.length : 0;

                        // 3番目の引数: リクエストヘッダー Map<String, String>
                        const reqHeaders: Record<string, string> = {};
                        try {
                            const headerMap = arguments[2];
                            if (headerMap) {
                                const entrySet = headerMap.entrySet();
                                const iter = entrySet.iterator();
                                while (iter.hasNext()) {
                                    const entry = iter.next();
                                    reqHeaders[entry.getKey().toString()] = entry.getValue().toString();
                                }
                            }
                        } catch (he) { }

                        // 5番目の引数: UserAuthenticationData auth
                        let userAuthData: any = null;
                        try {
                            const authObj = arguments[4];
                            if (authObj) {
                                userAuthData = {};
                                // getScheme() -> UserAuthenticationScheme
                                try {
                                    const scheme = authObj.getScheme();
                                    userAuthData.scheme = scheme ? scheme.toString() : null;
                                } catch (_) {
                                    // ProGuard: try common obfuscated names
                                    try { userAuthData.scheme = authObj.a().toString(); } catch (_) {}
                                }
                                // toMslObject() / getAuthData() でJSON表現を取得
                                try {
                                    let mslObj: any = null;
                                    // 標準メソッド名を試す
                                    try { mslObj = authObj.toMslObject(null, null); } catch (_) {}
                                    if (!mslObj) {
                                        try { mslObj = authObj.getAuthData(null, null); } catch (_) {}
                                    }
                                    if (mslObj) {
                                        userAuthData.mslObject = mslObj.toString();
                                    }
                                } catch (_) {}
                                // toString() でフォールバック
                                try {
                                    userAuthData.toString = authObj.toString();
                                } catch (_) {}
                                // クラス名を記録（ProGuard後の実クラスを確認するため）
                                userAuthData.className = authObj.getClass().getName();
                                // 全フィールドを動的に読み取る
                                try {
                                    const fields = authObj.getClass().getDeclaredFields();
                                    const fieldData: Record<string, any> = {};
                                    for (let fi = 0; fi < fields.length; fi++) {
                                        try {
                                            fields[fi].setAccessible(true);
                                            const fName = fields[fi].getName();
                                            const fVal = fields[fi].get(authObj);
                                            fieldData[fName] = fVal ? fVal.toString() : null;
                                        } catch (_) {}
                                    }
                                    userAuthData.fields = fieldData;
                                } catch (_) {}
                                // スーパークラスのフィールドも読み取る
                                try {
                                    const superFields = authObj.getClass().getSuperclass().getDeclaredFields();
                                    const superFieldData: Record<string, any> = {};
                                    for (let si = 0; si < superFields.length; si++) {
                                        try {
                                            superFields[si].setAccessible(true);
                                            const sfName = superFields[si].getName();
                                            const sfVal = superFields[si].get(authObj);
                                            superFieldData[sfName] = sfVal ? sfVal.toString() : null;
                                        } catch (_) {}
                                    }
                                    userAuthData.superFields = superFieldData;
                                } catch (_) {}
                                logMsl("UserAuthData", JSON.stringify(userAuthData));
                            } else {
                                logMsl("UserAuthData", "null (no auth)");
                            }
                        } catch (authErr) {
                            logMsl("UserAuthData", "extraction error: " + authErr);
                            userAuthData = { error: authErr.toString() };
                        }

                        // 4番目の引数: userId
                        let userId: string | null = null;
                        try {
                            userId = arguments[3] ? arguments[3].toString() : null;
                        } catch (_) {}

                        logMsl("ApiHandlerImpl.apiRequest", url + " (" + bodySize + "B, " + Object.keys(reqHeaders).length + " headers, userId=" + userId + ")");
                        if (bodyStr) {
                            const preview = bodyStr.length > 300 ? bodyStr.substring(0, 300) + "..." : bodyStr;
                            console.log("  body: " + preview);
                        }
                        logData("msl.api", {
                            domain: domain,
                            url: url,
                            headers: reqHeaders,
                            body_size: bodySize,
                            userId: userId,
                            userauthdata: userAuthData,
                            params: bodyStr ? bodyStr.substring(0, 65536) : null
                        });
                        return this[name].apply(this, arguments);
                    };
                    console.log("[+] Hooked ApiHandlerImpl." + name);
                } catch (e2) {
                    console.log("[-] ApiHandlerImpl." + name + " hook: " + e2);
                }
            }
        });
    } catch (e) {
        console.log("[-] ApiHandlerImpl: " + e);
    }

    // -------------------------------------------------------
    // BaseHandler.processRequest -- MSLレスポンス処理
    // Reads full response body from MessageInputStream
    // -------------------------------------------------------
    try {
        const BaseHandler = Java.use("com.netflix.msl.client.impl.handler.BaseHandler");
        const methods = BaseHandler.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            const paramCount = m.getParameterTypes().length;
            const retType = m.getReturnType().getName();
            console.log("[*] BaseHandler." + name + "(" + paramCount + ") -> " + retType);

            // processRequest returns the parsed response (byte[] or String)
            if (name === "processRequest" && paramCount === 1) {
                try {
                    BaseHandler[name].implementation = function (request: any) {
                        const result = this[name](request);
                        try {
                            if (result) {
                                const cls = result.getClass();
                                const allFields = cls.getDeclaredFields();

                                // デバッグ: フィールド構造をダンプ
                                const fieldInfo: string[] = [];
                                for (let di = 0; di < allFields.length; di++) {
                                    try {
                                        allFields[di].setAccessible(true);
                                        const fn = allFields[di].getName();
                                        const ft = allFields[di].getType().getName();
                                        const fv = allFields[di].get(result);
                                        fieldInfo.push(fn + ":" + ft + "=" + (fv ? "(" + (typeof fv) + ")" : "null"));
                                    } catch (_) {
                                        fieldInfo.push(allFields[di].getName() + ":?");
                                    }
                                }
                                // スーパークラスも
                                try {
                                    const superFields = cls.getSuperclass().getDeclaredFields();
                                    for (let si = 0; si < superFields.length; si++) {
                                        try {
                                            superFields[si].setAccessible(true);
                                            const fn = superFields[si].getName();
                                            const ft = superFields[si].getType().getName();
                                            const fv = superFields[si].get(result);
                                            fieldInfo.push("super." + fn + ":" + ft + "=" + (fv ? "(" + (typeof fv) + ")" : "null"));
                                        } catch (_) { }
                                    }
                                } catch (_) { }
                                console.log("[DBG] processRequest result class=" + cls.getName() + " fields=[" + fieldInfo.join(", ") + "]");

                                // 動的フィールド探索: byte[] → body, Map → headers
                                let responseStr: string | null = null;
                                let domain = "msl.netflix.com";
                                let originUrl: string | null = null;
                                const headers: Record<string, string> = {};

                                for (let fi = 0; fi < allFields.length; fi++) {
                                    try {
                                        allFields[fi].setAccessible(true);
                                        const fieldType = allFields[fi].getType().getName();
                                        const fieldVal = allFields[fi].get(result);
                                        if (!fieldVal) continue;

                                        // byte[] → response body
                                        if (fieldType === "[B" && !responseStr) {
                                            const arrLen = fieldVal.length;
                                            console.log("[DBG] byte[] field '" + allFields[fi].getName() + "' length=" + arrLen);
                                            if (arrLen > 0) {
                                                const str = jbyteArrayToString(fieldVal);
                                                console.log("[DBG] jbyteArrayToString result: " + (str ? str.length + " chars, first50=" + str.substring(0, 50) : "null"));
                                                if (str && str.length > 0) {
                                                    responseStr = str;
                                                }
                                            }
                                        }

                                        // Map → headers
                                        if (fieldType === "java.util.Map" || fieldType.indexOf("Map") !== -1) {
                                            try {
                                                const entrySet = fieldVal.entrySet();
                                                const iter = entrySet.iterator();
                                                while (iter.hasNext()) {
                                                    const entry = iter.next();
                                                    const key = entry.getKey().toString();
                                                    let val = entry.getValue().toString();
                                                    if (val.startsWith("[") && val.endsWith("]")) {
                                                        val = val.substring(1, val.length - 1);
                                                    }
                                                    headers[key] = val;
                                                }
                                                if (headers["x-originating-url"]) {
                                                    originUrl = headers["x-originating-url"];
                                                    const domainMatch = originUrl.match(/^https?:\/\/([^\/\?:]+)/);
                                                    if (domainMatch) domain = domainMatch[1];
                                                }
                                            } catch (_me) { }
                                        }
                                    } catch (_fe) { }
                                }

                                // スーパークラスのフィールドも探索
                                if (!responseStr) {
                                    try {
                                        const superFields = cls.getSuperclass().getDeclaredFields();
                                        for (let si = 0; si < superFields.length; si++) {
                                            try {
                                                superFields[si].setAccessible(true);
                                                const fieldType = superFields[si].getType().getName();
                                                const fieldVal = superFields[si].get(result);
                                                if (!fieldVal) continue;
                                                if (fieldType === "[B") {
                                                    const str = jbyteArrayToString(fieldVal);
                                                    if (str && str.length > 0) {
                                                        responseStr = str;
                                                        break;
                                                    }
                                                }
                                            } catch (_sfe) { }
                                        }
                                    } catch (_se) { }
                                }

                                const bodySize = responseStr ? responseStr.length : 0;
                                const preview = responseStr ? (bodySize > 300 ? responseStr.substring(0, 300) + "..." : responseStr) : "(no body)";
                                logMsl("processRequest.response", "(" + bodySize + "B) " + (originUrl || "") + ": " + preview);

                                logData("msl.api.response", {
                                    domain: domain,
                                    url: originUrl,
                                    headers: headers,
                                    response: responseStr ? responseStr.substring(0, 262144) : null,
                                    size: bodySize
                                });
                            }
                        } catch (e2) {
                            console.log("[-] processRequest capture: " + e2);
                        }
                        return result;
                    };
                    console.log("[+] Hooked BaseHandler.processRequest");
                } catch (e2) {
                    console.log("[-] BaseHandler.processRequest hook: " + e2);
                }
            }
        });
    } catch (e) {
        console.log("[-] BaseHandler: " + e);
    }

    // -------------------------------------------------------
    // PayloadChunk -- MSLペイロードの復号後データ
    // 全コンストラクタをフック + getData メソッドもフック
    // -------------------------------------------------------
    try {
        const PayloadChunk = Java.use("com.netflix.msl.msg.PayloadChunk");
        const ctors = PayloadChunk.class.getDeclaredConstructors();
        console.log("[*] PayloadChunk constructors: " + ctors.length);
        ctors.forEach(function (c: any) {
            const params = c.getParameterTypes();
            const sig = [];
            for (let pi = 0; pi < params.length; pi++) sig.push(params[pi].getName());
            console.log("[*]   PayloadChunk(" + params.length + "): " + sig.join(", "));
        });

        // 全コンストラクタの $init をフック
        PayloadChunk.$init.overloads.forEach(function (overload: any) {
            const paramCount = overload.argumentTypes.length;
            overload.implementation = function () {
                // 7-arg: 6番目の引数が byte[] (ペイロードデータ)
                if (paramCount === 7 && arguments[5]) {
                    try {
                        const payloadBytes = arguments[5];
                        if (payloadBytes && payloadBytes.length > 0) {
                            const str = jbyteArrayToString(payloadBytes);
                            if (str && str.length > 0) {
                                const preview = str.length > 300 ? str.substring(0, 300) + "..." : str;
                                logMsl("PayloadChunk.init(7)", "(" + payloadBytes.length + "B): " + preview);
                                logData("msl.payload", {
                                    domain: "msl.netflix.com",
                                    size: payloadBytes.length,
                                    body: str.substring(0, 65536)
                                });
                            }
                        }
                    } catch (pe) {
                        console.log("[-] PayloadChunk 7-arg payload: " + pe);
                    }
                }

                overload.apply(this, arguments);

                // 3-arg (parse ctor): コンストラクタ後にフィールドから読み取り
                if (paramCount === 3) {
                    try {
                        const fields = PayloadChunk.class.getDeclaredFields();
                        for (let fj = 0; fj < fields.length; fj++) {
                            try {
                                if (fields[fj].getType().getName() !== "[B") continue;
                                fields[fj].setAccessible(true);
                                const val = fields[fj].get(this);
                                if (val && val.length > 0) {
                                    const str = jbyteArrayToString(val);
                                    if (str && str.length > 0) {
                                        const preview = str.length > 300 ? str.substring(0, 300) + "..." : str;
                                        logMsl("PayloadChunk.init(3)", "(" + val.length + "B, field=" + fields[fj].getName() + "): " + preview);
                                        logData("msl.payload", {
                                            domain: "msl.netflix.com",
                                            size: val.length,
                                            body: str.substring(0, 65536)
                                        });
                                        break;
                                    }
                                }
                            } catch (_) { }
                        }
                    } catch (_) { }
                }
            };
        });
        console.log("[+] Hooked PayloadChunk all " + PayloadChunk.$init.overloads.length + " constructors");

        // getData もフック (読み取り時のフォールバック)
        try {
            const getDataMethods = PayloadChunk.class.getDeclaredMethods();
            let getDataHooked = false;
            getDataMethods.forEach(function (m: any) {
                if (m.getReturnType().getName() === "[B" && m.getParameterTypes().length === 0 && !getDataHooked) {
                    const methodName = m.getName();
                    try {
                        PayloadChunk[methodName].implementation = function () {
                            const data = this[methodName]();
                            if (data && data.length > 0) {
                                const str = jbyteArrayToString(data);
                                if (str && str.length > 0) {
                                    const preview = str.length > 300 ? str.substring(0, 300) + "..." : str;
                                    logMsl("PayloadChunk." + methodName, "(" + data.length + "B): " + preview);
                                    logData("msl.payload", { domain: "msl.netflix.com", size: data.length, body: str.substring(0, 65536) });
                                }
                            }
                            return data;
                        };
                        console.log("[+] Hooked PayloadChunk." + methodName + " (getData)");
                        getDataHooked = true;
                    } catch (_) { }
                }
            });
        } catch (_) { }
    } catch (e) {
        console.log("[-] PayloadChunk: " + e);
    }

    // -------------------------------------------------------
    // MessageInputStream.read -- MSLレスポンスの読み取り (復号後)
    // チャンクを蓄積して、read=-1で完全なペイロードをログ
    // -------------------------------------------------------
    try {
        const MessageInputStream = Java.use("com.netflix.msl.msg.MessageInputStream");
        const streamBuffers: Record<number, string> = {};
        let streamSeq = 0;

        MessageInputStream.read.overload("[B", "int", "int").implementation = function (buf: any, off: any, len: any) {
            // Assign a unique ID to this stream instance
            if (!this.__msl_stream_id__) {
                this.__msl_stream_id__ = ++streamSeq;
            }
            const sid = this.__msl_stream_id__;

            const bytesRead = this.read(buf, off, len);
            if (bytesRead > 0) {
                try {
                    const JavaString = Java.use("java.lang.String");
                    const str = JavaString.$new(buf, off, bytesRead, "UTF-8");
                    const s = str.toString();
                    if (!streamBuffers[sid]) {
                        streamBuffers[sid] = "";
                    }
                    streamBuffers[sid] += s;
                } catch (e2) { }
            } else if (bytesRead === -1) {
                // Stream finished -- emit accumulated payload
                const accumulated = streamBuffers[sid];
                if (accumulated && accumulated.length > 0 && accumulated.indexOf("{") !== -1) {
                    const preview = accumulated.length > 300 ? accumulated.substring(0, 300) + "..." : accumulated;
                    logMsl("MessageInputStream.complete", "(" + accumulated.length + "B): " + preview);
                    logData("msl.response.payload", {
                        domain: "msl.netflix.com",
                        size: accumulated.length,
                        body: accumulated.substring(0, 262144)
                    });
                }
                delete streamBuffers[sid];
            }
            return bytesRead;
        };
        // Also hook close() to flush any remaining buffered data
        try {
            MessageInputStream.close.implementation = function () {
                const sid = this.__msl_stream_id__;
                if (sid && streamBuffers[sid]) {
                    const accumulated = streamBuffers[sid];
                    if (accumulated.length > 0 && accumulated.indexOf("{") !== -1) {
                        const preview = accumulated.length > 300 ? accumulated.substring(0, 300) + "..." : accumulated;
                        logMsl("MessageInputStream.close", "(" + accumulated.length + "B): " + preview);
                        logData("msl.response.payload", {
                            domain: "msl.netflix.com",
                            size: accumulated.length,
                            body: accumulated.substring(0, 262144)
                        });
                    }
                    delete streamBuffers[sid];
                }
                return this.close();
            };
        } catch (e2) {
            console.log("[-] MessageInputStream.close hook: " + e2);
        }

        console.log("[+] Hooked MessageInputStream.read (chunked accumulator)");
    } catch (e) {
        console.log("[-] MessageInputStream: " + e);
    }

    // -------------------------------------------------------
    // MslControl.e -- MSLリクエスト送信 (request submit)
    // -------------------------------------------------------
    try {
        const MslControl = Java.use("com.netflix.msl.msg.MslControl");
        const methods = MslControl.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            const paramCount = m.getParameterTypes().length;
            if (name === "e" && paramCount === 3) {
                console.log("[*] MslControl.e(3) -- primary request method");
            }
        });
    } catch (e) {
        console.log("[-] MslControl: " + e);
    }

    // -------------------------------------------------------
    // AppbootHandlerImpl -- appboot ハンドラ
    // -------------------------------------------------------
    try {
        const AppbootHandler = Java.use("com.netflix.msl.client.impl.handler.AppbootHandlerImpl");
        const methods = AppbootHandler.class.getDeclaredMethods();
        methods.forEach(function (m: any) {
            const name = m.getName();
            const paramCount = m.getParameterTypes().length;
            const retType = m.getReturnType().getName();
            console.log("[*] AppbootHandler." + name + "(" + paramCount + ") -> " + retType);

            // Hook appbootExecute or doAppbootRequest to capture appboot response
            if (name === "appbootExecute" && paramCount === 2) {
                try {
                    AppbootHandler[name].implementation = function (arg0: any, arg1: any) {
                        const result = this[name](arg0, arg1);
                        try {
                            if (result) {
                                const s = result.toString();
                                const preview = s.length > 300 ? s.substring(0, 300) + "..." : s;
                                logMsl("AppbootHandler.appbootExecute", "response (" + s.length + "B): " + preview);
                                logData("appboot.response", {
                                    domain: "appboot.netflix.com",
                                    response: s.substring(0, 65536),
                                    size: s.length
                                });
                            }
                        } catch (e2) {
                            console.log("[-] appbootExecute capture: " + e2);
                        }
                        return result;
                    };
                    console.log("[+] Hooked AppbootHandler.appbootExecute");
                } catch (e2) {
                    console.log("[-] AppbootHandler.appbootExecute hook: " + e2);
                }
            }
        });
    } catch (e) {
        console.log("[-] AppbootHandler: " + e);
    }

    // -------------------------------------------------------
    // UserAuthenticationData サブクラスの生成を追跡
    // 各認証スキームのコンストラクタをフックし、生成時のデータを記録
    // -------------------------------------------------------
    const authClasses = [
        { name: "EmailPasswordAuthenticationData", pkg: "com.netflix.msl.userauth.EmailPasswordAuthenticationData" },
        { name: "NetflixIdAuthenticationData", pkg: "com.netflix.msl.userauth.NetflixIdAuthenticationData" },
        { name: "UserIdTokenAuthenticationData", pkg: "com.netflix.msl.userauth.UserIdTokenAuthenticationData" },
        { name: "SsoTokenAuthenticationData", pkg: "com.netflix.msl.userauth.SsoTokenAuthenticationData" },
        { name: "SwitchProfileAuthenticationData", pkg: "com.netflix.msl.userauth.SwitchProfileAuthenticationData" },
    ];
    authClasses.forEach(function (cls) {
        try {
            const AuthClass = Java.use(cls.pkg);
            // コンストラクタをフック
            const ctors = AuthClass.class.getDeclaredConstructors();
            console.log("[*] " + cls.name + ": " + ctors.length + " constructor(s)");
            AuthClass.$init.overloads.forEach(function (overload: any) {
                overload.implementation = function () {
                    const args: any[] = [];
                    for (let ai = 0; ai < arguments.length; ai++) {
                        try {
                            args.push(arguments[ai] ? arguments[ai].toString() : null);
                        } catch (_) {
                            args.push("<unreadable>");
                        }
                    }
                    logMsl("AUTH." + cls.name, "created with " + arguments.length + " args: " + JSON.stringify(args));
                    const result = this.$init.apply(this, arguments);
                    // 生成後のフィールドを読み取り
                    const fieldData: Record<string, any> = {};
                    try {
                        const fields = this.getClass().getDeclaredFields();
                        for (let fi = 0; fi < fields.length; fi++) {
                            try {
                                fields[fi].setAccessible(true);
                                const fName = fields[fi].getName();
                                const fVal = fields[fi].get(this);
                                fieldData[fName] = fVal ? fVal.toString() : null;
                            } catch (_) {}
                        }
                    } catch (_) {}
                    // スーパークラスのフィールドも
                    try {
                        const superFields = this.getClass().getSuperclass().getDeclaredFields();
                        for (let si = 0; si < superFields.length; si++) {
                            try {
                                superFields[si].setAccessible(true);
                                const sfName = superFields[si].getName();
                                const sfVal = superFields[si].get(this);
                                fieldData["super." + sfName] = sfVal ? sfVal.toString() : null;
                            } catch (_) {}
                        }
                    } catch (_) {}
                    logMsl("AUTH." + cls.name, "fields: " + JSON.stringify(fieldData));
                    logData("msl.userauthdata", {
                        type: cls.name,
                        scheme: cls.name.replace("AuthenticationData", ""),
                        constructorArgs: args,
                        fields: fieldData
                    });
                    return result;
                };
            });
            console.log("[+] Hooked " + cls.name + " constructors");
        } catch (e: any) {
            console.log("[-] " + cls.name + ": " + e.message);
            // ProGuardで難読化されている可能性 -> クラス名を探索
            if (e.message && e.message.indexOf("ClassNotFoundException") !== -1) {
                console.log("[*] " + cls.name + " not found (ProGuard?), trying base class scan...");
            }
        }
    });

    // UserAuthenticationData 基底クラスのフック（サブクラスが見つからない場合の保険）
    try {
        const BaseUserAuth = Java.use("com.netflix.msl.userauth.UserAuthenticationData");
        console.log("[*] UserAuthenticationData base class found");
        // 全メソッドをリスト
        const baseMethods = BaseUserAuth.class.getDeclaredMethods();
        baseMethods.forEach(function (m: any) {
            console.log("[*] UserAuthenticationData." + m.getName() + "(" + m.getParameterTypes().length + ")");
        });
        // getScheme メソッドをフック（呼ばれるたびにスキーム名を記録）
        try {
            BaseUserAuth.getScheme.implementation = function () {
                const scheme = this.getScheme.call(this);
                logMsl("AUTH.getScheme", "-> " + scheme + " (class: " + this.getClass().getName() + ")");
                return scheme;
            };
            console.log("[+] Hooked UserAuthenticationData.getScheme");
        } catch (_) {
            // ProGuard: scheme取得メソッドが難読化されている場合
            console.log("[-] UserAuthenticationData.getScheme not found (ProGuard?)");
        }
    } catch (e: any) {
        console.log("[-] UserAuthenticationData base: " + e.message);
    }

    // IosMslClient.makeUserAuthData に相当するAndroid版を探索
    // Android版では MslClient / MslControlImpl 等が該当する可能性
    try {
        const MslClient = Java.use("com.netflix.msl.client.impl.MslClientImpl");
        const clientMethods = MslClient.class.getDeclaredMethods();
        clientMethods.forEach(function (m: any) {
            const mName = m.getName();
            // userAuth関連メソッドを探す
            if (mName.toLowerCase().indexOf("auth") !== -1 || mName.toLowerCase().indexOf("user") !== -1) {
                console.log("[*] MslClientImpl." + mName + "(" + m.getParameterTypes().length + " params) -> " + m.getReturnType().getName());
            }
        });
    } catch (e: any) {
        console.log("[-] MslClientImpl: " + e.message);
    }
}
