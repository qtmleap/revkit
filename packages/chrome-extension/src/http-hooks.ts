// ── HTTP フック (fetch / XHR / sendBeacon) ──

import { captured } from "./state";
import { logCapture } from "./msl-processor";
import { maybeUpdateEsnFromHeader } from "./esn";

const HTTP_PREFIX = "[HTTP-Capture]";
const MSL_URL_PATTERN = /netflix\.com\/nq\/msl_v1\//;

function isMSLEndpoint(url: string): boolean {
  try {
    return MSL_URL_PATTERN.test(url);
  } catch {
    return false;
  }
}

function headersToObject(
  headers: Headers | Array<[string, string]> | Record<string, string> | null | undefined,
): Record<string, string> {
  const obj: Record<string, string> = {};
  if (!headers) return obj;
  try {
    if (headers instanceof Headers) {
      headers.forEach((v, k) => { obj[k] = v; });
    } else if (Array.isArray(headers)) {
      for (const [k, v] of headers) obj[k] = v;
    } else {
      for (const k of Object.keys(headers)) obj[k] = headers[k];
    }
  } catch { /* ignore */ }
  return obj;
}

function extractEsn(headers: Record<string, string>): void {
  const esn = headers["x-netflix.esn"] ?? headers["X-Netflix.esn"];
  if (esn) maybeUpdateEsnFromHeader(esn);
}

interface XhrCaptureInfo {
  method: string;
  url: string;
  requestHeaders: Record<string, string>;
}

const XHR_CAPTURE_KEY = "__mslCaptureInfo__" as const;

interface InstrumentedXHR extends XMLHttpRequest {
  [XHR_CAPTURE_KEY]?: XhrCaptureInfo;
}

export function installHttpHooks(): void {
  // ── Hook: fetch ──
  const _fetch = window.fetch.bind(window);

  // @ts-expect-error fetch.preconnect は monkey-patch 対象外
  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = input instanceof Request ? input.url : String(input);
    if (!isMSLEndpoint(url)) return _fetch(input, init);

    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    let reqHeaders: Record<string, string> = {};
    if (input instanceof Request) reqHeaders = headersToObject(input.headers);
    if (init?.headers) {
      const h = init.headers instanceof Headers ? init.headers : new Headers(init.headers as HeadersInit);
      Object.assign(reqHeaders, headersToObject(h));
    }
    if (!reqHeaders["cookie"] && !reqHeaders["Cookie"] && document.cookie) {
      reqHeaders["Cookie"] = document.cookie;
    }
    extractEsn(reqHeaders);

    console.groupCollapsed(`${HTTP_PREFIX} >>> fetch ${method} ${url}`);
    console.log("Request headers:", reqHeaders);
    console.groupEnd();

    try {
      const response = await _fetch(input, init);
      const respHeaders = headersToObject(response.headers);
      extractEsn(respHeaders);
      const entry = logCapture("http.fetch", {
        url,
        method,
        requestHeaders: reqHeaders,
        statusCode: response.status,
        statusText: response.statusText,
        responseHeaders: respHeaders,
      });
      captured.httpCaptures.push(entry);
      return response;
    } catch (err) {
      logCapture("http.fetch.error", {
        url,
        method,
        requestHeaders: reqHeaders,
        error: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  };

  // ── Hook: XMLHttpRequest ──
  const _XHROpen = XMLHttpRequest.prototype.open;
  const _XHRSetReqHdr = XMLHttpRequest.prototype.setRequestHeader;
  const _XHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (this: InstrumentedXHR, method: string, url: string | URL): void {
    this[XHR_CAPTURE_KEY] = { method, url: String(url), requestHeaders: {} };
    return _XHROpen.apply(this, arguments as unknown as Parameters<typeof _XHROpen>);
  } as typeof XMLHttpRequest.prototype.open;

  XMLHttpRequest.prototype.setRequestHeader = function (this: InstrumentedXHR, name: string, value: string): void {
    const info = this[XHR_CAPTURE_KEY];
    if (info) info.requestHeaders[name] = value;
    return _XHRSetReqHdr.apply(this, arguments as unknown as Parameters<typeof _XHRSetReqHdr>);
  };

  XMLHttpRequest.prototype.send = function (this: InstrumentedXHR, body?: Document | XMLHttpRequestBodyInit | null): void {
    const info = this[XHR_CAPTURE_KEY];
    if (info && isMSLEndpoint(info.url)) {
      if (!info.requestHeaders["Cookie"] && !info.requestHeaders["cookie"] && document.cookie) {
        info.requestHeaders["Cookie"] = document.cookie;
      }
      extractEsn(info.requestHeaders);

      console.groupCollapsed(`${HTTP_PREFIX} >>> XHR ${info.method} ${info.url}`);
      console.log("Request headers:", info.requestHeaders);
      console.groupEnd();

      const self = this;
      const capturedInfo = info;
      self.addEventListener("load", function () {
        const rawHeaders = self.getAllResponseHeaders();
        const respHeaders: Record<string, string> = {};
        if (rawHeaders) {
          for (const line of rawHeaders.trim().split(/[\r\n]+/)) {
            const parts = line.split(": ");
            const key = parts.shift()!;
            respHeaders[key] = parts.join(": ");
          }
        }
        extractEsn(respHeaders);
        const entry = logCapture("http.xhr", {
          url: capturedInfo.url,
          method: capturedInfo.method,
          requestHeaders: capturedInfo.requestHeaders,
          statusCode: self.status,
          statusText: self.statusText,
          responseHeaders: respHeaders,
        });
        captured.httpCaptures.push(entry);
      });
      self.addEventListener("error", function () {
        logCapture("http.xhr.error", {
          url: capturedInfo.url,
          method: capturedInfo.method,
          requestHeaders: capturedInfo.requestHeaders,
          error: "Network error",
        });
      });
    }
    return _XHRSend.apply(this, arguments as unknown as Parameters<typeof _XHRSend>);
  };

  // ── Hook: sendBeacon ──
  const _sendBeacon = navigator.sendBeacon.bind(navigator);

  navigator.sendBeacon = function (url: string, data?: BodyInit | null): boolean {
    if (isMSLEndpoint(url)) {
      let dataSize = 0;
      if (data) {
        if (typeof data === "string") dataSize = data.length;
        else if (data instanceof Blob) dataSize = data.size;
        else if (data instanceof ArrayBuffer) dataSize = data.byteLength;
        else if (data instanceof FormData) dataSize = 0;
        else if ("byteLength" in data) dataSize = (data as Uint8Array).byteLength;
      }
      const entry = logCapture("http.sendBeacon", {
        url: String(url),
        method: "POST",
        dataSize,
      });
      captured.httpCaptures.push(entry);
    }
    return _sendBeacon(url, data);
  };

  console.log(`${HTTP_PREFIX} fetch / XHR / sendBeacon hooks installed`);
}
