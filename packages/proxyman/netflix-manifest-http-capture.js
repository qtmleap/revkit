/**
 * Netflix HTTP Manifest Capture — Proxyman Script
 *
 * URL Matching Rule:  *netflix.com/*manifest*
 *
 * StreamFab 等が使う非 MSL マニフェスト API をキャプチャする。
 * MSL 経由のマニフェスト (/nq/msl_v1/) は netflix-msl-capture.js が担当するため、
 * このスクリプトでは /nq/msl_v1/ を含む URL をスキップする。
 *
 * マッチする URL:
 *   - /playapi/cadmium/manifest/1
 *   - /msl/playapi/cadmium/licensedmanifest/1
 *
 * 保存先: ~/Desktop/netflix-msl-capture/ (MSL スクリプトと共通)
 *
 * 【Proxyman 設定】
 *   1. Script Menu > Script List (Opt+Cmd+I)
 *   2. 新規スクリプト作成
 *   3. URL Matching Rule: *netflix.com/*manifest*
 *   4. このスクリプトの内容を貼り付け
 *   5. Enable on Request ✓ (オン) / Enable on Response ✓ (オン)
 */

// ── アドオン読み込み ──
const {
  deepDecodeMSL,
  extractDecodedPayload,
  extractManifestData,
  extractEsnFromHeaders,
  parseMSLBody,
  buildKIDTable,
  safeStringify,
  timestamp,
  formatSize,
  tryParseJSON,
  b64Decode,
  setDecryptionKeys,
  getDecryptionKeys,
  decryptAesCbc,
} = require("@users/NetflixMSLParser.js");

// ── 設定 ──
const OUTPUT_DIR = "~/Desktop/netflix-msl-capture";
const LOG_FILE = OUTPUT_DIR + "/capture_log.jsonl";

// ── sharedState 初期化 ──
if (sharedState._httpManifestSeq === undefined) sharedState._httpManifestSeq = 0;

// ════════════════════════════════════════════════════════════════
// ヘルパー: URL パラメータをパース
// ════════════════════════════════════════════════════════════════

function parseQueryString(url) {
  var params = {};
  var idx = url.indexOf("?");
  if (idx === -1) return params;
  var qs = url.substring(idx + 1);
  var pairs = qs.split("&");
  for (var i = 0; i < pairs.length; i++) {
    var kv = pairs[i].split("=");
    var key = decodeURIComponent(kv[0]);
    var val = kv.length > 1 ? decodeURIComponent(kv.slice(1).join("=")) : "";
    params[key] = val;
  }
  return params;
}

// ════════════════════════════════════════════════════════════════
// ヘルパー: エンドポイント種別判定
// ════════════════════════════════════════════════════════════════

function classifyUrl(url) {
  if (url.indexOf("licensedmanifest") !== -1) return "licensedmanifest_http";
  if (url.indexOf("/playapi/cadmium/manifest") !== -1) return "manifest_http";
  return "manifest_unknown";
}

// ════════════════════════════════════════════════════════════════
// onRequest — リクエストボディ・パラメータのキャプチャ
// ════════════════════════════════════════════════════════════════

function onRequest(context, url, request) {
  // /nq/msl_v1/ は netflix-msl-capture.js が担当 → スキップ
  if (url.indexOf("/nq/msl_v1/") !== -1) return request;

  sharedState._httpManifestSeq++;
  var seq = sharedState._httpManifestSeq;
  var ts = new Date().toISOString();
  var endpoint = classifyUrl(url);
  var queryParams = parseQueryString(url);

  // ESN 抽出
  var esnInfo = extractEsnFromHeaders(request.headers);
  if (esnInfo) {
    sharedState._capturedESN = esnInfo.esn;
  }

  // リクエストボディのパース
  var rawBody = request.body || "";
  var bodyParsed = null;
  var bodyParams = {};

  if (rawBody) {
    // 生ボディ保存
    writeToFile(
      rawBody,
      OUTPUT_DIR + "/raw/http_request_" + seq + "_" + endpoint + "_" + timestamp() + ".bin"
    );

    if (typeof rawBody === "object") {
      bodyParsed = rawBody;
    } else if (typeof rawBody === "string") {
      // JSON ボディ
      bodyParsed = tryParseJSON(rawBody);
      if (!bodyParsed) {
        // URL-encoded form
        var pairs = rawBody.split("&");
        for (var i = 0; i < pairs.length; i++) {
          var kv = pairs[i].split("=");
          try {
            bodyParams[decodeURIComponent(kv[0])] = kv.length > 1 ? decodeURIComponent(kv.slice(1).join("=")) : "";
          } catch (e) {
            bodyParams[kv[0]] = kv.slice(1).join("=");
          }
        }
      }
    }

    // MSL envelope の可能性もチェック (licensedmanifest は MSL ラップされている場合がある)
    if (endpoint === "licensedmanifest_http") {
      var mslMessages = parseMSLBody(rawBody);
      if (mslMessages.length > 0) {
        var allDecoded = [];
        mslMessages.forEach(function (msg) {
          allDecoded.push(deepDecodeMSL(msg));
        });
        writeToFile(
          safeStringify({
            seq: seq,
            direction: "request",
            endpoint: endpoint,
            ts: ts,
            url: url,
            messages: allDecoded,
          }),
          OUTPUT_DIR + "/msl/http_request_" + seq + "_" + endpoint + "_" + timestamp() + ".json"
        );
      }
    }
  }

  // リクエスト情報を構造化して保存
  var requestCapture = {
    seq: seq,
    direction: "request",
    endpoint: endpoint,
    ts: ts,
    url: url,
    method: request.method || "POST",
    queryParams: queryParams,
    headers: request.headers,
    esn: (esnInfo && esnInfo.esn) || sharedState._capturedESN || null,
    body: bodyParsed || (Object.keys(bodyParams).length > 0 ? bodyParams : null),
    // StreamFab 判定用: User-Agent, クライアントタイプ
    userAgent: (request.headers || {})["User-Agent"] || (request.headers || {})["user-agent"] || null,
    clienttype: queryParams.clienttype || null,
    browsername: queryParams.browsername || null,
    browserversion: queryParams.browserversion || null,
    osname: queryParams.osname || null,
    osversion: queryParams.osversion || null,
  };

  writeToFile(
    safeStringify(requestCapture),
    OUTPUT_DIR + "/manifests/http_request_" + seq + "_" + endpoint + "_" + timestamp() + ".json"
  );

  console.log(
    "[HTTP-Manifest] REQUEST #" + seq + " " + endpoint +
    " client=" + (requestCapture.clienttype || "?") +
    " browser=" + (requestCapture.browsername || "?") + "/" + (requestCapture.browserversion || "?") +
    " os=" + (requestCapture.osname || "?") +
    " esn=" + (requestCapture.esn || "?")
  );

  // ログ
  writeToFile(
    JSON.stringify({
      seq: seq,
      type: "http_manifest.request",
      endpoint: endpoint,
      ts: ts,
      url: url,
      esn: requestCapture.esn,
      clienttype: requestCapture.clienttype,
      browsername: requestCapture.browsername,
    }) + "\n",
    LOG_FILE,
    { appendFile: true }
  );

  request.comment = "[HTTP-MF-REQ] #" + seq + " " + endpoint;
  return request;
}

// ════════════════════════════════════════════════════════════════
// onResponse — マニフェストレスポンスの解析
// ════════════════════════════════════════════════════════════════

function onResponse(context, url, request, response) {
  // /nq/msl_v1/ は netflix-msl-capture.js が担当 → スキップ
  if (url.indexOf("/nq/msl_v1/") !== -1) return response;

  var seq = sharedState._httpManifestSeq || 0;
  var ts = new Date().toISOString();
  var endpoint = classifyUrl(url);

  var rawBody = response.body || response.rawBody || "";
  if (!rawBody) return response;

  // 生レスポンスボディ保存
  writeToFile(
    rawBody,
    OUTPUT_DIR + "/raw/http_response_" + seq + "_" + endpoint + "_" + timestamp() + ".bin"
  );

  var manifest = null;
  var responseData = null;

  if (endpoint === "licensedmanifest_http") {
    // licensedmanifest: MSL エンベロープの可能性が高い
    var mslMessages = parseMSLBody(rawBody);
    if (mslMessages.length > 0) {
      var allDecoded = [];
      mslMessages.forEach(function (msg) {
        var expanded = deepDecodeMSL(msg);
        allDecoded.push(expanded);
        var decodedPayload = extractDecodedPayload(expanded);
        if (decodedPayload && typeof decodedPayload === "object") {
          manifest = extractManifestData(decodedPayload);
          responseData = decodedPayload;
        }
      });

      writeToFile(
        safeStringify({
          seq: seq,
          direction: "response",
          endpoint: endpoint,
          ts: ts,
          url: url,
          statusCode: response.statusCode,
          messages: allDecoded,
          decryptionAvailable: !!getDecryptionKeys().encryptionKey,
        }),
        OUTPUT_DIR + "/msl/http_response_" + seq + "_" + endpoint + "_" + timestamp() + ".json"
      );

      if (!manifest && !responseData) {
        console.log(
          "[HTTP-Manifest] licensedmanifest #" + seq +
          " — payload encrypted (AES-CBC). ALE keys " +
          (getDecryptionKeys().encryptionKey ? "available but decryption failed" : "NOT available") +
          ". Raw body saved."
        );
      }
    } else {
      // JSON レスポンスの可能性
      responseData = typeof rawBody === "string" ? tryParseJSON(rawBody) : rawBody;
    }
  } else {
    // manifest API: 通常の JSON レスポンス
    if (typeof rawBody === "object") {
      responseData = rawBody;
    } else if (typeof rawBody === "string") {
      responseData = tryParseJSON(rawBody);
    }

    if (responseData) {
      // manifest API のレスポンスは result にマニフェストが入っている場合がある
      manifest = extractManifestData(responseData);
    }
  }

  // マニフェスト検出時の保存
  if (manifest) {
    var movieId = manifest.movieId || "unknown";

    // マニフェスト本体
    writeToFile(
      safeStringify(manifest),
      OUTPUT_DIR + "/manifests/http_manifest_" + movieId + "_" + endpoint + "_" + timestamp() + ".json"
    );

    // KID テーブル
    var kidTable = buildKIDTable(manifest);
    if (kidTable.length > 0) {
      writeToFile(
        safeStringify(kidTable),
        OUTPUT_DIR + "/manifests/http_kid_table_" + movieId + "_" + endpoint + "_" + timestamp() + ".json"
      );

      // KID が全て null かチェック
      var hasAnyKid = kidTable.some(function (row) { return !!row.kid; });

      var readable = "# KID Table — movieId: " + movieId + " (source: " + endpoint + ")\n\n";
      if (!hasAnyKid) {
        readable += "> **Note:** manifest API (`/playapi/cadmium/manifest/1`) には DRM Key ID が含まれない。\n";
        readable += "> KID は `licensedmanifest` からのみ取得可能。\n\n";
      }
      readable += "| Resolution | Bitrate | KID | Profile |\n";
      readable += "|------------|---------|-----|----------|\n";
      kidTable.forEach(function (row) {
        if (row.boundary) readable += "|---|---|---|---|\n";
        readable +=
          "| " + row.res_w + "x" + row.res_h +
          " | " + (row.bitrate > 10000 ? (row.bitrate / 1000).toFixed(0) : row.bitrate) + " kbps" +
          " | " + row.kid_short +
          " | " + row.content_profile +
          " |\n";
      });
      writeToFile(readable, OUTPUT_DIR + "/manifests/http_kid_table_" + movieId + "_" + endpoint + ".md");
    }

    var videoCount = 0;
    var audioCount = 0;
    manifest.videoTracks.forEach(function (vt) { videoCount += vt.streams.length; });
    manifest.audioTracks.forEach(function (at) { audioCount += at.streams.length; });

    console.log(
      "[HTTP-Manifest] MANIFEST detected #" + seq +
      ": movieId=" + movieId +
      " video=" + videoCount +
      " audio=" + audioCount +
      " source=" + endpoint
    );
  }

  // レスポンス全体も保存（マニフェスト以外のフィールドも含む）
  if (responseData && !manifest) {
    writeToFile(
      safeStringify({
        seq: seq,
        direction: "response",
        endpoint: endpoint,
        ts: ts,
        url: url,
        statusCode: response.statusCode,
        data: responseData,
      }),
      OUTPUT_DIR + "/manifests/http_response_" + seq + "_" + endpoint + "_" + timestamp() + ".json"
    );
  }

  // ログ
  writeToFile(
    JSON.stringify({
      seq: seq,
      type: "http_manifest.response",
      endpoint: endpoint,
      ts: ts,
      url: url,
      statusCode: response.statusCode,
      manifestDetected: !!manifest,
      movieId: manifest ? manifest.movieId : null,
    }) + "\n",
    LOG_FILE,
    { appendFile: true }
  );

  // レスポンスにコメント付与
  var commentParts = ["[HTTP-MF] #" + seq + " " + endpoint];
  if (manifest) commentParts.push("MANIFEST(id=" + manifest.movieId + ")");
  response.comment = commentParts.join(" ");
  response.color = manifest ? "#2196F3" : "#FF9800";

  return response;
}
