/**
 * Netflix MSL Capture — Proxyman Script
 *
 * URL Matching Rule:  *netflix.com/nq/msl_v1/*
 *
 * MSL エンドポイントへの全リクエスト/レスポンスをキャプチャし、
 * MSL メッセージのデコード・復号、マニフェスト抽出、ALE 鍵抽出、ESN 取得を行う。
 *
 * 保存先: ~/Desktop/netflix-msl-capture/
 *
 * 【Proxyman 設定】
 *   1. Script Menu > Script List (Opt+Cmd+I)
 *   2. 新規スクリプト作成
 *   3. URL Matching Rule: *netflix.com/nq/msl_v1/*
 *   4. このスクリプトの内容を貼り付け
 *   5. Enable on Request ✓ (オン) / Enable on Response ✓ (オン)
 */

// ── アドオン読み込み ──
const {
  deepDecodeMSL,
  extractDecodedPayload,
  extractManifestData,
  extractAleKeys,
  extractEsnFromHeaders,
  extractEsnFromSender,
  parseMSLBody,
  buildKIDTable,
  safeStringify,
  timestamp,
  formatSize,
  setDecryptionKeys,
  getDecryptionKeys,
} = require("@users/NetflixMSLParser.js");

// ── 設定 ──
const OUTPUT_DIR = "~/Desktop/netflix-msl-capture";
const SAVE_RAW_BODIES = true;
const SAVE_DECODED_MSL = true;
const SAVE_MANIFEST = true;
const SAVE_ALE_KEYS = true;
const SAVE_HEADERS = true;
const SAVE_COOKIES = true;
const SAVE_REQUEST_BODIES = true;
const LOG_FILE = OUTPUT_DIR + "/capture_log.jsonl";

// ── sharedState 初期化 ──
if (sharedState._mslSeq === undefined) sharedState._mslSeq = 0;
if (sharedState._capturedManifests === undefined) sharedState._capturedManifests = 0;
if (sharedState._capturedAleKeys === undefined) sharedState._capturedAleKeys = 0;
if (sharedState._capturedESN === undefined) sharedState._capturedESN = "";

// ── 前回キャプチャ済みの ALE 鍵があれば復号鍵としてセット ──
if (sharedState._aleEncKey && sharedState._aleHmacKey) {
  setDecryptionKeys(sharedState._aleEncKey, sharedState._aleHmacKey);
}

// ════════════════════════════════════════════════════════════════
// onRequest — リクエストボディの解析・保存
// ════════════════════════════════════════════════════════════════

function onRequest(context, url, request) {
  if (!SAVE_REQUEST_BODIES) return request;

  sharedState._mslReqSeq = (sharedState._mslReqSeq || 0) + 1;
  var reqSeq = sharedState._mslReqSeq;
  var ts = new Date().toISOString();

  var rawBody = request.body || "";
  if (!rawBody) return request;

  // URL からエンドポイント種別を判別
  var endpoint = "unknown";
  if (url.indexOf("pbo_manifests") !== -1) endpoint = "manifest_msl";
  else if (url.indexOf("pbo_licenses") !== -1) endpoint = "license";
  else if (url.indexOf("pbo_tokens") !== -1) endpoint = "ale_provision";
  else if (url.indexOf("licensedmanifest") !== -1) endpoint = "licensedmanifest";
  else if (url.indexOf("/events") !== -1) endpoint = "events";
  else if (url.indexOf("getProxyEsn") !== -1) endpoint = "getProxyEsn";
  else if (url.indexOf("/config") !== -1) endpoint = "config";
  else if (url.indexOf("pathEvaluator") !== -1) endpoint = "pathEvaluator";
  else if (url.indexOf("graphql") !== -1) endpoint = "graphql";

  // 生のリクエストボディを保存
  var rawFile = OUTPUT_DIR + "/raw/request_" + reqSeq + "_" + endpoint + "_" + timestamp() + ".bin";
  writeToFile(rawBody, rawFile);

  // MSL メッセージとしてパース・デコード
  var mslMessages = parseMSLBody(rawBody);
  if (mslMessages.length > 0) {
    var allDecoded = [];
    mslMessages.forEach(function (msg) {
      var expanded = deepDecodeMSL(msg);
      allDecoded.push(expanded);

      // sender から ESN
      if (msg.sender) {
        var esn = extractEsnFromSender(msg.sender);
        if (esn) sharedState._capturedESN = esn.esn;
      }
    });

    // デコード済みリクエストを保存
    var decodedFile = OUTPUT_DIR + "/msl/request_" + reqSeq + "_" + endpoint + "_" + timestamp() + ".json";
    writeToFile(
      safeStringify({
        seq: reqSeq,
        direction: "request",
        endpoint: endpoint,
        ts: ts,
        url: url,
        requestHeaders: request.headers,
        messages: allDecoded,
      }),
      decodedFile
    );

    // マニフェスト関連リクエストの場合、パラメータを詳細にログ
    if (endpoint === "manifest_msl" || endpoint === "licensedmanifest") {
      var manifestParams = null;
      allDecoded.forEach(function (expanded) {
        var payload = extractDecodedPayload(expanded);
        if (payload && typeof payload === "object") {
          manifestParams = {
            endpoint: endpoint,
            url: (payload.url || payload.body && payload.body.url || null),
            params: payload.params || payload.body && payload.body.params || null,
            esn: sharedState._capturedESN || null,
            drmType: payload.drmType || null,
            profiles: payload.profiles || null,
            languages: payload.languages || null,
            showAllSubDubTracks: payload.showAllSubDubTracks,
          };
        }
      });

      if (manifestParams) {
        var paramsFile = OUTPUT_DIR + "/manifests/request_params_" + reqSeq + "_" + endpoint + "_" + timestamp() + ".json";
        writeToFile(safeStringify(manifestParams), paramsFile);
        console.log(
          "[MSL-Capture] Manifest REQUEST detected: endpoint=" + endpoint +
          " esn=" + (manifestParams.esn || "?") +
          " url=" + (manifestParams.url || "?")
        );
      }
    }
  }

  // リクエストログ
  var logEntry = {
    seq: reqSeq,
    type: "http.request",
    endpoint: endpoint,
    ts: ts,
    url: url,
    esn: sharedState._capturedESN || null,
    mslMessageCount: mslMessages.length,
  };
  writeToFile(JSON.stringify(logEntry) + "\n", LOG_FILE, { appendFile: true });

  // リクエストにコメント付与
  var commentParts = ["[MSL-REQ] #" + reqSeq + " " + endpoint];
  request.comment = commentParts.join(" ");

  return request;
}

// ════════════════════════════════════════════════════════════════
// onResponse — キャプチャ＋解析＋復号
// ════════════════════════════════════════════════════════════════

function onResponse(context, url, request, response) {
  sharedState._mslSeq++;
  var seq = sharedState._mslSeq;
  var ts = new Date().toISOString();

  // ESN 抽出（リクエスト＋レスポンスヘッダー）
  var esnInfo =
    extractEsnFromHeaders(request.headers) ||
    extractEsnFromHeaders(response.headers);
  if (esnInfo) {
    sharedState._capturedESN = esnInfo.esn;
  }

  // リクエストの Cookie を保存
  var cookies = (request.headers || {})["Cookie"] || (request.headers || {})["cookie"] || "";
  if (cookies && SAVE_COOKIES) {
    var netscapeLines = cookies.split(";").map(function (c) {
      var parts = c.trim().split("=");
      var name = parts.shift();
      var value = parts.join("=");
      return ".netflix.com\tTRUE\t/\tTRUE\t0\t" + name + "\t" + value;
    });
    writeToFile(netscapeLines.join("\n") + "\n", OUTPUT_DIR + "/cookies/cookies.txt");
  }

  // リクエスト＋レスポンスヘッダーを保存
  if (SAVE_HEADERS) {
    var headerFile =
      OUTPUT_DIR + "/headers/response_" + seq + "_" + timestamp() + ".json";
    writeToFile(
      safeStringify({
        seq: seq,
        ts: ts,
        url: url,
        statusCode: response.statusCode,
        requestHeaders: request.headers,
        responseHeaders: response.headers,
      }),
      headerFile
    );
  }

  // Set-Cookie を保存
  var setCookie =
    response.headers["Set-Cookie"] ||
    response.headers["set-cookie"] ||
    "";
  if (setCookie && SAVE_COOKIES) {
    writeToFile(
      ts + " " + setCookie + "\n",
      OUTPUT_DIR + "/cookies/set_cookies.log",
      { appendFile: true }
    );
  }

  var logEntry = {
    seq: seq,
    type: "http.response",
    ts: ts,
    url: url,
    statusCode: response.statusCode,
    esn: sharedState._capturedESN || null,
  };

  // ── レスポンス本文の解析 ──
  var rawBody = response.body || response.rawBody || "";
  var foundManifest = null;
  var foundAleKeys = null;

  if (rawBody) {
    // 生の本文を保存
    if (SAVE_RAW_BODIES) {
      var rawFile =
        OUTPUT_DIR + "/raw/response_" + seq + "_" + timestamp() + ".bin";
      writeToFile(rawBody, rawFile);
    }

    // MSL メッセージとしてパース
    var mslMessages = parseMSLBody(rawBody);
    if (mslMessages.length > 0) {
      logEntry.mslMessageCount = mslMessages.length;

      var allDecoded = [];

      mslMessages.forEach(function (msg, idx) {
        var expanded = deepDecodeMSL(msg);
        allDecoded.push(expanded);
        var decodedPayload = extractDecodedPayload(expanded);

        // sender から ESN
        if (msg.sender) {
          var esn = extractEsnFromSender(msg.sender);
          if (esn) sharedState._capturedESN = esn.esn;
        }

        // ── マニフェスト検出 ──
        if (decodedPayload && typeof decodedPayload === "object") {
          var manifest = extractManifestData(decodedPayload);
          if (manifest) {
            foundManifest = manifest;
            sharedState._capturedManifests++;
            logEntry.manifestDetected = true;
            logEntry.movieId = manifest.movieId;

            var videoCount = 0;
            var audioCount = 0;
            manifest.videoTracks.forEach(function (vt) {
              videoCount += vt.streams.length;
            });
            manifest.audioTracks.forEach(function (at) {
              audioCount += at.streams.length;
            });
            logEntry.videoStreams = videoCount;
            logEntry.audioStreams = audioCount;

            console.log(
              "[MSL-Capture] Manifest detected: movieId=" +
              manifest.movieId +
              " video=" +
              videoCount +
              " audio=" +
              audioCount
            );
          }

          // ── ALE 鍵検出 → 復号鍵としてセット ──
          var aleResult = extractAleKeys(
            decodedPayload.result || decodedPayload
          );
          if (aleResult) {
            foundAleKeys = aleResult;
            sharedState._capturedAleKeys++;
            logEntry.aleKeysDetected = true;
            logEntry.aleScheme = aleResult.scheme;

            // 復号鍵をセット (以降の MSL メッセージで AES-CBC 復号が有効に)
            setDecryptionKeys(aleResult.encryptionKey, aleResult.hmacKey);
            sharedState._aleEncKey = aleResult.encryptionKey;
            sharedState._aleHmacKey = aleResult.hmacKey;

            console.log(
              "[MSL-Capture] ALE Keys detected → decryption enabled:" +
              "\n  HMAC-SHA256: " + aleResult.hmacKey +
              "\n  AES-CBC:     " + aleResult.encryptionKey +
              "\n  KID:         " + aleResult.kid +
              "\n  Scheme:      " + aleResult.scheme
            );
          }
        }
      });

      // デコード済み MSL の保存
      if (SAVE_DECODED_MSL) {
        var decodedFile =
          OUTPUT_DIR + "/msl/response_" + seq + "_" + timestamp() + ".json";
        writeToFile(
          safeStringify({
            seq: seq,
            direction: "response",
            ts: ts,
            url: url,
            statusCode: response.statusCode,
            messages: allDecoded,
          }),
          decodedFile
        );
      }
    }
  }

  // ── マニフェストの個別保存 ──
  if (foundManifest && SAVE_MANIFEST) {
    var movieId = foundManifest.movieId || "unknown";
    var manifestFile =
      OUTPUT_DIR + "/manifests/manifest_" + movieId + "_" + timestamp() + ".json";
    writeToFile(safeStringify(foundManifest), manifestFile);

    // KID テーブルも保存
    var kidTable = buildKIDTable(foundManifest);
    if (kidTable.length > 0) {
      var kidFile =
        OUTPUT_DIR + "/manifests/kid_table_" + movieId + "_" + timestamp() + ".json";
      writeToFile(safeStringify(kidTable), kidFile);

      var readable = "# KID Table — movieId: " + movieId + "\n\n";
      readable += "| Resolution | Bitrate | KID | Profile |\n";
      readable += "|------------|---------|-----|----------|\n";
      kidTable.forEach(function (row) {
        if (row.boundary) readable += "|---|---|---|---|\n";
        // bitrate: bps (>10000) なら kbps に変換、既に kbps ならそのまま
        var bitrateKbps = row.bitrate > 10000 ? (row.bitrate / 1000).toFixed(0) : row.bitrate;
        readable +=
          "| " + row.res_w + "x" + row.res_h +
          " | " + bitrateKbps + " kbps" +
          " | " + row.kid_short +
          " | " + row.content_profile +
          " |\n";
      });
      writeToFile(readable, OUTPUT_DIR + "/manifests/kid_table_" + movieId + ".md");
    }
  }

  // ── ALE 鍵の個別保存 ──
  if (foundAleKeys && SAVE_ALE_KEYS) {
    writeToFile(
      JSON.stringify(foundAleKeys) + "\n",
      OUTPUT_DIR + "/keys/ale_keys.jsonl",
      { appendFile: true }
    );
    writeToFile(
      safeStringify(foundAleKeys),
      OUTPUT_DIR + "/keys/ale_" + (foundAleKeys.kid || seq) + "_" + timestamp() + ".json"
    );
  }

  // ── ESN の保存 ──
  if (sharedState._capturedESN) {
    logEntry.esn = sharedState._capturedESN;
    writeToFile(sharedState._capturedESN + "\n", OUTPUT_DIR + "/esn.txt");
  }

  // JSONL ログ書き込み
  writeToFile(JSON.stringify(logEntry) + "\n", LOG_FILE, { appendFile: true });

  // レスポンスにコメント付与
  var commentParts = ["[MSL] #" + seq];
  if (foundManifest)
    commentParts.push("MANIFEST(id=" + foundManifest.movieId + ")");
  if (foundAleKeys) commentParts.push("ALE-KEYS");
  response.comment = commentParts.join(" ");
  response.color = foundManifest || foundAleKeys ? "#4CAF50" : "#9E9E9E";

  return response;
}
