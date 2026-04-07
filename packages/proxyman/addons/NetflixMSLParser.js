/**
    {
        "name": "Netflix MSL Parser",
        "description": "Netflix MSL (Media Service Layer) message parser — decodes envelopes, extracts manifests, ALE keys, ESN",
        "author": "frida-project",
        "tags": "netflix,msl,drm,widevine,manifest"
    }
**/

// ════════════════════════════════════════════════════════════════
// Base64 helpers
// ════════════════════════════════════════════════════════════════

function b64Decode(str) {
  try {
    // Proxyman の JS 環境では atob が使える
    return atob(str);
  } catch (e) {
    return null;
  }
}

function b64urlDecode(b64url) {
  var pad = (4 - (b64url.length % 4)) % 4;
  var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return b64Decode(b64);
}

function b64urlToBytes(b64url) {
  var decoded = b64urlDecode(b64url);
  if (!decoded) return null;
  var bytes = [];
  for (var i = 0; i < decoded.length; i++) {
    bytes.push(decoded.charCodeAt(i));
  }
  return bytes;
}

function bytesToHex(bytes) {
  return bytes
    .map(function (b) {
      return ("0" + b.toString(16)).slice(-2);
    })
    .join("");
}

// ════════════════════════════════════════════════════════════════
// LZW Decoder (Netflix MSL variant)
// ════════════════════════════════════════════════════════════════

function decodeLZW(input) {
  try {
    var decoded = b64Decode(input);
    if (!decoded) return null;
    var bytes = [];
    for (var i = 0; i < decoded.length; i++) {
      bytes.push(decoded.charCodeAt(i));
    }
    if (bytes.length === 0) return null;

    var bitPos = 0;
    var totalBits = bytes.length * 8;

    function readBits(n) {
      if (bitPos + n > totalBits) return -1;
      var val = 0;
      for (var i = 0; i < n; i++) {
        var byteIdx = (bitPos + i) >> 3;
        var bitIdx = 7 - ((bitPos + i) & 7);
        if (bytes[byteIdx] & (1 << bitIdx)) val |= 1 << (n - 1 - i);
      }
      bitPos += n;
      return val;
    }

    var dict = [];
    for (var i = 0; i < 256; i++) dict[i] = [i];

    var bits = 8;
    var output = [];
    var code = readBits(bits);
    if (code === -1 || !dict[code]) return null;
    var prev = dict[code];
    for (var i = 0; i < prev.length; i++) output.push(prev[i]);

    while (true) {
      if (dict.length === 1 << bits) bits++;
      code = readBits(bits);
      if (code === -1) break;
      var entry;
      if (code < dict.length) {
        entry = dict[code];
      } else if (code === dict.length) {
        entry = prev.concat([prev[0]]);
      } else {
        break;
      }
      for (var i = 0; i < entry.length; i++) output.push(entry[i]);
      dict.push(prev.concat([entry[0]]));
      prev = entry;
    }

    // UTF-8 decode
    var result = "";
    for (var i = 0; i < output.length; i++) {
      result += String.fromCharCode(output[i]);
    }
    return result;
  } catch (e) {
    return null;
  }
}

// ════════════════════════════════════════════════════════════════
// JSON helpers
// ════════════════════════════════════════════════════════════════

function tryParseJSON(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
}

function safeStringify(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch (e) {
    return String(obj);
  }
}

// ════════════════════════════════════════════════════════════════
// AES-CBC 復号 (CryptoJS)
// ════════════════════════════════════════════════════════════════

var CryptoJS = require("@addons/CryptoJS.js");

// 現在の ALE 鍵を保持
var _currentKeys = {
  encryptionKey: null, // hex string (AES-CBC)
  hmacKey: null,       // hex string (HMAC-SHA256)
};

function setDecryptionKeys(encKeyHex, hmacKeyHex) {
  _currentKeys.encryptionKey = encKeyHex;
  _currentKeys.hmacKey = hmacKeyHex;
}

function getDecryptionKeys() {
  return _currentKeys;
}

/**
 * AES-CBC で MSL ペイロードを復号
 * MSL の暗号化フォーマット: base64(IV[16] || ciphertext)
 */
function decryptAesCbc(dataB64, keyHex) {
  if (!dataB64 || !keyHex) return null;
  try {
    var raw = b64Decode(dataB64);
    if (!raw || raw.length < 17) return null; // IV(16) + 最低1ブロック

    // IV = 先頭16バイト, ciphertext = 残り
    var ivWords = CryptoJS.enc.Latin1.parse(raw.substring(0, 16));
    var ciphertextStr = raw.substring(16);
    var ciphertext = CryptoJS.enc.Latin1.parse(ciphertextStr);
    var key = CryptoJS.enc.Hex.parse(keyHex);

    var decrypted = CryptoJS.AES.decrypt(
      { ciphertext: ciphertext },
      key,
      { iv: ivWords, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
    );

    var plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    if (!plaintext) return null;
    return plaintext;
  } catch (e) {
    return null;
  }
}

// ════════════════════════════════════════════════════════════════
// MSL Envelope Decoder
// ════════════════════════════════════════════════════════════════

function decodeChunkData(dataStr, compressionalgo) {
  if (!dataStr) return null;

  // 1. LZW 圧縮の場合
  if (compressionalgo === "LZW") {
    var decompressed = decodeLZW(dataStr);
    if (decompressed) return tryParseJSON(decompressed) || decompressed;
  }

  // 2. 通常の base64 デコード
  var inner = b64Decode(dataStr);
  if (inner) {
    var parsed = tryParseJSON(inner);
    if (parsed) return parsed;
    // 印字可能テキストならそのまま返す
    if (inner.length > 0 && inner.charCodeAt(0) >= 0x20) return inner;
  }

  // 3. AES-CBC 復号を試みる (ALE 鍵がある場合)
  if (_currentKeys.encryptionKey) {
    var decrypted = decryptAesCbc(dataStr, _currentKeys.encryptionKey);
    if (decrypted) {
      // 復号後が LZW 圧縮されている場合
      if (compressionalgo === "LZW") {
        var decompDecrypted = decodeLZW(decrypted);
        if (decompDecrypted) return tryParseJSON(decompDecrypted) || decompDecrypted;
      }
      return tryParseJSON(decrypted) || decrypted;
    }
  }

  return null;
}

/**
 * MSL メッセージのデコード
 * HTTP 本文の JSON を受け取り、base64 エンコードされたフィールドをデコードする
 */
function deepDecodeMSL(obj) {
  if (!obj || typeof obj !== "object") return obj;

  var decoded = {};
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    decoded[keys[i]] = obj[keys[i]];
  }

  var compress = decoded.compressionalgo || null;

  // headerdata: base64 → JSON
  if (typeof decoded.headerdata === "string") {
    var hdrText = b64Decode(decoded.headerdata);
    var hdr = tryParseJSON(hdrText);
    if (hdr && typeof hdr === "object") {
      decoded._headerdata_decoded = hdr;
    }
  }

  // payload: base64 → JSON chunk → data
  if (typeof decoded.payload === "string") {
    var chunkText = b64Decode(decoded.payload);
    var chunk = tryParseJSON(chunkText);
    if (chunk) {
      decoded._payload_decoded = chunk;
      if (chunk.data) {
        var algo = chunk.compressionalgo || compress;
        decoded._payload_data = decodeChunkData(chunk.data, algo);
      }
    }
  }

  // data field (payload chunk format)
  if (typeof decoded.data === "string" && decoded.messageid !== undefined) {
    decoded._data_decoded = decodeChunkData(decoded.data, compress);
  }

  // payloads array
  if (Array.isArray(decoded.payloads)) {
    decoded._payloads_decoded = decoded.payloads.map(function (p) {
      if (typeof p === "string") {
        var chunkText = b64Decode(p);
        var chunk = tryParseJSON(chunkText);
        if (chunk && chunk.data) {
          var algo = chunk.compressionalgo || compress;
          var inner = decodeChunkData(chunk.data, algo);
          return { _chunk: chunk, _data: inner };
        }
        return chunk || p;
      }
      return p;
    });
  }

  // servicetokens
  if (Array.isArray(decoded.servicetokens)) {
    decoded._servicetokens_decoded = decoded.servicetokens.map(function (st) {
      if (typeof st.tokendata === "string") {
        var tdText = b64Decode(st.tokendata);
        var td = tryParseJSON(tdText);
        if (td) {
          var result = {};
          var tdKeys = Object.keys(td);
          for (var i = 0; i < tdKeys.length; i++) result[tdKeys[i]] = td[tdKeys[i]];
          if (td.servicedata) {
            var sd = b64Decode(td.servicedata);
            result._servicedata_decoded = sd ? tryParseJSON(sd) || sd : null;
          }
          return result;
        }
      }
      return st;
    });
  }

  // useridtoken
  if (decoded.useridtoken && typeof decoded.useridtoken === "object") {
    if (typeof decoded.useridtoken.tokendata === "string") {
      var uitText = b64Decode(decoded.useridtoken.tokendata);
      decoded._useridtoken_decoded = tryParseJSON(uitText);
    }
  }

  return decoded;
}

/**
 * デコード済みペイロードの抽出
 */
function extractDecodedPayload(expanded) {
  return (
    expanded._data_decoded ||
    expanded._payload_data ||
    expanded._payload_decoded ||
    null
  );
}

// ════════════════════════════════════════════════════════════════
// Manifest Extractor
// ════════════════════════════════════════════════════════════════

function formatDrmHeaderId(hex) {
  if (!hex || hex.length !== 32) return hex || null;
  return (
    hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" +
    hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20)
  );
}

/**
 * デコード済みペイロードからマニフェスト情報を抽出
 */
function extractManifestData(payload) {
  if (!payload || typeof payload !== "object") return null;

  var rawResult = payload.result || payload;
  if (!rawResult) return null;
  if (!rawResult.video_tracks && !rawResult.audio_tracks) return null;

  var manifest = {
    movieId: rawResult.movieId != null ? String(rawResult.movieId) : null,
    duration: rawResult.duration || null,
    servers: rawResult.servers || [],
    videoTracks: [],
    audioTracks: [],
    textTracks: [],
  };

  if (rawResult.video_tracks) {
    manifest.videoTracks = rawResult.video_tracks.map(function (vt) {
      return {
        trackType: vt.trackType,
        track_id: vt.track_id,
        maxWidth: vt.maxWidth,
        maxHeight: vt.maxHeight,
        drmHeader: vt.drmHeader
          ? { bytes: vt.drmHeader.bytes, keyId: vt.drmHeader.keyId }
          : null,
        streams: (vt.streams || []).map(function (s) {
          return {
            res_w: s.res_w,
            res_h: s.res_h,
            bitrate: s.bitrate,
            size: s.size,
            vmaf: s.vmaf,
            content_profile: s.content_profile,
            downloadable_id: s.downloadable_id,
            kid: formatDrmHeaderId(s.drmHeaderId || ""),
            urls: s.urls || [],
          };
        }),
      };
    });
  }

  if (rawResult.audio_tracks) {
    manifest.audioTracks = rawResult.audio_tracks.map(function (at) {
      return {
        language: at.language,
        languageDescription: at.languageDescription,
        channels: at.channels,
        trackType: at.trackType,
        track_id: at.track_id,
        streams: (at.streams || []).map(function (s) {
          return {
            bitrate: s.bitrate,
            size: s.size,
            content_profile: s.content_profile,
            downloadable_id: s.downloadable_id,
            urls: s.urls || [],
          };
        }),
      };
    });
  }

  if (rawResult.timedtexttracks) {
    manifest.textTracks = rawResult.timedtexttracks
      .filter(function (tt) {
        return !tt.isNoneTrack;
      })
      .map(function (tt) {
        return {
          language: tt.language,
          languageDescription: tt.languageDescription,
          trackType: tt.trackType,
          downloadableId: tt.downloadableId,
          urls: tt.ttDownloadables,
        };
      });
  }

  return manifest;
}

// ════════════════════════════════════════════════════════════════
// ALE Key Extractor
// ════════════════════════════════════════════════════════════════

/**
 * MSL provision レスポンスから ALE 鍵を抽出
 * keyx.scheme=CLEAR の場合、keyx.data.key に 32 バイトの鍵素材が含まれる
 *   bytes[0:16] = HMAC-SHA256 鍵
 *   bytes[16:32] = AES-CBC 暗号鍵
 */
function extractAleKeys(payload) {
  if (!payload || typeof payload !== "object") return null;

  // provisionResponse を探す
  var provResponse = payload.provisionResponse;
  if (!provResponse) return null;

  var tokenObj;
  if (typeof provResponse === "string") {
    tokenObj = tryParseJSON(provResponse);
  } else {
    tokenObj = provResponse;
  }
  if (!tokenObj || !tokenObj.keyx) return null;

  var keyx = tokenObj.keyx;
  if (!keyx.data || !keyx.data.key) return null;

  var keyBytes = b64urlToBytes(keyx.data.key);
  if (!keyBytes || keyBytes.length < 32) return null;

  var hmacHex = bytesToHex(keyBytes.slice(0, 16));
  var aesHex = bytesToHex(keyBytes.slice(16, 32));

  // JWE header
  var jweToken = tokenObj.token || "";
  var jweAlg = "?";
  var jweEnc = "?";
  if (jweToken) {
    try {
      var parts = jweToken.split(".");
      if (parts.length === 5) {
        var hdrDecoded = b64urlDecode(parts[0]);
        var hdr = tryParseJSON(hdrDecoded);
        if (hdr) {
          jweAlg = hdr.alg || "?";
          jweEnc = hdr.enc || "?";
        }
      }
    } catch (e) {
      /* ignore */
    }
  }

  return {
    encryptionKey: aesHex,
    hmacKey: hmacHex,
    kid: keyx.kid || "",
    jweToken: jweToken,
    scheme: keyx.scheme || "",
    rawKeyHex: bytesToHex(keyBytes),
    jweAlg: jweAlg,
    jweEnc: jweEnc,
    capturedAt: new Date().toISOString(),
  };
}

// ════════════════════════════════════════════════════════════════
// ESN Extractor
// ════════════════════════════════════════════════════════════════

function extractEsnFromHeaders(headers) {
  if (!headers) return null;
  var esn =
    headers["x-netflix.esn"] ||
    headers["X-Netflix.esn"] ||
    headers["X-Netflix.Esn"] ||
    headers["X-NETFLIX.ESN"];
  if (!esn) return null;

  var prv = null;
  var pxa = null;
  var parts = esn.split("|");
  if (parts.length >= 1) prv = parts[0];
  if (parts.length >= 2) pxa = parts[1];

  return { esn: esn, prv: prv, pxa: pxa };
}

function extractEsnFromSender(sender) {
  if (!sender || typeof sender !== "string") return null;
  return { esn: sender, prv: sender, pxa: null };
}

// ════════════════════════════════════════════════════════════════
// HTTP Body Parser
// MSL エンドポイントの本文は複数の JSON オブジェクトが連結されている場合がある
// ════════════════════════════════════════════════════════════════

function parseMSLBody(body) {
  if (!body) return [];

  // Proxyman が自動パースしてオブジェクトになっている場合
  if (typeof body === "object" && !Array.isArray(body)) {
    return [body];
  }
  if (Array.isArray(body)) {
    return body;
  }

  // 文字列の場合
  if (typeof body !== "string") {
    // Uint8Array 等 → 文字列変換を試みる
    try {
      body = String(body);
    } catch (e) {
      return [];
    }
  }

  // 単一 JSON の場合
  var single = tryParseJSON(body);
  if (single) return [single];

  // 複数 JSON の連結（改行区切り）
  var messages = [];
  var lines = body.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (!line) continue;
    var parsed = tryParseJSON(line);
    if (parsed) messages.push(parsed);
  }
  return messages;
}

// ════════════════════════════════════════════════════════════════
// KID Table Builder
// ════════════════════════════════════════════════════════════════

function buildKIDTable(manifest) {
  if (!manifest || !manifest.videoTracks) return [];
  var rows = [];
  manifest.videoTracks.forEach(function (vt) {
    var sortedStreams = vt.streams.slice().sort(function (a, b) {
      return a.bitrate - b.bitrate;
    });
    var prevKid = null;
    sortedStreams.forEach(function (s) {
      var boundary = prevKid !== null && s.kid !== prevKid;
      rows.push({
        res_w: s.res_w,
        res_h: s.res_h,
        bitrate: s.bitrate,
        kid: s.kid,
        kid_short: s.kid ? s.kid.slice(0, 8) + "..." : "-",
        content_profile: s.content_profile,
        boundary: boundary,
      });
      prevKid = s.kid;
    });
  });
  return rows;
}

// ════════════════════════════════════════════════════════════════
// Format helpers
// ════════════════════════════════════════════════════════════════

function formatSize(bytes) {
  if (!bytes || bytes <= 0) return "?";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(0) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

// ════════════════════════════════════════════════════════════════
// Exports
// ════════════════════════════════════════════════════════════════

exports.b64Decode = b64Decode;
exports.b64urlDecode = b64urlDecode;
exports.b64urlToBytes = b64urlToBytes;
exports.bytesToHex = bytesToHex;
exports.decodeLZW = decodeLZW;
exports.tryParseJSON = tryParseJSON;
exports.safeStringify = safeStringify;
exports.deepDecodeMSL = deepDecodeMSL;
exports.extractDecodedPayload = extractDecodedPayload;
exports.extractManifestData = extractManifestData;
exports.extractAleKeys = extractAleKeys;
exports.extractEsnFromHeaders = extractEsnFromHeaders;
exports.extractEsnFromSender = extractEsnFromSender;
exports.parseMSLBody = parseMSLBody;
exports.buildKIDTable = buildKIDTable;
exports.formatSize = formatSize;
exports.timestamp = timestamp;
exports.decodeChunkData = decodeChunkData;
exports.setDecryptionKeys = setDecryptionKeys;
exports.getDecryptionKeys = getDecryptionKeys;
exports.decryptAesCbc = decryptAesCbc;
