// ── Web Crypto API フック ──

import { captured, profileOverrides } from "./state";
import { logCapture, logMSLMessage } from "./msl-processor";
import { rewriteManifestProfiles } from "./profile-override";
import {
  bufToHex,
  bufToB64,
  getAlgorithmName,
  tryDecodeText,
  tryParseJSON,
  decodeLZW,
  encodeLZW,
  bytesToB64,
} from "./utils";
import { LZWChunkSchema, zodParse } from "./schemas";

const PREFIX = "[MSL-Capture]";

// ── Original Crypto references ──
const _generateKey = crypto.subtle.generateKey.bind(crypto.subtle);
const _importKey = crypto.subtle.importKey.bind(crypto.subtle);
const _exportKey = crypto.subtle.exportKey.bind(crypto.subtle);
const _deriveKey = crypto.subtle.deriveKey.bind(crypto.subtle);
const _deriveBits = crypto.subtle.deriveBits.bind(crypto.subtle);
const _sign = crypto.subtle.sign.bind(crypto.subtle);
const _encrypt = crypto.subtle.encrypt.bind(crypto.subtle);
const _decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
const _unwrapKey = crypto.subtle.unwrapKey.bind(crypto.subtle);
const _wrapKey = crypto.subtle.wrapKey.bind(crypto.subtle);

async function tryExportKey(key: CryptoKey): Promise<unknown> {
  if (!key) return null;
  try {
    return await _exportKey("jwk", key);
  } catch {
    return { error: "non-extractable", type: key.type, algorithm: key.algorithm };
  }
}

async function tryExportKeyRaw(key: CryptoKey): Promise<string | null> {
  try {
    return bufToHex(await _exportKey("raw", key) as ArrayBuffer);
  } catch {
    return null;
  }
}

export function installCryptoHooks(): void {
  // ── Hook: generateKey ──
  crypto.subtle.generateKey = (async (
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey | CryptoKeyPair> => {
    const result = await _generateKey(algorithm, true, keyUsages);
    const data: Record<string, unknown> = {
      algorithm: getAlgorithmName(algorithm),
      algorithmDetail: algorithm,
      originalExtractable: extractable,
      keyUsages,
    };
    if ("privateKey" in result) {
      data.publicKey = await tryExportKey(result.publicKey);
      data.privateKey = await tryExportKey(result.privateKey);
    } else {
      data.key = await tryExportKey(result);
      data.keyRaw = await tryExportKeyRaw(result);
    }
    const entry = logCapture("generateKey", data);
    captured.generateKey.push(entry);
    return result;
  }) as typeof crypto.subtle.generateKey;

  // ── Hook: importKey ──
  crypto.subtle.importKey = (async (
    format: KeyFormat,
    keyData: JsonWebKey | BufferSource,
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> => {
    const result = await (_importKey as Function)(format, keyData, algorithm, true, keyUsages) as CryptoKey;
    const data: Record<string, unknown> = {
      format,
      algorithm: getAlgorithmName(algorithm),
      algorithmDetail: algorithm,
      originalExtractable: extractable,
      keyUsages,
    };
    if (format === "jwk") {
      data.keyData = keyData;
    } else if (format === "raw") {
      const bytes = keyData instanceof ArrayBuffer ? new Uint8Array(keyData) : new Uint8Array((keyData as Uint8Array).buffer);
      data.keyDataHex = bufToHex(bytes);
      data.keyDataB64 = bufToB64(bytes);
    } else {
      const bytes = keyData instanceof ArrayBuffer ? new Uint8Array(keyData) : new Uint8Array((keyData as Uint8Array).buffer);
      data.keyDataB64 = bufToB64(bytes);
    }
    data.exportedKey = await tryExportKey(result);
    const entry = logCapture("importKey", data);
    captured.importKey.push(entry);
    return result;
  }) as typeof crypto.subtle.importKey;

  // ── Hook: deriveKey ──
  crypto.subtle.deriveKey = (async (
    algorithm: AlgorithmIdentifier,
    baseKey: CryptoKey,
    derivedKeyAlgorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> => {
    const result = await (_deriveKey as Function)(algorithm, baseKey, derivedKeyAlgorithm, true, keyUsages) as CryptoKey;
    const data = {
      algorithm: getAlgorithmName(algorithm),
      algorithmDetail: algorithm,
      derivedKeyAlgorithm,
      originalExtractable: extractable,
      keyUsages,
      derivedKey: await tryExportKey(result),
      derivedKeyRaw: await tryExportKeyRaw(result),
    };
    const entry = logCapture("deriveKey", data);
    captured.deriveKey.push(entry);
    return result;
  }) as typeof crypto.subtle.deriveKey;

  // ── Hook: deriveBits ──
  crypto.subtle.deriveBits = (async (
    algorithm: AlgorithmIdentifier,
    baseKey: CryptoKey,
    length: number,
  ): Promise<ArrayBuffer> => {
    const result = await _deriveBits(algorithm, baseKey, length);
    logCapture("deriveBits", {
      algorithm: getAlgorithmName(algorithm),
      length,
      bitsHex: bufToHex(result),
    });
    return result;
  }) as typeof crypto.subtle.deriveBits;

  // ── Hook: sign ──
  crypto.subtle.sign = (async (
    algorithm: AlgorithmIdentifier,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer> => {
    const result = await _sign(algorithm, key, data);
    const entry = logCapture("sign", {
      algorithm: getAlgorithmName(algorithm),
      algorithmDetail: algorithm,
      keyInfo: await tryExportKey(key),
      dataSize: data instanceof ArrayBuffer ? data.byteLength : (data as Uint8Array).byteLength,
      signatureHex: bufToHex(result),
    });
    captured.sign.push(entry);
    return result;
  }) as typeof crypto.subtle.sign;

  // ── Hook: encrypt ──
  crypto.subtle.encrypt = (async (
    algorithm: AlgorithmIdentifier,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer> => {
    const algoName = getAlgorithmName(algorithm);
    let actualData: BufferSource = data;

    if (profileOverrides.enabled) {
      try {
        const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data as Uint8Array;
        const text = tryDecodeText(bytes);
        if (text) {
          const json = tryParseJSON(text);
          if (json && typeof json === "object") {
            const lzwChunk = zodParse(LZWChunkSchema, json);
            if (lzwChunk) {
              const innerText = decodeLZW(lzwChunk.data);
              if (innerText) {
                const innerJson = tryParseJSON(innerText);
                if (innerJson && typeof innerJson === "object" && rewriteManifestProfiles(innerJson)) {
                  const reEncoded = encodeLZW(JSON.stringify(innerJson));
                  if (reEncoded) {
                    const modified = { ...(json as Record<string, unknown>), data: bytesToB64(reEncoded) };
                    actualData = new TextEncoder().encode(JSON.stringify(modified));
                    console.log(PREFIX, "[Profile Override] PayloadChunk rewritten");
                  }
                }
              }
            } else if (rewriteManifestProfiles(json)) {
              actualData = new TextEncoder().encode(JSON.stringify(json));
              console.log(PREFIX, "[Profile Override] Plaintext JSON rewritten");
            }
          }
        }
      } catch (e) {
        console.warn(PREFIX, "[Profile Override] Error:", e);
      }
    }

    const actualBytes = actualData instanceof ArrayBuffer ? new Uint8Array(actualData) : actualData as Uint8Array;
    logMSLMessage("encrypt", actualBytes, algoName);
    const result = await _encrypt(algorithm, key, actualData);
    const entry = logCapture("encrypt", {
      algorithm: algoName,
      algorithmDetail: algorithm,
      keyInfo: await tryExportKey(key),
      plaintextSize: actualBytes.byteLength,
    });
    captured.encrypt.push(entry);
    return result;
  }) as typeof crypto.subtle.encrypt;

  // ── Hook: decrypt ──
  crypto.subtle.decrypt = (async (
    algorithm: AlgorithmIdentifier,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer> => {
    const result = await _decrypt(algorithm, key, data);
    const algoName = getAlgorithmName(algorithm);
    logMSLMessage("decrypt", result, algoName);
    const dataSize = data instanceof ArrayBuffer ? data.byteLength : (data as Uint8Array).byteLength;
    const entry = logCapture("decrypt", {
      algorithm: algoName,
      algorithmDetail: algorithm,
      keyInfo: await tryExportKey(key),
      ciphertextSize: dataSize,
      plaintextSize: result.byteLength,
    });
    captured.decrypt.push(entry);
    return result;
  }) as typeof crypto.subtle.decrypt;

  // ── Hook: wrapKey ──
  crypto.subtle.wrapKey = (async (
    format: KeyFormat,
    key: CryptoKey,
    wrappingKey: CryptoKey,
    wrapAlgorithm: AlgorithmIdentifier,
  ): Promise<ArrayBuffer> => {
    const result = await _wrapKey(format, key, wrappingKey, wrapAlgorithm);
    logCapture("wrapKey", {
      format,
      algorithm: getAlgorithmName(wrapAlgorithm),
      wrappedKeyB64: bufToB64(result),
    });
    return result;
  }) as typeof crypto.subtle.wrapKey;

  // ── Hook: unwrapKey ──
  crypto.subtle.unwrapKey = (async (
    format: KeyFormat,
    wrappedKey: BufferSource,
    unwrappingKey: CryptoKey,
    unwrapAlgo: AlgorithmIdentifier,
    unwrappedKeyAlgo: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[],
  ): Promise<CryptoKey> => {
    const result = await (_unwrapKey as Function)(format, wrappedKey, unwrappingKey, unwrapAlgo, unwrappedKeyAlgo, true, keyUsages) as CryptoKey;
    logCapture("unwrapKey", {
      format,
      unwrapAlgorithm: getAlgorithmName(unwrapAlgo),
      unwrappedKeyAlgorithm: unwrappedKeyAlgo,
      originalExtractable: extractable,
      keyUsages,
      unwrappedKey: await tryExportKey(result),
    });
    return result;
  }) as typeof crypto.subtle.unwrapKey;

  console.log(`${PREFIX} Web Crypto API hooks installed`);
}
