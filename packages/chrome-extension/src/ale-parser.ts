// ── ALE (Adaptive Licensed Experience) Provision パーサー ──
// keyx.scheme=CLEAR の場合、新しい MSL 鍵が平文で keyx.data.key に含まれる。
// keyx.data.key は 32 バイト (b64url): bytes[0:16]=HMAC鍵, bytes[16:32]=AES-CBC鍵

import type { AleKeys } from "./types";
import { bufToHex, b64urlToBytes } from "./utils";
import {
  ProvisionResultSchema,
  ProvisionTokenSchema,
  JWEHeaderSchema,
  zodParse,
  zodParseJSON,
} from "./schemas";

export function extractAleKeys(payload: unknown): AleKeys | null {
  const provResult = zodParse(ProvisionResultSchema, payload);
  if (!provResult) return null;

  const tokenObj = zodParseJSON(ProvisionTokenSchema, provResult.provisionResponse);
  if (!tokenObj) return null;

  const keyx = tokenObj.keyx;
  const keyBytes = b64urlToBytes(keyx.data.key);
  if (!keyBytes || keyBytes.length < 32) return null;

  const hmacHex = bufToHex(keyBytes.slice(0, 16));
  const aesHex = bufToHex(keyBytes.slice(16, 32));

  // JWE ヘッダー情報
  const jweToken = tokenObj.token;
  let jweAlg = "?";
  let jweEnc = "?";
  if (jweToken) {
    try {
      const parts = jweToken.split(".");
      if (parts.length === 5) {
        const hdrB64 = parts[0].replace(/-/g, "+").replace(/_/g, "/");
        const padded = hdrB64 + "=".repeat((4 - (hdrB64.length % 4)) % 4);
        const hdr = zodParseJSON(JWEHeaderSchema, atob(padded));
        if (hdr) {
          jweAlg = hdr.alg ?? "?";
          jweEnc = hdr.enc ?? "?";
        }
      }
    } catch { /* ignore */ }
  }

  console.log(
    "[MSL-Capture] [ALE] New MSL keys extracted:",
    `\n  HMAC-SHA256 : ${hmacHex}`,
    `\n  AES-CBC     : ${aesHex}`,
    `\n  KID         : ${keyx.kid}`,
    `\n  JWE alg/enc : ${jweAlg}/${jweEnc}`,
  );

  return {
    encryptionKey: aesHex,
    hmacKey: hmacHex,
    kid: keyx.kid,
    jweToken: jweToken ?? "",
    scheme: keyx.scheme,
    rawKeyHex: bufToHex(keyBytes),
    capturedAt: new Date().toISOString(),
  };
}
