// ── ユーティリティ関数 ──

export function safeStringify(obj: unknown): string {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

export function toBytes(source: ArrayBuffer | Uint8Array): Uint8Array {
  if (source instanceof Uint8Array) return source;
  return new Uint8Array(source);
}

export function bufToHex(buf: ArrayBuffer | Uint8Array): string {
  return Array.from(toBytes(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function bufToB64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = toBytes(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function tryDecodeText(buf: ArrayBuffer | Uint8Array): string | null {
  try {
    const bytes = toBytes(buf);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    let nonPrintable = 0;
    for (let i = 0; i < Math.min(text.length, 256); i++) {
      const c = text.charCodeAt(i);
      if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) nonPrintable++;
    }
    if (nonPrintable > text.length * 0.1) return null;
    return text;
  } catch {
    return null;
  }
}

export function tryParseJSON(text: string | null): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function tryDecodeB64(str: string): string | null {
  try {
    return atob(str);
  } catch {
    return null;
  }
}

export function b64ToBytes(str: string): Uint8Array | null {
  try {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

export function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function formatSize(bytes: number | undefined): string {
  if (!bytes || bytes <= 0) return "?";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(0) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

export function formatKID(hex: string): string {
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export function identifySystem(systemIdHex: string): string {
  const systems: Record<string, string> = {
    "edef8ba979d64acea3c827dcd51d21ed": "Widevine",
    "9a04f07998404286ab92e65be0885f95": "PlayReady",
    "1077efecc0b24d02ace33c1e52e2fb4b": "W3C Common (cenc)",
  };
  return systems[systemIdHex] ?? "Unknown";
}

export function getAlgorithmName(algorithm: AlgorithmIdentifier): string {
  return typeof algorithm === "string" ? algorithm : algorithm.name;
}

export function b64urlToBytes(b64url: string): Uint8Array | null {
  const pad = (4 - (b64url.length % 4)) % 4;
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return b64ToBytes(b64);
}

// ── LZW Decoder (Netflix MSL variant) ──

export function decodeLZW(input: string | Uint8Array): string | null {
  try {
    let bytes: Uint8Array;
    if (typeof input === "string") {
      const decoded = b64ToBytes(input);
      if (!decoded) return null;
      bytes = decoded;
    } else {
      bytes = input;
    }
    if (bytes.length === 0) return null;

    let bitPos = 0;
    const totalBits = bytes.length * 8;

    function readBits(n: number): number {
      if (bitPos + n > totalBits) return -1;
      let val = 0;
      for (let i = 0; i < n; i++) {
        const byteIdx = (bitPos + i) >> 3;
        const bitIdx = 7 - ((bitPos + i) & 7);
        if (bytes[byteIdx] & (1 << bitIdx)) val |= 1 << (n - 1 - i);
      }
      bitPos += n;
      return val;
    }

    const dict: number[][] = [];
    for (let i = 0; i < 256; i++) dict[i] = [i];

    let bits = 8;
    const output: number[] = [];
    let code = readBits(bits);
    if (code === -1 || !dict[code]) return null;
    let prev = dict[code];
    for (let i = 0; i < prev.length; i++) output.push(prev[i]);

    while (true) {
      if (dict.length === 1 << bits) bits++;
      code = readBits(bits);
      if (code === -1) break;
      let entry: number[];
      if (code < dict.length) {
        entry = dict[code];
      } else if (code === dict.length) {
        entry = prev.concat([prev[0]]);
      } else {
        break;
      }
      for (let i = 0; i < entry.length; i++) output.push(entry[i]);
      dict.push(prev.concat([entry[0]]));
      prev = entry;
    }
    return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(output));
  } catch {
    return null;
  }
}

// ── LZW Encoder (Netflix MSL variant) ──

export function encodeLZW(input: string | Uint8Array): Uint8Array | null {
  try {
    let bytes: Uint8Array;
    if (typeof input === "string") {
      bytes = new TextEncoder().encode(input);
    } else {
      bytes = input;
    }
    if (bytes.length === 0) return null;

    const dict = new Map<string, number>();
    for (let i = 0; i < 256; i++) dict.set(String.fromCharCode(i), i);
    let nextCode = 256;
    let bits = 8;
    const codes: Array<{ code: number; bits: number }> = [];
    let w = String.fromCharCode(bytes[0]);

    for (let i = 1; i < bytes.length; i++) {
      const c = String.fromCharCode(bytes[i]);
      const wc = w + c;
      if (dict.has(wc)) {
        w = wc;
      } else {
        codes.push({ code: dict.get(w)!, bits });
        dict.set(wc, nextCode++);
        if (nextCode > 1 << bits) bits++;
        w = c;
      }
    }
    codes.push({ code: dict.get(w)!, bits });

    const outBits: number[] = [];
    for (const { code, bits: b } of codes) {
      for (let i = b - 1; i >= 0; i--) outBits.push((code >> i) & 1);
    }
    const outBytes = new Uint8Array(Math.ceil(outBits.length / 8));
    for (let i = 0; i < outBits.length; i++) {
      if (outBits[i]) outBytes[i >> 3] |= 1 << (7 - (i & 7));
    }
    return outBytes;
  } catch {
    return null;
  }
}
