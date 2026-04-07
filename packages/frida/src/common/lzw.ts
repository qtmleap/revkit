// ── LZW Decoder (Netflix MSL variant) ──

import { base64ToBytes, utf8Decode } from "./base64";

export function decodeLZW(input: string | Uint8Array): string | null {
    try {
        let bytes: Uint8Array;
        if (typeof input === "string") {
            const decoded = base64ToBytes(input);
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
        return utf8Decode(new Uint8Array(output));
    } catch {
        return null;
    }
}
