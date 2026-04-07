// ── PSSH / KID パーサー ──

import { bufToHex, bufToB64, formatKID, identifySystem } from "./utils";

export interface PSSHBox {
  version: number;
  systemId: string;
  systemName: string;
  kids?: string[];
  data_b64?: string;
  data_hex?: string;
}

export interface ParsedPSSH {
  raw_b64: string;
  raw_hex: string;
  boxes: PSSHBox[];
}

export function parsePSSH(initData: Uint8Array): ParsedPSSH {
  const view = new DataView(initData.buffer, initData.byteOffset, initData.byteLength);
  const result: ParsedPSSH = {
    raw_b64: bufToB64(initData),
    raw_hex: bufToHex(initData),
    boxes: [],
  };

  let offset = 0;
  while (offset < view.byteLength) {
    if (offset + 8 > view.byteLength) break;
    const boxSize = view.getUint32(offset);
    if (boxSize < 8 || offset + boxSize > view.byteLength) break;

    const boxType = String.fromCharCode(
      view.getUint8(offset + 4),
      view.getUint8(offset + 5),
      view.getUint8(offset + 6),
      view.getUint8(offset + 7),
    );

    if (boxType === "pssh") {
      const version = view.getUint8(offset + 8);
      const systemId = bufToHex(new Uint8Array(initData.buffer, initData.byteOffset + offset + 12, 16));
      const box: PSSHBox = { version, systemId, systemName: identifySystem(systemId) };

      if (version === 1) {
        const kidCount = view.getUint32(offset + 28);
        box.kids = [];
        for (let i = 0; i < kidCount; i++) {
          const kidOffset = offset + 32 + i * 16;
          if (kidOffset + 16 <= offset + boxSize) {
            box.kids.push(formatKID(bufToHex(new Uint8Array(initData.buffer, initData.byteOffset + kidOffset, 16))));
          }
        }
      }

      let dataOffset: number;
      let dataSize: number;
      if (version === 0) {
        dataSize = view.getUint32(offset + 28);
        dataOffset = offset + 32;
      } else {
        const kidCount = view.getUint32(offset + 28);
        dataOffset = offset + 32 + kidCount * 16 + 4;
        dataSize = dataOffset + 4 <= offset + boxSize ? view.getUint32(dataOffset - 4) : 0;
      }
      if (dataSize && dataOffset + dataSize <= offset + boxSize) {
        box.data_b64 = bufToB64(new Uint8Array(initData.buffer, initData.byteOffset + dataOffset, dataSize));
        box.data_hex = bufToHex(new Uint8Array(initData.buffer, initData.byteOffset + dataOffset, dataSize));
      }

      result.boxes.push(box);
    }
    offset += boxSize;
  }
  return result;
}
