// ── 軽量 ZIP ビルダー (STORE / 無圧縮) ──
// ブラウザ環境で外部依存なしに ZIP ファイルを生成する。
// 全エントリは STORE (method=0) で格納する。

interface ZipEntry {
  name: Uint8Array; // UTF-8 encoded filename
  data: Uint8Array;
  crc32: number;
}

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function encodeUTF8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function writeU16(buf: Uint8Array, offset: number, val: number): void {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
}

function writeU32(buf: Uint8Array, offset: number, val: number): void {
  buf[offset] = val & 0xff;
  buf[offset + 1] = (val >>> 8) & 0xff;
  buf[offset + 2] = (val >>> 16) & 0xff;
  buf[offset + 3] = (val >>> 24) & 0xff;
}

export class ZipBuilder {
  private entries: ZipEntry[] = [];

  /** ファイルを追加 (パスは "dir/file.json" 形式) */
  addFile(path: string, content: string | Uint8Array): void {
    const data = typeof content === "string" ? encodeUTF8(content) : content;
    this.entries.push({
      name: encodeUTF8(path),
      data,
      crc32: crc32(data),
    });
  }

  /** JSON オブジェクトをファイルとして追加 */
  addJSON(path: string, obj: unknown): void {
    this.addFile(path, JSON.stringify(obj, null, 2));
  }

  /** ZIP バイナリを生成 */
  build(): Uint8Array {
    // サイズ計算
    let localSize = 0;
    for (const e of this.entries) {
      localSize += 30 + e.name.length + e.data.length;
    }
    let centralSize = 0;
    for (const e of this.entries) {
      centralSize += 46 + e.name.length;
    }
    const totalSize = localSize + centralSize + 22;
    const buf = new Uint8Array(totalSize);
    let offset = 0;
    const offsets: number[] = [];

    // Local file headers + data
    for (const e of this.entries) {
      offsets.push(offset);
      // signature
      writeU32(buf, offset, 0x04034b50); offset += 4;
      // version needed
      writeU16(buf, offset, 20); offset += 2;
      // flags (bit 11 = UTF-8)
      writeU16(buf, offset, 0x0800); offset += 2;
      // compression method (STORE)
      writeU16(buf, offset, 0); offset += 2;
      // mod time / date
      writeU16(buf, offset, 0); offset += 2;
      writeU16(buf, offset, 0); offset += 2;
      // crc32
      writeU32(buf, offset, e.crc32); offset += 4;
      // compressed size
      writeU32(buf, offset, e.data.length); offset += 4;
      // uncompressed size
      writeU32(buf, offset, e.data.length); offset += 4;
      // filename length
      writeU16(buf, offset, e.name.length); offset += 2;
      // extra field length
      writeU16(buf, offset, 0); offset += 2;
      // filename
      buf.set(e.name, offset); offset += e.name.length;
      // data
      buf.set(e.data, offset); offset += e.data.length;
    }

    // Central directory
    const centralStart = offset;
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];
      // signature
      writeU32(buf, offset, 0x02014b50); offset += 4;
      // version made by
      writeU16(buf, offset, 20); offset += 2;
      // version needed
      writeU16(buf, offset, 20); offset += 2;
      // flags (UTF-8)
      writeU16(buf, offset, 0x0800); offset += 2;
      // compression method (STORE)
      writeU16(buf, offset, 0); offset += 2;
      // mod time / date
      writeU16(buf, offset, 0); offset += 2;
      writeU16(buf, offset, 0); offset += 2;
      // crc32
      writeU32(buf, offset, e.crc32); offset += 4;
      // compressed size
      writeU32(buf, offset, e.data.length); offset += 4;
      // uncompressed size
      writeU32(buf, offset, e.data.length); offset += 4;
      // filename length
      writeU16(buf, offset, e.name.length); offset += 2;
      // extra field length
      writeU16(buf, offset, 0); offset += 2;
      // comment length
      writeU16(buf, offset, 0); offset += 2;
      // disk number start
      writeU16(buf, offset, 0); offset += 2;
      // internal attributes
      writeU16(buf, offset, 0); offset += 2;
      // external attributes
      writeU32(buf, offset, 0); offset += 4;
      // local header offset
      writeU32(buf, offset, offsets[i]); offset += 4;
      // filename
      buf.set(e.name, offset); offset += e.name.length;
    }

    // End of central directory
    writeU32(buf, offset, 0x06054b50); offset += 4;
    // disk number
    writeU16(buf, offset, 0); offset += 2;
    // disk with central dir
    writeU16(buf, offset, 0); offset += 2;
    // entries on disk
    writeU16(buf, offset, this.entries.length); offset += 2;
    // total entries
    writeU16(buf, offset, this.entries.length); offset += 2;
    // central dir size
    writeU32(buf, offset, centralSize); offset += 4;
    // central dir offset
    writeU32(buf, offset, centralStart); offset += 4;
    // comment length
    writeU16(buf, offset, 0); offset += 2;

    return buf;
  }
}
