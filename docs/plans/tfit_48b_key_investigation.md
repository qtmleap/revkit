# Work Plan: 48B HMAC 鍵と DH Public Key TFIT エンコードの調査

Date: 2026-04-09

## Goal

1. 48B HMAC 鍵の生成メカニズムを特定する
2. DH 公開鍵 → key 33.6 (352B/144B) の TFIT エンコード方法を解明する

## Tasks

### Reverse Engineer (静的解析)
- [ ] 1. radare2 で `nflxDhDerive` (0x0feec) を逆アセンブリし、HMAC 呼び出しへの 48B 鍵の流れを特定
- [ ] 2. Ghidra headless で `nflxDhDerive` をデコンパイルし、SHA384 → 48B 鍵の入力を特定
- [ ] 3. `genModelGroupKeys` (0x1db74) をデコンパイルし、TFIT テーブル選択と DH 公開鍵エンコードロジックを解明
- [ ] 4. NFWebCrypto のデータセグメントで TFIT テーブル候補 (4KB+ 中エントロピー領域) をスキャン

### Frida Engineer (動的解析)
- [ ] 5. `HMAC_Init_ex` にスタックトレース付きフックを追加し、48B 鍵設定時のコールチェーンを取得
- [ ] 6. `EVP_KDF_derive` / `EVP_PKEY_derive` をフックし、DH 後に KDF が呼ばれるか確認
- [ ] 7. DH_compute_key 出力バッファからの memcpy/memmove をトレースし、48B 鍵バッファへの書き込みを追跡

### Tweak Engineer (動的解析)
- [ ] 8. SHA384 (one-shot) フックを追加 — 48B 鍵が SHA384 出力なら入力データを特定
- [ ] 9. `_TFIT_wbaes_ecb_encrypt_iAES11` シンボルをフックし、key 33.6 構築時の TFIT ECB 暗号化を追跡

### Python Engineer (エミュレーション)
- [ ] 10. Unicorn Engine で NFWebCrypto の TFIT 関数を ARM64 エミュレートし、DH 公開鍵 → key 33.6 変換を再現
- [ ] 11. 48B 鍵の導出が判明したら `derive_initial_session_keys()` を更新し、Tweak/Frida 非依存にする

## Execution Order

1. **並列 — 静的解析 + 動的解析**
   - RE: タスク 1-4 (Ghidra/r2 で関数解析)
   - Frida: タスク 5-7 (スタックトレース + KDF フック)
   - Tweak: タスク 8-9 (SHA384 + TFIT フック追加)
2. **順次 — 相関分析**
   - 静的解析で特定した関数アドレスと動的解析のログを照合
3. **順次 — エミュレーション**
   - タスク 10-11 (判明したアルゴリズムを Unicorn + Python で再現)

## Deliverables

- `docs/spec/msl_48b_key_derivation.md`: 48B 鍵の導出アルゴリズム文書
- `tools/re/analyze_nflxDhDerive.py`: r2pipe による nflxDhDerive 解析スクリプト
- `tools/emulate_tfit.py`: Unicorn による TFIT エミュレーション
- `src/netflix_msl/crypto.py`: 更新版 (48B 鍵自力導出)

## Key Hypothesis (静的解析から)

RE エージェントの予備調査により:
- **48B 鍵 = SHA384(AppleNativeKey.getBytes())** — DH コンテキストの `+0x28` オフセットに格納された鍵オブジェクトの SHA384 ハッシュ
- `nflxDhDerive` (0x0feec) 内の 0x10174 で `SHA384` が呼ばれ、その出力が 0x101a0 の `HMAC` に渡される
- `genModelGroupKeys` (0x1db74) が TFIT テーブル (`_TFIT_key_iAES11_mgkiPhone`) を使用して DH 公開鍵をエンコード

## Risks / Notes

- `nflxDhDerive` のアドレスは静的解析の推定であり、ASLR で実行時にずれる
- Unicorn エミュレーションは Mach-O ロード + リロケーション処理が必要
- TFIT テーブルがバイナリバージョンに依存するため、バージョン 15.48.1 固有の結果になる
