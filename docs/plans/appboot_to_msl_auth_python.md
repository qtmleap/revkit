# Work Plan: Pure Python App-Boot to MSL Authentication
Date: 2026-04-09

## Goal
appboot から MSL 認証までの全フローを純粋な Python で実行可能にする。
未知の値の出所を調査し、バイナリにハードコードされている場合はその箇所を特定・報告する。

## Tasks

### Reverse Engineer (静的バイナリ解析)
- [x] NFWebCrypto.framework から `kAppBootKey` (RSA-4096 SPKI/DER) を抽出 → `constants.IOS_APPBOOT_RSA_KEY_DER`
- [x] NFWebCrypto.framework から `kAppBootEccKey` (ECDSA P-256 SPKI/DER) を抽出 → `constants.IOS_APPBOOT_ECC_KEY_DER`
- [x] DH prime `p` (1024-bit, 128B) の完全な値を確認 → MslClient @ `0x001265a0` → `constants.IOS_DH_P`
- [x] `apphmac` の HMAC 鍵素材を特定 → **ハードコード鍵なし、全 6 call site がランタイム導出**
- [x] `device_key_data` (6,576B) の構築ロジックを解明 → **CBOR ランタイム組立 (IosMGKAuthenticationData)**
- [x] `devicetoken` の生成関数を特定 → **Nbp.framework NRM サービスからランタイム取得**

### Frida Engineer (ランタイムキャプチャ)
- [x] `hook_entityauth_capture.js` 作成: devicetoken / apphmac / device_key_data キャプチャ
- [x] `hook_nfwebcrypto_keys.js` 作成: kAppBootKey / kAppBootEccKey をメモリスキャン + importKey フック
- [x] `hook_appboot_dh.js` 拡張: DH prime `p` の完全な 128B をログ出力

### Python Engineer (実装)
- [x] `crypto.py`: DH 鍵生成/共有秘密計算ラッパー (`cryptography` ライブラリ使用)
- [x] `crypto.py`: Phase 0 MGK 導出の統合 (`emulate_tfit.py` をライブラリとして呼び出し)
- [x] `crypto.py`: Phase 3 KDF 配線 (enc_key_0, sign_key_0 → enc_key_1, sign_key_1, session_bind)
- [x] `crypto.py`: Phase 2 KDF 配線 (session_bind → 48B key → HMAC-SHA384 → session keys)
- [x] `cbor_encoder.py`: appboot CBOR リクエストビルダー (entity_auth_data + key_request_data)
- [x] `cbor_decoder.py`: appboot CBOR レスポンスパーサー (key 33.6, 33.9, nfvdid, deviceIdToken 抽出)
- [x] 新規 `ios_client.py`: エンドツーエンド iOS MSL セッションオーケストレーター
- [x] `tools/verify_full_key_chain.py`: 既知テストベクトルによる全フェーズ回帰テスト (12/12 PASS)

## Execution Order

1. **Parallel (Phase A — 調査)**:
   - RE: バイナリ解析 (kAppBootKey, kAppBootEccKey, DH prime, apphmac key, device_key_data, devicetoken)
   - Frida: ランタイムキャプチャフック作成 & 実行
2. **Sequential (Phase B — Python 実装 / 調査結果依存)**:
   - Python: DH ラッパー + KDF 配線 (DH prime 確定後)
   - Python: appboot リクエスト/レスポンスビルダー (entity_auth_data 構造確定後)
3. **Sequential (Phase C — 統合)**:
   - Python: ios_client.py オーケストレーター
   - Python: 回帰テスト

## Deliverables
- `src/netflix_msl/ios_client.py`: iOS appboot → MSL 認証の Python クライアント
- `src/netflix_msl/crypto.py`: DH + 全 KDF フェーズ統合
- `src/netflix_msl/cbor_encoder.py`: appboot CBOR リクエスト構築
- `src/netflix_msl/cbor_decoder.py`: appboot CBOR レスポンス解析
- `tools/verify_full_key_chain.py`: エンドツーエンド回帰テスト
- `packages/frida/hook_entityauth_capture.js`: entity_auth_data 値キャプチャ
- `packages/frida/hook_nfwebcrypto_keys.js`: 署名検証鍵ダンプ
- `docs/spec/unknown_values_report.md`: 未知の値の調査結果レポート

## Unknown Values (調査対象)

| 値 | サイズ | 現状 | 出所 |
|----|--------|------|------|
| `kAppBootKey` | 550B (RSA-4096 DER) | **抽出済み** | NFWebCrypto @ `0x0020cd31` (Base64) |
| `kAppBootEccKey` | 91B (P-256 DER) | **抽出済み** | NFWebCrypto @ `0x0020d10c` (Base64) |
| `devicetoken` | 216B protobuf | **要ランタイムキャプチャ** | Nbp.framework NRM サービス応答 |
| `apphmac` | 32B HMAC-SHA256 | **要ランタイムキャプチャ** | ランタイム導出 (固定鍵なし) |
| `device_key_data` | ~6,576B | **構造解明済み** | CBOR ランタイム組立 (IosMGKAuthenticationData) |
| DH prime `p` | 128B | **抽出済み** | MslClient @ `0x001265a0` (__TEXT.__const) |

## Risks / Notes
- `devicetoken` はデバイス固有値の可能性が高く、Python 単体での生成は不可能かもしれない → キャプチャした値のハードコードで代替
- `device_key_data` も同様にデバイス固有の可能性あり
- appboot.netflix.com は SSL ピンニングあり → Python からの直接接続にはプロキシ経由が必要
- TFIT WB-AES エミュレーションは Unicorn 依存 (ARM64 エミュレータ)
