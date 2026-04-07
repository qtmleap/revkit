# 作業計画書: iOS MSL/appboot セッション鍵キャプチャと Python 完全再現

日時: 2026-04-07T00:00:00+09:00

## 目標

iOS Netflix の MSL 及び appboot で復号できていないメッセージの暗号化鍵を取得し、最終的に Python コードだけで完全再現できるようにする。

## 現状の課題

- DH 共有シークレット (`NFWebCrypto::dhDerive()`) が未キャプチャ
- HKDF 出力 (セッション鍵導出) が未キャプチャ
- CCCrypt で取れている鍵に KAT/TFIT ノイズが混在
- Python MSL クライアントが Scheme 3 (DH/ECDH) に未対応
- Tweak の MslClient offset フックが ElleKit で失敗

## タスク一覧

### frida-engineer 担当

- [x] **F1: NFWebCrypto シンボル列挙と dhDerive/HKDF 関数の特定**
  - NFWebCrypto.framework のエクスポートシンボルをスキャンし、dhDerive / HKDF 関連関数のアドレスを特定
  - CommonCrypto の `CCKeyDerivationHMAC` も候補として調査

- [x] **F2: HKDF フック実装** (最優先)
  - HKDF 関数の入力 (ikm=DH共有シークレット, salt, info, length) と出力 (導出鍵) をキャプチャ
  - これが取れれば DH フック不要で直接セッション鍵が得られる

- [x] **F3: NFWebCrypto::dhDerive() フック実装** (F2 の fallback)
  - ECDH 共有シークレットの raw bytes をキャプチャ
  - F2 が取れない場合のバックアップ

- [x] **F4: IosSessionCryptoContext コンストラクタフック**
  - セッション確立時の AES 暗号鍵と HMAC 鍵のペアを this ポインタから読み出し
  - F2/F3 と独立して並行実施可能

- [x] **F5: CCCrypt フックの呼び出し元フィルタリング**
  - `Thread.backtrace()` で NFWebCrypto/MslClient フレームを含む呼び出しのみ記録
  - KAT/TFIT ノイズを除外

### tweak-engineer 担当

- [x] **T1: MslClient シンボル解決を dlsym 方式に変更**
  - offset ベースのフックを廃止し、`dlopen` + `dlsym` で `_aesCbcEncrypt` 等のシンボルを解決
  - ElleKit の offset フック失敗を回避

- [x] **T2: `_dyld_register_func_for_add_image` による遅延ロード対応**
  - MslClient が bootstrapTweak() 時点で未ロードの場合のリトライ機構
  - dyld ロード完了時にフック関数を差し込む

- [x] **T3: EVP_CipherInit_ex ログの MSL 文脈フィルタリング**
  - `backtrace()` でコールスタックを取得し、MslClient 起因の呼び出しのみログ出力

### python-engineer 担当

- [x] **P1: Frida 鍵素材の取り込みインターフェース**
  - `import_session_keys(enc_key: bytes, sign_key: bytes)` の実装
  - Scheme 3 の鍵を外部注入してセッションを構成

- [x] **P2: CBOR MSL レスポンスの復号パイプライン**
  - `msl_decoder.py` と `client.py` のセッション鍵を連携
  - CBOR バイナリ → パース → AES-CBC 復号 → 平文 JSON 抽出

- [x] **P3: キャプチャバイナリのオフライン検証 CLI**
  - Frida/mitmproxy でキャプチャした `.bin` + 鍵素材 JSON を入力
  - 復号結果を標準出力するスクリプト (`tools/` 配下)

- [x] **P4: CBOR MSL リクエストのエンコーダー実装**
  - JSON ベースのリクエスト構築を iOS 向け CBOR フォーマットに対応
  - 数値キーマッピングは `msl_decoder.py` の逆引き

- [x] **P5: FAIRPLAY_MGK_APPID エンティティ認証データの組み立て**
  - apphmac, appid, devicetoken, ESN 等の CBOR エンコード
  - iOS appboot リクエストの完全生成

## 実行順序

### Phase A: 鍵キャプチャ (並列)
1. **並列:** F1 (シンボル列挙) + T1 (dlsym 方式) + T2 (dyld 遅延ロード) + P1 (鍵取り込み口)
2. **依存:** F1 完了後 → F2 (HKDF フック) + F3 (dhDerive フック) + F4 (コンストラクタフック) を並列
3. **並列:** F5 (CCCrypt フィルタ) + T3 (EVP フィルタ)

### Phase B: 復号パイプライン (Phase A の鍵取得後)
4. **並列:** P2 (CBOR 復号パイプライン) + P3 (オフライン検証 CLI)

### Phase C: リクエスト完全再現
5. **順次:** P4 (CBOR エンコーダー) → P5 (entity auth)

## 成果物

- `packages/frida/hook_netflix_ios.js`: dhDerive/HKDF/IosSessionCryptoContext フック追加
- `packages/tweak/NetflixSSLBypass/Sources/NetflixSSLBypass/Tweak.x.swift`: dlsym 方式 + dyld 遅延ロード
- `src/netflix_msl/crypto.py`: Scheme 3 鍵取り込みインターフェース
- `src/netflix_msl/cbor_client.py`: iOS CBOR MSL クライアント (新規)
- `tools/decrypt_capture.py`: オフライン復号検証 CLI (新規)

## リスク・注意点

- NFWebCrypto 内の HKDF が CommonCrypto 経由でない場合、シンボル特定に時間がかかる可能性
- dhDerive のシンボルが strip されている可能性 → offset フォールバック必要
- Scheme 3 の鍵導出パラメータ (salt, info) が不明 → Frida キャプチャで判明するまで Python 側は仮実装
- Tweak の dlsym が MslClient の C++ mangled name で失敗する可能性 → nm で事前確認
