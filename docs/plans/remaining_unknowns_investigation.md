# Work Plan: Remaining Unknowns Investigation

Date: 2026-04-09

## Goal

key 33.6 の未解明部分 (CBOR ヘッダ、リクエスト固有領域、144B バリアント) と kAppBootKey/kAppBootEccKey の用途を特定する。

## Tasks

### Python Engineer (データ分析)
- [ ] 1. 239 サンプルの CBOR ヘッダ (128B) をデコードし、固定バイトと可変バイトを特定
- [ ] 2. リクエスト固有領域 (64B) をパースし、メッセージ ID / タイムスタンプを識別
- [ ] 3. 144B バリアント (17 サンプル) と 352B バリアントの構造差分を分析

### Reverse Engineer (静的解析)
- [ ] 4. NFWebCrypto で kAppBootKey / kAppBootEccKey のシンボル参照先を特定し、使用コードパスを解明

## Execution Order

1. Parallel: タスク 1-3 (Python データ分析) + タスク 4 (静的解析)
2. Sequential: 結果統合 + ドキュメント更新

## Deliverables

- `tools/analyze_key336_structure.py`: CBOR ヘッダ + 固有領域 + 144B バリアント解析
- `docs/spec/msl_key336_plaintext_structure.md`: key 33.6 平文の完全な構造仕様
- kAppBootKey / kAppBootEccKey の用途レポート

## Risks / Notes

- CBOR ヘッダが Argo バイナリ内で構築されるため、NFWebCrypto の静的解析だけでは解明不可
- 144B バリアントは少数 (17/239) のためサンプル不足の可能性
