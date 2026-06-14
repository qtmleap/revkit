# @ultemica/yaneuraou-wasm-mobility-cfworkers

Cloudflare Workers 上で動作するやねうら王 (YaneuraOu) 将棋エンジンの WASM パッケージ。

Mobility (KIKI) 評価関数 — 駒種×距離×方向 164 params を Ridge fit した学習済み小型線形評価。
重みは WASM バイナリに焼き込み済みなので、外部の評価関数ファイルは不要。

## 仕様

- エンジン: YaneuraOu Mobility (KIKI) (V8.50) — 学習済み 164 次元線形評価関数
- 評価関数: 同梱 (`eval/mobility/mobility_weights_embedded.cpp`、外部ファイル不要)
- スレッド: 1 固定 (Workers は SharedArrayBuffer 不可)
- WASM SIMD: 有効 (V8 対応)
- メモリ: 64MB initial / 128MB max / 2MB stack

## セットアップ

### 1. ファイル配置

```
your-worker/
  src/
    index.ts          # Worker エントリ
  public/
    eval/nn.bin       # 評価関数 (Static Assets)
    book/user_book1.db  # 定跡 (任意)
  lib/
    yaneuraou.js      # このパッケージから
    yaneuraou.wasm    # このパッケージから
    index.js          # このパッケージから (createEngine)
    index.d.ts        # 型定義
```

### 2. Worker コード

```ts
import { createEngine, type Engine, type EvalResult } from "./lib/index.js";
import YaneuraOuFactory from "./lib/yaneuraou.js";

let enginePromise: Promise<Engine> | null = null;

function getEngine(env: Env): Promise<Engine> {
  if (!enginePromise) {
    enginePromise = (async () => {
      const evalBin = await env.ASSETS.fetch("https://dummy/eval/nn.bin")
        .then((r) => r.arrayBuffer());

      // 定跡 (任意)
      const bookDb = await env.ASSETS.fetch("https://dummy/book/user_book1.db")
        .then((r) => r.arrayBuffer())
        .catch(() => undefined);

      return createEngine({
        factory: YaneuraOuFactory,
        wasmBinary: undefined as any,
        evalBin,
        bookDb,
        bookFile: bookDb ? "user_book1.db" : undefined,
        usiHash: 16,
      });
    })();
  }
  return enginePromise;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const { sfen, byoyomi = 1000 } = await req.json<{
      sfen: string;
      byoyomi?: number;
    }>();

    const engine = await getEngine(env);
    const result = await engine.eval({ sfen, byoyomi });
    return Response.json(result);
  },
};
```

### 3. wrangler.toml

```toml
name = "shogi-engine"
main = "src/index.ts"
compatibility_date = "2024-01-01"
assets = { directory = "./public" }

[vars]
# 環境変数があれば
```

## API

### `createEngine(opts): Promise<Engine>`

エンジンを初期化する。Isolate のライフサイクルで 1 回だけ呼ぶ。

| オプション | 型 | 必須 | 説明 |
|---|---|---|---|
| `factory` | `YaneuraOuFactory` | yes | `yaneuraou.js` の default export |
| `wasmBinary` | `ArrayBuffer` | no | `.wasm` バイナリ。bundler が自動解決する場合は省略可 |
| `evalBin` | `ArrayBuffer` | no | NNUE 評価関数 (nn.bin) の中身 |
| `evalFile` | `string` | no | MEMFS 上のファイル名。デフォルト `"nn.bin"` |
| `bookDb` | `ArrayBuffer` | no | 定跡ファイルの中身 |
| `bookFile` | `string` | no | 定跡ファイル名。`bookDb` を渡すときは必須 |
| `usiHash` | `number` | no | ハッシュテーブル MB。デフォルト `16` |

### `engine.eval(req): Promise<EvalResult>`

1 局面を評価する。内部で自動直列化されるので並行呼び出し可。

| フィールド | 型 | 説明 |
|---|---|---|
| `sfen` | `string` | SFEN 文字列 |
| `byoyomi` | `number` | 思考時間 ms (デフォルト 500)。`go movetime` として発行 |
| `skillLevel` | `number` | 0-20。デフォルト 20 (全力) |
| `multiPv` | `number` | MultiPV。デフォルト 1 |
| `depthLimit` | `number` | 探索深さ上限。0 = 無制限 |
| `nodesLimit` | `number` | ノード数上限。0 = 無制限 |

### `EvalResult`

```ts
{
  bestmove: string;       // "2g2f"
  ponder: string | null;  // "8c8d"
  score: {
    kind: "cp" | "mate";
    value: number;        // centipawn or mate count
    bound?: "lowerbound" | "upperbound";
  } | null;
  depth: number | null;
  nodes: number | null;
  timeMs: number | null;
  pv: string[] | null;    // ["2g2f", "8c8d", "7g7f", ...]
}
```

### `engine.evalBatch(reqs): Promise<EvalResult[]>`

複数局面を一括評価。Batch 内では `usinewgame` を送らないので置換表が再利用される。
棋譜のように手順が連続する局面列では、同じ思考時間でも実効探索深さが伸びる。

### `engine.send(cmd: string)`

生の USI コマンドを送る。上級者向け。

### `engine.dispose()`

エンジンを破棄する。

## 評価関数と定跡の入手先

| ファイル | URL | サイズ |
|---|---|---|
| suishopetite nn.bin (KP256) | 本パッケージの WASM に対応する評価関数。別途配布 | 873KB |
| 100テラショック定跡 | `https://github.com/yaneurao/YaneuraOu/releases/download/BOOK-100T-Shock/100T-shock-book.zip` | 4.7MB |

## 制約

| 項目 | 値 |
|---|---|
| WASM メモリ上限 | 128MB |
| 評価関数 | KP256 のみ (HalfKP 62MB は OOM) |
| 定跡 | 100テラショック (4.7MB) まで。700テラ (32MB) は OOM |
| スレッド | 1 固定 |
| CPU 時間 | Workers paid plan: 30 秒/req |
| 探索中の stop | 不可 (single-thread のため) |

## ライセンス

GPL-3.0 (YaneuraOu 本体のライセンスに準拠)
