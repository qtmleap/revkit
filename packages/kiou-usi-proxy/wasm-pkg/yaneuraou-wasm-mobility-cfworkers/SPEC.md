# YaneuraOu WASM for Cloudflare Workers -- LLM Specification

This document is for LLMs and AI agents that integrate with or generate code for this package.

## Package Identity

- npm scope: `@ultemica/yaneuraou-wasm-mobility-cfworkers`
- Engine: YaneuraOu Mobility (KIKI) V8.50 (`YANEURAOU_ENGINE_KIKI`)
- Runtime: Cloudflare Workers (V8 Isolate, single-thread, WASM SIMD)
- License: GPL-3.0
- Eval data: embedded (`eval/mobility/mobility_weights_embedded.cpp`, 164-dim learned linear, no external file required)

## Module Exports

```
"." -> dist/index.js    (createEngine, types)
"./engine" -> dist/yaneuraou.js  (Emscripten factory)
"./wasm" -> dist/yaneuraou.wasm  (WASM binary)
```

## Core Function

```ts
import { createEngine } from "@ultemica/yaneuraou-wasm-mobility-cfworkers";

const engine = await createEngine({
  factory: YaneuraOuFactory,   // from "./engine" or "./yaneuraou.js"
  wasmBinary?: ArrayBuffer,    // from "./wasm" or bundler auto-resolve
  evalBin?: ArrayBuffer,       // NNUE eval file (nn.bin, ~873KB for KP256)
  evalFile?: string,           // default "nn.bin"
  bookDb?: ArrayBuffer,        // opening book (user_book1.db, max ~5MB)
  bookFile?: string,           // required when bookDb is provided
  usiHash?: number,            // hash table MB, default 16
  handshakeTimeoutMs?: number, // default 10000
  readyTimeoutMs?: number,     // default 30000
});
```

## Engine Methods

### eval(req: EvalRequest): Promise<EvalResult>

Evaluate a single position. Automatically serialized -- safe to call concurrently.

```ts
interface EvalRequest {
  sfen: string;          // SFEN notation, e.g. "lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b - 1"
  byoyomi?: number;      // think time ms, default 500, issued as "go movetime"
  skillLevel?: number;   // 0-20, default 20 (full strength)
  multiPv?: number;      // default 1
  depthLimit?: number;   // 0 = unlimited
  nodesLimit?: number;   // 0 = unlimited
}
```

```ts
interface EvalResult {
  bestmove: string;              // USI move, e.g. "2g2f", "B*6f"
  ponder: string | null;
  score: Score | null;
  depth: number | null;
  seldepth: number | null;
  nodes: number | null;
  timeMs: number | null;
  pv: string[] | null;           // principal variation as USI moves
  lastInfo: string | null;       // raw "info ..." line
  bestmoveLine: string;          // raw "bestmove ..." line
}

type Score = {
  kind: "cp" | "mate";
  value: number;                 // centipawns or mate-in-N
  bound?: "lowerbound" | "upperbound";
};
```

### evalBatch(reqs: EvalRequest[]): Promise<EvalResult[]>

Batch evaluation. Sends `usinewgame` once at start, then processes positions sequentially.
Transposition table is reused across positions in the batch (no reset between positions).
Use for game analysis where consecutive positions share search tree data.

### send(cmd: string): void

Send a raw USI command. For advanced use only.

### dispose(): void

Terminate the engine. Safe to call multiple times.

## SFEN Format

Shogi Forsyth-Edwards Notation. Board is described from rank 1 (top) to rank 9 (bottom), files from 9 (left) to 1 (right) from Black's perspective.

Piece letters: K(king), R(rook), B(bishop), G(gold), S(silver), N(knight), L(lance), P(pawn).
Uppercase = Black (sente), lowercase = White (gote). Promoted pieces prefixed with `+`.

Format: `<board> <side> <hand> <move_number>`

Examples:
- Startpos: `lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b - 1`
- With hand pieces: `...  b S2P 1` (Black holds 1 silver, 2 pawns)

## USI Move Format

- Normal move: `<from><to>` e.g. `7g7f` (file+rank from, file+rank to)
- Promotion: `<from><to>+` e.g. `8h2b+`
- Drop: `<PIECE>*<to>` e.g. `B*6f` (drop bishop at 6f)

Files: 1-9 (right to left). Ranks: a-i (top to bottom).

## Memory Budget (128MB WASM limit)

| Component | Size |
|---|---|
| WASM initial heap | 64MB |
| nn.bin (KP256 eval) | ~1MB |
| 100T-shock book | ~5MB |
| USI_Hash 16MB | 16MB |
| Engine internal | ~5MB |
| **Headroom** | **~37MB** |

Hard limits:
- Eval file: KP256 only (~1MB). HalfKP (62MB) does NOT fit.
- Book: up to ~5MB. 700T-shock (32MB) causes OOM.
- USI_Hash: 16MB is safe. 32MB works but reduces headroom.

## Initialization Sequence

1. `factory({ wasmBinary })` -- instantiate WASM module
2. `FS.writeFile("/eval/nn.bin", ...)` -- write eval to MEMFS
3. `FS.writeFile("/book/user_book1.db", ...)` -- write book to MEMFS (optional)
4. `postMessage("usi")` -- USI handshake, wait for "usiok"
5. `setoption name EvalDir value /eval`
6. `setoption name BookDir value /book` (if book provided)
7. `setoption name BookFile value user_book1.db` (if book provided)
8. `postMessage("isready")` -- loads NNUE weights + book, wait for "readyok"
9. Engine ready

## Behavioral Notes

- `eval()` sends `usinewgame` + `isready` before each call (clears TT).
- `evalBatch()` sends `usinewgame` + `isready` once, then reuses TT across positions.
- When a book hit occurs: `depth: 0`, `nodes` is small, `timeMs` is ~0-2ms.
- Book miss: falls back to normal search with `go movetime`.
- `score.kind === "mate"` means `score.value` is mate-in-N moves (positive = engine wins).
- Concurrent `eval()` calls are automatically serialized via promise chain.
- The engine cannot be stopped mid-search (single-thread limitation).

## Error Handling

- Wrong eval architecture (e.g. HalfKP file into KP256 engine): `exit(1)` during `isready`.
- Eval file missing: `exit(1)` during `isready`.
- Timeout: `createEngine` throws with descriptive message ("usi -> usiok timeout", etc.).
- OOM: `RuntimeError: Aborted()` -- reduce book size or hash.

## Cloudflare Workers Deployment Pattern

```ts
// Cache engine across requests in the same isolate
let enginePromise: Promise<Engine> | null = null;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (!enginePromise) {
      enginePromise = createEngine({ /* ... */ });
    }
    const engine = await enginePromise;
    const result = await engine.eval({ sfen: "...", byoyomi: 1000 });
    return Response.json(result);
  },
};
```

The engine survives across requests within the same V8 isolate.
Cloudflare may evict the isolate at any time; the next request will re-initialize.
