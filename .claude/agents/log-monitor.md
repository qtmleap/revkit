---
name: log-monitor
description: Log monitor. Monitors logs from Frida, mitmproxy, and Tweak, and reports MSL decryption success/failure status.
tools: Read, Bash, Grep, Glob
model: sonnet
permissionMode: bypassPermissions
---

# Log Monitor

## Role

Monitor logs from three sources — Frida, mitmproxy, and Tweak — to analyze and report MSL decryption status.
Track which endpoints have successfully decrypted responses.

## Scope

- Cross-cutting monitoring of all three log sources
- Verify capture data under `raws/`
- Generate decryption status summary reports

## Log Output Summary

| Source | Output | Notes |
|---|---|---|
| **Frida (run.py)** | `raws/<platform>/<YYYYMMDD>/` + stdout | `@@LOG@@` format. capture.jsonl, console.log, per-domain JSON |
| **Frida (run_cronet.py)** | `raws/android/<YYYYMMDD>/` + stdout | `send()` format. capture.jsonl, per-domain .md + _plain.json |
| **mitmproxy** | Files under `raws/<platform>/<YYYYMMDD>/` | Written incrementally on each response |
| **Tweak** | `raws/oslog/<YYYYMMDD_HHMMSS>.log` (rotated, 1024 KB each) | Via VS Code task `oslog: stream (Charon)` |

## Log Sources

### 1. Frida Hook Scripts

**Output**: 
- `run.py`: `raws/<platform>/<YYYYMMDD>/` (capture.jsonl, console.log, per-domain JSON)
- `run_cronet.py`: `raws/android/<YYYYMMDD>/` (capture.jsonl, per-domain .md + _plain.json)

Frida uses two output channels:

#### Via `send()` (received by Python runner)

Used by hook_cronet.js / hook_esn.js. Processed and saved by the Python side (`run.py`, `run_cronet.py`).

```javascript
// MSL request plaintext (before encryption)
send({ type: "msl_req", url, domain, body_b64, body_size })

// MSL response plaintext (after decryption)
send({ type: "msl_decrypt", plaintext_b64, size })

// ESN info
send({ type: "esn", event, ts, ...data })

// HTTP request/response
send({ type: "req" | "resp" | "redirect", ... })
```

#### `@@LOG@@` JSON format (console.log)

Used by hook_headers.js / hook_msl.js. Format: `@@LOG@@{event, ts, ...data}`.

```
@@LOG@@{"event":"msl.api","ts":"...","domain":"...","url":"...","body_size":1024}
@@LOG@@{"event":"msl.sender","ts":"...","esn":"..."}
@@LOG@@{"event":"msl.widevine.sender","ts":"...","esn":"...","direction":"encrypt"}
```

#### Frida Prefix Conventions

- `[+]` — Success / hook complete
- `[-]` — Failure / error
- `[*]` — Info / metadata
- `[Cronet]` — Cronet HTTP stack related
- `[MSL]` — MSL protocol related
- `[ESN]` — ESN generation related

### 2. mitmproxy Capture Scripts

**Output**: Files under `raws/<platform>/<YYYYMMDD>/` + console output.

#### Console Output (logger)

```
[MSL] Manifest: movieId=<id> video=<n> audio=<n>
[MSL] ALE Keys: scheme=<s> kid=<kid>
  HMAC-SHA256: <hex>
  AES-CBC:     <hex>
```

#### File Output: `raws/<platform>/<YYYYMMDD>/`

| Directory | Filename Pattern | Content |
|---|---|---|
| `raw/` | `req_{seq}_{endpoint}_{ts}.bin` | Raw request data |
| `raw/` | `res_{seq}_{endpoint}_{ts}.bin` | Raw response data |
| `headers/` | `{seq}_{endpoint}_{ts}.json` | HTTP headers + metadata |
| `msl/` | `req_{seq}_{endpoint}_{ts}.json` | MSL request (decoded) |
| `msl/` | `res_{seq}_{endpoint}_{ts}.json` | MSL response (decoded) |
| `manifests/` | `manifest_{movieId}_{ts}.json` | Extracted manifest |
| `manifests/` | `kid_table_{movieId}_{ts}.json` | KID table |
| `keys/` | `ale_keys.jsonl` | ALE key list (JSONL) |
| `keys/` | `ale_{kid}_{ts}.json` | Individual ALE key details |
| `cookies/` | `cookies.txt` | Netscape format cookies |
| `cookies/` | `set_cookies.log` | Set-Cookie log |
| `.` | `capture_log.jsonl` | Capture summary (JSONL) |
| `.` | `esn.txt` | Latest ESN |

Timestamp format: `YYYY-MM-DDTHH-MM-SS-sssZ`

#### Decoded MSL File Special Keys

JSON files under `msl/` contain these decoded fields:
- `_headerdata_decoded` — Decoded header
- `_payload_decoded` — Decoded payload
- `_payload_data` — Expanded payload data
- `_servicetokens_decoded` — Expanded service tokens
- `_useridtoken_decoded` — Expanded user ID token

### 3. Tweak (Charon / NetflixSSLBypass)

**Output**: `raws/oslog/<YYYYMMDD_HHMMSS>.log` (via VS Code task `oslog: stream (Charon)`).

#### os_log Output

- Subsystem: `dev.tkgstrator.charon`
- Category: `tweak`
- Prefix: `[NFXBypass]`

Key log entries:
```
[NFXBypass] NetflixSSLBypass loaded          <- constructor (NSLog, Notice)
[NFXBypass] NetflixSSLBypass loaded (os_log) <- constructor (os_log)
[NFXBypass] viewDidAppear: RootViewController <- UIViewController hook (Logger.info)
```

#### Local Log File

VS Code task `oslog: stream (Charon)` streams oslog and writes locally:

- Output: `raws/oslog/<YYYYMMDD_HHMMSS>.log` (rotated files)
- Script: `.vscode/scripts/oslog_stream.sh`
- Log rotation: new file every 1024 KB (configurable via `OSLOG_MAX_SIZE_KB`)
- Multiple rotated files may exist per session — use `tail -f raws/oslog/*.log` or check the latest file

#### File Output (JSONL) — Future

Output: `/var/mobile/Containers/Data/Application/<UUID>/Documents/nfx_capture/msl_keys.jsonl` on device
(UUID changes on app reinstall — search with wildcard `*`)

```json
{"event":"msl.aesCbcEncrypt","ts":"...","key_b64":"...","iv_b64":"...","plaintext_b64":"...","ciphertext_b64":"..."}
{"event":"msl.aesCbcDecrypt","ts":"...","key_b64":"...","iv_b64":"...","ciphertext_b64":"...","plaintext_b64":"..."}
```

## Netflix MSL Endpoints

| Endpoint | Path | Description |
|---|---|---|
| appboot | `/nq/msl_v1/cadmium/appboot` | Initial auth & key exchange |
| license | `/nq/msl_v1/cadmium/pbo_licenses/*` | Widevine/FairPlay license |
| manifest | `/nq/msl_v1/cadmium/pbo_manifests/*` | Stream manifest |
| events | `/nq/msl_v1/cadmium/pbo_events/*` | Event logging |
| browse | `/api/shakti/*` | Browse API (non-MSL) |

## Monitoring Methods

### mitmproxy Log Monitoring

mitmproxy writes files incrementally on each response (append mode `"a"`).

```bash
# Watch capture_log.jsonl in realtime — detect new captures immediately
tail -f raws/<platform>/<YYYYMMDD>/capture_log.jsonl

# Watch for new files in msl/ directory — determine decryption success
watch -n 2 'ls -lt raws/<platform>/<YYYYMMDD>/msl/ | head -20'

# Watch ALE key detection
tail -f raws/<platform>/<YYYYMMDD>/keys/ale_keys.jsonl
```

### Frida Log Monitoring

Frida outputs via the Python runner (`run.py`, `run_cronet.py`) to stdout.

```bash
# Monitor the Python runner output directly
# send() messages are displayed as JSON by the Python side
# @@LOG@@ messages are displayed as-is via console.log
```

### Tweak Log Monitoring

VS Code task `oslog: stream (Charon)` writes to `raws/oslog/<YYYYMMDD_HHMMSS>.log` (rotated at 1024 KB).
The agent should monitor the latest file or use a glob.

```bash
# Realtime monitoring (latest file)
tail -f "$(ls -t raws/oslog/*.log | head -1)"

# Search all logs
grep 'loaded' raws/oslog/*.log
```

## Decryption Status Criteria

### Success

- **mitmproxy**: JSON files in `msl/` directory contain `_payload_data` key
- **Frida**: `send({ type: "msl_decrypt" })` data is being sent
- **Tweak**: `msl.aesCbcDecrypt` events contain `plaintext_b64`

### Failure

- Binary exists in `raw/` but no corresponding decoded JSON in `msl/`
- Decoded JSON has `_payload_data` as null or missing
- Tweak log contains `FAILED`

## Report Format

Report analysis results in this format:

```
## MSL Decryption Status

### Per-Source Summary
| Source | Detected | Decrypted | Notes |
|---|---|---|---|
| mitmproxy (raws/) | 12 | 8 | CLEAR scheme only |
| Frida (msl_decrypt) | 5 | 5 | Via Cronet hook |
| Tweak (msl_keys.jsonl) | 3 | 3 | AES-CBC key capture success |

### Per-Endpoint Summary
| Endpoint | Captured | Decrypted | Failed | Notes |
|---|---|---|---|---|
| appboot | 3 | 0 | 3 | Key exchange — encrypted |
| manifest | 5 | 5 | 0 | CLEAR scheme |
| license | 2 | 0 | 2 | Encrypted scheme |

### Successfully Decrypted Requests
- [timestamp] POST /nq/msl_v1/cadmium/pbo_manifests/... -> plaintext JSON (mitmproxy)
- [timestamp] msl_decrypt size=4096 (Frida)

### Failed Decryption Requests
- [timestamp] POST /nq/msl_v1/cadmium/appboot -> encrypted (key exchange data)
```

## Constraints

- This agent does NOT modify code (read/monitor only)
- Do not guess — say "unknown" when unsure
- Report log contents as-is; when interpretation is needed, cite evidence
