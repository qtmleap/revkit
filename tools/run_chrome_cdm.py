#!/usr/bin/env python3
"""Chrome Widevine CDM L3 Hook Runner - macOS

Chrome のマルチプロセスアーキテクチャに対応し、CDM をロードする
Utility プロセス (Chrome Helper) を自動検出して Frida をアタッチする。

使い方:
  1. Chrome を起動する (DRM コンテンツの再生前)
  2. このスクリプトを実行:
     python run_chrome_cdm.py
  3. Chrome で DRM コンテンツを再生 (Netflix, YouTube Premium, etc.)
  4. コンソールに CDM のフックログが出力される
  5. Ctrl+C で終了

ログ出力先:
  logs/chrome_YYYYMMDD/
    cdm/
      0001_cdm.createInstance.json
      0002_cdm.createSession.json
      ...
    capture.jsonl
    console.log
"""

import frida
import json
import os
import re
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

LOG_PREFIX = "@@LOG@@"

# Chrome Helper プロセス名 (macOS)
CHROME_HELPER_NAMES = [
    "Google Chrome Helper (Renderer)",
    "Google Chrome Helper (GPU)",
    "Google Chrome Helper",
    "Google Chrome Helper (Plugin)",
]

# Widevine CDM ライブラリ名
CDM_MODULE = "libwidevinecdm.dylib"

# フックスクリプトパス
HOOK_SCRIPT = Path(__file__).parent / "scripts" / "hook_chrome_cdm.js"


def sanitize(name: str) -> str:
    """Sanitize filename component."""
    return re.sub(r"[^\w.\-]", "_", name)[:80]


def deep_parse_json(obj):
    """Recursively parse JSON strings."""
    if isinstance(obj, str):
        s = obj.strip()
        if s.startswith(("{", "[")):
            try:
                return deep_parse_json(json.loads(s))
            except (json.JSONDecodeError, TypeError):
                pass
        return obj
    if isinstance(obj, dict):
        return {k: deep_parse_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deep_parse_json(v) for v in obj]
    return obj


class ChromeCdmHooker:
    """Chrome CDM Frida Hooker."""

    def __init__(self, script_path: Path):
        self.script_path = script_path
        self.session_dir = self._make_session_dir()
        self.capture_file = self.session_dir / "capture.jsonl"
        self.console_file = self.session_dir / "console.log"
        self.seq = 0
        self.domain_counts: dict[str, int] = {}
        self.log_count = 0
        self.sessions: list[frida.core.Session] = []
        self.scripts: list[frida.core.Script] = []
        self.hooked_pids: set[int] = set()
        self.running = True

        # 前回のログを削除
        for f in (self.capture_file, self.console_file):
            if f.exists():
                f.unlink()

    def _make_session_dir(self) -> Path:
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        d = Path("logs") / f"chrome_{session_id}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _on_message(self, message: dict, data):
        """Frida メッセージハンドラ.

        Frida は console.log() を { type: "log", level: "info", payload: "..." } で送る。
        send() は { type: "send", payload: ... } で送る。
        """
        msg_type = message.get("type", "")
        if msg_type == "send":
            payload = message.get("payload", "")
            if isinstance(payload, str):
                self._handle_line(payload)
        elif msg_type == "log":
            payload = message.get("payload", "")
            if isinstance(payload, str):
                self._handle_line(payload)
        elif msg_type == "error":
            desc = message.get("description", "")
            stack = message.get("stack", "")
            print(f"[!] Script error: {desc}")
            if stack:
                print(f"    {stack[:200]}")

    def _handle_line(self, line: str):
        """1行のフック出力を処理."""
        if line.startswith(LOG_PREFIX):
            json_str = line[len(LOG_PREFIX) :]
            try:
                entry = json.loads(json_str)
            except json.JSONDecodeError:
                print(line)
                return

            # capture.jsonl に保存
            with open(self.capture_file, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.log_count += 1
            self.seq += 1

            event = entry.get("event", "unknown")

            # ディレクトリ決定
            save_dir = self.session_dir / "cdm"
            save_dir.mkdir(parents=True, exist_ok=True)

            path_key = "cdm"
            self.domain_counts[path_key] = self.domain_counts.get(path_key, 0) + 1
            dseq = self.domain_counts[path_key]

            base = f"{dseq:04d}_{sanitize(event)}"
            with open(save_dir / f"{base}.json", "w") as f:
                json.dump(deep_parse_json(entry), f, ensure_ascii=False, indent=2)

            # コンソール表示
            self._print_event(entry, event, path_key)
        else:
            # 通常のコンソール出力
            print(line)
            with open(self.console_file, "a") as f:
                f.write(line + "\n")

    def _print_event(self, entry: dict, event: str, path_key: str):
        """イベントをコンソールに表示."""
        if event == "cdm.version":
            print(f"  [CDM] Version: {entry.get('version', '?')}")
        elif event == "cdm.createInstance":
            ks = entry.get("key_system", "?")
            iv = entry.get("interface_version", "?")
            print(f"  [CDM] CreateCdmInstance key_system={ks} interface_v={iv}")
        elif event == "cdm.initialize":
            level = entry.get("drm_level", "?")
            print(f"  [CDM] Initialize DRM_Level={level}")
        elif event == "cdm.setServerCertificate":
            size = entry.get("cert_size", 0)
            print(f"  [CDM] SetServerCertificate cert_size={size}")
        elif event == "cdm.createSession":
            init_type = entry.get("init_data_type", "?")
            init_size = entry.get("init_data_size", 0)
            sess_type = entry.get("session_type", "?")
            print(
                f"  [CDM] CreateSession type={sess_type} init_data={init_type} ({init_size}B)"
            )
            # PSSH がある場合は表示
            pssh = entry.get("init_data_hex", "")
            if pssh:
                print(f"    PSSH: {pssh[:120]}{'...' if len(pssh) > 120 else ''}")
        elif event == "cdm.updateSession":
            sid = entry.get("session_id", "?")
            rsize = entry.get("response_size", 0)
            print(
                f"  [CDM] UpdateSession (License Response) session={sid} response_size={rsize}"
            )
        elif event == "cdm.closeSession":
            sid = entry.get("session_id", "?")
            print(f"  [CDM] CloseSession session={sid}")
        elif event == "cdm.decrypt":
            count = entry.get("count", 0)
            scheme = entry.get("encryption_scheme", "?")
            key_id = entry.get("key_id", "")
            size = entry.get("data_size", 0)
            print(
                f"  [CDM] Decrypt #{count} scheme={scheme} size={size} key_id={key_id[:32]}"
            )
        elif event == "cdm.verifyHost":
            result = entry.get("result", False)
            print(f"  [CDM] VerifyHost -> {'PASS' if result else 'FAIL'}")
        else:
            print(f"  [{path_key}] {event}")

    def find_and_hook_cdm_processes(self):
        """CDM をロードしている Chrome Helper プロセスを探し、即座にフックする.

        スキャンとフックを一体化することで、detach → re-attach 間にプロセスが
        消えてしまう問題を回避する。
        """
        device = frida.get_local_device()

        try:
            processes = device.enumerate_processes()
        except frida.ServerNotRunningError:
            print("[!] Frida server not available")
            return

        for proc in processes:
            if proc.pid in self.hooked_pids:
                continue
            if not ("Chrome Helper" in proc.name):
                continue

            try:
                session = device.attach(proc.pid)

                # CDM がロードされているか確認
                probe = session.create_script(f"""
                    var mod = Process.findModuleByName("{CDM_MODULE}");
                    send(mod ? JSON.stringify({{
                        name: mod.name,
                        base: mod.base.toString(),
                        size: mod.size,
                        path: mod.path
                    }}) : null);
                """)
                result = {"value": None}

                def on_probe_msg(msg, _data):
                    if msg["type"] == "send":
                        result["value"] = msg["payload"]

                probe.on("message", on_probe_msg)
                probe.load()
                time.sleep(0.3)
                probe.unload()

                if not result["value"]:
                    # CDM なし → detach
                    session.detach()
                    continue

                # CDM 発見 → そのままフックスクリプトを注入 (detach しない)
                info = json.loads(result["value"])
                print(f"[+] CDM found in PID {proc.pid} ({proc.name})")
                print(f"    {info['name']} at {info['base']} ({info['size']} bytes)")
                print(f"    {info['path']}")

                _pid = proc.pid

                def on_detached(reason, crash=None, _p=_pid):
                    print(f"[!] Detached from PID {_p}: {reason}")
                    self.hooked_pids.discard(_p)

                session.on("detached", on_detached)

                script_code = self.script_path.read_text()
                script = session.create_script(script_code)
                script.on("message", self._on_message)
                script.load()

                self.sessions.append(session)
                self.scripts.append(script)
                self.hooked_pids.add(proc.pid)
                print(f"[+] Hooked PID {proc.pid}")

            except (
                frida.ProcessNotFoundError,
                frida.PermissionDeniedError,
                frida.TransportError,
                frida.InvalidOperationError,
            ):
                pass
            except Exception as e:
                pass

    def run(self):
        """メインループ."""
        print("=" * 70)
        print("[*] Chrome Widevine CDM L3 Hook Runner - macOS")
        print(f"[*] {datetime.now().isoformat()}")
        print(f"[*] Script: {self.script_path}")
        print(f"[*] Session: {self.session_dir}")
        print("=" * 70)

        if not self.script_path.exists():
            print(f"[!] Script not found: {self.script_path}")
            print("[*] Run the TypeScript compiler first:")
            print(
                f"    cd scripts && npx esbuild src/chrome/index.ts --bundle --outfile=hook_chrome_cdm.js"
            )
            sys.exit(1)

        # Chrome プロセスを探す
        device = frida.get_local_device()
        chrome_running = False
        for proc in device.enumerate_processes():
            if proc.name == "Google Chrome":
                chrome_running = True
                break

        if not chrome_running:
            print("[!] Google Chrome is not running.")
            print("[*] Please launch Chrome first, then run this script.")
            sys.exit(1)

        print("[*] Chrome is running. Scanning for CDM processes...")
        print("[*] If CDM is not yet loaded, play DRM content in Chrome.")
        print("[*] Press Ctrl+C to stop.\n")

        # 初回スキャン
        self.find_and_hook_cdm_processes()

        if not self.hooked_pids:
            print("[*] No CDM process found yet. Polling every 2 seconds...")

        def shutdown(sig, frame):
            print("\n[*] Shutting down...")
            self.running = False

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        # ポーリングループ
        while self.running:
            time.sleep(2)
            if self.running:
                self.find_and_hook_cdm_processes()

        # クリーンアップ
        for script in self.scripts:
            try:
                script.unload()
            except Exception:
                pass
        for session in self.sessions:
            try:
                session.detach()
            except Exception:
                pass

        print(f"\n[*] {self.log_count} events captured")
        for d, c in sorted(self.domain_counts.items(), key=lambda x: -x[1]):
            print(f"    {d}: {c}")
        print(f"[*] Session: {self.session_dir}")


def main():
    script_path = HOOK_SCRIPT
    hooker = ChromeCdmHooker(script_path)
    hooker.run()


if __name__ == "__main__":
    main()
