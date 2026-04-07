#!/usr/bin/env python3
"""Chrome Widevine CDM RSA Key Dumper via lldb

lldb で CDM プロセスにアタッチし、BoringSSL の RSA_sign に
ブレークポイントを設定して RSA 秘密鍵をダンプする。

lldb はコードインジェクションを行わないため VerifyCdmHost_0 に検出されない。

使い方:
  1. Chrome で DRM コンテンツを再生中に
  2. sudo uv run python dump_rsa_key.py
  3. Chrome で別の動画を開くか再生を再開して新しいライセンスリクエストを発生させる
"""

import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def find_cdm_pid() -> int | None:
    result = subprocess.run(["ps", "aux"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "CdmServiceBroker" in line or "sandbox-type=cdm" in line:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    continue
    return None


def main():
    print("=" * 60)
    print("[*] Chrome Widevine CDM RSA Key Dumper (lldb)")
    print("[*] %s" % datetime.now().isoformat())
    print("=" * 60)
    print()

    if os.geteuid() != 0:
        print("[!] Root required. Run with: sudo uv run python dump_rsa_key.py")
        sys.exit(1)

    pid = find_cdm_pid()
    if not pid:
        print("[!] CDM process not found.")
        print("[*] Play DRM content in Chrome first.")
        sys.exit(1)

    print("[+] CDM process: PID %d" % pid)

    output_dir = Path("logs") / ("lldb_%s" % datetime.now().strftime("%Y%m%d_%H%M%S"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # lldb hook script
    hook_script = Path(__file__).parent / "scripts" / "lldb_rsa_hook.py"
    if not hook_script.exists():
        print("[!] %s not found" % hook_script)
        sys.exit(1)

    # lldb command file
    lldb_cmds = output_dir / "lldb_commands.txt"
    lldb_cmds.write_text(
        "process attach --pid %d\n"
        "command script import %s\n"
        "command script add -f lldb_rsa_hook.setup_breakpoints setup_bp\n"
        "setup_bp\n"
        "continue\n" % (pid, hook_script)
    )

    # Set output dir via env
    env = os.environ.copy()
    env["RSA_DUMP_DIR"] = str(output_dir)

    print("[*] Launching lldb, attaching to PID %d..." % pid)
    print("[*] Output dir: %s" % output_dir)
    print("[*] Trigger a new license request (open another DRM video).")
    print("[*] Press Ctrl+C to stop and detach.")
    print()

    try:
        proc = subprocess.Popen(
            ["lldb", "--batch", "--source", str(lldb_cmds)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip()
            if line:
                print("  [lldb] %s" % line)

            if "DER saved:" in line:
                print()
                print("=" * 60)
                print("[+] RSA private key extracted!")
                print("=" * 60)

        proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Results
    der_files = sorted(output_dir.glob("private_key_*.der"))
    json_files = sorted(output_dir.glob("rsa_dump_*.json"))

    if der_files:
        print()
        print("[+] Extracted %d key(s):" % len(der_files))
        for f in der_files:
            print("    %s (%d bytes)" % (f, f.stat().st_size))
        print()
        print("[*] Verify: uv run python verify_key.py %s" % der_files[0])
    elif json_files:
        print()
        print("[*] %d RSA dump(s) (DER build may have failed):" % len(json_files))
        for f in json_files:
            print("    %s" % f)
    else:
        print()
        print("[-] No RSA key data captured.")
        print("[*] Try opening a new DRM video to trigger RSA_sign.")


if __name__ == "__main__":
    main()
