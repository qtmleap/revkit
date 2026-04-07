"""CLI エントリポイント — python -m netflix_msl で実行可能."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from netflix_msl.client import NetflixMSL
from netflix_msl.constants import ENetflixAudioCodec, ENetflixVideoCodec


def main():
    parser = argparse.ArgumentParser(
        description="Netflix MSL Client — StreamFab NetflixMSL RE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
例:
  python -m netflix_msl --viewable-id 81756595
  python -m netflix_msl --viewable-id 81756595 --video-codec hevc --audio-codec atmos
  python -m netflix_msl --viewable-id 81756595 --download-segment
  python -m netflix_msl --viewable-id 81756595 --clear-cache
""",
    )
    parser.add_argument("--viewable-id", required=True, help="Netflix viewableId")
    parser.add_argument(
        "--esn",
        default=os.environ.get("NETFLIX_ESN", ""),
        help="ESN (default: $NETFLIX_ESN)",
    )
    parser.add_argument(
        "--video-codec",
        default="h264",
        choices=["h264", "hevc", "vp9", "av1"],
        help="Video codec (default: h264)",
    )
    parser.add_argument(
        "--audio-codec",
        default="heaac",
        choices=["heaac", "ddplus", "atmos"],
        help="Audio codec (default: heaac)",
    )
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--cache-dir", default="cache", help="MSL cache directory")
    parser.add_argument(
        "--download-segment",
        action="store_true",
        help="Download first encrypted video segment (1MB)",
    )
    parser.add_argument(
        "--clear-cache", action="store_true", help="Clear MSL cache before starting"
    )
    parser.add_argument("--locale", default="en-US", help="Locale ID (default: en-US)")
    args = parser.parse_args()

    netflix_id = os.environ.get("NETFLIX_ID", "")
    secure_netflix_id = os.environ.get("SECURE_NETFLIX_ID", "")
    esn = args.esn

    if not netflix_id or not secure_netflix_id:
        print("[!] 環境変数 NETFLIX_ID と SECURE_NETFLIX_ID を設定してください")
        print("    ブラウザの DevTools -> Application -> Cookies から取得:")
        print("    export NETFLIX_ID='<NetflixId cookie value>'")
        print("    export SECURE_NETFLIX_ID='<SecureNetflixId cookie value>'")
        sys.exit(1)

    if not esn:
        print("[!] ESN が未設定。--esn または NETFLIX_ESN 環境変数で指定してください")
        print("    export NETFLIX_ESN='NFCDCH-MC-...'")
        sys.exit(1)

    if args.clear_cache:
        cache_file = Path(args.cache_dir) / "MSLDATA"
        if cache_file.exists():
            cache_file.unlink()
            print(f"[Cache] Cleared {cache_file}")

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # ---- クライアント初期化 ----
    client = NetflixMSL(esn, netflix_id, secure_netflix_id, cache_dir=args.cache_dir)
    client.locale = args.locale

    print("=" * 60)
    print("Netflix MSL Client — StreamFab NetflixMSL RE")
    print("=" * 60)
    print(f"ESN:        {esn}")
    print(f"viewableId: {args.viewable_id}")
    print(f"video:      {args.video_codec}")
    print(f"audio:      {args.audio_codec}")
    print(f"locale:     {args.locale}")
    print("=" * 60)

    # Step 1: MSL 初期化
    if not client.init_msl_data():
        print(
            "\n[FAIL] MSL 初期化失敗。Cookie/ESN が無効か、Netflix がリクエストを拒否"
        )
        sys.exit(1)

    # Step 2: マニフェスト取得
    manifest = client.load_manifest(
        args.viewable_id,
        video_codec=args.video_codec,
        audio_codec=args.audio_codec,
    )
    if not manifest:
        print("\n[FAIL] マニフェスト取得失敗")
        sys.exit(1)

    manifest_path = out / f"manifest_{args.viewable_id}.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"\n    Manifest saved -> {manifest_path}")

    # Step 3: ストリーム情報抽出
    streams = client.extract_streams(manifest)

    streams_path = out / f"streams_{args.viewable_id}.json"
    with open(streams_path, "w") as f:
        json.dump(streams, f, ensure_ascii=False, indent=2, default=list)
    print(f"    Streams saved -> {streams_path}")

    # Step 4 (オプション): セグメント DL
    if args.download_segment and streams["video_streams"]:
        best = max(streams["video_streams"], key=lambda s: s["bitrate"])
        if best["urls"]:
            seg_path = out / f"segment_{args.viewable_id}_encrypted.mp4"
            client.download_segment(
                best["urls"][0],
                str(seg_path),
                byte_range="0-1048575",
            )

    # ---- サマリー ----
    print("\n" + "=" * 60)
    print("結果サマリー")
    print("=" * 60)
    print("  Step 1: MSL 鍵交換 (ASYMMETRIC_WRAPPED)        ... OK")
    print(
        f"  Step 2: マニフェスト取得 (pbo_manifests)        "
        f"... {'OK' if manifest else 'FAIL'}"
    )
    print(
        f"  Step 3: KID/PSSH/CDN URL 抽出                  ... KIDs: {streams['kids']}"
    )
    if args.download_segment:
        print("  Step 4: 暗号化セグメント DL                    ... CENC 暗号化済み")
    print("  Step 5: CEK 取得                                ... N/A (CDM 必要)")
    print("  Step 6: CENC 復号                               ... N/A (CEK 必要)")

    print()
    print("CEK 取得には以下のいずれかが必要:")
    print("  A) pywidevine + L3 デバイス鍵 (revocation リスクあり)")
    print("  B) Frida で Chrome/StreamFab の CDM をフック")
    print("  C) リモート CDM サーバー (StreamFab の CMutualCDMServer 相当)")

    if streams["pssh"]:
        print()
        print("PSSH data (CDM への入力として使用):")
        for p in streams["pssh"]:
            print(f"  systemId: {p['systemId']}")
            print(f"  keyId:    {p['keyId']}")
            if p["data"]:
                print(f"  data:     {p['data'][:80]}...")


if __name__ == "__main__":
    main()
