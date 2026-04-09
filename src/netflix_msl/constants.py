"""定数・列挙値・プロファイル定義 (StreamFab バイナリから抽出)"""

from __future__ import annotations

# ============================================================================
# エンドポイント
# ============================================================================

ENDPOINTS = {
    "pbo_manifests": "https://www.netflix.com/nq/msl_v1/cadmium/pbo_manifests/%5E1.0.0/router",
    "licensed_manifest": "https://www.netflix.com/msl/playapi/cadmium/licensedmanifest/1",
    "pbo_licenses": "https://www.netflix.com/nq/msl_v1/cadmium/pbo_licenses/%5E1.0.0/router",
    "metadata": (
        "https://www.netflix.com/nq/website/memberapi/release/metadata"
        "?movieid={movie_id}&drmSystem=widevine"
        "&isWatchlistEnabled=false&isShortformEnabled=false"
        "&isVolatileBillboardsEnabled=false"
    ),
}

# ============================================================================
# クエリパラメータ (StreamFab デフォルト)
# ============================================================================

DEFAULT_QUERY_PARAMS = {
    "clienttype": "akira",
    "uiversion": "v930f5871",
    "browsername": "chrome",
    "browserversion": "131.0.0.0",
    "osname": "windows",
    "osversion": "10.0",
}

# ============================================================================
# バージョン文字列 (バイナリ内定数)
# ============================================================================

UI_VERSION = "shakti-v25d2fa21"
UI_PLATFORM = "SHAKTI"
CLIENT_VERSION = "6.0011.474.011"

# ============================================================================
# 暗号化定数
# ============================================================================

KEY_ID_CONSTANT = "A1F6F6308F6F7F875C5E9562EF792CAE"
RSA_KEYPAIR_ID = "rsaKeypairId"

# iOS MSL Scheme 5 KDF 定数 (NFWebCrypto.framework @ 0x1ac8f5)
IOS_KDF_PSK = bytes.fromhex("027617984f6227539a630b897c017d69")
IOS_KDF_NONCE = bytes.fromhex("809f82a7addf548d3ea9dd067ff9bb91")

# iOS DH パラメータ (1024-bit, g=5, p は Netflix 固有値)
# 出典: raws/msl_keys.json "dh_p" / "dh_g"
IOS_DH_P = int(
    "9694e9d8d93a5ac74c509b4bbce85e92132cd19cce477d1a7e47d527d9ec291515f0b8b3e1"
    "eaed5006e1b1b91ea25b91a01b10e2e834b8d660b2e321ad644ce1a83b328d9014ee7e16f1"
    "e44ffe89579ac3ee47d668b6b76687c2fe90a35b5e6028fd04efea882373ecf60ba2f637e4"
    "cdaa1b6089d6c0b561a8e520e796de27df",
    16,
)
IOS_DH_G = 5

# appboot エンドポイント
IOS_APPBOOT_ENDPOINT = "https://appboot.netflix.com/appboot/"

# key 33.6 scheme_data の固定デバイスヘッダー (128B)
# 180 個の 352B appboot サンプルのうち 165 個 (標準 iPhone) で共通の定数。
# plaintext[0:128] の値 (XOR 復号後)。
# 出典: raws/ios/20260408/raw の 352B appboot キャプチャから実測。
IOS_KEY336_DEVICE_HEADER: bytes = bytes.fromhex(
    "d9d9f7a7"  # CBOR: tag(55799) + map(7)
    "1b00000000000000245835"  # pair 0 key: uint64 = 0x24 (36)
    "d9002e54"  # pair 0 val: tag(46) bytes(20) header
    "bc1b00000000000026a53c"  # pair 0 val continued + pair 1 key start
    "7283497e"
    "4fbc1b000000000027a4c17f"  # pair 1 val: bytes(15) start + ...
    "30cc1b1a05ef544e"
    "1b00000027a4c17f154e797f6b8f"
    "4f4e1b00000027a4d28b0e4e797f6b8f"
    "4f4e3181a21b27a4d28b0e4e7960c894"
    "4f4e3181a21b2797b1c649056260c894"
    "4f4e3181987a168cb1c64905"
)

# ============================================================================
# User-Agent
# ============================================================================

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# ============================================================================
# enum 定義 (バイナリ内列挙値)
# ============================================================================


class ENetflixVideoCodec:
    """enum ENetflixVideoCodec"""

    H264 = "h264"
    HEVC = "hevc"
    VP9 = "vp9"
    AV1 = "av1"


class ENetflixProfile:
    """enum ENetflixProfile — 解像度プロファイル"""

    SD = "sd"
    HD = "hd"
    UHD = "uhd"


class ENetflixAudioCodec:
    """enum ENetflixAudioCodec"""

    HEAAC = "heaac"
    DDPLUS = "ddplus"
    ATMOS = "atmos"


# ============================================================================
# プロファイル定義 (バイナリから抽出した全プロファイル文字列)
# ============================================================================

# --- H.264 ---
H264_PROFILES = [
    "playready-h264mpl22-dash",
    "playready-h264mpl30-dash",
    "playready-h264mpl31-dash",
    "playready-h264mpl40-dash",
    "playready-h264hpl30-dash",
    "playready-h264hpl31-dash",
    "playready-h264hpl40-dash",
    "h264mpl22-dash-playready-prk-qc",
    "h264mpl30-dash-playready-prk-qc",
    "h264mpl31-dash-playready-prk-qc",
    "h264mpl40-dash-playready-prk-qc",
    "h264hpl31-dash-playready-live",
    "h264hpl40-dash-playready-live",
]

# --- HEVC ---
_HEVC_LEVELS = ["L30", "L31", "L40", "L41", "L50", "L51"]
HEVC_PROFILES = (
    [f"hevc-main10-{l}-dash-cenc" for l in _HEVC_LEVELS]
    + [f"hevc-main10-{l}-dash-cenc-prk" for l in _HEVC_LEVELS]
    + [f"hevc-hdr-main10-{l}-dash-cenc" for l in _HEVC_LEVELS]
    + [f"hevc-dv5-main10-{l}-dash-cenc" for l in _HEVC_LEVELS]
)

# --- VP9 ---
_VP9_LEVELS = ["L21", "L30", "L31", "L40", "L50", "L51"]
VP9_PROFILES = [f"vp9-profile0-{l}-dash-cenc" for l in _VP9_LEVELS]

# --- AV1 ---
_AV1_LEVELS = ["L20", "L21", "L30", "L31", "L40", "L41", "L50", "L51"]
AV1_PROFILES = [f"av1-main-{l}-dash-cbcs-prk" for l in _AV1_LEVELS] + [
    f"av1-hdr10plus-main-{l}-dash-cbcs-prk" for l in _AV1_LEVELS
]

# --- オーディオ ---
AUDIO_PROFILES_HEAAC = ["heaac-2-dash", "heaac-2hq-dash"]
AUDIO_PROFILES_HEAAC_51 = ["heaac-5.1-dash", "heaac-5.1hq-dash"]
AUDIO_PROFILES_DDPLUS = ["ddplus-2.0-dash", "ddplus-5.1-dash", "ddplus-5.1hq-dash"]
AUDIO_PROFILES_ATMOS = ["ddplus-atmos-dash"]

# --- 字幕/画像 ---
SUBTITLE_PROFILES = ["webvtt-lssdh-ios8", "simplesdh"]
IMAGE_PROFILES = ["BIF240", "BIF320"]


# ============================================================================
# プロファイル選択ヘルパー
# ============================================================================


def get_video_profiles(codec: str = ENetflixVideoCodec.H264) -> list[str]:
    """ビデオコーデックに応じたプロファイルリストを返す."""
    profiles = {
        ENetflixVideoCodec.H264: H264_PROFILES,
        ENetflixVideoCodec.HEVC: H264_PROFILES + HEVC_PROFILES,
        ENetflixVideoCodec.VP9: H264_PROFILES + VP9_PROFILES,
        ENetflixVideoCodec.AV1: H264_PROFILES + AV1_PROFILES,
    }
    return profiles.get(codec, H264_PROFILES)


def get_audio_profiles(codec: str = ENetflixAudioCodec.HEAAC) -> list[str]:
    """オーディオコーデックに応じたプロファイルリストを返す."""
    profiles = {
        ENetflixAudioCodec.HEAAC: AUDIO_PROFILES_HEAAC,
        ENetflixAudioCodec.DDPLUS: AUDIO_PROFILES_HEAAC + AUDIO_PROFILES_DDPLUS,
        ENetflixAudioCodec.ATMOS: AUDIO_PROFILES_HEAAC
        + AUDIO_PROFILES_DDPLUS
        + AUDIO_PROFILES_ATMOS,
    }
    return profiles.get(codec, AUDIO_PROFILES_HEAAC)
