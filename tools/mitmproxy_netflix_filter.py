"""mitmproxy addon: Netflix 関連ドメインのみ傍受し、それ以外は TLS パススルー.

非対象ドメインの connect/disconnect/TLS エラーログも抑制する。

Usage:
  mitmdump -s tools/mitmproxy_netflix_filter.py
  mitmproxy -s tools/mitmproxy_netflix_filter.py
"""

import logging
import re

from mitmproxy import tls

logger = logging.getLogger(__name__)

# 傍受対象ドメイン (部分一致)
INTERCEPT_DOMAINS = (
    "netflix.com",
    "nflxext.com",
    "nflxso.net",
    "nflximg.net",
    "nflxvideo.net",
)

# ログメッセージからホスト名を抽出するパターン
# "server connect cl4.apple.com:443" や "handshake failed ... for cl4.apple.com" 等にマッチ
_HOST_RE = re.compile(
    r"([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})(?::\d+)?"
)


def _should_intercept(hostname: str) -> bool:
    return any(hostname == d or hostname.endswith(f".{d}") for d in INTERCEPT_DOMAINS)


def _is_connection_noise(msg: str) -> bool:
    """非対象ドメインの接続・切断・TLS エラーログかどうか判定する."""
    keywords = (
        "client connect",
        "client disconnect",
        "server connect",
        "server disconnect",
        "handshake failed",
        "does not trust the proxy",
    )
    msg_lower = msg.lower()
    if not any(kw in msg_lower for kw in keywords):
        return False
    # メッセージ中のホスト名を抽出
    hosts = _HOST_RE.findall(msg)
    if not hosts:
        return False
    # いずれかのホストが傍受対象なら表示する
    return not any(_should_intercept(h) for h in hosts)


class _NoiseFilter(logging.Filter):
    """非対象ドメインの接続系ログを抑制する logging フィルタ."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if _is_connection_noise(msg):
            return False
        return True


def load(loader):
    """addon ロード時に logging フィルタを登録する."""
    # mitmproxy.proxy 配下のロガーにフィルタを追加
    for name in (
        "mitmproxy.proxy",
        "mitmproxy.proxy.layers",
        "mitmproxy.proxy.layers.tls",
    ):
        logging.getLogger(name).addFilter(_NoiseFilter())
    # ルートロガーにも追加 (mitmdump のデフォルト出力をカバー)
    logging.getLogger().addFilter(_NoiseFilter())
    logger.info("Netflix filter loaded: non-target domain logs suppressed")


def tls_clienthello(data: tls.ClientHelloData):
    hostname = data.context.server.address[0] if data.context.server.address else ""
    if not _should_intercept(hostname):
        data.ignore_connection = True
        logger.debug("TLS passthrough: %s", hostname)
