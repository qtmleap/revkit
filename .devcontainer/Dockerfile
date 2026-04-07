FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# ── Reverse Engineering Tools (apt) ──
# radare2  : ARM64 逆アセンブル・バイナリ解析 (Mach-O / ELF)
# apktool  : Android APK リソース展開・smali 逆アセンブル
RUN \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y \
    wget \
    unzip \
    jq \
    radare2 \
    apktool

# ── jadx (GitHub Release) ──
# Android APK → Java 逆コンパイル (プラットフォーム非依存 JAR、JRE は devcontainer feature の Java で提供)
RUN JADX_URL=$(wget -qO- https://api.github.com/repos/skylot/jadx/releases/latest | jq -r '.assets[] | select(.name | test("^jadx-[0-9].*\\.zip$")) | .browser_download_url') && \
    wget -q "$JADX_URL" -O /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui && \
    rm /tmp/jadx.zip

# ── Ghidra (Headless) ──
# NSA 製リバースエンジニアリングツール。ヘッドレスモードで C++ 擬似コード生成に使用
# 使い方: analyzeHeadless /tmp/project name -import <binary>
RUN GHIDRA_URL=$(wget -qO- https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | jq -r '.assets[] | select(.name | test("PUBLIC.*\\.zip$")) | .browser_download_url') && \
    wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    GHIDRA_DIR=$(find /opt -maxdepth 1 -name 'ghidra_*' -type d) && \
    ln -s "$GHIDRA_DIR" /opt/ghidra && \
    rm /tmp/ghidra.zip
ENV PATH="/opt/ghidra/support:$PATH"

# ── ipsw ──
# Go 製 Mach-O 解析ツール。iOS バイナリの ObjC/Swift クラスダンプ、シンボル解析に使用
# 使い方: ipsw macho info <binary> --class-dump
RUN IPSW_URL=$(wget -qO- https://api.github.com/repos/blacktop/ipsw/releases/latest | jq -r '.assets[] | select(.name | test("^ipsw_.*linux_arm64\\.tar\\.gz$")) | .browser_download_url') && \
    wget -q "$IPSW_URL" -O /tmp/ipsw.tar.gz && \
    tar xzf /tmp/ipsw.tar.gz -C /usr/local/bin ipsw && \
    rm /tmp/ipsw.tar.gz
