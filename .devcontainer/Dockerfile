FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04
ARG _REMOTE_USER_HOME=/home/vscode

# ── Reverse Engineering Tools + Theos 依存パッケージ (apt) ──
RUN \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    jq \
    radare2 \
    apktool \
    make \
    perl \
    fakeroot \
    zip \
    xz-utils \
    lzma \
    libtinfo6 \
    libxml2 \
    libncurses6 \
    libz3-dev

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

# ── Theos 本体 ──
USER vscode
ENV THEOS=/home/vscode/theos
RUN git clone --recursive https://github.com/theos/theos.git ${THEOS}

# ── Toolchain (L1ghtmann, aarch64 対応) ──
RUN ARCH=$(uname -m) && \
    curl -fsSL "https://github.com/L1ghtmann/llvm-project/releases/latest/download/iOSToolchain-${ARCH}.tar.xz" \
    | tar xJ -C ${THEOS}/toolchain

# ── Swift Toolchain (kabiroberai, iOS クロスコンパイル用) ──
RUN ARCH=$(uname -m) && \
    curl -fsSL "https://github.com/kabiroberai/swift-toolchain-linux/releases/download/v2.3.0/swift-5.8-ubuntu22.04-${ARCH}.tar.xz" \
    | tar xJ -C ${THEOS}/toolchain

# ── ホスト Swift (SPM ビルド用) ──
USER root
RUN ARCH=$(uname -m) && \
    curl -fsSL "https://download.swift.org/swift-5.8.1-release/ubuntu2204-${ARCH}/swift-5.8.1-RELEASE/swift-5.8.1-RELEASE-ubuntu22.04-${ARCH}.tar.gz" \
    | tar xz --strip-components=2 -C /usr
USER vscode

# ── iOS SDKs (15.6 + 16.5) ──
RUN curl -fsSL "https://github.com/theos/sdks/archive/master.tar.gz" \
    | tar xz -C /tmp && \
    mv /tmp/sdks-master/iPhoneOS15.6.sdk ${THEOS}/sdks/ && \
    mv /tmp/sdks-master/iPhoneOS16.5.sdk ${THEOS}/sdks/ && \
    rm -rf /tmp/sdks-master
