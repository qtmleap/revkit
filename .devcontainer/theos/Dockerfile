FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# ── Theos + Swift 依存パッケージ ──
RUN \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    make \
    perl \
    fakeroot \
    zip \
    unzip \
    xz-utils \
    lzma \
    libtinfo6 \
    libxml2 \
    libncurses6 \
    libz3-dev

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

# ── ビルド用作業ディレクトリ ──
WORKDIR /home/vscode/app
