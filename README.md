# revkit

[![日本語](https://img.shields.io/badge/lang-日本語-blue)](docs/README.ja.md)

A reverse-engineering toolkit for iOS and Android applications.

- **iOS Tweak Development** — Build and deploy Substrate tweaks via Theos/Orion (arm64, rootless)
- **Frida Hooks** — Runtime analysis and dynamic instrumentation for iOS / Android apps
- **mitmproxy** — Programmable HTTPS traffic capture and protocol decoding
- **Binary Analysis** — Static analysis of APK / IPA binaries with Ghidra, radare2, jadx, ipsw

## Repository Structure

```
.
├── packages/
│   ├── frida/                  # Frida hook scripts (TypeScript → JS)
│   │   └── src/
│   │       ├── ios/            #   iOS hooks (ObjC/C++)
│   │       ├── android/        #   Android hooks (Java/JNI)
│   │       └── common/         #   Shared utilities
│   ├── mitmproxy/              # mitmproxy addons
│   └── tweak/                  # iOS Tweaks (Theos/Orion)
│
├── tools/                      # Python utilities
│   ├── run.py                  #   Frida hook runner
│   ├── transformers/           #   Log transformers (Frida → unified format)
│   └── ...
│
├── handlers/                   # Objection handlers (CommonCrypto, Security, etc.)
├── docs/                       # Analysis results & specifications
├── assets/                     # IPA/APK binaries (.gitignore)
├── raws/                       # Raw Frida capture logs (.gitignore)
└── logs/                       # Transformed logs (.gitignore)
```

## Development Environment

Everything is pre-configured in a DevContainer. Run `Rebuild Container` to get all tools ready.

### Runtimes

| Tool | Purpose |
|------|---------|
| Python 3.12 (uv) | Utilities, log transformation, analysis scripts |
| Node.js 25.x | Frida script build (frida-compile) |
| Bun | Chrome extension build |
| Frida 17.x | Dynamic instrumentation |
| mitmproxy | Programmable HTTPS proxy |

### Reverse Engineering Tools

| Tool | Purpose |
|------|---------|
| radare2 | ARM64 disassembly & binary analysis |
| Ghidra (headless) | Pseudocode generation & function analysis |
| jadx | Android APK → Java decompilation |
| apktool | Android APK resource extraction & smali |
| ipsw | iOS Mach-O analysis, ObjC/Swift class dump |
| lief (Python) | Mach-O/ELF binary parser |
| capstone (Python) | ARM64 disassembler |
| unicorn (Python) | CPU emulation |
| pywidevine (Python) | Widevine DRM analysis |

### iOS Tweak Development

| Tool | Purpose |
|------|---------|
| Theos | Tweak build system |
| Orion | Swift tweak framework |
| Swift 5.8 (cross-compile) | Cross-compilation for iOS |
| iOS SDK 15.6 / 16.5 | Build targets |

## macOS Host Setup

The DevContainer runs inside Docker Desktop's Linux VM and cannot communicate with iOS devices directly. Use iproxy over USB to avoid issues with Wi-Fi IP changes or network instability.

### 1. Install iproxy (macOS)

```bash
brew install libimobiledevice
```

### 2. Start iproxy (macOS)

With the iPhone connected via USB:

```bash
iproxy 2222 22 &
iproxy 27042 27042 &
```

- `2222 → 22`: SSH
- `27042 → 27042`: Frida

### Connection Diagram

| Purpose | Direction | Route |
|---------|-----------|-------|
| **SSH** | Container → Device | `ssh iPhone` → `host.docker.internal:2222` → iproxy (USB) → device:22 |
| **Frida** | Container → Device | `frida -H host.docker.internal` → iproxy (USB) → device:27042 |
| **mitmproxy** | Device → Container | Set device Wi-Fi proxy to macOS LAN IP:9080 |

## Usage

### Frida Hooks

```bash
# iOS (spawn via objection)
uv run python tools/run.py packages/frida/<script>.js

# Android (spawn mode)
uv run python tools/run.py --android packages/frida/<script>.js
```

Set device hosts in `.env` (use `host.docker.internal` when going through iproxy):

```
IOS_HOST=host.docker.internal
ANDROID_HOST=192.168.x.x
```

### mitmproxy

#### Device Setup

1. Set the device's Wi-Fi proxy to the macOS LAN IP, port `9080`
2. Open `http://mitm.it` on the device and install the CA certificate
   - iOS: Settings → General → VPN & Device Management → install mitmproxy → Settings → General → About → Certificate Trust Settings → enable

#### Launch

```bash
uv run mitmdump --listen-port 9080 --set block_global=false \
    -s packages/mitmproxy/<addon>.py
```

Addons are located in `packages/mitmproxy/`.

### iOS Tweaks (Theos)

```bash
# Build
make -C packages/tweak/<tweak>

# Package (.deb)
make -C packages/tweak/<tweak> package

# Install to device
make -C packages/tweak/<tweak> package install THEOS_DEVICE_IP=<device-ip>
```

### Binary Analysis

```bash
# iOS: ObjC/Swift class dump
ipsw macho info <binary> --class-dump

# Android: APK decompilation
jadx -d /tmp/out <apk>

# Ghidra headless analysis
analyzeHeadless /tmp/project name -import <binary>
```

## Claude Code Skills

Project-specific slash commands available inside Claude Code.

| Command | Description |
|---------|-------------|
| `/compose` | Assemble an Agent Team as leader and run the plan → approve → execute workflow |

### Agents

Specialized agents invoked by `/compose`.

| Agent | Responsibility |
|-------|---------------|
| `tweak-engineer` | iOS Tweak development (Orion/Theos, ElleKit C hooks) |
| `frida-engineer` | Frida hook scripts, runtime analysis |
| `mitmproxy-engineer` | mitmproxy addons, traffic capture |
| `python-engineer` | Python utilities, decoders, data processing |
| `log-monitor` | Frida/mitmproxy/Tweak log monitoring & reporting |
