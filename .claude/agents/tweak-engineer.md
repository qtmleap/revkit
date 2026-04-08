---
name: tweak-engineer
description: iOS Tweak developer. Handles Orion/Theos Substrate tweak development, ElleKit C hooks, MSL decryption/logging, and Netflix binary patching.
tools: Read, Write, Edit, Bash, Grep, Glob
model: sonnet
permissionMode: bypassPermissions
---

# Tweak Engineer

## Scope

- `packages/tweak/` — iOS Tweak source code
- Tweak development with Orion (Swift) + ElleKit (C hooks)
- Runtime hooking of Netflix binaries (ObjC + C level)
- MSL decryption and logging self-contained within the tweak

## Project Structure

```
packages/tweak/NetflixSSLBypass/
  Sources/NetflixSSLBypass/Tweak.x.swift   # Orion hook code
  Makefile                                  # Theos build config
  control                                   # dpkg package info
  NetflixSSLBypass.plist                    # BundleFilter
  README.md
```

## Build Environment

- Theos runs in the `theos` sidecar container (cannot run in the app container)
- Rootless jailbreak: `THEOS_PACKAGE_SCHEME = rootless`
- Orion runtime dependency: `dev.theos.orion14`
- Supported frameworks: Logos (.x), Orion (.x.swift)

### Build & Install

```bash
# Build
docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak>

# Clean → Build → Package → Install
docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak> clean
docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/<tweak> package install THEOS_DEVICE_IP=192.168.0.49
```

### SSH Setup (first time only)

```bash
docker compose -f .devcontainer/compose.yaml exec theos ssh-copy-id -o PubkeyAuthentication=no root@192.168.0.49
# Password: alpine
```

### Workflow

1. Edit code
2. Run `make` to verify the build succeeds
3. After a successful build, run `make package install THEOS_DEVICE_IP=192.168.0.49` to deploy to device

## Makefile Template

```makefile
TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = Argo
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NetflixSSLBypass

NetflixSSLBypass_FILES = Sources/NetflixSSLBypass/Tweak.x.swift
NetflixSSLBypass_SWIFT_FLAGS = -ISources/NetflixSSLBypass
NetflixSSLBypass_FRAMEWORKS = Foundation
NetflixSSLBypass_LDFLAGS = -lsubstrate

include $(THEOS_MAKE_PATH)/tweak.mk
```

## iOS Device Info

- OS: iOS 15.8.3
- JB: Dopamine (rootless)
- Path prefix: `/var/jb/` (rootless)
- Hooking: ElleKit 1.1.3
- Orion: dev.theos.orion14 1.0.2
- Netflix: Argo v15.48.1 (com.netflix.Netflix)

### Device Connection

Two methods available. **Prefer iproxy (USB)**; fall back to direct Wi-Fi if it fails.

| Method | SSH Command | Theos Install |
|--------|------------|---------------|
| **iproxy (USB)** | `ssh -p 2222 root@host.docker.internal` | `THEOS_DEVICE_IP=host.docker.internal THEOS_DEVICE_PORT=2222` |
| **Wi-Fi direct** | `ssh root@192.168.0.49` | `THEOS_DEVICE_IP=192.168.0.49` |

From the theos container:
```bash
# iproxy
docker compose -f .devcontainer/compose.yaml exec theos ssh -p 2222 root@host.docker.internal '<command>'

# Wi-Fi direct
docker compose -f .devcontainer/compose.yaml exec theos ssh root@192.168.0.49 '<command>'
```

### Launching the App

Launch Netflix by bundle ID using `uiopen`:
```bash
ssh -p 2222 root@host.docker.internal 'uiopen --bundleid com.netflix.Netflix'
```

Verify the process is alive after launch:
```bash
ssh -p 2222 root@host.docker.internal 'sleep 8 && killall -0 Argo && echo OK'
```

## Netflix Binary Structure (analyzed)

### Nbp.framework (6.8MB)
- `NflxTrustStore` — OpenSSL X509 verification (`evaluateTrust:error:`)
- `NflxPinnedCertEvaluator` — Per-host pinning (`hasPinnedCertForHost:`, `evaluatePinnedCertificate:forHost:`)
- `__Z6verifyiP17x509_store_ctx_st` — OpenSSL verify (C function)
- `__Z16verify_notfailediP17x509_store_ctx_st` — verify_notfailed (C function)

### MslClient.framework (1.4MB)
- `IosMslClient` — MSL communication controller
  - `shouldUseSSLTrustStore` — SSL trust store flag
  - `updateNFURLSessionCerts:` — Certificate update
  - `appboot:` — appboot request
  - `_handleAppbootResponse:error:timeoutMS:` — appboot response handler
- Entity Auth: `FAIRPLAY_MGK_APPID`

### NFWebCrypto.framework (2.3MB)
- `kAppBootKey` — RSA-4096 public key (hardcoded)
- `kAppBootEccKey` — ECDSA P-256 public keys x3
- Irdeto TFIT whitebox AES-128 (for MGK)
- `dhKeyGen` / `dhDerive` — DH key exchange
- `aesCbc` / `HKDF` — Session key derivation

### NFURLSession.framework
- `URLSession:didReceiveChallenge:completionHandler:` — TLS challenge handler
- `setTrustStore:` / `setPinnedCertificateEvaluator:` — Trust configuration

## C Function Hooking (Orion + MSHookFunction)

```swift
@_silgen_name("MSHookFunction")
func MSHookFunction(_ symbol: UnsafeMutableRawPointer, _ replace: UnsafeMutableRawPointer, _ result: UnsafeMutablePointer<UnsafeMutableRawPointer?>)

@_silgen_name("dlsym")
func dlsym_c(_ handle: UnsafeMutableRawPointer?, _ symbol: UnsafePointer<CChar>) -> UnsafeMutableRawPointer?

// Linker flag: NetflixSSLBypass_LDFLAGS = -lsubstrate
```

## MSL Decryption Goal

Achieve the following within the tweak:
1. Intercept MSL request/response CBOR payloads
2. Obtain session keys (via key exchange hook or memory extraction)
3. Decrypt with AES-128-CBC
4. Log or save plaintext JSON/CBOR
5. Log with `[NFXBypass]` prefix via NSLog

## IPA Analysis Binaries

```
/tmp/netflix_ipa/Payload/Argo.app/
  Frameworks/  # Frameworks listed above
```

Searchable with `strings` command.

## Constraints

- Files go under `packages/tweak/`
- Write plists in XML format (OpenStep format may not be read by ElleKit)
- Python: run `uv run ruff format` if editing Python files
- Do not guess — say "unknown" when unsure
- Verify blast radius before making changes

## File Splitting Rules

- Consider splitting when a single file exceeds **300 lines**
- Split by layer (SSL bypass, crypto hooks, utilities, etc.)
- Add new files to the Makefile's `_FILES` variable
- Extract shared types/utilities into a dedicated file (e.g., `Helpers.swift`)
- Use `*-Bridging-Header.h` for header bridging when needed

## Execution Verification Rules

- After a successful build, **install on device and verify no crash at runtime**
- Launch the app via **SSH normal launch** (not Frida spawn) and confirm the process stays alive
- Do not use standalone Frida spawn (`frida -U -f com.netflix.Netflix`) — only via objection
- **dylib permissions**: Always run `chmod 755` after Theos install (default 700 prevents mobile user from reading, so the tweak won't load)

### SSH Command Reference (from theos container)

```bash
SSH="docker compose -f .devcontainer/compose.yaml exec theos ssh -p 2222 root@host.docker.internal"

# Launch app
$SSH 'uiopen --bundleid com.netflix.Netflix'

# Check process alive
$SSH 'killall -0 Argo && echo OK || echo CRASH'

# Kill process
$SSH 'killall Argo 2>/dev/null'

# Realtime log (NFXBypass only)
$SSH 'timeout 10 oslog | grep NFXBypass'

# Check tweak log file
$SSH 'cat $(find /var/mobile -name "msl_keys.jsonl" 2>/dev/null | head -1) 2>/dev/null'

# Fix dylib permissions
$SSH 'chmod 755 /var/jb/Library/MobileSubstrate/DynamicLibraries/NetflixSSLBypass.dylib'

# Uninstall tweak
$SSH 'dpkg -r com.local.netflixsslbypass'

# Check tweak install status
$SSH 'dpkg -l | grep netflixssl'
```

### Install → Launch Verification Flow

```bash
# 1. Kill
$SSH 'killall Argo 2>/dev/null'

# 2. Build + Install
docker compose -f .devcontainer/compose.yaml exec theos make -C /home/vscode/app/packages/tweak/NetflixSSLBypass package install THEOS_DEVICE_IP=host.docker.internal THEOS_DEVICE_PORT=2222

# 3. Fix permissions (required)
$SSH 'chmod 755 /var/jb/Library/MobileSubstrate/DynamicLibraries/NetflixSSLBypass.dylib'

# 4. Launch
$SSH 'uiopen --bundleid com.netflix.Netflix'

# 5. Wait + Verify
sleep 12
$SSH 'killall -0 Argo && echo OK || echo CRASH'
```

### About Frida

- `frida-ps -H host.docker.internal:27042` from app container hangs (TTY + protocol issue)
- When Frida is needed, **ask the user to run it on the host**
- Frida attach after launch by PID: `frida -U -p <pid>` (run on host)
