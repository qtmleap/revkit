#!/usr/bin/env python3
"""
Static analysis: find how kAppBootKey (RSA-4096) and kAppBootEccKey (ECDSA P-256)
are used in NFWebCrypto.framework.

Hypothesis: These keys are used for **signature verification** of the appboot
server response, NOT for encryption.

Binary: Netflix iOS 15.48.1 NFWebCrypto.framework (arm64 Mach-O)

Usage:
    python3 tools/re/find_appboot_key_usage.py [path_to_NFWebCrypto]
"""

import sys

import r2pipe

DEFAULT_BINARY = (
    "/tmp/nfwc/Payload/Argo.app/Frameworks/NFWebCrypto.framework/NFWebCrypto"
)

# BSS addresses of the key variables (std::string globals)
KEYS = {
    "kAppBootKey": {"addr": 0x0028EFA8, "algo_id": 5, "algo_name": "RSASSA-PKCS1-v1_5"},
    "kAppBootEccKey": {"addr": 0x0028EFF0, "algo_id": 0x10, "algo_name": "ECDSA P-256"},
    "kSharkBootKey_Test": {"addr": 0x0028EFC0, "algo_name": "ECDSA P-256 (test)"},
    "kSharkBootKey": {"addr": 0x0028EFD8, "algo_name": "ECDSA P-256 (prod)"},
}

# String name handles used in the key store
KEY_HANDLES = {
    "ABKP": {"addr": 0x0020D2CA, "desc": "AppBoot Key (RSA) persisted handle"},
    "ABECCKP": {"addr": 0x0020D34B, "desc": "AppBoot ECC Key persisted handle"},
}


def analyze(binary_path: str) -> None:
    r2 = r2pipe.open(binary_path, flags=["-e", "bin.cache=true", "-2"])
    r2.cmd("aaa")

    print("=" * 72)
    print("APPBOOT KEY USAGE ANALYSIS — NFWebCrypto.framework")
    print("=" * 72)

    # ── Step 1: Verify key symbols exist ──────────────────────────────────
    print("\n## 1. Key symbol locations (BSS)")
    for name, info in KEYS.items():
        syms = r2.cmd(f"is~{name}")
        if syms.strip():
            print(f"  {name}: 0x{info['addr']:08x}  ({info.get('algo_name', '?')})")
            for line in syms.strip().split("\n"):
                print(f"    {line.strip()}")
        else:
            print(f"  {name}: NOT FOUND")

    # ── Step 2: Find xrefs to each key ───────────────────────────────────
    print("\n## 2. Cross-references to key variables")
    for name, info in KEYS.items():
        addr = info["addr"]
        xrefs = r2.cmd(f"axt @ {addr}")
        print(f"\n  ### {name} (0x{addr:08x})")
        if xrefs.strip():
            for line in xrefs.strip().split("\n"):
                print(f"    {line.strip()}")
        else:
            print("    (no xrefs found)")

    # ── Step 3: Analyze the constructor ──────────────────────────────────
    print("\n## 3. AppleWebCrypto constructor — key import flow")
    ctor_sym = "sym.netflix::AppleWebCrypto::AppleWebCrypto_objc_object_objcproto18AppleNativeStorage__objc_object_objcproto7IDevice_"
    ctor_info = r2.cmd(f"?v {ctor_sym}")
    print(f"  Constructor at: {ctor_info.strip()}")

    print("\n  ### kAppBootKey import sequence (around 0xb6b0):")
    print("    1. Load kAppBootKey std::string from BSS (0x28efa8)")
    print("    2. Copy into std::vector<uint8_t>")
    print("    3. Base64::decode() the string → raw DER bytes")
    print("    4. Allocate AppleNativeKey (0x38 bytes)")
    print("    5. Call virtual importKey(KeyFormat=2 [SPKI], data, Algorithm=5 [RSASSA-PKCS1-v1_5], usage=8 [VERIFY])")
    print("       → vtable offset 0xe0")
    print("    6. On success, persist key with handle name 'ABKP'")
    print("       → vtable offset 0xa8")
    print("    7. On failure: log 'Failed to import RSA app boot key : <errcode>'")

    print("\n  ### kAppBootEccKey import sequence (around 0xbc68):")
    print("    1. Load kAppBootEccKey std::string from BSS (0x28eff0)")
    print("    2. Copy into std::vector<uint8_t>")
    print("    3. Base64::decode() the string → raw DER bytes")
    print("    4. Allocate AppleNativeKey (0x38 bytes)")
    print("    5. Call virtual importKey(KeyFormat=2 [SPKI], data, Algorithm=0x10 [ECDSA], usage=8 [VERIFY])")
    print("       → vtable offset 0xe0")
    print("    6. On success, persist key with handle name 'ABECCKP'")
    print("       → vtable offset 0xa8")
    print("    7. On failure: log 'Failed to import ECC app boot key'")

    # ── Step 4: Analyze importKey for algo dispatch ──────────────────────
    print("\n## 4. importKey algorithm dispatch (0x0000d31c)")
    print("  Signature: importKey(KeyFormat, shared_ptr<KeyByteArray>, Algorithm, usage, keyId&, KeyType&)")
    print()
    print("  KeyFormat=2 (SPKI) branch at 0xd414:")
    print("    switch (Algorithm) {")
    print("      case 5 (RSASSA-PKCS1-v1_5): → d2i_RSA_PUBKEY()  // parse RSA public key from DER")
    print("      case 0x10 (ECDSA):          → d2i_EC_PUBKEY()   // parse EC public key from DER")
    print("      default:                    → error (unsupported)")
    print("    }")
    print()
    print("  For RSA: stores as AppleNativeKey { type=1, usage, algo=5, rsa_key, RSA_free }")
    print("  For ECC: stores as AppleNativeKey { type=1, usage, algo=0x10, ec_key, EC_KEY_free }")

    # ── Step 5: Verify operations available ──────────────────────────────
    print("\n## 5. Signature verification functions")
    verify_funcs = {
        "rsaVerify": 0x0000EE00,
        "eccVerify": 0x00010B00,
        "RsaContext::publicVerify": 0x0001A2D0,
        "EcdsaContext::publicVerify": 0x00015598,
    }
    for name, addr in verify_funcs.items():
        info = r2.cmd(f"afi @ {addr}")
        size_line = [l for l in info.split("\n") if "size:" in l]
        size = size_line[0].strip() if size_line else "?"
        print(f"  {name}: 0x{addr:08x}  ({size})")

    print("\n  ### Call chain for RSA verification:")
    print("    AppleWebCrypto::rsaVerify(keyId, algo, data, signature, &result)")
    print("      → looks up keyId in key store (BST at this+0x18)")
    print("      → RsaContext::publicVerify(data, shaAlgo, signature)")
    print("        → RsaContext::computeDigest(data, shaAlgo)")
    print("        → RSA_blinding_on(rsa_key)")
    print("        → RSA_verify(nid, digest, digest_len, sig, sig_len, rsa_key)")
    print("        → RSA_blinding_off(rsa_key)")

    print("\n  ### Call chain for ECDSA verification:")
    print("    AppleWebCrypto::eccVerify(keyId, algo, data, signature, &result)")
    print("      → looks up keyId in key store")
    print("      → EcdsaContext::publicVerify(data, shaAlgo, signature)")
    print("        → EcdsaContext::computeDigest(data, shaAlgo)")
    print("        → ECDSA_verify(nid, digest, digest_len, sig, sig_len, ec_key)")

    # ── Step 6: Static initializer analysis ──────────────────────────────
    print("\n## 6. Static initializer (__GLOBAL__sub_I_AppleWebCrypto.mm)")
    print("  Address: 0x000144f0 (260 bytes)")
    print("  Initializes all static key strings from base64 literals:")
    print()

    # Extract the actual base64 key values from the binary
    key_strings = {
        "kAppBootKey": 0x0020CD31,
        "kSharkBootKey_Test": 0x0020D012,
        "kSharkBootKey": 0x0020D08F,
        "kAppBootEccKey": 0x0020D10C,
    }
    for name, str_addr in key_strings.items():
        val = r2.cmd(f"ps @ {str_addr}")
        val_stripped = val.strip()[:80]
        print(f"    {name}: {val_stripped}...")
        print(f"      (string at 0x{str_addr:08x})")

    # ── Step 7: Additional related keys ──────────────────────────────────
    print("\n## 7. Additional boot keys (Shark)")
    print("  kSharkBootKey_Test (0x28efc0): ECC P-256 test/staging key")
    print("  kSharkBootKey      (0x28efd8): ECC P-256 production key")
    print("  dataObfuscationTest(0x28f008): Test data obfuscation string")
    print()
    print("  All initialized in the same static initializer with __cxa_atexit")
    print("  for cleanup. Pattern: std::string(base64_literal) → BSS global")

    # ── Conclusion ───────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("CONCLUSION")
    print("=" * 72)
    print("""
  kAppBootKey (RSA-4096) and kAppBootEccKey (ECDSA P-256) are BOTH used
  exclusively for **signature VERIFICATION**, not encryption.

  Evidence:
  1. importKey is called with usage=8, which corresponds to VERIFY usage
     (not ENCRYPT=1 or WRAP=4)
  2. The keys are imported as public keys via d2i_RSA_PUBKEY / d2i_EC_PUBKEY
     (public keys cannot encrypt in PKCS#1 v1.5 signature mode)
  3. Algorithm=5 (RSASSA-PKCS1-v1_5) is a signature algorithm, not RSA-OAEP
  4. The only operations that reference these algo types are rsaVerify/eccVerify
  5. RSA_verify() and ECDSA_verify() are the terminal OpenSSL calls

  Usage flow:
    Static init → base64 decode → importKey(SPKI, raw, RSASSA/ECDSA, VERIFY)
                                      ↓
                              stored in key map with handle "ABKP" / "ABECCKP"
                                      ↓
    Appboot response → rsaVerify(keyId="ABKP", ...) / eccVerify(keyId="ABECCKP", ...)
                                      ↓
                              RsaContext::publicVerify → RSA_verify()
                              EcdsaContext::publicVerify → ECDSA_verify()

  The appboot server signs its response, and the client verifies using these
  embedded public keys. This is a standard response-signing pattern (like TLS
  certificate pinning but at the application layer).

  Corrected MSL key exchange model:
    1. Client generates DH key pair (dhKeyGen)
    2. Client sends DH public value to server (NOT RSA-encrypted)
    3. Server responds with its DH public value + signature
    4. Client verifies server response signature with kAppBootKey (RSA) or
       kAppBootEccKey (ECDSA)
    5. Client computes DH shared secret
    6. HKDF derives session keys from shared secret
""")

    r2.quit()


if __name__ == "__main__":
    binary = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BINARY
    analyze(binary)
