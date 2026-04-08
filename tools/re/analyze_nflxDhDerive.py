#!/usr/bin/env python3
"""
Static analysis script for NFWebCrypto nflxDhDerive key derivation.

Extracts the 48-byte HMAC key derivation chain from the NFWebCrypto binary
using radare2 (r2pipe).

Usage:
    pip install r2pipe
    python analyze_nflxDhDerive.py <path_to_NFWebCrypto_binary>
"""
import sys
import r2pipe
import struct


def analyze(binary_path: str) -> None:
    r2 = r2pipe.open(binary_path, flags=["-e", "bin.cache=true"])
    r2.cmd("aaa")

    print("=" * 70)
    print("NFWebCrypto nflxDhDerive 48-byte HMAC Key Derivation Analysis")
    print("=" * 70)

    # 1. Find HMAC symbol and xrefs
    print("\n[1] HMAC symbol xrefs:")
    hmac_addr = 0x0DBA78
    xrefs = r2.cmd(f"axt @ {hmac_addr}")
    for line in xrefs.strip().split("\n"):
        if "nflxDhDerive" in line:
            print(f"  -> HMAC call in nflxDhDerive: {line.strip()}")

    # 2. Dump the SHA384 call site
    print("\n[2] SHA384 call in nflxDhDerive:")
    sha384_call = 0x00010174
    r2.cmd(f"s {sha384_call - 0x1C}")
    disasm = r2.cmd("pd 8")
    print(disasm)

    # 3. Dump the HMAC call site
    print("\n[3] HMAC-SHA384 call in nflxDhDerive (48B key):")
    hmac_call = 0x000101A0
    r2.cmd(f"s {hmac_call - 0x20}")
    disasm = r2.cmd("pd 10")
    print(disasm)

    # 4. Dump static data (PSK salt and info nonce)
    print("\n[4] Static embedded data:")
    psk_addr = 0x1AC8F5
    nonce_addr = 0x1AC905
    r2.cmd(f"s {psk_addr}")
    print(f"  PSK (salt) @ 0x{psk_addr:06x}:")
    print("  " + r2.cmd("px 16"))
    r2.cmd(f"s {nonce_addr}")
    print(f"  Nonce (info) @ 0x{nonce_addr:06x}:")
    print("  " + r2.cmd("px 16"))

    # 5. getBytes XOR deobfuscation
    print("\n[5] AppleNativeKey::getBytes() XOR deobfuscation:")
    r2.cmd("s 0xd82c")
    disasm = r2.cmd("pd 12")
    print(disasm)

    # 6. Key splitting
    print("\n[6] HMAC output key splitting:")
    r2.cmd("s 0x101a8")
    disasm = r2.cmd("pd 20")
    print(disasm)

    print("\n" + "=" * 70)
    print("DERIVATION CHAIN SUMMARY")
    print("=" * 70)
    print("""
    nflxDhDerive(this, dh_pub_key_vec, dh_key_handle, &enc_key_id, &sign_key_id, &wrap_key_id):

    1. Lookup DH private key by dh_key_handle in key store (BST walk)
    2. DH_compute_key(shared_secret_buf, peer_pub_bn, dh_priv_key)
       -> raw DH shared secret (up to DH_size bytes)
    3. If shared_secret[0] != 0x00:
         prepend 0x00 byte -> [0x00 || shared_secret]
    4. native_key_bytes = AppleNativeKey::getBytes(dh_priv_key)
       (XOR-deobfuscates stored key material)
    5. sha384_key = SHA384(native_key_bytes, native_key_len)
       -> 48 bytes
    6. hmac_out = HMAC(EVP_sha384, sha384_key, 48,
                       [0x00 || shared_secret], len, output_buf, NULL)
       -> 48 bytes
    7. enc_key   = hmac_out[0:16]   (AES-128 encryption key)
       sign_key  = hmac_out[16:48]  (HMAC-SHA256 signing key, 32 bytes)
    8. wrap_key  = hmac_out[0:48]   (full 48 bytes, key type 0x70/HMAC_SHA384)

    Static data used AFTER derivation (for key wrapping / HKDF):
      PSK  (salt)  = 16 bytes @ 0x1ac8f5
      Info (nonce)  = 16 bytes @ 0x1ac905
    """)

    r2.quit()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        binary = "/tmp/nfwc/Payload/Argo.app/Frameworks/NFWebCrypto.framework/NFWebCrypto"
    else:
        binary = sys.argv[1]
    analyze(binary)
