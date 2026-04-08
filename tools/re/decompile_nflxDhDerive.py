#!/usr/bin/env python3
"""
Pseudocode reconstruction for NFWebCrypto::nflxDhDerive using LIEF + Capstone.

Produces a C-like pseudocode from the disassembly of nflxDhDerive
(the vector<unsigned char> variant at offset 0xFEEC).

Usage:
    pip install lief capstone
    python decompile_nflxDhDerive.py [<binary_path>]
"""
import sys

try:
    import lief
    import capstone
except ImportError:
    print("Install dependencies: pip install lief capstone")
    sys.exit(1)


BINARY_DEFAULT = "/tmp/nfwc/Payload/Argo.app/Frameworks/NFWebCrypto.framework/NFWebCrypto"

# Key function offsets
NFLX_DH_DERIVE = 0xFEEC
NFLX_DH_DERIVE_END = 0xFEEC + 1452
GETBYTES = 0xD7E0
GETBYTES_END = 0xD7E0 + 140


def disassemble_range(binary_data: bytes, start: int, end: int) -> list:
    """Disassemble a range of bytes using Capstone."""
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    code = binary_data[start:end]
    return list(md.disasm(code, start))


def print_pseudocode():
    """Print reconstructed pseudocode based on static analysis."""
    print("""
// ============================================================
// Reconstructed pseudocode for nflxDhDerive (0xFEEC - 0x10498)
// from NFWebCrypto.framework/NFWebCrypto (arm64, Netflix 15.48.1)
// ============================================================

// Signature (from RTTI / demangled symbol):
// netflix::AppleWebCrypto::nflxDhDerive(
//     unsigned int dh_key_handle,           // x1 (w27) - handle to DH private key
//     const vector<uint8_t>& peer_pub_key,  // x2 (x20) - peer's DH public key
//     unsigned int derivation_handle,       // x3 (w21) - looked up in key store
//     unsigned int& enc_key_id,             // x4 (x26) - output: encryption key ID
//     unsigned int& sign_key_id,            // x5 (x24) - output: signing key ID
//     unsigned int& wrap_key_id             // x6 (x23) - output: wrap key ID
// ) -> return_struct (via x8/x22)

uint32_t nflxDhDerive(
    AppleWebCrypto* this,          // x0/x25
    uint32_t dh_key_handle,        // x1/w27
    const vector<uint8_t>& peer_pub_key,  // x2/x20
    uint32_t derivation_handle,    // x3/w21
    uint32_t& enc_key_id,         // x4/x26
    uint32_t& sign_key_id,        // x5/x24
    uint32_t& wrap_key_id         // x6/x23
)
{
    // Step 0: Lock mutex at this+0x40
    mutex_lock(&this->mutex);                              // 0xFF34

    // Step 1: Validate input vector size
    //   peer_pub_key must be exactly 0x80 (128) bytes
    //   (checks: end - begin - 0x82 + 3 <= 0, i.e., size in [0x80, 0x82])
    size_t pub_key_len = peer_pub_key.end() - peer_pub_key.begin();
    if (pub_key_len < 0x80 || pub_key_len > 0x82) {       // 0xFF38-0xFF48
        *result = 4;  // ERROR: invalid input
        goto cleanup;
    }

    // Step 2: Look up DH private key by dh_key_handle in BST
    AppleNativeKey* dh_priv_entry = bst_find(this->key_store, dh_key_handle);
    if (dh_priv_entry == NULL) {                           // 0xFF64-0xFF94
        *result = 3;  // ERROR: key not found
        goto cleanup;
    }

    // Step 3: Get DH parameters and compute shared secret
    DH* dh = dh_priv_entry->dh_handle;                    // [x24+0x28] -> [+0x20]
    int dh_size = DH_size(dh);                             // 0xFFA4

    vector<uint8_t> shared_secret;
    shared_secret.resize(dh_size);                         // 0xFFC4-0xFFDC
    bzero(shared_secret.data(), dh_size);

    // Step 4: Convert peer public key bytes to BIGNUM
    BIGNUM* pub_bn = BN_bin2bn(
        peer_pub_key.data(),
        peer_pub_key.size() - peer_pub_key.data(),         // 0x10000-0x10008
        NULL
    );                                                      // 0x1000C

    // Step 5: Validate peer public key
    int codes = 0;
    if (DH_check_pub_key(dh, pub_bn, &codes) != 1 || codes != 0) {
        *result = 3;                                        // 0x10028-0x10038
        goto cleanup_bn;
    }

    // Step 6: Compute DH shared secret
    int ss_len = DH_compute_key(shared_secret.data(), pub_bn, dh);
    if (ss_len < 0) {                                      // 0x1004C-0x10050
        *result = 3;
        goto cleanup_bn;
    }

    // Step 7: Ensure leading zero byte (MSL wire format)
    if (shared_secret[0] != 0x00) {                        // 0x10058-0x1005C
        // Prepend 0x00 byte
        uint8_t zero = 0x00;
        shared_secret.insert(shared_secret.begin(), zero);  // 0x10060-0x1006C
    }
    // shared_secret is now [0x00 || raw_DH_shared_secret]

    // Step 8: Look up derivation key by derivation_handle
    AppleNativeKey* deriv_entry = bst_find(this->key_store, derivation_handle);
    if (deriv_entry == NULL) {                              // 0x10070-0x100A4
        *result = 3;
        goto cleanup_bn;
    }

    // ============================================================
    // CRITICAL: 48-byte HMAC key derivation
    // ============================================================

    // Step 9: Allocate 48-byte (0x30) output buffer
    uint8_t* sha384_out = new uint8_t[0x30];               // 0x10120-0x1012C
    memset(sha384_out, 0, 0x30);

    // Step 10: Get raw key bytes from the derivation key
    //   AppleNativeKey::getBytes() XOR-decodes the stored key material
    //   using the obfuscation byte at key->offset_0x0C
    shared_ptr<KeyByteArray> key_bytes = deriv_entry->getBytes();  // 0x10158-0x10164

    // Step 11: SHA-384 hash of the native key material -> 48-byte key
    //   This is THE derivation of the 48-byte HMAC key.
    //   Input:  raw bytes of the "derivation key" (variable length)
    //   Output: 48 bytes (SHA-384 digest)
    uint8_t* sha384_key = SHA384(
        key_bytes.data(),       // x0 = key data pointer
        key_bytes.size(),       // x1 = key data length
        sha384_out              // x2 = output buffer (48 bytes)
    );                                                      // 0x10168-0x10174

    if (sha384_key == NULL) {                               // 0x1017C
        *result = 2;
        goto cleanup_all;
    }

    // Step 12: HMAC-SHA384 using the SHA-384 hash as key
    //   key     = SHA384(native_key_bytes)     -- 48 bytes (0x30)
    //   message = [0x00 || DH_shared_secret]   -- 129 bytes typically
    //   output  = HMAC-SHA384(key, message)    -- 48 bytes
    const EVP_MD* md = EVP_sha384();                        // 0x10180
    uint8_t* hmac_result = HMAC(
        md,                             // x0 = EVP_sha384()
        sha384_out,                     // x1 = 48-byte SHA-384 key
        0x30,                           // w2 = key length = 48
        shared_secret.data(),           // x3 = [0x00 || DH_shared_secret]
        shared_secret.size(),           // x4 = shared secret length
        hmac_output_buf,                // x5 = output buffer (from shared_ptr)
        NULL                            // x6 = NULL (no output length needed)
    );                                                      // 0x101A0

    if (hmac_result == NULL) {                              // 0x101A4
        *result = 2;
        goto cleanup_all;
    }

    // ============================================================
    // Step 13: Split HMAC output into enc_key, sign_key, wrap_key
    // ============================================================

    // enc_key  = hmac_output[0:16]   -- 16 bytes (AES-128-CBC encryption key)
    shared_ptr<KeyByteArray> enc_key_data(
        hmac_output, hmac_output + 0x10                     // 0x101A8-0x101CC
    );

    // sign_key = hmac_output[16:48]  -- 32 bytes (HMAC-SHA256 signing key)
    shared_ptr<KeyByteArray> sign_key_data(
        hmac_output + 0x10, hmac_output + 0x30              // 0x101D0-0x101F8
    );

    // ============================================================
    // Step 14: Create salt and info for subsequent HKDF (key wrapping)
    // ============================================================

    // PSK (Pre-Shared Key / salt) -- 16 bytes embedded in binary
    // Address: 0x1AC8F5
    uint8_t psk[16];
    memcpy(psk, (void*)0x1AC8F5, 16);                      // 0x1020C-0x10218

    // Nonce (info) -- 16 bytes embedded in binary
    // Address: 0x1AC905
    uint8_t nonce[16];
    memcpy(nonce, (void*)0x1AC905, 16);                     // 0x10230-0x1023C

    // Step 15: Call virtual method (vtable[0x130/8]) for key registration
    //   This appears to be a key-import/registration call that
    //   stores the derived HMAC output + salt + nonce together
    this->vtable->registerDerivedKeys(                      // 0x10264-0x10280
        this, sign_key_data, psk, nonce, hmac_shared_ptr
    );

    // Step 16: Store enc_key as AppleNativeKey (type=3, extractable=1)
    AppleNativeKey* enc_nk = new AppleNativeKey(
        0,      // key_id placeholder
        3,      // type = AES (0x3)
        1,      // extractable = true
        enc_key_data
    );                                                      // 0x102EC-0x10300
    enc_key_id = this->insertKey(enc_nk, false);            // vtable[0x138]

    // Step 17: Store sign_key as AppleNativeKey (type=0xC, extractable=0)
    AppleNativeKey* sign_nk = new AppleNativeKey(
        0,
        0xC,    // type = HMAC_SHA256 (0xC)
        0,      // extractable = false
        sign_key_data
    );                                                      // 0x1036C-0x10380
    sign_key_id = this->insertKey(sign_nk, false);          // vtable[0x138]

    // Step 18: Store wrap_key (full 48B) as AppleNativeKey (type=0x70, subtype=0xC)
    AppleNativeKey* wrap_nk = new AppleNativeKey(
        0,
        0x70,   // type = HMAC_SHA384 (0x70)
        0xC,    // subtype/usage
        hmac_output_shared_ptr
    );                                                      // 0x103EC-0x10400
    wrap_key_id = this->insertKey(wrap_nk, false);          // vtable[0x138]

    *result = 1;  // SUCCESS                                // 0x10444-0x10448

cleanup_all:
    // ... cleanup shared_ptrs, free sha384_out, BN_free(pub_bn) ...

    mutex_unlock(&this->mutex);                             // 0x100FC
    return;
}


// ============================================================
// AppleNativeKey::getBytes() at 0xD7E0
// XOR deobfuscation of stored key material
// ============================================================

shared_ptr<KeyByteArray> AppleNativeKey::getBytes() {
    // key_data stored at this->key_array (offset 0x10)
    // obfuscation mask at this->xor_byte (offset 0x0C)

    KeyByteArray* raw = this->key_array;                    // [this+0x10]
    uint8_t* begin = raw->begin();                          // [raw+8]
    uint8_t* end   = raw->end();                            // [raw+16]

    // Create a copy of the key data
    shared_ptr<KeyByteArray> result = make_shared(begin, end);

    // XOR each byte with the obfuscation mask
    uint8_t mask = this->xor_byte;                          // [this+0x0C]
    uint8_t* out = result->data();
    size_t len = end - begin;
    for (size_t i = 0; i < len; i++) {                      // 0xD82C-0xD858
        out[i] = out[i] ^ mask;
    }
    return result;
}
""")


def main():
    binary_path = sys.argv[1] if len(sys.argv) > 1 else BINARY_DEFAULT

    try:
        binary = lief.parse(binary_path)
        if binary is None:
            print(f"ERROR: Could not parse {binary_path}")
            sys.exit(1)
        print(f"Binary: {binary_path}")
        print(f"Format: {binary.format}")

        with open(binary_path, "rb") as f:
            data = f.read()

        # Disassemble key sections
        print("\n--- nflxDhDerive SHA384 call site (0x10158-0x10178) ---")
        for insn in disassemble_range(data, 0x10158, 0x10178):
            print(f"  0x{insn.address:08x}:  {insn.mnemonic}\t{insn.op_str}")

        print("\n--- nflxDhDerive HMAC call site (0x10180-0x101A4) ---")
        for insn in disassemble_range(data, 0x10180, 0x101A4):
            print(f"  0x{insn.address:08x}:  {insn.mnemonic}\t{insn.op_str}")

        print("\n--- getBytes XOR loop (0xD82C-0xD868) ---")
        for insn in disassemble_range(data, 0xD82C, 0xD868):
            print(f"  0x{insn.address:08x}:  {insn.mnemonic}\t{insn.op_str}")

        # Dump static data
        psk = data[0x1AC8F5:0x1AC8F5 + 16]
        nonce = data[0x1AC905:0x1AC905 + 16]
        print(f"\n--- Static PSK (salt) @ 0x1AC8F5 ---")
        print(f"  {psk.hex()}")
        print(f"\n--- Static nonce (info) @ 0x1AC905 ---")
        print(f"  {nonce.hex()}")

    except Exception as e:
        print(f"Binary analysis error: {e}")
        print("Falling back to pseudocode-only output.\n")

    print_pseudocode()


if __name__ == "__main__":
    main()
