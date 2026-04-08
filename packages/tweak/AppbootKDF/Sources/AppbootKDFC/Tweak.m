#import <Orion/Orion.h>
#import <os/log.h>
#import <substrate.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>

// ---------------------------------------------------------------------------
// os_log channels — subsystem "com.netflix.kdf", category per function
// ---------------------------------------------------------------------------

static os_log_t g_log_dhDerive  = NULL;
static os_log_t g_log_hkdf      = NULL;
static os_log_t g_log_aesCbc    = NULL;
static os_log_t g_log_hmac      = NULL;
static os_log_t g_log_general   = NULL;

// ---------------------------------------------------------------------------
// File log (mirrors AppbootKeyExtract convention)
// ---------------------------------------------------------------------------

static NSString *g_logFile = nil;

static void file_log(os_log_t channel, NSString *msg) {
    if (channel) {
        os_log(channel, "%{public}s", msg.UTF8String);
    }
    if (g_logFile) {
        @try {
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.dateFormat = @"HH:mm:ss.SSS";
            NSString *line = [NSString stringWithFormat:@"%@ %@\n",
                              [df stringFromDate:[NSDate date]], msg];
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logFile];
            if (!fh) {
                [line writeToFile:g_logFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
            } else {
                [fh seekToEndOfFile];
                [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                [fh closeFile];
            }
        } @catch (NSException *e) {}
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static NSString *hexEncode(const uint8_t *data, size_t len) {
    if (!data || len == 0) return @"(null)";
    NSMutableString *s = [NSMutableString stringWithCapacity:len * 2];
    for (size_t i = 0; i < len; i++) {
        [s appendFormat:@"%02x", data[i]];
    }
    return s;
}

static NSString *hexEncodeShort(const uint8_t *data, size_t len) {
    if (!data || len == 0) return @"(null)";
    if (len <= 64) return hexEncode(data, len);
    NSString *head = hexEncode(data, 32);
    NSString *tail = hexEncode(data + len - 16, 16);
    return [NSString stringWithFormat:@"%@...%@ (%zuB)", head, tail, len];
}

// Reentrancy guard
static volatile int g_inHook = 0;

// ---------------------------------------------------------------------------
// Opaque types (OpenSSL / BoringSSL)
// ---------------------------------------------------------------------------

typedef struct dh_st         DH;
typedef struct bignum_st     BIGNUM;

// BN helper function pointers (resolved in constructor, used by multiple hooks)
static int (*fn_BN_num_bits_int)(const BIGNUM *) = NULL;
static int (*fn_BN_bn2bin)(const BIGNUM *, unsigned char *) = NULL;

// TFIT chain state (shared between AES_set_encrypt_key and AES_encrypt hooks)
static volatile int g_tfit_active = 0;
static int g_tfit_pair_count = 0;
typedef struct evp_md_st     EVP_MD;
typedef struct hmac_ctx_st   HMAC_CTX;
typedef struct engine_st     ENGINE;
typedef struct aes_key_st    AES_KEY;

// ---------------------------------------------------------------------------
// HOOK 0a: DH_generate_key  (DH key pair generation)
//
// Signature: int DH_generate_key(DH *dh)
// Returns:   1 on success
//
// After call, use DH_get0_key to extract pub_key and priv_key BIGNUMs.
// ---------------------------------------------------------------------------

static int (*orig_DH_generate_key)(DH *dh);
static void (*fn_DH_get0_key)(const DH *, const BIGNUM **, const BIGNUM **) = NULL;

static int hook_DH_generate_key(DH *dh) {
    int ret = orig_DH_generate_key(dh);

    if (ret == 1 && !g_inHook && fn_DH_get0_key && fn_BN_num_bits_int && fn_BN_bn2bin) {
        g_inHook = 1;

        const BIGNUM *pub = NULL, *priv = NULL;
        fn_DH_get0_key(dh, &pub, &priv);

        if (pub) {
            int pubBits = fn_BN_num_bits_int(pub);
            int pubBytes = (pubBits + 7) / 8;
            if (pubBytes > 0 && pubBytes <= 1024) {
                uint8_t *buf = (uint8_t *)malloc((size_t)pubBytes);
                if (buf) {
                    fn_BN_bn2bin(pub, buf);
                    file_log(g_log_dhDerive,
                             [NSString stringWithFormat:@"[dhGenerate] client_pub_key(%dB)=%@",
                              pubBytes, hexEncode(buf, (size_t)pubBytes)]);
                    free(buf);
                }
            }
        }

        if (priv) {
            int privBits = fn_BN_num_bits_int(priv);
            int privBytes = (privBits + 7) / 8;
            if (privBytes > 0 && privBytes <= 1024) {
                uint8_t *buf = (uint8_t *)malloc((size_t)privBytes);
                if (buf) {
                    fn_BN_bn2bin(priv, buf);
                    file_log(g_log_dhDerive,
                             [NSString stringWithFormat:@"[dhGenerate] client_priv_key(%dB)=%@",
                              privBytes, hexEncode(buf, (size_t)privBytes)]);
                    free(buf);
                }
            }
        }

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 0b: RSA_public_encrypt
//
// Signature: int RSA_public_encrypt(int flen, const unsigned char *from,
//                                   unsigned char *to, RSA *rsa, int padding)
// Returns:   size of encrypted data (e.g., 512 for RSA-4096), -1 on error
//
// Captures: input plaintext, output ciphertext, padding mode
// ---------------------------------------------------------------------------

typedef struct rsa_st RSA;

static int (*orig_RSA_public_encrypt)(int flen, const unsigned char *from,
                                       unsigned char *to, RSA *rsa, int padding);

static int hook_RSA_public_encrypt(int flen, const unsigned char *from,
                                    unsigned char *to, RSA *rsa, int padding) {
    int ret = orig_RSA_public_encrypt(flen, from, to, rsa, padding);

    if (!g_inHook) {
        g_inHook = 1;

        NSString *inHex = hexEncodeShort(from, (size_t)flen);
        NSString *outHex = (ret > 0) ? hexEncodeShort(to, (size_t)ret) : @"(failed)";

        // padding: 1=PKCS1, 3=NONE, 4=OAEP, 5=PSS
        NSString *padStr;
        switch (padding) {
            case 1: padStr = @"PKCS1_v1_5"; break;
            case 3: padStr = @"NONE"; break;
            case 4: padStr = @"OAEP"; break;
            default: padStr = [NSString stringWithFormat:@"%d", padding]; break;
        }

        file_log(g_log_general,
                 [NSString stringWithFormat:
                  @"[RSA_public_encrypt] padding=%@ in(%dB)=%@ out(%dB)=%@",
                  padStr, flen, inHex, ret, outHex]);

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 0c: EVP_PKEY_encrypt (higher-level RSA/EC encryption)
//
// Signature: int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
//                                 unsigned char *out, size_t *outlen,
//                                 const unsigned char *in, size_t inlen)
// Returns:   1 on success
// ---------------------------------------------------------------------------

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

static int (*orig_EVP_PKEY_encrypt)(EVP_PKEY_CTX *ctx,
                                     unsigned char *out, size_t *outlen,
                                     const unsigned char *in, size_t inlen);

static int hook_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                                  unsigned char *out, size_t *outlen,
                                  const unsigned char *in, size_t inlen) {
    int ret = orig_EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);

    if (!g_inHook && ret == 1 && out && outlen && *outlen > 0) {
        g_inHook = 1;

        NSString *inHex = hexEncodeShort(in, inlen);
        NSString *outHex = hexEncodeShort(out, *outlen);

        file_log(g_log_general,
                 [NSString stringWithFormat:
                  @"[EVP_PKEY_encrypt] in(%zuB)=%@ out(%zuB)=%@",
                  inlen, inHex, *outlen, outHex]);

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 1: DH_compute_key  (primary Phase 2 entry point)
//
// Signature: int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
// Returns:   length of computed shared secret in bytes (128 for 1024-bit DH)
//
// Captures:
//   - peer_pub_key  (server DH public key bytes)
//   - shared_secret (raw DH output before any KDF)
// ---------------------------------------------------------------------------

static int (*orig_DH_compute_key)(unsigned char *key, const BIGNUM *pub_key, DH *dh);

static int hook_DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh) {
    int ret = orig_DH_compute_key(key, pub_key, dh);

    if (ret > 0 && !g_inHook) {
        g_inHook = 1;

        // Capture shared secret output
        NSString *ssHex = hexEncode(key, (size_t)ret);
        file_log(g_log_dhDerive,
                 [NSString stringWithFormat:@"[dhDerive] shared_secret(%dB)=%@", ret, ssHex]);

        // Capture peer public key (server's DH public key)
        if (pub_key && fn_BN_num_bits_int && fn_BN_bn2bin) {
            int pubBits = fn_BN_num_bits_int(pub_key);
            int pubBytes = (pubBits + 7) / 8;
            if (pubBytes > 0 && pubBytes <= 1024) {
                uint8_t *buf = (uint8_t *)malloc((size_t)pubBytes);
                if (buf) {
                    fn_BN_bn2bin(pub_key, buf);
                    file_log(g_log_dhDerive,
                             [NSString stringWithFormat:@"[dhDerive] peer_pub_key(%dB)=%@",
                              pubBytes, hexEncodeShort(buf, (size_t)pubBytes)]);
                    free(buf);
                }
            }
        }

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 2: HKDF_extract
//
// Signature: int HKDF_extract(uint8_t *out_key, size_t *out_len,
//                             const EVP_MD *digest,
//                             const uint8_t *secret, size_t secret_len,
//                             const uint8_t *salt, size_t salt_len)
// Returns: 1 on success
//
// Captures: IKM, salt, PRK output
// ---------------------------------------------------------------------------

static int (*orig_HKDF_extract)(uint8_t *out_key, size_t *out_len,
                                const EVP_MD *digest,
                                const uint8_t *secret, size_t secret_len,
                                const uint8_t *salt, size_t salt_len);

static int hook_HKDF_extract(uint8_t *out_key, size_t *out_len,
                              const EVP_MD *digest,
                              const uint8_t *secret, size_t secret_len,
                              const uint8_t *salt, size_t salt_len) {
    int ret = orig_HKDF_extract(out_key, out_len, digest, secret, secret_len, salt, salt_len);

    if (ret == 1 && !g_inHook) {
        g_inHook = 1;

        NSString *ikmHex  = hexEncodeShort(secret, secret_len);
        NSString *saltHex = (salt && salt_len > 0) ? hexEncode(salt, salt_len) : @"(empty)";
        NSString *prkHex  = (out_key && out_len && *out_len > 0)
                            ? hexEncode(out_key, *out_len) : @"(null)";

        file_log(g_log_hkdf,
                 [NSString stringWithFormat:
                  @"[HKDF_extract] ikm(%zuB)=%@ salt(%zuB)=%@ prk(%zuB)=%@",
                  secret_len, ikmHex, salt_len, saltHex,
                  out_len ? *out_len : 0, prkHex]);

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 3: HKDF_expand
//
// Signature: int HKDF_expand(uint8_t *out_key, size_t out_len,
//                            const EVP_MD *digest,
//                            const uint8_t *prk, size_t prk_len,
//                            const uint8_t *info, size_t info_len)
// Returns: 1 on success
//
// Captures: PRK, info string, OKM output
// ---------------------------------------------------------------------------

static int (*orig_HKDF_expand)(uint8_t *out_key, size_t out_len,
                               const EVP_MD *digest,
                               const uint8_t *prk, size_t prk_len,
                               const uint8_t *info, size_t info_len);

static int hook_HKDF_expand(uint8_t *out_key, size_t out_len,
                             const EVP_MD *digest,
                             const uint8_t *prk, size_t prk_len,
                             const uint8_t *info, size_t info_len) {
    int ret = orig_HKDF_expand(out_key, out_len, digest, prk, prk_len, info, info_len);

    if (ret == 1 && !g_inHook) {
        g_inHook = 1;

        NSString *prkHex  = (prk && prk_len > 0) ? hexEncode(prk, prk_len) : @"(null)";
        NSString *infoHex = (info && info_len > 0) ? hexEncode(info, info_len) : @"(empty)";

        // info may be a printable ASCII label — try logging as string too
        NSString *infoStr = @"";
        if (info && info_len > 0 && info_len < 128) {
            NSString *candidate = [[NSString alloc] initWithBytes:info
                                                           length:info_len
                                                         encoding:NSUTF8StringEncoding];
            if (candidate) {
                infoStr = [NSString stringWithFormat:@" info_str=\"%@\"", candidate];
            }
        }

        NSString *okmHex = (out_key && out_len > 0) ? hexEncode(out_key, out_len) : @"(null)";

        file_log(g_log_hkdf,
                 [NSString stringWithFormat:
                  @"[HKDF_expand] prk(%zuB)=%@ info(%zuB)=%@%@ okm(%zuB)=%@",
                  prk_len, prkHex, info_len, infoHex, infoStr, out_len, okmHex]);

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 4: HKDF (one-shot, BoringSSL)
//
// Signature: int HKDF(uint8_t *out_key, size_t out_len,
//                     const EVP_MD *digest,
//                     const uint8_t *secret, size_t secret_len,
//                     const uint8_t *salt, size_t salt_len,
//                     const uint8_t *info, size_t info_len)
// Returns: 1 on success
//
// Captures: all HKDF inputs + OKM in one shot
// ---------------------------------------------------------------------------

static int (*orig_HKDF)(uint8_t *out_key, size_t out_len,
                        const EVP_MD *digest,
                        const uint8_t *secret, size_t secret_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len);

static int hook_HKDF(uint8_t *out_key, size_t out_len,
                     const EVP_MD *digest,
                     const uint8_t *secret, size_t secret_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len) {
    int ret = orig_HKDF(out_key, out_len, digest, secret, secret_len,
                        salt, salt_len, info, info_len);

    if (ret == 1 && !g_inHook) {
        g_inHook = 1;

        NSString *ikmHex  = hexEncodeShort(secret, secret_len);
        NSString *saltHex = (salt && salt_len > 0) ? hexEncode(salt, salt_len) : @"(empty)";
        NSString *infoHex = (info && info_len > 0) ? hexEncode(info, info_len) : @"(empty)";
        NSString *okmHex  = (out_key && out_len > 0) ? hexEncode(out_key, out_len) : @"(null)";

        // info printable check
        NSString *infoStr = @"";
        if (info && info_len > 0 && info_len < 128) {
            NSString *candidate = [[NSString alloc] initWithBytes:info
                                                           length:info_len
                                                         encoding:NSUTF8StringEncoding];
            if (candidate) {
                infoStr = [NSString stringWithFormat:@" info_str=\"%@\"", candidate];
            }
        }

        file_log(g_log_hkdf,
                 [NSString stringWithFormat:
                  @"[HKDF] ikm(%zuB)=%@ salt(%zuB)=%@ info(%zuB)=%@%@ okm(%zuB)=%@",
                  secret_len, ikmHex, salt_len, saltHex, info_len, infoHex, infoStr,
                  out_len, okmHex]);

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 5: AES_set_encrypt_key / AES_set_decrypt_key
//
// These are the lowest-level AES key schedule setups in OpenSSL.
// Hooking these reliably captures any AES-128 key material.
// AES_cbc_encrypt MSHookFunction is avoided (known trampoline crash).
//
// Signature: int AES_set_encrypt_key(const unsigned char *userKey, int bits,
//                                    AES_KEY *key)
// ---------------------------------------------------------------------------

static int (*orig_AES_set_encrypt_key)(const unsigned char *userKey, int bits, AES_KEY *key);

static int hook_AES_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key) {
    if (!g_inHook && userKey && (bits == 128 || bits == 256)) {
        g_inHook = 1;
        int keyLen = bits / 8;
        NSString *keyHex = hexEncode(userKey, (size_t)keyLen);
        file_log(g_log_aesCbc,
                 [NSString stringWithFormat:@"[aesCbc] AES_set_encrypt_key bits=%d key=%@",
                  bits, keyHex]);

        // Detect KAT marker to activate TFIT capture
        if (bits == 256) {
            static const uint8_t kat_inc[32] = {
                0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
            };
            if (memcmp(userKey, kat_inc, 32) == 0) {
                g_tfit_active = 1;
                g_tfit_pair_count = 0;
                file_log(g_log_aesCbc, @"[TFIT] === chain started (KAT marker detected) ===");
            }
        }
        // Deactivate on AES-128 (session key = end of TFIT chain)
        if (bits == 128 && g_tfit_active) {
            file_log(g_log_aesCbc,
                     [NSString stringWithFormat:@"[TFIT] === chain ended (%d pairs captured) ===",
                      g_tfit_pair_count]);
            g_tfit_active = 0;
        }

        g_inHook = 0;
    }
    return orig_AES_set_encrypt_key(userKey, bits, key);
}

static int (*orig_AES_set_decrypt_key)(const unsigned char *userKey, int bits, AES_KEY *key);

static int hook_AES_set_decrypt_key(const unsigned char *userKey, int bits, AES_KEY *key) {
    if (!g_inHook && userKey && (bits == 128 || bits == 256)) {
        g_inHook = 1;
        int keyLen = bits / 8;
        NSString *keyHex = hexEncode(userKey, (size_t)keyLen);
        file_log(g_log_aesCbc,
                 [NSString stringWithFormat:@"[aesCbc] AES_set_decrypt_key bits=%d key=%@",
                  bits, keyHex]);
        g_inHook = 0;
    }
    return orig_AES_set_decrypt_key(userKey, bits, key);
}

// ---------------------------------------------------------------------------
// HOOK 6: HMAC (one-shot)
//
// Signature: unsigned char *HMAC(const EVP_MD *evp_md,
//                                const void *key, int key_len,
//                                const unsigned char *d, size_t n,
//                                unsigned char *md, unsigned int *md_len)
// Returns: pointer to HMAC output buffer
//
// Captures: algorithm (via EVP_MD pointer value), key, data, digest output
// ---------------------------------------------------------------------------

static unsigned char *(*orig_HMAC)(const EVP_MD *evp_md,
                                    const void *key, int key_len,
                                    const unsigned char *d, size_t n,
                                    unsigned char *md, unsigned int *md_len);

static unsigned char *hook_HMAC(const EVP_MD *evp_md,
                                 const void *key, int key_len,
                                 const unsigned char *d, size_t n,
                                 unsigned char *md, unsigned int *md_len) {
    unsigned char *ret = orig_HMAC(evp_md, key, key_len, d, n, md, md_len);

    if (!g_inHook && ret && key && key_len > 0 && key_len <= 256) {
        g_inHook = 1;

        NSString *keyHex  = hexEncode((const uint8_t *)key, (size_t)key_len);
        NSString *dataHex = hexEncodeShort((const uint8_t *)d, n);
        unsigned int outLen = (md_len && *md_len > 0) ? *md_len : 32;
        NSString *outHex  = ret ? hexEncode(ret, (size_t)outLen) : @"(null)";

        file_log(g_log_hmac,
                 [NSString stringWithFormat:
                  @"[HMAC] key(%dB)=%@ data(%zuB)=%@ digest(%uB)=%@",
                  key_len, keyHex, n, dataHex, outLen, outHex]);

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 7: HMAC_Init_ex (streaming HMAC key capture)
//
// Signature: int HMAC_Init_ex(HMAC_CTX *ctx,
//                             const void *key, int key_len,
//                             const EVP_MD *md, ENGINE *impl)
// ---------------------------------------------------------------------------

static int (*orig_HMAC_Init_ex)(HMAC_CTX *ctx, const void *key, int key_len,
                                const EVP_MD *md, ENGINE *impl);

static int hook_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
                              const EVP_MD *md, ENGINE *impl) {
    int ret = orig_HMAC_Init_ex(ctx, key, key_len, md, impl);

    if (!g_inHook && key && key_len > 0 && key_len <= 256) {
        g_inHook = 1;
        NSString *keyHex = hexEncode((const uint8_t *)key, (size_t)key_len);
        if (key_len == 48) {
            void *caller = __builtin_return_address(0);
            file_log(g_log_hmac,
                     [NSString stringWithFormat:@"[HMAC] HMAC_Init_ex 48B_key ctx=%p key=%@ caller=%p",
                      (void *)ctx, keyHex, caller]);
        } else {
            file_log(g_log_hmac,
                     [NSString stringWithFormat:@"[HMAC] HMAC_Init_ex ctx=%p key(%dB)=%@",
                      (void *)ctx, key_len, keyHex]);
        }
        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 8: HMAC_Final (streaming HMAC output capture)
//
// Signature: int HMAC_Final(HMAC_CTX *ctx,
//                           unsigned char *md, unsigned int *md_len)
// ---------------------------------------------------------------------------

static int (*orig_HMAC_Final)(HMAC_CTX *ctx, unsigned char *md, unsigned int *md_len);

static int hook_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *md_len) {
    int ret = orig_HMAC_Final(ctx, md, md_len);

    if (!g_inHook && ret == 1 && md && md_len && *md_len > 0) {
        g_inHook = 1;
        NSString *digestHex = hexEncode(md, (size_t)*md_len);
        file_log(g_log_hmac,
                 [NSString stringWithFormat:@"[HMAC] HMAC_Final ctx=%p digest(%uB)=%@",
                  (void *)ctx, *md_len, digestHex]);
        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 9: AES_encrypt (single-block ECB, TFIT chain I/O capture)
//
// Signature: void AES_encrypt(const unsigned char *in, unsigned char *out,
//                             const AES_KEY *key)
//
// Captures 16-byte input and 16-byte output for each TFIT round.
// Only logged when g_tfit_active (between KAT marker and DH_compute_key).
// ---------------------------------------------------------------------------

static void (*orig_AES_encrypt)(const unsigned char *in, unsigned char *out,
                                 const AES_KEY *key);

static void hook_AES_encrypt(const unsigned char *in, unsigned char *out,
                              const AES_KEY *key) {
    // Capture input before call
    uint8_t in_copy[16];
    if (in && g_tfit_active && !g_inHook) {
        memcpy(in_copy, in, 16);
    }

    orig_AES_encrypt(in, out, key);

    if (g_tfit_active && !g_inHook && in && out) {
        g_inHook = 1;
        g_tfit_pair_count++;
        NSString *inHex = hexEncode(in_copy, 16);
        NSString *outHex = hexEncode(out, 16);
        file_log(g_log_aesCbc,
                 [NSString stringWithFormat:@"[AES_encrypt] #%d in=%@ out=%@",
                  g_tfit_pair_count, inHex, outHex]);
        g_inHook = 0;
    }
}

// ---------------------------------------------------------------------------
// HOOK 10: SHA384 (one-shot)
//
// Signature: unsigned char *SHA384(const unsigned char *d, size_t n,
//                                  unsigned char *md)
// Returns: pointer to 48-byte digest buffer
//
// Captures: input data (up to 256B logged as hex), input length, 48B output
// ---------------------------------------------------------------------------

static unsigned char *(*orig_SHA384)(const unsigned char *d, size_t n,
                                      unsigned char *md);

static unsigned char *hook_SHA384(const unsigned char *d, size_t n,
                                   unsigned char *md) {
    unsigned char *ret = orig_SHA384(d, n, md);

    if (!g_inHook && ret) {
        g_inHook = 1;

        size_t logLen = (n > 256) ? 256 : n;
        NSString *inHex  = hexEncode(d, logLen);
        NSString *suffix = (n > 256)
            ? [NSString stringWithFormat:@"...(%zuB total)", n]
            : @"";
        NSString *outHex = hexEncode(ret, 48);

        file_log(g_log_general,
                 [NSString stringWithFormat:@"[SHA384] in(%zuB)=%@%@ out(48B)=%@",
                  n, inHex, suffix, outHex]);

        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 11: _TFIT_wbaes_ecb_encrypt_iAES11 (whitebox AES block encrypt)
//
// Resolved at runtime via dlsym; skipped if symbol not found.
// Captures 16-byte input and 16-byte output per call.
// ---------------------------------------------------------------------------

static void (*orig_TFIT_wbaes)(const unsigned char *in, unsigned char *out,
                                const void *ctx);

static void hook_TFIT_wbaes(const unsigned char *in, unsigned char *out,
                             const void *ctx) {
    uint8_t in_copy[16];
    if (in && !g_inHook) {
        memcpy(in_copy, in, 16);
    }

    orig_TFIT_wbaes(in, out, ctx);

    if (!g_inHook && in && out) {
        g_inHook = 1;
        NSString *inHex  = hexEncode(in_copy, 16);
        NSString *outHex = hexEncode(out, 16);
        file_log(g_log_aesCbc,
                 [NSString stringWithFormat:@"[TFIT_wbaes] in=%@ out=%@",
                  inHex, outHex]);
        g_inHook = 0;
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

__attribute__((constructor)) static void init(void) {
    orion_init();

    // Create os_log channels: subsystem "com.netflix.kdf", category per function
    g_log_dhDerive = os_log_create("com.netflix.kdf", "dhDerive");
    g_log_hkdf     = os_log_create("com.netflix.kdf", "HKDF");
    g_log_aesCbc   = os_log_create("com.netflix.kdf", "aesCbc");
    g_log_hmac     = os_log_create("com.netflix.kdf", "HMAC");
    g_log_general  = os_log_create("com.netflix.kdf", "general");

    // File log for easy retrieval
    g_logFile = [NSTemporaryDirectory()
                 stringByAppendingPathComponent:@"appboot_kdf.log"];
    file_log(g_log_general, @"=== AppbootKDF loaded ===");

    // Locate NFWebCrypto
    void *nfwc = dlopen("@rpath/NFWebCrypto.framework/NFWebCrypto", RTLD_NOLOAD);
    if (!nfwc) {
        nfwc = dlopen("/var/containers/Bundle/Application/2A734797-B5EA-4048-B255-C90EA4D50196/Argo.app/Frameworks/NFWebCrypto.framework/NFWebCrypto", RTLD_NOLOAD);
    }
    if (!nfwc) {
        file_log(g_log_general, @"[-] NFWebCrypto not loaded yet — retrying with RTLD_LAZY");
        // Try to load it (last resort)
        nfwc = dlopen("@rpath/NFWebCrypto.framework/NFWebCrypto", RTLD_LAZY);
    }

    if (!nfwc) {
        file_log(g_log_general, @"[-] NFWebCrypto could not be found — no hooks installed");
        return;
    }

    file_log(g_log_general, @"[+] NFWebCrypto found");

    // Resolve BN helper functions (needed for peer public key capture)
    fn_BN_num_bits_int = (int (*)(const BIGNUM *))dlsym(nfwc, "BN_num_bits");
    fn_BN_bn2bin = (int (*)(const BIGNUM *, unsigned char *))dlsym(nfwc, "BN_bn2bin");
    fn_DH_get0_key = (void (*)(const DH *, const BIGNUM **, const BIGNUM **))dlsym(nfwc, "DH_get0_key");
    if (fn_BN_num_bits_int) file_log(g_log_general, @"[+] BN_num_bits resolved");
    if (fn_BN_bn2bin)       file_log(g_log_general, @"[+] BN_bn2bin resolved");
    if (fn_DH_get0_key)     file_log(g_log_general, @"[+] DH_get0_key resolved");

    // ---- HOOK 0a: DH_generate_key ----
    void *sym = dlsym(nfwc, "DH_generate_key");
    if (sym) {
        MSHookFunction(sym, (void *)hook_DH_generate_key, (void **)&orig_DH_generate_key);
        file_log(g_log_general, @"[+] DH_generate_key hooked");
    } else {
        file_log(g_log_general, @"[-] DH_generate_key not found");
    }

    // ---- HOOK 0b: RSA_public_encrypt ----
    sym = dlsym(nfwc, "RSA_public_encrypt");
    if (sym) {
        MSHookFunction(sym, (void *)hook_RSA_public_encrypt, (void **)&orig_RSA_public_encrypt);
        file_log(g_log_general, @"[+] RSA_public_encrypt hooked");
    } else {
        file_log(g_log_general, @"[-] RSA_public_encrypt not found");
    }

    // ---- HOOK 0c: EVP_PKEY_encrypt ----
    sym = dlsym(nfwc, "EVP_PKEY_encrypt");
    if (sym) {
        MSHookFunction(sym, (void *)hook_EVP_PKEY_encrypt, (void **)&orig_EVP_PKEY_encrypt);
        file_log(g_log_general, @"[+] EVP_PKEY_encrypt hooked");
    } else {
        file_log(g_log_general, @"[-] EVP_PKEY_encrypt not found");
    }

    // ---- HOOK 1: DH_compute_key (dhDerive) ----
    sym = dlsym(nfwc, "DH_compute_key");
    if (sym) {
        MSHookFunction(sym, (void *)hook_DH_compute_key, (void **)&orig_DH_compute_key);
        file_log(g_log_general, @"[+] DH_compute_key (dhDerive) hooked");
    } else {
        file_log(g_log_general, @"[-] DH_compute_key not found");
    }

    // ---- HOOK 2: HKDF_extract ----
    sym = dlsym(nfwc, "HKDF_extract");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HKDF_extract, (void **)&orig_HKDF_extract);
        file_log(g_log_general, @"[+] HKDF_extract hooked");
    } else {
        file_log(g_log_general, @"[-] HKDF_extract not found");
    }

    // ---- HOOK 3: HKDF_expand ----
    sym = dlsym(nfwc, "HKDF_expand");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HKDF_expand, (void **)&orig_HKDF_expand);
        file_log(g_log_general, @"[+] HKDF_expand hooked");
    } else {
        file_log(g_log_general, @"[-] HKDF_expand not found");
    }

    // ---- HOOK 4: HKDF one-shot (BoringSSL) ----
    sym = dlsym(nfwc, "HKDF");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HKDF, (void **)&orig_HKDF);
        file_log(g_log_general, @"[+] HKDF (one-shot) hooked");
    } else {
        file_log(g_log_general, @"[-] HKDF not found");
    }

    // ---- HOOK 5a: AES_set_encrypt_key (aesCbc key setup) ----
    sym = dlsym(nfwc, "AES_set_encrypt_key");
    if (sym) {
        MSHookFunction(sym, (void *)hook_AES_set_encrypt_key, (void **)&orig_AES_set_encrypt_key);
        file_log(g_log_general, @"[+] AES_set_encrypt_key (aesCbc) hooked");
    } else {
        file_log(g_log_general, @"[-] AES_set_encrypt_key not found");
    }

    // ---- HOOK 5b: AES_set_decrypt_key (aesCbc key setup) ----
    sym = dlsym(nfwc, "AES_set_decrypt_key");
    if (sym) {
        MSHookFunction(sym, (void *)hook_AES_set_decrypt_key, (void **)&orig_AES_set_decrypt_key);
        file_log(g_log_general, @"[+] AES_set_decrypt_key (aesCbc) hooked");
    } else {
        file_log(g_log_general, @"[-] AES_set_decrypt_key not found");
    }

    // ---- HOOK 9: AES_encrypt (TFIT chain I/O) ----
    sym = dlsym(nfwc, "AES_encrypt");
    if (sym) {
        MSHookFunction(sym, (void *)hook_AES_encrypt, (void **)&orig_AES_encrypt);
        file_log(g_log_general, @"[+] AES_encrypt hooked");
    } else {
        file_log(g_log_general, @"[-] AES_encrypt not found");
    }

    // ---- HOOK 6: HMAC one-shot ----
    sym = dlsym(nfwc, "HMAC");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HMAC, (void **)&orig_HMAC);
        file_log(g_log_general, @"[+] HMAC (one-shot) hooked");
    } else {
        file_log(g_log_general, @"[-] HMAC not found");
    }

    // ---- HOOK 7: HMAC_Init_ex (streaming HMAC) ----
    sym = dlsym(nfwc, "HMAC_Init_ex");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HMAC_Init_ex, (void **)&orig_HMAC_Init_ex);
        file_log(g_log_general, @"[+] HMAC_Init_ex hooked");
    } else {
        file_log(g_log_general, @"[-] HMAC_Init_ex not found");
    }

    // ---- HOOK 8: HMAC_Final (streaming HMAC) ----
    sym = dlsym(nfwc, "HMAC_Final");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HMAC_Final, (void **)&orig_HMAC_Final);
        file_log(g_log_general, @"[+] HMAC_Final hooked");
    } else {
        file_log(g_log_general, @"[-] HMAC_Final not found");
    }

    // ---- HOOK 10: SHA384 one-shot ----
    sym = dlsym(nfwc, "SHA384");
    if (sym) {
        MSHookFunction(sym, (void *)hook_SHA384, (void **)&orig_SHA384);
        file_log(g_log_general, @"[+] SHA384 hooked");
    } else {
        file_log(g_log_general, @"[-] SHA384 not found");
    }

    // ---- HOOK 11: _TFIT_wbaes_ecb_encrypt_iAES11 (whitebox AES) ----
    sym = dlsym(nfwc, "_TFIT_wbaes_ecb_encrypt_iAES11");
    if (!sym) {
        // Some builds export without leading underscore
        sym = dlsym(nfwc, "TFIT_wbaes_ecb_encrypt_iAES11");
    }
    if (sym) {
        MSHookFunction(sym, (void *)hook_TFIT_wbaes, (void **)&orig_TFIT_wbaes);
        file_log(g_log_general, @"[+] TFIT_wbaes_ecb_encrypt_iAES11 hooked");
    } else {
        file_log(g_log_general, @"[-] TFIT_wbaes_ecb_encrypt_iAES11 not found (skipped)");
    }

    file_log(g_log_general, @"=== AppbootKDF hooks installed ===");
}
