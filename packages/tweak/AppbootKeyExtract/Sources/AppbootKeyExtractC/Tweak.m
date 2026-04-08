#import <Orion/Orion.h>
#import <os/log.h>
#import <substrate.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
// Security types come from Foundation/CoreFoundation headers

static os_log_t g_log = NULL;
static NSString *g_logFile = nil;
static NSString *g_keyFile = nil;

// Key storage — accumulated during session
static NSMutableDictionary *g_keys = nil;
static NSMutableArray *g_aesKeys = nil;
static NSMutableArray *g_hmacKeys = nil;
static BOOL g_appbootDone = NO;

// DH shared secret — stored so HMAC_Update can compare
static uint8_t g_dhSharedSecret[256];
static int g_dhSharedSecretLen = 0;

// Reentrancy guard for hooks that may be called by TLS internally
static volatile int g_inHook = 0;

#define NFXKEY_LOG(fmt, ...) \
    do { \
        if (g_log) { os_log(g_log, fmt, ##__VA_ARGS__); } \
        NSLog(@"[NFXKey] " fmt, ##__VA_ARGS__); \
    } while (0)

static void file_log(NSString *msg) {
    if (!g_logFile) return;
    @try {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"HH:mm:ss.SSS";
        NSString *line = [NSString stringWithFormat:@"%@ %@\n", [df stringFromDate:[NSDate date]], msg];
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

static NSString *hexEncode(const uint8_t *data, int len) {
    NSMutableString *s = [NSMutableString stringWithCapacity:len * 2];
    for (int i = 0; i < len; i++) {
        [s appendFormat:@"%02x", data[i]];
    }
    return s;
}

static void saveKeysToFile(void) {
    if (!g_keyFile || !g_keys) return;
    @try {
        NSData *json = [NSJSONSerialization dataWithJSONObject:g_keys
                                                      options:NSJSONWritingPrettyPrinted
                                                        error:nil];
        if (json) {
            [json writeToFile:g_keyFile atomically:YES];
            file_log([NSString stringWithFormat:@"[keys] saved to %@", g_keyFile]);
        }
    } @catch (NSException *e) {}
}

// ---------------------------------------------------------------------------
// OpenSSL function pointers (resolved via dlsym)
// ---------------------------------------------------------------------------

typedef struct dh_st DH;
typedef struct bignum_st BIGNUM;

static void (*fn_DH_get0_key)(const DH *, const BIGNUM **, const BIGNUM **);
static void (*fn_DH_get0_pqg)(const DH *, const BIGNUM **, const BIGNUM **, const BIGNUM **);
static int (*fn_BN_num_bits)(const BIGNUM *);
static int (*fn_BN_bn2bin)(const BIGNUM *, unsigned char *);

// ---------------------------------------------------------------------------
// Hook: DH_generate_key
// ---------------------------------------------------------------------------

static int (*orig_DH_generate_key)(DH *dh);
static int hook_DH_generate_key(DH *dh) {
    int ret = orig_DH_generate_key(dh);
    if (ret == 1 && fn_DH_get0_key && fn_BN_num_bits && fn_BN_bn2bin) {
        const BIGNUM *pub = NULL, *priv = NULL;
        fn_DH_get0_key(dh, &pub, &priv);

        if (pub) {
            int pubBytes = (fn_BN_num_bits(pub) + 7) / 8;
            if (pubBytes > 0 && pubBytes <= 1024) {
                uint8_t *buf = (uint8_t *)malloc(pubBytes);
                fn_BN_bn2bin(pub, buf);
                NSString *hex = hexEncode(buf, pubBytes);
                file_log([NSString stringWithFormat:@"[DH_generate_key] pub_key (%d bytes)=%@",
                          pubBytes, hex]);
                g_keys[@"dh_pub_key"] = hex;
                free(buf);
            }
        }

        if (priv) {
            int privBytes = (fn_BN_num_bits(priv) + 7) / 8;
            if (privBytes > 0 && privBytes <= 1024) {
                uint8_t *buf = (uint8_t *)malloc(privBytes);
                fn_BN_bn2bin(priv, buf);
                NSString *hex = hexEncode(buf, privBytes);
                file_log([NSString stringWithFormat:@"[DH_generate_key] priv_key (%d bytes)=%@",
                          privBytes, hex]);
                g_keys[@"dh_priv_key"] = hex;
                free(buf);
            }
        }

        if (fn_DH_get0_pqg) {
            const BIGNUM *p = NULL, *q = NULL, *g = NULL;
            fn_DH_get0_pqg(dh, &p, &q, &g);

            if (p) {
                int pBytes = (fn_BN_num_bits(p) + 7) / 8;
                if (pBytes > 0 && pBytes <= 4096) {
                    uint8_t *buf = (uint8_t *)malloc(pBytes);
                    fn_BN_bn2bin(p, buf);
                    NSString *hex = hexEncode(buf, pBytes);
                    file_log([NSString stringWithFormat:@"[DH_generate_key] dh_p (%d bytes) head=%02x%02x%02x%02x",
                              pBytes, buf[0], buf[1], buf[2], buf[3]]);
                    g_keys[@"dh_p"] = hex;
                    free(buf);
                }
            }

            if (g) {
                int gBytes = (fn_BN_num_bits(g) + 7) / 8;
                if (gBytes > 0 && gBytes <= 4096) {
                    uint8_t *buf = (uint8_t *)malloc(gBytes);
                    fn_BN_bn2bin(g, buf);
                    NSString *hex = hexEncode(buf, gBytes);
                    file_log([NSString stringWithFormat:@"[DH_generate_key] dh_g (%d bytes) head=%02x",
                              gBytes, buf[0]]);
                    g_keys[@"dh_g"] = hex;
                    free(buf);
                }
            }
        }

        saveKeysToFile();
    }
    return ret;
}

// SHA function pointers (resolved in constructor)
static unsigned char *(*fn_SHA384)(const unsigned char *d, size_t n, unsigned char *md);
static unsigned char *(*fn_SHA256)(const unsigned char *d, size_t n, unsigned char *md);

// ---------------------------------------------------------------------------
// Hook: DH_compute_key
// ---------------------------------------------------------------------------

static int (*orig_DH_compute_key)(unsigned char *key, const BIGNUM *pub_key, DH *dh);
static int hook_DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh) {
    int ret = orig_DH_compute_key(key, pub_key, dh);
    if (ret > 0) {
        NSString *hex = hexEncode(key, ret);
        file_log([NSString stringWithFormat:@"[DH_compute_key] shared_secret (%d bytes)=%@",
                  ret, hex]);
        g_keys[@"dh_shared_secret"] = hex;

        // Store shared secret globally for HMAC_Update comparison
        int copyLen = ret < (int)sizeof(g_dhSharedSecret) ? ret : (int)sizeof(g_dhSharedSecret);
        memcpy(g_dhSharedSecret, key, copyLen);
        g_dhSharedSecretLen = copyLen;

        // Compute SHA-384 and SHA-256 of shared_secret as PSK candidates
        // Guard against re-entrancy since SHA functions may invoke hooked code
        if (!g_inHook) {
            g_inHook = 1;

            if (fn_SHA384) {
                uint8_t digest384[48];
                if (fn_SHA384(key, (size_t)ret, digest384)) {
                    NSString *sha384Hex = hexEncode(digest384, 48);
                    file_log([NSString stringWithFormat:@"[DH_compute_key] SHA384(shared_secret)=%@", sha384Hex]);
                    g_keys[@"dh_sha384"] = sha384Hex;
                    // First 16 bytes as PSK candidate
                    g_keys[@"dh_sha384_16"] = hexEncode(digest384, 16);
                    file_log([NSString stringWithFormat:@"[DH_compute_key] PSK_candidate_sha384[:16]=%@",
                              g_keys[@"dh_sha384_16"]]);
                }
            }

            if (fn_SHA256) {
                uint8_t digest256[32];
                if (fn_SHA256(key, (size_t)ret, digest256)) {
                    NSString *sha256Hex = hexEncode(digest256, 32);
                    file_log([NSString stringWithFormat:@"[DH_compute_key] SHA256(shared_secret)=%@", sha256Hex]);
                    g_keys[@"dh_sha256"] = sha256Hex;
                    // First 16 bytes as PSK candidate
                    g_keys[@"dh_sha256_16"] = hexEncode(digest256, 16);
                    file_log([NSString stringWithFormat:@"[DH_compute_key] PSK_candidate_sha256[:16]=%@",
                              g_keys[@"dh_sha256_16"]]);
                }
            }

            // null-padded shared_secret (leading zero padding to 256 bytes) SHA-384
            // MSL Java reference uses a fixed-length big-endian representation
            if (fn_SHA384 && ret < 256) {
                uint8_t padded[256];
                memset(padded, 0, sizeof(padded));
                memcpy(padded + 256 - ret, key, ret);
                uint8_t digest384p[48];
                if (fn_SHA384(padded, 256, digest384p)) {
                    NSString *sha384pHex = hexEncode(digest384p, 48);
                    file_log([NSString stringWithFormat:@"[DH_compute_key] SHA384(padded_shared_secret)=%@", sha384pHex]);
                    g_keys[@"dh_sha384_padded"] = sha384pHex;
                    g_keys[@"dh_sha384_padded_16"] = hexEncode(digest384p, 16);
                    file_log([NSString stringWithFormat:@"[DH_compute_key] PSK_candidate_sha384_padded[:16]=%@",
                              g_keys[@"dh_sha384_padded_16"]]);
                }
            }

            g_inHook = 0;
        }

        saveKeysToFile();
    }
    return ret;
}

// ---------------------------------------------------------------------------
// Hook: AES_set_encrypt_key / AES_set_decrypt_key
// ---------------------------------------------------------------------------

static int (*orig_AES_set_encrypt_key)(const unsigned char *userKey, int bits, void *key);
static int hook_AES_set_encrypt_key(const unsigned char *userKey, int bits, void *key) {
    if (g_inHook) return orig_AES_set_encrypt_key(userKey, bits, key);
    g_inHook = 1;
    int keyLen = bits / 8;
    if (keyLen == 16 || keyLen == 32) {
        NSString *hex = hexEncode(userKey, keyLen);
        file_log([NSString stringWithFormat:@"[AES_set_encrypt_key] bits=%d key=%@", bits, hex]);

        // Track AES-128 keys for session key identification
        if (bits == 128) {
            NSString *phase = g_appbootDone ? @"post_appboot" : @"pre_appboot";
            NSDictionary *entry = @{@"key": hex, @"bits": @(bits), @"phase": phase};
            // Only add if not duplicate of last entry
            if (g_aesKeys.count == 0 || ![g_aesKeys.lastObject[@"key"] isEqualToString:hex]) {
                [g_aesKeys addObject:entry];
            }
            // Update current session enc_key
            g_keys[g_appbootDone ? @"session_enc_key" : @"pre_session_enc_key"] = hex;
        }
    }
    g_inHook = 0;
    return orig_AES_set_encrypt_key(userKey, bits, key);
}

static int (*orig_AES_set_decrypt_key)(const unsigned char *userKey, int bits, void *key);
static int hook_AES_set_decrypt_key(const unsigned char *userKey, int bits, void *key) {
    if (g_inHook) return orig_AES_set_decrypt_key(userKey, bits, key);
    g_inHook = 1;
    int keyLen = bits / 8;
    if (keyLen == 16 || keyLen == 32) {
        file_log([NSString stringWithFormat:@"[AES_set_decrypt_key] bits=%d key=%@",
                  bits, hexEncode(userKey, keyLen)]);
    }
    g_inHook = 0;
    return orig_AES_set_decrypt_key(userKey, bits, key);
}

// ---------------------------------------------------------------------------
// Hook: HMAC
// ---------------------------------------------------------------------------

static unsigned char *(*orig_HMAC)(const void *evp_md, const void *key, int key_len,
                                    const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len);
static unsigned char *hook_HMAC(const void *evp_md, const void *key, int key_len,
                                 const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len) {
    if (g_inHook) return orig_HMAC(evp_md, key, key_len, d, n, md, md_len);
    g_inHook = 1;
    if (key_len == 32) {
        NSString *hex = hexEncode((const uint8_t *)key, key_len);
        file_log([NSString stringWithFormat:@"[HMAC] key_len=%d key=%@", key_len, hex]);

        NSString *phase = g_appbootDone ? @"post_appboot" : @"pre_appboot";
        NSDictionary *entry = @{@"key": hex, @"phase": phase};
        if (g_hmacKeys.count == 0 || ![g_hmacKeys.lastObject[@"key"] isEqualToString:hex]) {
            [g_hmacKeys addObject:entry];
        }
        // Update current session hmac_key
        g_keys[g_appbootDone ? @"session_hmac_key" : @"pre_session_hmac_key"] = hex;
    }
    g_inHook = 0;
    return orig_HMAC(evp_md, key, key_len, d, n, md, md_len);
}

// ---------------------------------------------------------------------------
// Hook: HKDF_extract / HKDF_Expand
// ---------------------------------------------------------------------------

static int (*orig_HKDF_extract)(uint8_t *out_key, size_t *out_len,
                                const void *digest,
                                const uint8_t *secret, size_t secret_len,
                                const uint8_t *salt, size_t salt_len);
static int hook_HKDF_extract(uint8_t *out_key, size_t *out_len,
                              const void *digest,
                              const uint8_t *secret, size_t secret_len,
                              const uint8_t *salt, size_t salt_len) {
    int ret = orig_HKDF_extract(out_key, out_len, digest, secret, secret_len, salt, salt_len);
    if (ret == 1 && out_key && out_len) {
        NSString *saltHex = (salt && salt_len > 0) ? hexEncode(salt, (int)salt_len) : @"(null)";
        NSString *ikmHex  = (secret && secret_len > 0) ? hexEncode(secret, (int)secret_len) : @"(null)";
        NSString *prkHex  = hexEncode(out_key, (int)*out_len);

        file_log([NSString stringWithFormat:@"[HKDF_extract] salt(%zu)=%@ ikm(%zu)=%@ prk(%zu)=%@",
                  salt_len, saltHex, secret_len, ikmHex, *out_len, prkHex]);
        NFXKEY_LOG("[HKDF_extract] salt(%zu)=%@ ikm(%zu)=%@ prk(%zu)=%@",
                   salt_len, saltHex, secret_len, ikmHex, *out_len, prkHex);

        g_keys[@"hkdf_salt"] = saltHex;
        g_keys[@"hkdf_ikm"]  = ikmHex;
        g_keys[@"hkdf_prk"]  = prkHex;
        saveKeysToFile();
    }
    return ret;
}

static int (*orig_HKDF_expand)(uint8_t *out_key, size_t out_len,
                               const void *digest,
                               const uint8_t *prk, size_t prk_len,
                               const uint8_t *info, size_t info_len);
static int hook_HKDF_expand(uint8_t *out_key, size_t out_len,
                             const void *digest,
                             const uint8_t *prk, size_t prk_len,
                             const uint8_t *info, size_t info_len) {
    int ret = orig_HKDF_expand(out_key, out_len, digest, prk, prk_len, info, info_len);
    if (ret == 1 && out_key && out_len > 0) {
        NSString *prkHex  = (prk && prk_len > 0) ? hexEncode(prk, (int)prk_len) : @"(null)";
        NSString *infoHex = (info && info_len > 0) ? hexEncode(info, (int)info_len) : @"(null)";
        NSString *okmHex  = hexEncode(out_key, (int)out_len);

        file_log([NSString stringWithFormat:@"[HKDF_expand] prk(%zu)=%@ info(%zu)=%@ okm(%zu)=%@",
                  prk_len, prkHex, info_len, infoHex, out_len, okmHex]);
        NFXKEY_LOG("[HKDF_expand] prk(%zu)=%@ info(%zu)=%@ okm(%zu)=%@",
                   prk_len, prkHex, info_len, infoHex, out_len, okmHex);

        g_keys[@"hkdf_info"]    = infoHex;
        g_keys[@"hkdf_okm"]     = okmHex;
        g_keys[@"hkdf_okm_len"] = @(out_len);
        saveKeysToFile();
    }
    return ret;
}

// ---------------------------------------------------------------------------
// Hook: HMAC_Init_ex / HMAC_Update / HMAC_Final (streaming HMAC API)
// ---------------------------------------------------------------------------

typedef struct hmac_ctx_st HMAC_CTX;
typedef struct env_md_st EVP_MD;
typedef struct engine_st ENGINE;

static int (*orig_HMAC_Init_ex)(HMAC_CTX *ctx, const void *key, int key_len,
                                const EVP_MD *md, ENGINE *impl);
static int hook_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
                              const EVP_MD *md, ENGINE *impl) {
    int ret = orig_HMAC_Init_ex(ctx, key, key_len, md, impl);
    if (g_inHook) return ret;
    g_inHook = 1;
    if (key != NULL && key_len > 0 && key_len <= 256) {
        NSString *keyHex = hexEncode((const uint8_t *)key, key_len);
        file_log([NSString stringWithFormat:@"[HMAC_Init_ex] ctx=%p key_len=%d key=%@",
                  (void *)ctx, key_len, keyHex]);

        // PSK-size key detection (16 bytes = possible PSK)
        if (key_len == 16) {
            file_log([NSString stringWithFormat:@"[HMAC_Init_ex] *** PSK-SIZE KEY *** ctx=%p key=%@",
                      (void *)ctx, keyHex]);

            // Check if PSK matches or is contained in the DH shared_secret
            if (g_dhSharedSecretLen >= 16) {
                BOOL found = NO;
                for (int offset = 0; offset <= g_dhSharedSecretLen - 16; offset++) {
                    if (memcmp((const uint8_t *)key, g_dhSharedSecret + offset, 16) == 0) {
                        file_log([NSString stringWithFormat:
                                  @"[HMAC_Init_ex] *** PSK MATCHES DH shared_secret at offset %d ***",
                                  offset]);
                        found = YES;
                        break;
                    }
                }
                if (!found) {
                    file_log(@"[HMAC_Init_ex] PSK-size key does NOT match DH shared_secret");
                }
            } else {
                file_log(@"[HMAC_Init_ex] PSK-size key seen (no DH shared_secret yet)");
            }
        }
    }
    g_inHook = 0;
    return ret;
}

static int (*orig_HMAC_Update)(HMAC_CTX *ctx, const unsigned char *data, size_t len);
static int hook_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len) {
    int ret = orig_HMAC_Update(ctx, data, len);
    if (g_inHook) return ret;
    g_inHook = 1;
    if (data != NULL && len <= 256) {
        NSString *dataHex = hexEncode(data, (int)len);
        file_log([NSString stringWithFormat:@"[HMAC_Update] ctx=%p len=%zu data=%@",
                  (void *)ctx, len, dataHex]);

        // Check if the input matches the stored DH shared_secret
        if (g_dhSharedSecretLen > 0 && len >= 16) {
            int cmpLen = (int)len < g_dhSharedSecretLen ? (int)len : g_dhSharedSecretLen;
            if (memcmp(data, g_dhSharedSecret, cmpLen) == 0) {
                file_log([NSString stringWithFormat:
                          @"[HMAC_Update] *** DATA MATCHES DH shared_secret (first %d bytes) ctx=%p ***",
                          cmpLen, (void *)ctx]);
            }
        }
    } else if (data != NULL && len > 256) {
        file_log([NSString stringWithFormat:@"[HMAC_Update] ctx=%p len=%zu (data too long, skipping hex)",
                  (void *)ctx, len]);
    }
    g_inHook = 0;
    return ret;
}

static int (*orig_HMAC_Final)(HMAC_CTX *ctx, unsigned char *md, unsigned int *md_len);
static int hook_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *md_len) {
    int ret = orig_HMAC_Final(ctx, md, md_len);
    if (g_inHook) return ret;
    g_inHook = 1;
    if (ret == 1 && md != NULL && md_len != NULL && *md_len > 0) {
        NSString *digestHex = hexEncode(md, (int)*md_len);
        file_log([NSString stringWithFormat:@"[HMAC_Final] ctx=%p digest_len=%u digest=%@",
                  (void *)ctx, *md_len, digestHex]);
    }
    g_inHook = 0;
    return ret;
}

// ---------------------------------------------------------------------------
// Hook: AES_cbc_encrypt
// ---------------------------------------------------------------------------

typedef struct aes_key_st AES_KEY;

static void (*orig_AES_cbc_encrypt)(const unsigned char *in, unsigned char *out, size_t length,
                                    const AES_KEY *key, unsigned char *ivec, int enc);
static void hook_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length,
                                  const AES_KEY *key, unsigned char *ivec, int enc) {
    // Step 1: pure passthrough — no logging at all
    orig_AES_cbc_encrypt(in, out, length, key, ivec, enc);
}

// ---------------------------------------------------------------------------
// Hook: EVP_CipherInit_ex / EVP_CipherUpdate / EVP_CipherFinal_ex
// DISABLED: EVP hooks cause "RSA public key not found" error.
//           NFWebCrypto's OpenSSL EVP is only used for TFIT (ENC), never for MSL decrypt.
// ---------------------------------------------------------------------------

#if 0  // EVP hooks disabled — kept for reference

// Opaque EVP_CIPHER_CTX — we only need the pointer as a tracking key
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct engine_st ENGINE;

// Track per-context state: direction + key + iv
#define MAX_EVP_TRACK 32
static struct {
    void *ctx;
    int enc;          // 1=encrypt, 0=decrypt
    uint8_t key[32];
    int keyLen;
    uint8_t iv[16];
} g_evpTrack[MAX_EVP_TRACK];
static int g_evpTrackCount = 0;

static int evpTrackFind(void *ctx) {
    for (int i = 0; i < g_evpTrackCount; i++) {
        if (g_evpTrack[i].ctx == ctx) return i;
    }
    return -1;
}

// EVP_CipherInit_ex(ctx, type, impl, key, iv, enc)
static int (*orig_EVP_CipherInit_ex)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                                      ENGINE *impl, const unsigned char *key,
                                      const unsigned char *iv, int enc);
static int hook_EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                                   ENGINE *impl, const unsigned char *key,
                                   const unsigned char *iv, int enc) {
    int ret = orig_EVP_CipherInit_ex(ctx, type, impl, key, iv, enc);

    if (g_inHook) return ret;
    g_inHook = 1;

    if (key) {
        int idx = evpTrackFind(ctx);
        if (idx < 0 && g_evpTrackCount < MAX_EVP_TRACK) {
            idx = g_evpTrackCount++;
        }
        if (idx >= 0) {
            g_evpTrack[idx].ctx = ctx;
            g_evpTrack[idx].enc = enc;
            g_evpTrack[idx].keyLen = 16;
            memcpy(g_evpTrack[idx].key, key, 16);
            memset(g_evpTrack[idx].iv, 0, 16);
            if (iv) memcpy(g_evpTrack[idx].iv, iv, 16);
        }

        if (iv) {
            NSString *direction = enc ? @"ENC" : @"DEC";
            NSString *keyHex = hexEncode(key, 16);
            NSString *ivHex = hexEncode(iv, 16);
            file_log([NSString stringWithFormat:@"[EVP_CipherInit_ex] dir=%@ key=%@ iv=%@",
                      direction, keyHex, ivHex]);
        }
    }

    g_inHook = 0;
    return ret;
}

// EVP_CipherUpdate(ctx, out, outl, in, inl)
static int (*orig_EVP_CipherUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                     int *outl, const unsigned char *in, int inl);
static int hook_EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                  int *outl, const unsigned char *in, int inl) {
    int ret = orig_EVP_CipherUpdate(ctx, out, outl, in, inl);

    if (g_inHook) return ret;
    g_inHook = 1;

    int idx = evpTrackFind(ctx);
    if (idx < 0) { g_inHook = 0; return ret; }
    static const uint8_t zeroIv[16] = {0};
    if (memcmp(g_evpTrack[idx].iv, zeroIv, 16) == 0) { g_inHook = 0; return ret; }

    int enc = g_evpTrack[idx].enc;
    NSString *direction = (enc == 1) ? @"ENC" : (enc == 0) ? @"DEC" : @"???";

    int logLen = (inl < 64) ? inl : 64;
    int outLen = (outl && *outl < 64) ? *outl : 64;
    NSString *inHex = in ? hexEncode(in, logLen) : @"(null)";
    NSString *outHex = (out && outl) ? hexEncode(out, outLen) : @"(null)";

    file_log([NSString stringWithFormat:@"[EVP_CipherUpdate] dir=%@ inl=%d outl=%d in[:%d]=%@ out[:%d]=%@",
              direction, inl, outl ? *outl : 0, logLen, inHex, outLen, outHex]);

    if (enc == 0 && outl && *outl <= 128 && *outl > 0 && out) {
        file_log([NSString stringWithFormat:@"[EVP_CipherUpdate] DEC full_out(%d)=%@",
                  *outl, hexEncode(out, *outl)]);
    }

    g_inHook = 0;
    return ret;
}

// EVP_CipherFinal_ex(ctx, out, outl)
static int (*orig_EVP_CipherFinal_ex)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
static int hook_EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl) {
    int ret = orig_EVP_CipherFinal_ex(ctx, out, outl);

    if (g_inHook) return ret;
    g_inHook = 1;

    int idx = evpTrackFind(ctx);
    int enc = (idx >= 0) ? g_evpTrack[idx].enc : -1;
    NSString *direction = (enc == 1) ? @"ENC" : (enc == 0) ? @"DEC" : @"???";

    if (outl && *outl > 0 && out) {
        file_log([NSString stringWithFormat:@"[EVP_CipherFinal_ex] dir=%@ outl=%d out=%@",
                  direction, *outl, hexEncode(out, *outl)]);
    } else {
        file_log([NSString stringWithFormat:@"[EVP_CipherFinal_ex] dir=%@ outl=%d",
                  direction, outl ? *outl : 0]);
    }

    if (idx >= 0) {
        g_evpTrack[idx] = g_evpTrack[--g_evpTrackCount];
    }

    g_inHook = 0;
    return ret;
}

// ---------------------------------------------------------------------------
// Hook: EVP_DecryptInit_ex / EVP_DecryptUpdate / EVP_DecryptFinal_ex
// ---------------------------------------------------------------------------

static int (*orig_EVP_DecryptInit_ex)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                                       ENGINE *impl, const unsigned char *key,
                                       const unsigned char *iv);
static int hook_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                                    ENGINE *impl, const unsigned char *key,
                                    const unsigned char *iv) {
    int ret = orig_EVP_DecryptInit_ex(ctx, type, impl, key, iv);

    if (g_inHook) return ret;
    g_inHook = 1;

    if (key) {
        int idx = evpTrackFind(ctx);
        if (idx < 0 && g_evpTrackCount < MAX_EVP_TRACK) {
            idx = g_evpTrackCount++;
        }
        if (idx >= 0) {
            g_evpTrack[idx].ctx = ctx;
            g_evpTrack[idx].enc = 0;
            memcpy(g_evpTrack[idx].key, key, 16);
            memset(g_evpTrack[idx].iv, 0, 16);
            if (iv) memcpy(g_evpTrack[idx].iv, iv, 16);
        }

        NSString *keyHex = hexEncode(key, 16);
        NSString *ivHex = iv ? hexEncode(iv, 16) : @"(null)";
        file_log([NSString stringWithFormat:@"[EVP_DecryptInit_ex] key=%@ iv=%@", keyHex, ivHex]);
    }

    g_inHook = 0;
    return ret;
}

static int (*orig_EVP_DecryptUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                      int *outl, const unsigned char *in, int inl);
static int hook_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   int *outl, const unsigned char *in, int inl) {
    int ret = orig_EVP_DecryptUpdate(ctx, out, outl, in, inl);

    if (g_inHook) return ret;
    g_inHook = 1;

    int logLen = (inl < 64) ? inl : 64;
    int outLen = (outl && *outl < 64) ? *outl : 64;
    NSString *inHex = in ? hexEncode(in, logLen) : @"(null)";
    NSString *outHex = (out && outl) ? hexEncode(out, outLen) : @"(null)";

    file_log([NSString stringWithFormat:@"[EVP_DecryptUpdate] inl=%d outl=%d in[:%d]=%@ out[:%d]=%@",
              inl, outl ? *outl : 0, logLen, inHex, outLen, outHex]);

    if (outl && *outl <= 128 && *outl > 0 && out) {
        file_log([NSString stringWithFormat:@"[EVP_DecryptUpdate] full_out(%d)=%@",
                  *outl, hexEncode(out, *outl)]);
    }

    g_inHook = 0;
    return ret;
}

static int (*orig_EVP_DecryptFinal_ex)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
static int hook_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl) {
    int ret = orig_EVP_DecryptFinal_ex(ctx, out, outl);

    if (g_inHook) return ret;
    g_inHook = 1;

    if (outl && *outl > 0 && out) {
        file_log([NSString stringWithFormat:@"[EVP_DecryptFinal_ex] outl=%d out=%@",
                  *outl, hexEncode(out, *outl)]);
    } else {
        file_log([NSString stringWithFormat:@"[EVP_DecryptFinal_ex] outl=%d", outl ? *outl : 0]);
    }

    int idx = evpTrackFind(ctx);
    if (idx >= 0) {
        g_evpTrack[idx] = g_evpTrack[--g_evpTrackCount];
    }

    g_inHook = 0;
    return ret;
}

#endif  // EVP hooks disabled

// ---------------------------------------------------------------------------
// Hook: IosMslClient.setDidAppboot:
// ---------------------------------------------------------------------------

static void (*orig_setDidAppboot)(id self, SEL _cmd, BOOL value);
static void hook_setDidAppboot(id self, SEL _cmd, BOOL value) {
    file_log([NSString stringWithFormat:@"setDidAppboot: %d", value]);
    NFXKEY_LOG("setDidAppboot: %d", value);

    if (value) {
        g_appbootDone = YES;
        // Snapshot pre-appboot keys
        g_keys[@"aes_key_history"] = [g_aesKeys copy];
        g_keys[@"hmac_key_history"] = [g_hmacKeys copy];
    }

    orig_setDidAppboot(self, _cmd, value);

    if (value) {
        // Save after original method (which may trigger key exchange)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            // Final save with post-appboot keys
            g_keys[@"aes_key_history"] = [g_aesKeys copy];
            g_keys[@"hmac_key_history"] = [g_hmacKeys copy];

            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss";
            g_keys[@"timestamp"] = [df stringFromDate:[NSDate date]];

            saveKeysToFile();
            file_log(@"[keys] final save after appboot");
        });
    }
}

// SSL bypass removed — use Frida ssl-pinning.ts if needed

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

__attribute__((constructor)) static void init(void) {
    orion_init();
    g_log = os_log_create("dev.tkgstrator.charon", "keyextract");
    g_logFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"nfxkey.log"];
    g_keyFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"msl_keys.json"];

    g_keys = [NSMutableDictionary dictionary];
    g_aesKeys = [NSMutableArray array];
    g_hmacKeys = [NSMutableArray array];
    g_appbootDone = NO;

    file_log(@"=== AppbootKeyExtract loaded ===");
    NFXKEY_LOG("AppbootKeyExtract loaded");

    // Keychain clear trigger: if /tmp/clear_keychain exists, delete all Keychain items
    // Uses dlsym to avoid linking Security.framework (caused crashes before)
    NSString *triggerPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"clear_keychain"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:triggerPath]) {
        file_log(@"[!] clear_keychain trigger found — deleting Keychain items");
        void *secLib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOLOAD);
        if (!secLib) secLib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        if (secLib) {
            typedef int32_t (*SecItemDelete_t)(CFDictionaryRef);
            SecItemDelete_t secItemDeleteFn = (SecItemDelete_t)dlsym(secLib, "SecItemDelete");
            if (secItemDeleteFn) {
                NSArray *classNames = @[@"genp", @"inet", @"keys", @"cert"];
                for (NSString *cls_str in classNames) {
                    NSDictionary *query = @{@"class": cls_str};
                    int32_t status = secItemDeleteFn((__bridge CFDictionaryRef)query);
                    file_log([NSString stringWithFormat:@"[!] SecItemDelete(class=%@) status=%d",
                              cls_str, status]);
                }
                file_log(@"[!] Keychain cleared");
            } else {
                file_log(@"[!] SecItemDelete not found via dlsym");
            }
        } else {
            file_log(@"[!] Security.framework not loaded");
        }
        [[NSFileManager defaultManager] removeItemAtPath:triggerPath error:nil];
        file_log(@"[!] trigger file removed");
    }

    // SSL bypass removed — use Frida ssl-pinning.ts if needed

    // Hook IosMslClient.setDidAppboot:
    Class cls = objc_getClass("IosMslClient");
    if (cls) {
        MSHookMessageEx(cls, @selector(setDidAppboot:),
                        (IMP)hook_setDidAppboot, (IMP *)&orig_setDidAppboot);
        file_log(@"[+] setDidAppboot: hooked");
        NFXKEY_LOG("  [+] setDidAppboot: hooked");
    }

    // Hook NFWebCrypto functions
    void *nfwc = dlopen("@rpath/NFWebCrypto.framework/NFWebCrypto", RTLD_NOLOAD);
    if (!nfwc) {
        nfwc = dlopen("/usr/lib/libNFWebCrypto.dylib", RTLD_NOLOAD);
    }
    if (nfwc) {
        // Resolve helper functions
        fn_DH_get0_key = (void (*)(const DH *, const BIGNUM **, const BIGNUM **))dlsym(nfwc, "DH_get0_key");
        fn_DH_get0_pqg = (void (*)(const DH *, const BIGNUM **, const BIGNUM **, const BIGNUM **))dlsym(nfwc, "DH_get0_pqg");
        fn_BN_num_bits = (int (*)(const BIGNUM *))dlsym(nfwc, "BN_num_bits");
        fn_BN_bn2bin = (int (*)(const BIGNUM *, unsigned char *))dlsym(nfwc, "BN_bn2bin");

        // Resolve SHA functions for PSK candidate derivation from DH shared_secret
        fn_SHA384 = (unsigned char *(*)(const unsigned char *, size_t, unsigned char *))dlsym(nfwc, "SHA384");
        fn_SHA256 = (unsigned char *(*)(const unsigned char *, size_t, unsigned char *))dlsym(nfwc, "SHA256");
        if (fn_SHA384) {
            file_log(@"[+] SHA384 resolved");
        } else {
            file_log(@"[-] SHA384 not found in NFWebCrypto");
        }
        if (fn_SHA256) {
            file_log(@"[+] SHA256 resolved");
        } else {
            file_log(@"[-] SHA256 not found in NFWebCrypto");
        }

        // === ALL HOOKS DISABLED FOR BISECT ===
        // Uncomment one group at a time to find which causes RSA error

        // --- Group 1: DH hooks --- ENABLED
        void *dhGenKey = dlsym(nfwc, "DH_generate_key");
        void *dhCompKey = dlsym(nfwc, "DH_compute_key");
        if (dhGenKey) { MSHookFunction(dhGenKey, (void *)hook_DH_generate_key, (void **)&orig_DH_generate_key); file_log(@"[+] DH_generate_key hooked"); }
        if (dhCompKey) { MSHookFunction(dhCompKey, (void *)hook_DH_compute_key, (void **)&orig_DH_compute_key); file_log(@"[+] DH_compute_key hooked"); }

        // --- Group 2: AES key setup hooks --- ENABLED
        void *aesEncKey = dlsym(nfwc, "AES_set_encrypt_key");
        void *aesDecKey = dlsym(nfwc, "AES_set_decrypt_key");
        if (aesEncKey) { MSHookFunction(aesEncKey, (void *)hook_AES_set_encrypt_key, (void **)&orig_AES_set_encrypt_key); file_log(@"[+] AES_set_encrypt_key hooked"); }
        if (aesDecKey) { MSHookFunction(aesDecKey, (void *)hook_AES_set_decrypt_key, (void **)&orig_AES_set_decrypt_key); file_log(@"[+] AES_set_decrypt_key hooked"); }

        // --- Group 3: HMAC (one-shot) hook --- ENABLED
        void *hmacFn = dlsym(nfwc, "HMAC");
        if (hmacFn) { MSHookFunction(hmacFn, (void *)hook_HMAC, (void **)&orig_HMAC); file_log(@"[+] HMAC hooked"); }

        // --- Group 4: Streaming HMAC hooks --- ENABLED
        void *hmacInitEx = dlsym(nfwc, "HMAC_Init_ex");
        void *hmacUpdate = dlsym(nfwc, "HMAC_Update");
        void *hmacFinal  = dlsym(nfwc, "HMAC_Final");
        if (hmacInitEx) { MSHookFunction(hmacInitEx, (void *)hook_HMAC_Init_ex, (void **)&orig_HMAC_Init_ex); file_log(@"[+] HMAC_Init_ex hooked"); }
        if (hmacUpdate) { MSHookFunction(hmacUpdate, (void *)hook_HMAC_Update, (void **)&orig_HMAC_Update); file_log(@"[+] HMAC_Update hooked"); }
        if (hmacFinal) { MSHookFunction(hmacFinal, (void *)hook_HMAC_Final, (void **)&orig_HMAC_Final); file_log(@"[+] HMAC_Final hooked"); }

        // --- Group 5: AES-CBC hook --- DISABLED (MSHookFunction breaks AES_cbc_encrypt trampoline)
        // void *aesCbcFn = dlsym(nfwc, "AES_cbc_encrypt");
        // if (aesCbcFn) { MSHookFunction(aesCbcFn, (void *)hook_AES_cbc_encrypt, (void **)&orig_AES_cbc_encrypt); file_log(@"[+] AES_cbc_encrypt hooked"); }
        file_log(@"[i] AES_cbc_encrypt hook disabled (trampoline issue)");

        file_log(@"[i] All hooks disabled for bisect");
    } else {
        file_log(@"[-] NFWebCrypto not loaded");
        NFXKEY_LOG("  [-] NFWebCrypto not loaded");
    }

    NFXKEY_LOG("AppbootKeyExtract: done");
}
