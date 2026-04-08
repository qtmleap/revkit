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
typedef struct evp_md_st     EVP_MD;
typedef struct hmac_ctx_st   HMAC_CTX;
typedef struct engine_st     ENGINE;
typedef struct aes_key_st    AES_KEY;

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

static int (*fn_BN_num_bits_int)(const BIGNUM *) = NULL;
static int (*fn_BN_bn2bin)(const BIGNUM *, unsigned char *) = NULL;

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
        file_log(g_log_hmac,
                 [NSString stringWithFormat:@"[HMAC] HMAC_Init_ex ctx=%p key(%dB)=%@",
                  (void *)ctx, key_len, keyHex]);
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
    if (fn_BN_num_bits_int) file_log(g_log_general, @"[+] BN_num_bits resolved");
    if (fn_BN_bn2bin)       file_log(g_log_general, @"[+] BN_bn2bin resolved");

    // ---- HOOK 1: DH_compute_key (dhDerive) ----
    void *sym = dlsym(nfwc, "DH_compute_key");
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

    file_log(g_log_general, @"=== AppbootKDF hooks installed ===");
}
