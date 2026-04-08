#import <Orion/Orion.h>
#import <os/log.h>
#import <substrate.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static os_log_t g_log = NULL;
static NSString *g_logFile = nil;
static NSString *g_keyFile = nil;

// Key storage — accumulated during session
static NSMutableDictionary *g_keys = nil;
static NSMutableArray *g_aesKeys = nil;
static NSMutableArray *g_hmacKeys = nil;
static BOOL g_appbootDone = NO;

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
        saveKeysToFile();
    }
    return ret;
}

// ---------------------------------------------------------------------------
// Hook: AES_set_encrypt_key / AES_set_decrypt_key
// ---------------------------------------------------------------------------

static int (*orig_AES_set_encrypt_key)(const unsigned char *userKey, int bits, void *key);
static int hook_AES_set_encrypt_key(const unsigned char *userKey, int bits, void *key) {
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
    return orig_AES_set_encrypt_key(userKey, bits, key);
}

static int (*orig_AES_set_decrypt_key)(const unsigned char *userKey, int bits, void *key);
static int hook_AES_set_decrypt_key(const unsigned char *userKey, int bits, void *key) {
    int keyLen = bits / 8;
    if (keyLen == 16 || keyLen == 32) {
        file_log([NSString stringWithFormat:@"[AES_set_decrypt_key] bits=%d key=%@",
                  bits, hexEncode(userKey, keyLen)]);
    }
    return orig_AES_set_decrypt_key(userKey, bits, key);
}

// ---------------------------------------------------------------------------
// Hook: HMAC
// ---------------------------------------------------------------------------

static unsigned char *(*orig_HMAC)(const void *evp_md, const void *key, int key_len,
                                    const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len);
static unsigned char *hook_HMAC(const void *evp_md, const void *key, int key_len,
                                 const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len) {
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

        // DH hooks
        void *dhGenKey = dlsym(nfwc, "DH_generate_key");
        void *dhCompKey = dlsym(nfwc, "DH_compute_key");

        if (dhGenKey) {
            MSHookFunction(dhGenKey, (void *)hook_DH_generate_key, (void **)&orig_DH_generate_key);
            file_log(@"[+] DH_generate_key hooked");
            NFXKEY_LOG("  [+] DH_generate_key hooked");
        }

        if (dhCompKey) {
            MSHookFunction(dhCompKey, (void *)hook_DH_compute_key, (void **)&orig_DH_compute_key);
            file_log(@"[+] DH_compute_key hooked");
            NFXKEY_LOG("  [+] DH_compute_key hooked");
        }

        // AES hooks
        void *aesEncKey = dlsym(nfwc, "AES_set_encrypt_key");
        void *aesDecKey = dlsym(nfwc, "AES_set_decrypt_key");
        void *hmacFn = dlsym(nfwc, "HMAC");

        if (aesEncKey) {
            MSHookFunction(aesEncKey, (void *)hook_AES_set_encrypt_key, (void **)&orig_AES_set_encrypt_key);
            file_log(@"[+] AES_set_encrypt_key hooked");
            NFXKEY_LOG("  [+] AES_set_encrypt_key hooked");
        }

        if (aesDecKey) {
            MSHookFunction(aesDecKey, (void *)hook_AES_set_decrypt_key, (void **)&orig_AES_set_decrypt_key);
            file_log(@"[+] AES_set_decrypt_key hooked");
            NFXKEY_LOG("  [+] AES_set_decrypt_key hooked");
        }

        if (hmacFn) {
            MSHookFunction(hmacFn, (void *)hook_HMAC, (void **)&orig_HMAC);
            file_log(@"[+] HMAC hooked");
            NFXKEY_LOG("  [+] HMAC hooked");
        }

        // HKDF hooks — try lowercase first (BoringSSL), then PascalCase
        void *hkdfExtract = dlsym(nfwc, "HKDF_extract");
        if (!hkdfExtract) {
            hkdfExtract = dlsym(nfwc, "HKDF_Extract");
            if (hkdfExtract) {
                file_log(@"[!] HKDF_extract not found, using HKDF_Extract");
            }
        }

        void *hkdfExpand = dlsym(nfwc, "HKDF_expand");
        if (!hkdfExpand) {
            hkdfExpand = dlsym(nfwc, "HKDF_Expand");
            if (hkdfExpand) {
                file_log(@"[!] HKDF_expand not found, using HKDF_Expand");
            }
        }

        if (hkdfExtract) {
            MSHookFunction(hkdfExtract, (void *)hook_HKDF_extract, (void **)&orig_HKDF_extract);
            file_log(@"[+] HKDF_extract hooked");
            NFXKEY_LOG("  [+] HKDF_extract hooked");
        } else {
            file_log(@"[-] HKDF_extract not found (tried HKDF_extract / HKDF_Extract)");
            NFXKEY_LOG("  [-] HKDF_extract not found");
        }

        if (hkdfExpand) {
            MSHookFunction(hkdfExpand, (void *)hook_HKDF_expand, (void **)&orig_HKDF_expand);
            file_log(@"[+] HKDF_expand hooked");
            NFXKEY_LOG("  [+] HKDF_expand hooked");
        } else {
            file_log(@"[-] HKDF_expand not found (tried HKDF_expand / HKDF_Expand)");
            NFXKEY_LOG("  [-] HKDF_expand not found");
        }
    } else {
        file_log(@"[-] NFWebCrypto not loaded");
        NFXKEY_LOG("  [-] NFWebCrypto not loaded");
    }

    NFXKEY_LOG("AppbootKeyExtract: done");
}
