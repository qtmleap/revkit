#import <Orion/Orion.h>
#import <os/log.h>
#import <substrate.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static os_log_t g_log = NULL;
static NSString *g_logFile = nil;

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

// ---------------------------------------------------------------------------
// Hook: AES_set_encrypt_key / AES_set_decrypt_key from NFWebCrypto
// int AES_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key)
// ---------------------------------------------------------------------------

static int (*orig_AES_set_encrypt_key)(const unsigned char *userKey, int bits, void *key);
static int hook_AES_set_encrypt_key(const unsigned char *userKey, int bits, void *key) {
    int keyLen = bits / 8;
    if (keyLen == 16 || keyLen == 32) {
        file_log([NSString stringWithFormat:@"[AES_set_encrypt_key] bits=%d key=%@",
                  bits, hexEncode(userKey, keyLen)]);
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
// Hook: HMAC from NFWebCrypto
// unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
//                     const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len)
// ---------------------------------------------------------------------------

static unsigned char *(*orig_HMAC)(const void *evp_md, const void *key, int key_len,
                                    const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len);
static unsigned char *hook_HMAC(const void *evp_md, const void *key, int key_len,
                                 const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len) {
    if (key_len == 32) {
        file_log([NSString stringWithFormat:@"[HMAC] key_len=%d key=%@",
                  key_len, hexEncode((const uint8_t *)key, key_len)]);
    }
    return orig_HMAC(evp_md, key, key_len, d, n, md, md_len);
}

// ---------------------------------------------------------------------------
// Hook: IosMslClient.setDidAppboot:
// ---------------------------------------------------------------------------

static void (*orig_setDidAppboot)(id self, SEL _cmd, BOOL value);
static void hook_setDidAppboot(id self, SEL _cmd, BOOL value) {
    file_log([NSString stringWithFormat:@"setDidAppboot: %d", value]);
    NFXKEY_LOG("setDidAppboot: %d", value);
    orig_setDidAppboot(self, _cmd, value);
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

__attribute__((constructor)) static void init(void) {
    orion_init();
    g_log = os_log_create("dev.tkgstrator.charon", "keyextract");
    g_logFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"nfxkey.log"];

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

    // Hook AES_set_encrypt_key / AES_set_decrypt_key from NFWebCrypto
    void *nfwc = dlopen("@rpath/NFWebCrypto.framework/NFWebCrypto", RTLD_NOLOAD);
    if (!nfwc) {
        nfwc = dlopen("/usr/lib/libNFWebCrypto.dylib", RTLD_NOLOAD);
    }
    if (nfwc) {
        void *aesEncKey = dlsym(nfwc, "AES_set_encrypt_key");
        void *aesDecKey = dlsym(nfwc, "AES_set_decrypt_key");
        void *hmacFn = dlsym(nfwc, "HMAC");

        if (aesEncKey) {
            MSHookFunction(aesEncKey, (void *)hook_AES_set_encrypt_key, (void **)&orig_AES_set_encrypt_key);
            file_log(@"[+] AES_set_encrypt_key hooked");
            NFXKEY_LOG("  [+] AES_set_encrypt_key hooked");
        } else {
            file_log(@"[-] AES_set_encrypt_key not found");
        }

        if (aesDecKey) {
            MSHookFunction(aesDecKey, (void *)hook_AES_set_decrypt_key, (void **)&orig_AES_set_decrypt_key);
            file_log(@"[+] AES_set_decrypt_key hooked");
            NFXKEY_LOG("  [+] AES_set_decrypt_key hooked");
        } else {
            file_log(@"[-] AES_set_decrypt_key not found");
        }

        if (hmacFn) {
            MSHookFunction(hmacFn, (void *)hook_HMAC, (void **)&orig_HMAC);
            file_log(@"[+] HMAC hooked");
            NFXKEY_LOG("  [+] HMAC hooked");
        } else {
            file_log(@"[-] HMAC not found");
        }
    } else {
        file_log(@"[-] NFWebCrypto not loaded");
        NFXKEY_LOG("  [-] NFWebCrypto not loaded");
    }

    NFXKEY_LOG("AppbootKeyExtract: done");
}
