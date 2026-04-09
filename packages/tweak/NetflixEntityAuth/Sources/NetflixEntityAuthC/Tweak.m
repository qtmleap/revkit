#import <Orion/Orion.h>
#import <os/log.h>
#import <substrate.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <string.h>
#import <stdint.h>
#import <mach-o/dyld.h>

// ---------------------------------------------------------------------------
// os_log channels
// ---------------------------------------------------------------------------

static os_log_t g_log_entity  = NULL;
static os_log_t g_log_hmac    = NULL;
static os_log_t g_log_general = NULL;

// ---------------------------------------------------------------------------
// File log — written to NSTemporaryDirectory() (app-sandboxed temp)
// also attempted in /var/tmp for root-accessible retrieval
// ---------------------------------------------------------------------------

static NSString *g_logFile  = nil;
static NSString *g_logFile2 = nil;  // secondary log path in /var/tmp

static void file_log_path(NSString *path, NSString *msg) {
    if (!path) return;
    @try {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"HH:mm:ss.SSS";
        NSString *line = [NSString stringWithFormat:@"%@ %@\n",
                          [df stringFromDate:[NSDate date]], msg];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) {
            [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    } @catch (NSException *e) {}
}

static void file_log(os_log_t channel, NSString *msg) {
    // Always emit via NSLog so it shows up in oslog output
    NSLog(@"[NFXEntityAuth] %@", msg);
    if (channel) {
        os_log(channel, "%{public}s", msg.UTF8String);
    }
    if (g_logFile)  file_log_path(g_logFile, msg);
    if (g_logFile2) file_log_path(g_logFile2, msg);
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

static void writeBinFile(NSString *path, const uint8_t *data, size_t len) {
    if (!data || len == 0 || !path) return;
    @try {
        NSData *d = [NSData dataWithBytes:data length:len];
        [d writeToFile:path atomically:YES];
    } @catch (NSException *e) {}
}

// Reentrancy guard
static volatile int g_inHook = 0;

// Counter for large HMAC data dumps
static int g_hmacDumpCount = 0;

// ---------------------------------------------------------------------------
// HMAC_CTX tracking table
// Correlates ctx pointer -> accumulated state across Init/Update/Final calls.
// ---------------------------------------------------------------------------

#define HMAC_CTX_TABLE_SIZE 32

typedef struct {
    void    *ctx;           // non-NULL means slot is in use
    uint8_t  key[128];
    int      key_len;
    int      md_nid;        // NID of the EVP_MD (or -1 if unknown)
    uint8_t  data_head[64]; // first 64B of input data
    size_t   data_head_len;
    size_t   data_total;
    int      seq;           // call sequence number
} HmacCtxEntry;

static HmacCtxEntry g_hmacCtxTable[HMAC_CTX_TABLE_SIZE];
static int g_hmacCtxSeq = 0;

static HmacCtxEntry *hmacCtxFind(void *ctx) {
    for (int i = 0; i < HMAC_CTX_TABLE_SIZE; i++) {
        if (g_hmacCtxTable[i].ctx == ctx) return &g_hmacCtxTable[i];
    }
    return NULL;
}

static HmacCtxEntry *hmacCtxAlloc(void *ctx) {
    // Reuse existing slot
    HmacCtxEntry *e = hmacCtxFind(ctx);
    if (e) return e;
    // Find free slot
    for (int i = 0; i < HMAC_CTX_TABLE_SIZE; i++) {
        if (g_hmacCtxTable[i].ctx == NULL) {
            memset(&g_hmacCtxTable[i], 0, sizeof(HmacCtxEntry));
            g_hmacCtxTable[i].ctx   = ctx;
            g_hmacCtxTable[i].md_nid = -1;
            g_hmacCtxTable[i].seq   = __sync_fetch_and_add(&g_hmacCtxSeq, 1);
            return &g_hmacCtxTable[i];
        }
    }
    // Table full — evict slot 0
    memset(&g_hmacCtxTable[0], 0, sizeof(HmacCtxEntry));
    g_hmacCtxTable[0].ctx    = ctx;
    g_hmacCtxTable[0].md_nid = -1;
    g_hmacCtxTable[0].seq    = __sync_fetch_and_add(&g_hmacCtxSeq, 1);
    return &g_hmacCtxTable[0];
}

static void hmacCtxFree(void *ctx) {
    HmacCtxEntry *e = hmacCtxFind(ctx);
    if (e) memset(e, 0, sizeof(HmacCtxEntry));
}

// ---------------------------------------------------------------------------
// EVP_DigestCtx tracking table (for SHA384 incremental)
// ---------------------------------------------------------------------------

#define EVP_CTX_TABLE_SIZE 16

typedef struct {
    void    *ctx;
    int      md_nid;
    uint8_t  data_head[64];
    size_t   data_head_len;
    size_t   data_total;
    int      seq;
} EvpCtxEntry;

static EvpCtxEntry g_evpCtxTable[EVP_CTX_TABLE_SIZE];
static int g_evpCtxSeq = 0;

static EvpCtxEntry *evpCtxFind(void *ctx) {
    for (int i = 0; i < EVP_CTX_TABLE_SIZE; i++) {
        if (g_evpCtxTable[i].ctx == ctx) return &g_evpCtxTable[i];
    }
    return NULL;
}

static EvpCtxEntry *evpCtxAlloc(void *ctx) {
    EvpCtxEntry *e = evpCtxFind(ctx);
    if (e) return e;
    for (int i = 0; i < EVP_CTX_TABLE_SIZE; i++) {
        if (g_evpCtxTable[i].ctx == NULL) {
            memset(&g_evpCtxTable[i], 0, sizeof(EvpCtxEntry));
            g_evpCtxTable[i].ctx  = ctx;
            g_evpCtxTable[i].md_nid = -1;
            g_evpCtxTable[i].seq  = __sync_fetch_and_add(&g_evpCtxSeq, 1);
            return &g_evpCtxTable[i];
        }
    }
    memset(&g_evpCtxTable[0], 0, sizeof(EvpCtxEntry));
    g_evpCtxTable[0].ctx   = ctx;
    g_evpCtxTable[0].md_nid = -1;
    g_evpCtxTable[0].seq   = __sync_fetch_and_add(&g_evpCtxSeq, 1);
    return &g_evpCtxTable[0];
}

static void evpCtxFree(void *ctx) {
    EvpCtxEntry *e = evpCtxFind(ctx);
    if (e) memset(e, 0, sizeof(EvpCtxEntry));
}

// ---------------------------------------------------------------------------
// Opaque types (OpenSSL)
// ---------------------------------------------------------------------------

typedef struct evp_md_st EVP_MD;

// ---------------------------------------------------------------------------
// HOOK 1: HMAC (one-shot) from NFWebCrypto.framework
//
// Signature: unsigned char *HMAC(const EVP_MD *evp_md,
//                                const void *key, int key_len,
//                                const unsigned char *d, size_t n,
//                                unsigned char *md, unsigned int *md_len)
//
// Filter: 32-byte (SHA-256) outputs only.
// Logs key_hex, key_len, data_hex, data_len, output_hex.
// Saves first 32B output to /var/tmp/entityauth_apphmac.bin
// ---------------------------------------------------------------------------

static unsigned char *(*orig_HMAC)(const EVP_MD *evp_md,
                                    const void *key, int key_len,
                                    const unsigned char *d, size_t n,
                                    unsigned char *md, unsigned int *md_len);

static BOOL g_apphmacSaved = NO;

static unsigned char *hook_HMAC(const EVP_MD *evp_md,
                                 const void *key, int key_len,
                                 const unsigned char *d, size_t n,
                                 unsigned char *md, unsigned int *md_len) {
    unsigned char *ret = orig_HMAC(evp_md, key, key_len, d, n, md, md_len);

    if (!g_inHook && ret) {
        unsigned int outLen = (md_len && *md_len > 0) ? *md_len : 0;

        // Determine actual output length: if md_len not set, check EVP_MD output size
        // For SHA-256 the output is 32 bytes
        if (outLen == 0 && ret) {
            // Assume 32B if md_len is not set and key_len is plausible
            outLen = 32;
        }

        // Only capture 32-byte (SHA-256) outputs — that is the apphmac
        if (outLen == 32 && key && key_len > 0 && key_len <= 256) {
            g_inHook = 1;

            NSString *keyHex  = hexEncodeShort((const uint8_t *)key, (size_t)key_len);
            NSString *dataHex = hexEncodeShort((const uint8_t *)d, n);
            NSString *outHex  = hexEncode(ret, 32);

            file_log(g_log_hmac,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth][HMAC] key(%dB)=%@ data(%zuB)=%@ digest(32B)=%@",
                      key_len, keyHex, n, dataHex, outHex]);

            // Save first 32B HMAC as candidate apphmac
            if (!g_apphmacSaved) {
                NSString *tmpDir = NSTemporaryDirectory();
                writeBinFile([tmpDir stringByAppendingPathComponent:@"entityauth_apphmac.bin"], ret, 32);
                writeBinFile([tmpDir stringByAppendingPathComponent:@"entityauth_hmac_key.bin"],
                             (const uint8_t *)key, (size_t)key_len);
                writeBinFile([tmpDir stringByAppendingPathComponent:@"entityauth_hmac_data.bin"],
                             (const uint8_t *)d, n);
                file_log(g_log_hmac, @"[NFXEntityAuth][HMAC] apphmac candidate saved to app tmp dir");
                g_apphmacSaved = YES;
            }

            // Save large HMAC data blobs (> 1KB) — likely appboot request body
            if (n > 1024) {
                NSString *tmpDir = NSTemporaryDirectory();
                int idx = __sync_fetch_and_add(&g_hmacDumpCount, 1);
                NSString *dataPath = [tmpDir stringByAppendingPathComponent:
                                      [NSString stringWithFormat:@"entityauth_hmac_blob_%03d_data.bin", idx]];
                NSString *keyPath  = [tmpDir stringByAppendingPathComponent:
                                      [NSString stringWithFormat:@"entityauth_hmac_blob_%03d_key.bin", idx]];
                NSString *sigPath  = [tmpDir stringByAppendingPathComponent:
                                      [NSString stringWithFormat:@"entityauth_hmac_blob_%03d_sig.bin", idx]];
                writeBinFile(dataPath, (const uint8_t *)d, n);
                writeBinFile(keyPath,  (const uint8_t *)key, (size_t)key_len);
                writeBinFile(sigPath,  ret, 32);
                file_log(g_log_hmac,
                         [NSString stringWithFormat:
                          @"[NFXEntityAuth][HMAC] large blob saved: idx=%d data=%zuB key=%dB",
                          idx, n, key_len]);
            }

            g_inHook = 0;
        }
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 2: HMAC_CTX_new — log context creation
// ---------------------------------------------------------------------------

static void *(*orig_HMAC_CTX_new)(void);

static void *hook_HMAC_CTX_new(void) {
    void *ctx = orig_HMAC_CTX_new ? orig_HMAC_CTX_new() : NULL;
    if (ctx && !g_inHook) {
        g_inHook = 1;
        hmacCtxAlloc(ctx);
        file_log(g_log_hmac,
                 [NSString stringWithFormat:@"[NFXEntityAuth][HMAC_CTX_new] ctx=%p", ctx]);
        g_inHook = 0;
    }
    return ctx;
}

// ---------------------------------------------------------------------------
// HOOK 3: HMAC_Init_ex(ctx, key, key_len, evp_md, engine)
// ---------------------------------------------------------------------------

static int (*orig_HMAC_Init_ex)(void *ctx, const void *key, int key_len,
                                 const EVP_MD *evp_md, void *engine);

// Forward-declare so we can get NID inside the hook
typedef int (*EVP_MD_type_fn)(const EVP_MD *);
static EVP_MD_type_fn g_EVP_MD_type = NULL;

static int hook_HMAC_Init_ex(void *ctx, const void *key, int key_len,
                               const EVP_MD *evp_md, void *engine) {
    int ret = orig_HMAC_Init_ex ? orig_HMAC_Init_ex(ctx, key, key_len, evp_md, engine) : 1;

    if (ctx && !g_inHook) {
        g_inHook = 1;

        HmacCtxEntry *e = hmacCtxAlloc(ctx);
        if (e && key && key_len > 0 && key_len <= (int)sizeof(e->key)) {
            memcpy(e->key, key, (size_t)key_len);
            e->key_len = key_len;
        }
        if (e && evp_md && g_EVP_MD_type) {
            e->md_nid = g_EVP_MD_type(evp_md);
        }
        // Reset data tracking on re-init
        if (e) {
            e->data_head_len = 0;
            e->data_total    = 0;
        }

        int nid = e ? e->md_nid : -1;
        int seq = e ? e->seq : -1;
        NSString *keyHex = (key && key_len > 0)
            ? hexEncodeShort((const uint8_t *)key, (size_t)key_len) : @"(null)";

        file_log(g_log_hmac,
                 [NSString stringWithFormat:
                  @"[NFXEntityAuth][HMAC_Init_ex] seq=%d ctx=%p nid=%d key(%dB)=%@",
                  seq, ctx, nid, key_len, keyHex]);
        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 4: HMAC_Update(ctx, data, len)
// ---------------------------------------------------------------------------

static int (*orig_HMAC_Update)(void *ctx, const unsigned char *data, size_t len);

static int hook_HMAC_Update(void *ctx, const unsigned char *data, size_t len) {
    int ret = orig_HMAC_Update ? orig_HMAC_Update(ctx, data, len) : 1;

    if (ctx && !g_inHook) {
        g_inHook = 1;

        HmacCtxEntry *e = hmacCtxFind(ctx);
        if (e) {
            // Accumulate first 64B of data
            if (data && len > 0 && e->data_head_len < sizeof(e->data_head)) {
                size_t copy = sizeof(e->data_head) - e->data_head_len;
                if (copy > len) copy = len;
                memcpy(e->data_head + e->data_head_len, data, copy);
                e->data_head_len += copy;
            }
            e->data_total += len;
        }

        int seq = e ? e->seq : -1;
        NSString *dataHex = (data && len > 0)
            ? hexEncodeShort((const uint8_t *)data, len) : @"(null)";
        file_log(g_log_hmac,
                 [NSString stringWithFormat:
                  @"[NFXEntityAuth][HMAC_Update] seq=%d ctx=%p data(%zuB)=%@",
                  seq, ctx, len, dataHex]);
        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 5: HMAC_Final(ctx, md, md_len)
// ---------------------------------------------------------------------------

static int (*orig_HMAC_Final)(void *ctx, unsigned char *md, unsigned int *md_len);

static int hook_HMAC_Final(void *ctx, unsigned char *md, unsigned int *md_len) {
    int ret = orig_HMAC_Final ? orig_HMAC_Final(ctx, md, md_len) : 1;

    if (ctx && !g_inHook) {
        g_inHook = 1;

        HmacCtxEntry *e = hmacCtxFind(ctx);
        unsigned int outLen = (md_len && *md_len > 0) ? *md_len : 0;
        // Derive expected output size from the tracked NID if md_len was not set
        if (outLen == 0 && md) {
            int nidGuess = e ? e->md_nid : -1;
            if (nidGuess == 673)      outLen = 48; // SHA384
            else if (nidGuess == 674) outLen = 64; // SHA512
            else                      outLen = 32; // SHA256 or unknown
        }

        int seq    = e ? e->seq : -1;
        int nid    = e ? e->md_nid : -1;
        int keyLen = e ? e->key_len : 0;
        NSString *keyHex = (e && e->key_len > 0)
            ? hexEncode(e->key, (size_t)e->key_len) : @"(none)";
        NSString *dataHeadHex = (e && e->data_head_len > 0)
            ? hexEncode(e->data_head, e->data_head_len) : @"(none)";
        NSString *outHex = (md && outLen > 0)
            ? hexEncode(md, outLen) : @"(null)";

        file_log(g_log_hmac,
                 [NSString stringWithFormat:
                  @"[NFXEntityAuth][HMAC_Final] seq=%d ctx=%p nid=%d key(%dB)=%@ "
                  @"data_total=%zuB data_head=%@ output(%uB)=%@",
                  seq, ctx, nid, keyLen, keyHex,
                  e ? e->data_total : (size_t)0, dataHeadHex,
                  outLen, outHex]);

        // If output is 48B (SHA384), log specially — first 32B might be the sign key
        if (outLen >= 48 && md) {
            NSString *first32 = hexEncode(md, 32);
            file_log(g_log_hmac,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth][HMAC_Final] SHA384 first32=%@", first32]);
        }

        hmacCtxFree(ctx);
        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 6: SHA384 one-shot
// unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md)
// ---------------------------------------------------------------------------

static unsigned char *(*orig_SHA384)(const unsigned char *d, size_t n, unsigned char *md);

static unsigned char *hook_SHA384(const unsigned char *d, size_t n, unsigned char *md) {
    unsigned char *ret = orig_SHA384 ? orig_SHA384(d, n, md) : NULL;

    if (!g_inHook && ret) {
        g_inHook = 1;
        NSString *dataHex = hexEncodeShort((const uint8_t *)d, n);
        NSString *outHex  = hexEncode(ret, 48);
        NSString *first32 = hexEncode(ret, 32);
        file_log(g_log_hmac,
                 [NSString stringWithFormat:
                  @"[NFXEntityAuth][SHA384] data(%zuB)=%@ digest(48B)=%@ first32=%@",
                  n, dataHex, outHex, first32]);
        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 7: EVP_DigestInit_ex(ctx, evp_md, engine) — track SHA384 incremental
// ---------------------------------------------------------------------------

static int (*orig_EVP_DigestInit_ex)(void *ctx, const EVP_MD *evp_md, void *engine);

static int hook_EVP_DigestInit_ex(void *ctx, const EVP_MD *evp_md, void *engine) {
    int ret = orig_EVP_DigestInit_ex ? orig_EVP_DigestInit_ex(ctx, evp_md, engine) : 1;

    if (ctx && !g_inHook) {
        g_inHook = 1;
        int nid = (evp_md && g_EVP_MD_type) ? g_EVP_MD_type(evp_md) : -1;
        // NID 673 = SHA384, 672 = SHA256, 674 = SHA512
        // Only track SHA384 (NID 673)
        if (nid == 673) {
            EvpCtxEntry *e = evpCtxAlloc(ctx);
            if (e) {
                e->md_nid        = nid;
                e->data_head_len = 0;
                e->data_total    = 0;
            }
            file_log(g_log_hmac,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth][EVP_DigestInit_ex] SHA384 seq=%d ctx=%p",
                      e ? e->seq : -1, ctx]);
        }
        g_inHook = 0;
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 8: EVP_DigestUpdate(ctx, data, len)
// ---------------------------------------------------------------------------

static int (*orig_EVP_DigestUpdate)(void *ctx, const void *data, size_t len);

static int hook_EVP_DigestUpdate(void *ctx, const void *data, size_t len) {
    int ret = orig_EVP_DigestUpdate ? orig_EVP_DigestUpdate(ctx, data, len) : 1;

    if (ctx && !g_inHook) {
        EvpCtxEntry *e = evpCtxFind(ctx);
        if (e) {
            g_inHook = 1;
            if (data && len > 0 && e->data_head_len < sizeof(e->data_head)) {
                size_t copy = sizeof(e->data_head) - e->data_head_len;
                if (copy > len) copy = len;
                memcpy(e->data_head + e->data_head_len, data, copy);
                e->data_head_len += copy;
            }
            e->data_total += len;
            NSString *dataHex = (data && len > 0)
                ? hexEncodeShort((const uint8_t *)data, len) : @"(null)";
            file_log(g_log_hmac,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth][EVP_DigestUpdate] SHA384 seq=%d ctx=%p data(%zuB)=%@",
                      e->seq, ctx, len, dataHex]);
            g_inHook = 0;
        }
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 9: EVP_DigestFinal_ex(ctx, md, s)
// ---------------------------------------------------------------------------

static int (*orig_EVP_DigestFinal_ex)(void *ctx, unsigned char *md, unsigned int *s);

static int hook_EVP_DigestFinal_ex(void *ctx, unsigned char *md, unsigned int *s) {
    int ret = orig_EVP_DigestFinal_ex ? orig_EVP_DigestFinal_ex(ctx, md, s) : 1;

    if (ctx && !g_inHook) {
        EvpCtxEntry *e = evpCtxFind(ctx);
        if (e) {
            g_inHook = 1;
            unsigned int outLen = (s && *s > 0) ? *s : 48; // SHA384 = 48B
            NSString *outHex  = (md && outLen > 0 && outLen <= 64)
                ? hexEncode(md, outLen) : @"(null)";
            NSString *first32 = (md && outLen >= 32)
                ? hexEncode(md, 32) : @"(short)";
            file_log(g_log_hmac,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth][EVP_DigestFinal_ex] SHA384 seq=%d ctx=%p "
                      @"data_total=%zuB output(%uB)=%@ first32=%@",
                      e->seq, ctx, e->data_total, outLen, outHex, first32]);
            evpCtxFree(ctx);
            g_inHook = 0;
        }
    }
    return ret;
}

// ---------------------------------------------------------------------------
// HOOK 10: AppleWebCrypto::HKDF — NFWebCrypto offset 0x00011900
//
// Static analysis confirms a single HKDF function at this offset:
//   netflix::AppleWebCrypto::HKDF(
//     x0: this,
//     x1: const vector<uint8_t>& ikm,         // first arg  (salt/IKM)
//     x2: const vector<uint8_t>& info,        // second arg (expand info)
//     x3: const shared_ptr<KeyByteArray>& key,// third arg  (input key material)
//     x8: shared_ptr<KeyByteArray>* output    // sret hidden pointer
//   )
//
// Internally it does:
//   prk  = HMAC-SHA256(key_bytes, ikm_bytes)   // Extract
//   okm  = HMAC-SHA256(prk, info_bytes)        // Expand (single block, 32B)
//
// ARM64 struct-return calling convention: output pointer in x8 (not x0).
// We use __builtin_return_address and a custom wrapper to access x8.
//
// Offset 0x11900 (file-relative) = runtime base + 0x11900.
// ---------------------------------------------------------------------------

// std::vector<uint8_t> layout: { ptr, end, cap_end } (3x uint8_t*)
typedef struct {
    const uint8_t *begin;
    const uint8_t *end;
    const uint8_t *cap;
} VecByteLayout;

// KeyByteArray is vector<uint8_t> with the same layout
typedef VecByteLayout KeyByteArrayLayout;

// shared_ptr<T> layout: { T *ptr, control_block* }
typedef struct {
    KeyByteArrayLayout *ptr;
    void               *ctrl;
} SharedPtrKeyBA;

// shared_ptr<KeyByteArray> output layout for sret:
// The output is written to *x8 which is a shared_ptr<KeyByteArray>.
// We need to read x8 BEFORE the call to know the address.
// Strategy: wrap with a custom calling convention trampoline that logs.
//
// Simpler approach: hook the function, call original, then read x8 output.
// We stash x8 using a thread-local-style global.

typedef void (*AppleWebCryptoHKDF_fn)(
    void                   *self,           // x0
    const VecByteLayout    *ikm,            // x1
    const VecByteLayout    *info,           // x2
    const SharedPtrKeyBA   *key,            // x3
    SharedPtrKeyBA         *output          // x8 — sret, NOT an explicit param
);

// We cannot directly declare the x8-passing convention in C, so we use a
// raw wrapper written in inline asm or model it as an extra argument.
// In practice, Clang/arm64 passes struct-return pointer in x8 when the
// return type is a non-trivially-copyable struct. Since we model this as
// void-returning with an extra pointer, we use __attribute__((ms_abi)) or
// simply pass the output pointer as x8 using a __attribute__((objc_method_family(none))).
//
// Safe approach: hook via MSHookFunction but declare a void-return function
// with an extra 5th parameter, then use the fact that arm64 ABI passes the
// 5th integer/pointer in x4 (not x8). This would be WRONG.
//
// Correct approach: use a naked / asm stub. Since that is complex, use the
// MSHookFunction mechanism that replaces the prologue. In our hook function,
// x8 comes in as the "hidden" sret and we can read it before calling orig.
//
// Practical pattern used by iOS reversers: declare the C prototype with an
// extra leading pointer parameter corresponding to x8, then swap x0 and x8.
// Clang will NOT do this automatically.
//
// Simplest safe method: use a Logos hook that captures x8 via asm, or use
// a different calling convention workaround. Here we use the following trick:
// Declare the function as returning a struct of two pointers (which forces
// x8 to be used as sret in the caller), then the hook gets x8 as x0 in the
// callee's frame when compiled with the same convention.
//
// Actually the cleanest method: register a post-hook by hooking *after* the
// prologue saves registers. Not feasible with MSHookFunction.
//
// Working approach: use __attribute__((naked)) for the trampoline.
// The hook function below is called with ARM64 registers as they arrive:
//   x0=this, x1=ikm, x2=info, x3=key, x8=output_sret.
// We grab x8 by reading it before jumping to orig via a small asm thunk.
// ---------------------------------------------------------------------------

// We store the pending output pointer in a volatile global (single-threaded
// assumption during HKDF, acceptable for a debugging tweak).
typedef struct {
    // A dummy struct with two pointers so the compiler uses x8 for sret
    void *a;
    void *b;
} SretDummy;

// Prototype that the compiler will call with sret in x8:
typedef SretDummy (*AppleWebCryptoHKDF_sret_fn)(
    void                   *self,
    const VecByteLayout    *ikm,
    const VecByteLayout    *info,
    const SharedPtrKeyBA   *key
);

static AppleWebCryptoHKDF_sret_fn orig_AppleWebCryptoHKDF = NULL;

static SretDummy hook_AppleWebCryptoHKDF(
    void                   *self,
    const VecByteLayout    *ikm,
    const VecByteLayout    *info,
    const SharedPtrKeyBA   *key)
{
    // Log inputs before calling original
    if (!g_inHook) {
        g_inHook = 1;

        // IKM: first vector arg
        NSString *ikmHex = @"(null)";
        size_t ikmLen = 0;
        if (ikm && ikm->begin && ikm->end >= ikm->begin) {
            ikmLen = (size_t)(ikm->end - ikm->begin);
            ikmHex = hexEncodeShort(ikm->begin, ikmLen);
        }

        // Info: second vector arg
        NSString *infoHex = @"(null)";
        size_t infoLen = 0;
        if (info && info->begin && info->end >= info->begin) {
            infoLen = (size_t)(info->end - info->begin);
            infoHex = hexEncodeShort(info->begin, infoLen);
        }

        // Key: shared_ptr<KeyByteArray> -> dereference.
        // KeyByteArray may have vtable or other preamble before vector data.
        // Dump raw bytes of the pointed-to object to discover actual layout.
        NSString *keyHex = @"(null)";
        size_t keyLen = 0;
        if (key && key->ptr) {
            // Dump first 128 bytes of the object for layout analysis
            const uint8_t *rawObj = (const uint8_t *)key->ptr;
            file_log(g_log_hmac,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth][HKDF] key->ptr raw(128B)=%@",
                      hexEncode(rawObj, 128)]);

            // Try multiple offsets: the actual data might be at +0, +8, +16, +24
            // Standard vector {begin,end,cap} but possibly after a vtable ptr
            for (int off = 0; off <= 48; off += 8) {
                const uint8_t **ptrs = (const uint8_t **)(rawObj + off);
                const uint8_t *b = ptrs[0];
                const uint8_t *e = ptrs[1];
                if (b && e && e > b && (size_t)(e - b) <= 256) {
                    keyLen = (size_t)(e - b);
                    keyHex = hexEncodeShort(b, keyLen);
                    file_log(g_log_hmac,
                             [NSString stringWithFormat:
                              @"[NFXEntityAuth][HKDF] key found at obj+%d: (%zuB)=%@",
                              off, keyLen, keyHex]);
                    break;
                }
            }
        }

        file_log(g_log_hmac,
                 [NSString stringWithFormat:
                  @"[NFXEntityAuth][HKDF] this=%p ikm(%zuB)=%@ info(%zuB)=%@ key(%zuB)=%@",
                  self, ikmLen, ikmHex, infoLen, infoHex, keyLen, keyHex]);

        g_inHook = 0;
    }

    // Call original
    SretDummy result = orig_AppleWebCryptoHKDF(self, ikm, info, key);

    // Log output: result struct holds {ptr, ctrl} of shared_ptr<KeyByteArray>
    if (!g_inHook) {
        g_inHook = 1;

        NSString *okmHex = @"(null)";
        size_t okmLen = 0;
        // The sret dummy contains the shared_ptr<KeyByteArray> fields
        // result.a = KeyByteArray* (the managed pointer)
        if (result.a) {
            const KeyByteArrayLayout *kba = (const KeyByteArrayLayout *)result.a;
            if (kba && kba->begin && kba->end >= kba->begin) {
                okmLen = (size_t)(kba->end - kba->begin);
                if (okmLen <= 128) {
                    okmHex = hexEncode(kba->begin, okmLen);
                } else {
                    okmHex = hexEncodeShort(kba->begin, okmLen);
                }
            }
        }

        file_log(g_log_hmac,
                 [NSString stringWithFormat:
                  @"[NFXEntityAuth][HKDF] okm(%zuB)=%@", okmLen, okmHex]);
        if (okmLen >= 32 && result.a) {
            const KeyByteArrayLayout *kba = (const KeyByteArrayLayout *)result.a;
            file_log(g_log_hmac,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth][HKDF] okm_first32=%@",
                      hexEncode(kba->begin, 32)]);
        }

        g_inHook = 0;
    }

    return result;
}

// ---------------------------------------------------------------------------
// HOOK 11: NSData dataWithContentsOfFile: — catch large file reads (4-10 KB)
//          that could be device_key_data / devicetoken source material.
// ---------------------------------------------------------------------------

static NSData *(*orig_dataWithContentsOfFile)(id cls, SEL sel, NSString *path);

static NSData *hook_dataWithContentsOfFile(id cls, SEL sel, NSString *path) {
    NSData *result = orig_dataWithContentsOfFile(cls, sel, path);

    if (!g_inHook && result && path) {
        NSUInteger len = [result length];
        // Filter: 4 KB – 10 KB range (likely device key data)
        if (len >= 4096 && len <= 10240) {
            g_inHook = 1;
            file_log(g_log_general,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth][NSData] dataWithContentsOfFile: path=%@ size=%luB",
                      path, (unsigned long)len]);
            // Save binary data
            NSString *safeName = [[path lastPathComponent]
                                   stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
            NSString *savePath = [NSTemporaryDirectory()
                                  stringByAppendingPathComponent:
                                  [NSString stringWithFormat:@"entityauth_fileread_%@.bin", safeName]];
            [result writeToFile:savePath atomically:YES];
            file_log(g_log_general,
                     [NSString stringWithFormat:@"[NFXEntityAuth][NSData] saved to %@", savePath]);
            g_inHook = 0;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// MslClient.framework hook setup
//
// FpsMgkAppIdAuthData constructor (offset 0x00028038):
//   x0: self (this pointer)
//   x1: &mgkid (std::string const&)
//   x2: &devtype (std::string const&)
//   x3: &appid (std::string const&)
//   w4: appkeyversion (int)
//   x5: &apphmac (std::string const&)
//   x6: AppleWebCrypto*
//   x7: SynchronizedCdmAuthGeneration*
//
// Note: IosMGKAuthenticationData at 0xd45c is LEGACY and never fires.
// The active scheme is FpsMgkAppIdAuthData.
// ---------------------------------------------------------------------------

// Helper: read libc++ std::string (SSO layout)
// If byte at [str+0x17] (sign bit) is non-negative => short string, data inline at str
// Otherwise => long string, pointer at [str], length at [str+8]
static NSString *readStdString(const void *strPtr) {
    if (!strPtr) return @"(nil)";
    const uint8_t *raw = (const uint8_t *)strPtr;
    int8_t signByte = (int8_t)raw[0x17];
    if (signByte >= 0) {
        // Short (SSO) string: length = signByte, data at raw[0]
        size_t len = (size_t)(uint8_t)signByte;
        return [[NSString alloc] initWithBytes:raw length:len encoding:NSUTF8StringEncoding] ?: @"(unreadable)";
    } else {
        // Long string: pointer at offset 0, length at offset 8
        const char *data = *(const char **)raw;
        size_t len = *(const size_t *)(raw + 8);
        if (!data || len == 0 || len > 65536) return @"(long/invalid)";
        return [[NSString alloc] initWithBytes:data length:len encoding:NSUTF8StringEncoding] ?: @"(unreadable)";
    }
}

typedef void (*FpsMgkAppIdAuthData_ctor_t)(void *self,
                                            const void *mgkid,
                                            const void *devtype,
                                            const void *appid,
                                            int appkeyversion,
                                            const void *apphmac,
                                            void *webCrypto,
                                            void *authGen);

static FpsMgkAppIdAuthData_ctor_t orig_FpsMgkAppIdAuthData_ctor = NULL;

static void hook_FpsMgkAppIdAuthData_ctor(void *self,
                                           const void *mgkid,
                                           const void *devtype,
                                           const void *appid,
                                           int appkeyversion,
                                           const void *apphmac,
                                           void *webCrypto,
                                           void *authGen) {
    // Call original first
    if (orig_FpsMgkAppIdAuthData_ctor) {
        orig_FpsMgkAppIdAuthData_ctor(self, mgkid, devtype, appid, appkeyversion, apphmac, webCrypto, authGen);
    }

    if (!g_inHook) {
        g_inHook = 1;

        NSString *mgkidStr   = readStdString(mgkid);
        NSString *devtypeStr = readStdString(devtype);
        NSString *appidStr   = readStdString(appid);
        NSString *apphmacStr = readStdString(apphmac);

        file_log(g_log_entity,
                 [NSString stringWithFormat:
                  @"[NFXEntityAuth][FpsMgkAppIdAuthData] mgkid=%@ devtype=%@ appid=%@ appkeyversion=%d apphmac=%@",
                  mgkidStr, devtypeStr, appidStr, appkeyversion, apphmacStr]);

        NSString *tmpDir = NSTemporaryDirectory();
        // Save all fields
        [mgkidStr writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_mgkid.txt"]
                   atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [devtypeStr writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_devtype.txt"]
                     atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [appidStr writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_appid.txt"]
                   atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [[NSString stringWithFormat:@"%d", appkeyversion]
            writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_appkeyversion.txt"]
            atomically:YES encoding:NSUTF8StringEncoding error:nil];

        if (apphmacStr && ![apphmacStr isEqualToString:@"(nil)"]) {
            [apphmacStr writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_apphmac_b64.txt"]
                         atomically:YES encoding:NSUTF8StringEncoding error:nil];
            // Decode base64 and save raw bytes
            NSData *hmacData = [[NSData alloc] initWithBase64EncodedString:apphmacStr options:0];
            if (hmacData) {
                [hmacData writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_apphmac_raw.bin"]
                           atomically:YES];
                file_log(g_log_entity,
                         [NSString stringWithFormat:@"[NFXEntityAuth][FpsMgkAppIdAuthData] apphmac_raw(%luB)=%@",
                          (unsigned long)[hmacData length],
                          hexEncode((const uint8_t *)[hmacData bytes], [hmacData length])]);
            }
        }

        g_inHook = 0;
    }
}

// ---------------------------------------------------------------------------
// MslClient.framework: getAuthData method hook for devicetoken
//
// The getAuthData method lives at vtable offset +0xe8.
// We hook it via ObjC message interception on the MslRegistration class or
// by hooking -[IosMGKAuthenticationData getAuthData] if accessible.
//
// Alternative: Hook -[MslRegistration getDeviceTokensWithCallback:]
// which is in Nbp.framework and passes devicetoken to its callback.
// We hook this ObjC method via MSHookMessageEx.
// ---------------------------------------------------------------------------

static void (*orig_getDeviceTokensWithCallback)(id self, SEL sel, id callback) = NULL;

static void hook_getDeviceTokensWithCallback(id self, SEL sel, id callback) {
    if (!g_inHook) {
        file_log(g_log_entity,
                 @"[NFXEntityAuth][MslRegistration] getDeviceTokensWithCallback: called");
    }

    // Wrap the callback to intercept the devicetoken argument
    // The callback is typically a block: ^(NSString *devicetoken, NSError *error)
    // We wrap it so we can log the value when it arrives.
    id wrappedCallback = nil;
    if (callback) {
        // Try to wrap as a block taking (id, id)
        __block id origBlock = [callback copy];
        wrappedCallback = ^(id arg0, id arg1) {
            if (!g_inHook) {
                g_inHook = 1;
                // arg0 is expected to be NSString* devicetoken
                if ([arg0 isKindOfClass:[NSString class]]) {
                    NSString *tokenStr = (NSString *)arg0;
                    file_log(g_log_entity,
                             [NSString stringWithFormat:
                              @"[NFXEntityAuth][devicetoken] len=%lu value=%@",
                              (unsigned long)[tokenStr length], tokenStr]);
                    NSString *dtTmpDir = NSTemporaryDirectory();
                    [tokenStr writeToFile:[dtTmpDir stringByAppendingPathComponent:@"entityauth_devicetoken.txt"]
                               atomically:YES
                                 encoding:NSUTF8StringEncoding
                                    error:nil];
                    // Also save as raw UTF-8 bytes
                    NSData *tokenData = [tokenStr dataUsingEncoding:NSUTF8StringEncoding];
                    if (tokenData) {
                        [tokenData writeToFile:[dtTmpDir stringByAppendingPathComponent:@"entityauth_devicetoken.bin"]
                                    atomically:YES];
                    }
                } else if ([arg0 isKindOfClass:[NSData class]]) {
                    NSData *tokenData = (NSData *)arg0;
                    file_log(g_log_entity,
                             [NSString stringWithFormat:
                              @"[NFXEntityAuth][devicetoken] NSData len=%lu hex=%@",
                              (unsigned long)[tokenData length],
                              hexEncodeShort((const uint8_t *)[tokenData bytes], [tokenData length])]);
                    [tokenData writeToFile:[NSTemporaryDirectory() stringByAppendingPathComponent:@"entityauth_devicetoken.bin"]
                                atomically:YES];
                } else {
                    file_log(g_log_entity,
                             [NSString stringWithFormat:
                              @"[NFXEntityAuth][devicetoken] arg0 class=%@ value=%@",
                              NSStringFromClass([arg0 class]), arg0]);
                }
                g_inHook = 0;
            }
            // Call original block
            if (origBlock) {
                void (^blk)(id, id) = origBlock;
                blk(arg0, arg1);
            }
        };
    }

    orig_getDeviceTokensWithCallback(self, sel, wrappedCallback ?: callback);
}

// ---------------------------------------------------------------------------
// Delayed MslClient hook installer
// Called after a short delay to give MslClient.framework time to load.
// ---------------------------------------------------------------------------

static BOOL g_mslHooked = NO;

static void installMslClientHooks(void) {
    if (g_mslHooked) return;

    void *msl = dlopen("@rpath/MslClient.framework/MslClient", RTLD_NOLOAD);
    if (!msl) {
        // Try common app container path patterns
        msl = dlopen("/var/containers/Bundle/Application/2A734797-B5EA-4048-B255-C90EA4D50196/Argo.app/Frameworks/MslClient.framework/MslClient", RTLD_NOLOAD);
    }
    if (!msl) {
        file_log(g_log_general, @"[NFXEntityAuth] MslClient not loaded yet");
        return;
    }

    file_log(g_log_general, @"[NFXEntityAuth] MslClient.framework found");

    // IosMGKAuthenticationData constructor at offset 0x0000d45c
    // We need the base address of the MslClient image.
    // Use dladdr or iterate _dyld_* APIs.
    // Approach: use dlsym for a known exported symbol to get image base,
    // then add offset.
    //
    // There are no guaranteed exported C symbols in MslClient that we know of,
    // so we use the image base directly via _dyld APIs.

    uint32_t imgCount = _dyld_image_count();
    uintptr_t mslBase = 0;
    for (uint32_t i = 0; i < imgCount; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "MslClient.framework/MslClient")) {
            mslBase = (uintptr_t)_dyld_get_image_header(i);
            file_log(g_log_general,
                     [NSString stringWithFormat:@"[NFXEntityAuth] MslClient base=0x%lx (%s)",
                      (unsigned long)mslBase, name]);
            break;
        }
    }

    if (mslBase == 0) {
        file_log(g_log_general, @"[NFXEntityAuth] MslClient base not found in dyld image list");
        return;
    }

    // FpsMgkAppIdAuthData constructor offset 0x00028038
    // This is the ACTIVE entity_auth_data class for appboot.
    // (IosMGKAuthenticationData at 0xd45c is LEGACY and never fires.)
    uintptr_t ctorAddr = mslBase + 0x28038;
    file_log(g_log_general,
             [NSString stringWithFormat:@"[NFXEntityAuth] FpsMgkAppIdAuthData ctor addr=0x%lx",
              (unsigned long)ctorAddr]);

    MSHookFunction((void *)ctorAddr,
                   (void *)hook_FpsMgkAppIdAuthData_ctor,
                   (void **)&orig_FpsMgkAppIdAuthData_ctor);
    file_log(g_log_general, @"[NFXEntityAuth] FpsMgkAppIdAuthData ctor hooked");

    g_mslHooked = YES;
}

// ---------------------------------------------------------------------------
// Nbp.framework: hook -[MslRegistration getDeviceTokensWithCallback:]
// ---------------------------------------------------------------------------

static BOOL g_nbpHooked = NO;

static void installNbpHooks(void) {
    if (g_nbpHooked) return;

    void *nbp = dlopen("@rpath/Nbp.framework/Nbp", RTLD_NOLOAD);
    if (!nbp) {
        nbp = dlopen("/var/containers/Bundle/Application/2A734797-B5EA-4048-B255-C90EA4D50196/Argo.app/Frameworks/Nbp.framework/Nbp", RTLD_NOLOAD);
    }
    if (!nbp) {
        file_log(g_log_general, @"[NFXEntityAuth] Nbp not loaded yet");
        return;
    }

    file_log(g_log_general, @"[NFXEntityAuth] Nbp.framework found");

    Class mslRegClass = NSClassFromString(@"MslRegistration");
    if (!mslRegClass) {
        file_log(g_log_general, @"[NFXEntityAuth] MslRegistration class not found");
        return;
    }

    SEL sel = NSSelectorFromString(@"getDeviceTokensWithCallback:");
    Method m = class_getInstanceMethod(mslRegClass, sel);
    if (!m) {
        file_log(g_log_general, @"[NFXEntityAuth] getDeviceTokensWithCallback: method not found");
        return;
    }

    MSHookMessageEx(mslRegClass,
                    sel,
                    (IMP)hook_getDeviceTokensWithCallback,
                    (IMP *)&orig_getDeviceTokensWithCallback);
    file_log(g_log_general, @"[NFXEntityAuth] getDeviceTokensWithCallback: hooked");
    g_nbpHooked = YES;
}

// ---------------------------------------------------------------------------
// NFWebCrypto HMAC hook installer
// ---------------------------------------------------------------------------

static BOOL g_nfwcHooked = NO;

static void installNFWebCryptoHooks(void) {
    if (g_nfwcHooked) return;

    void *nfwc = dlopen("@rpath/NFWebCrypto.framework/NFWebCrypto", RTLD_NOLOAD);
    if (!nfwc) {
        nfwc = dlopen("/var/containers/Bundle/Application/2A734797-B5EA-4048-B255-C90EA4D50196/Argo.app/Frameworks/NFWebCrypto.framework/NFWebCrypto", RTLD_NOLOAD);
    }
    if (!nfwc) {
        file_log(g_log_general, @"[NFXEntityAuth] NFWebCrypto not loaded yet — retrying with RTLD_LAZY");
        nfwc = dlopen("@rpath/NFWebCrypto.framework/NFWebCrypto", RTLD_LAZY);
    }
    if (!nfwc) {
        file_log(g_log_general, @"[NFXEntityAuth] NFWebCrypto not found");
        return;
    }

    file_log(g_log_general, @"[NFXEntityAuth] NFWebCrypto.framework found");

    void *sym = dlsym(nfwc, "HMAC");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HMAC, (void **)&orig_HMAC);
        file_log(g_log_general, @"[NFXEntityAuth] HMAC hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] HMAC symbol not found");
    }

    // Resolve EVP_MD_type for NID lookups in new hooks
    sym = dlsym(nfwc, "EVP_MD_type");
    if (sym) {
        g_EVP_MD_type = (EVP_MD_type_fn)sym;
        file_log(g_log_general, @"[NFXEntityAuth] EVP_MD_type resolved");
    }

    // HMAC_CTX_new
    sym = dlsym(nfwc, "HMAC_CTX_new");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HMAC_CTX_new, (void **)&orig_HMAC_CTX_new);
        file_log(g_log_general, @"[NFXEntityAuth] HMAC_CTX_new hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] HMAC_CTX_new not found");
    }

    // HMAC_Init_ex
    sym = dlsym(nfwc, "HMAC_Init_ex");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HMAC_Init_ex, (void **)&orig_HMAC_Init_ex);
        file_log(g_log_general, @"[NFXEntityAuth] HMAC_Init_ex hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] HMAC_Init_ex not found");
    }

    // HMAC_Update
    sym = dlsym(nfwc, "HMAC_Update");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HMAC_Update, (void **)&orig_HMAC_Update);
        file_log(g_log_general, @"[NFXEntityAuth] HMAC_Update hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] HMAC_Update not found");
    }

    // HMAC_Final
    sym = dlsym(nfwc, "HMAC_Final");
    if (sym) {
        MSHookFunction(sym, (void *)hook_HMAC_Final, (void **)&orig_HMAC_Final);
        file_log(g_log_general, @"[NFXEntityAuth] HMAC_Final hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] HMAC_Final not found");
    }

    // SHA384 one-shot
    sym = dlsym(nfwc, "SHA384");
    if (sym) {
        MSHookFunction(sym, (void *)hook_SHA384, (void **)&orig_SHA384);
        file_log(g_log_general, @"[NFXEntityAuth] SHA384 hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] SHA384 not found");
    }

    // EVP_DigestInit_ex
    sym = dlsym(nfwc, "EVP_DigestInit_ex");
    if (sym) {
        MSHookFunction(sym, (void *)hook_EVP_DigestInit_ex, (void **)&orig_EVP_DigestInit_ex);
        file_log(g_log_general, @"[NFXEntityAuth] EVP_DigestInit_ex hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] EVP_DigestInit_ex not found");
    }

    // EVP_DigestUpdate
    sym = dlsym(nfwc, "EVP_DigestUpdate");
    if (sym) {
        MSHookFunction(sym, (void *)hook_EVP_DigestUpdate, (void **)&orig_EVP_DigestUpdate);
        file_log(g_log_general, @"[NFXEntityAuth] EVP_DigestUpdate hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] EVP_DigestUpdate not found");
    }

    // EVP_DigestFinal_ex
    sym = dlsym(nfwc, "EVP_DigestFinal_ex");
    if (sym) {
        MSHookFunction(sym, (void *)hook_EVP_DigestFinal_ex, (void **)&orig_EVP_DigestFinal_ex);
        file_log(g_log_general, @"[NFXEntityAuth] EVP_DigestFinal_ex hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] EVP_DigestFinal_ex not found");
    }

    // AppleWebCrypto::HKDF at offset 0x11900 in NFWebCrypto image
    // Static analysis confirms this is a single C++ method that does
    // HMAC-SHA256 Extract + Expand and returns shared_ptr<KeyByteArray> via sret.
    // Calling convention (ARM64):
    //   x0=this, x1=ikm_vec*, x2=info_vec*, x3=key_sptr*, x8=output_sptr* (sret)
    // We hook by offset — offset confirmed via r2 afl output for v15.48.1.
    {
        uint32_t imgCount = _dyld_image_count();
        uintptr_t nfwcBase = 0;
        for (uint32_t i = 0; i < imgCount; i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "NFWebCrypto.framework/NFWebCrypto")) {
                nfwcBase = (uintptr_t)_dyld_get_image_header(i);
                file_log(g_log_general,
                         [NSString stringWithFormat:@"[NFXEntityAuth] NFWebCrypto base=0x%lx",
                          (unsigned long)nfwcBase]);
                break;
            }
        }

        if (nfwcBase != 0) {
            // AppleWebCrypto::HKDF at file offset 0x11900
            uintptr_t hkdfAddr = nfwcBase + 0x11900;
            file_log(g_log_general,
                     [NSString stringWithFormat:
                      @"[NFXEntityAuth] AppleWebCrypto::HKDF addr=0x%lx — installing hook",
                      (unsigned long)hkdfAddr]);
            MSHookFunction((void *)hkdfAddr,
                           (void *)hook_AppleWebCryptoHKDF,
                           (void **)&orig_AppleWebCryptoHKDF);
            file_log(g_log_general, @"[NFXEntityAuth] AppleWebCrypto::HKDF hooked");
        } else {
            file_log(g_log_general, @"[NFXEntityAuth] NFWebCrypto base not found — HKDF hook skipped");
        }
    }

    g_nfwcHooked = YES;
}

// ---------------------------------------------------------------------------
// NSData hook installer (global — no framework needed)
// ---------------------------------------------------------------------------

static void installNSDataHooks(void) {
    Class nsDataClass = [NSData class];
    SEL sel = @selector(dataWithContentsOfFile:);
    Method m = class_getClassMethod(nsDataClass, sel);
    if (m) {
        // Hook the class method via MSHookMessageEx on the metaclass
        MSHookMessageEx(object_getClass(nsDataClass),
                        sel,
                        (IMP)hook_dataWithContentsOfFile,
                        (IMP *)&orig_dataWithContentsOfFile);
        file_log(g_log_general, @"[NFXEntityAuth] NSData dataWithContentsOfFile: hooked");
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] NSData dataWithContentsOfFile: method not found");
    }
}

// ---------------------------------------------------------------------------
// Retry installer — polls for frameworks not yet loaded at constructor time
// ---------------------------------------------------------------------------

static void retryInstallHooks(void) {
    if (!g_nfwcHooked)  installNFWebCryptoHooks();
    if (!g_mslHooked)   installMslClientHooks();
    if (!g_nbpHooked)   installNbpHooks();

    BOOL allDone = g_nfwcHooked && g_mslHooked && g_nbpHooked;
    if (!allDone) {
        // Retry again after 2 seconds
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            retryInstallHooks();
        });
    } else {
        file_log(g_log_general, @"[NFXEntityAuth] All hooks installed");
    }
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

__attribute__((constructor)) static void init(void) {
    orion_init();

    g_log_entity  = os_log_create("com.netflix.entityauth", "entity");
    g_log_hmac    = os_log_create("com.netflix.entityauth", "hmac");
    g_log_general = os_log_create("com.netflix.entityauth", "general");

    // Primary log in sandboxed tmp (always writable by mobile user)
    g_logFile = [NSTemporaryDirectory()
                 stringByAppendingPathComponent:@"entityauth_capture.log"];
    // Secondary log in /var/tmp (accessible by root for easy retrieval)
    g_logFile2 = @"/var/tmp/entityauth_capture.log";

    file_log(g_log_general, @"=== NetflixEntityAuth loaded ===");

    // Install NSData hook immediately (Foundation is always loaded)
    installNSDataHooks();

    // Attempt immediate hook install for frameworks that may already be loaded
    installNFWebCryptoHooks();
    installMslClientHooks();
    installNbpHooks();

    // Schedule retries for frameworks that load after us
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        retryInstallHooks();
    });

    file_log(g_log_general, @"=== NetflixEntityAuth constructor done ===");
}
