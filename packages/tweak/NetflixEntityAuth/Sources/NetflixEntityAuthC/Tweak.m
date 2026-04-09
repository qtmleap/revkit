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
// HOOK 2: NSData dataWithContentsOfFile: — catch large file reads (4-10 KB)
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
// IosMGKAuthenticationData constructor (offset 0x0000d45c):
//   x0: self
//   x1: identity (NSString* — ESN)
//   x2: appid (NSString*)
//   x3: appkeyversion (int64)
//   x4: apphmac (NSString* — base64)
//   x5: shared_ptr<AppleWebCrypto>  (ignored)
//
// We hook via MSHookFunction using the resolved symbol address.
// ---------------------------------------------------------------------------

// ARM64 calling convention: ObjC id args are in x0..x7 registers.
// The constructor is a plain C++ function (not ObjC method), so we model
// it as a plain C function pointer with the matching argument layout.

typedef void (*IosMGKAuthData_ctor_t)(id self,
                                      NSString *identity,
                                      NSString *appid,
                                      int64_t appkeyversion,
                                      NSString *apphmac,
                                      void *webcrypto_ptr);

static IosMGKAuthData_ctor_t orig_IosMGKAuthData_ctor = NULL;

static void hook_IosMGKAuthData_ctor(id self,
                                      NSString *identity,
                                      NSString *appid,
                                      int64_t appkeyversion,
                                      NSString *apphmac,
                                      void *webcrypto_ptr) {
    // Call original first
    if (orig_IosMGKAuthData_ctor) {
        orig_IosMGKAuthData_ctor(self, identity, appid, appkeyversion, apphmac, webcrypto_ptr);
    }

    if (!g_inHook) {
        g_inHook = 1;

        file_log(g_log_entity,
                 [NSString stringWithFormat:
                  @"[NFXEntityAuth][IosMGKAuthData] identity=%@ appid=%@ appkeyversion=%lld apphmac=%@",
                  identity ?: @"(nil)", appid ?: @"(nil)", appkeyversion, apphmac ?: @"(nil)"]);

        NSString *tmpDir = NSTemporaryDirectory();
        // Write identity (ESN) to file
        if (identity) {
            [identity writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_identity.txt"]
                       atomically:YES
                         encoding:NSUTF8StringEncoding
                            error:nil];
        }
        // Write appid to file
        if (appid) {
            [appid writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_appid.txt"]
                    atomically:YES
                      encoding:NSUTF8StringEncoding
                         error:nil];
        }
        // Write appkeyversion
        NSString *akvStr = [NSString stringWithFormat:@"%lld", appkeyversion];
        [akvStr writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_appkeyversion.txt"]
                 atomically:YES
                   encoding:NSUTF8StringEncoding
                      error:nil];
        // Write apphmac base64
        if (apphmac) {
            [apphmac writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_apphmac_b64.txt"]
                      atomically:YES
                        encoding:NSUTF8StringEncoding
                           error:nil];
            // Decode base64 and save raw bytes
            NSData *hmacData = [[NSData alloc] initWithBase64EncodedString:apphmac options:0];
            if (hmacData) {
                [hmacData writeToFile:[tmpDir stringByAppendingPathComponent:@"entityauth_apphmac_raw.bin"]
                           atomically:YES];
                file_log(g_log_entity,
                         [NSString stringWithFormat:@"[NFXEntityAuth][IosMGKAuthData] apphmac_raw(%luB)=%@",
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

    // IosMGKAuthenticationData constructor offset 0x0000d45c
    // Note: on arm64 with ASLR the actual address = base + slide + text_offset
    // _dyld_get_image_header returns the load address (includes ASLR slide).
    // For a __TEXT segment starting at offset 0, the load address IS the base.
    // The offset 0xd45c is from the start of the binary (Mach-O header), which
    // equals the load address for arm64 dylibs.
    uintptr_t ctorAddr = mslBase + 0xd45c;
    file_log(g_log_general,
             [NSString stringWithFormat:@"[NFXEntityAuth] IosMGKAuthData ctor addr=0x%lx",
              (unsigned long)ctorAddr]);

    MSHookFunction((void *)ctorAddr,
                   (void *)hook_IosMGKAuthData_ctor,
                   (void **)&orig_IosMGKAuthData_ctor);
    file_log(g_log_general, @"[NFXEntityAuth] IosMGKAuthData ctor hooked");

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
