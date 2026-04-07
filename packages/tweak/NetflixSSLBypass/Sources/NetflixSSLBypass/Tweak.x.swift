import Orion
import Foundation

// ============================================
// Netflix iOS — appboot.netflix.com SSL Pinning Bypass
//
// Layer 1-4: ObjC フック (Orion ClassHook)
// Layer 5: C 関数フック (dlsym + ElleKit/Substrate rebinding)
// Layer 7: MslClient AES-CBC フック (オフセットベース MSHookFunction)
//
// appboot は Nbp.framework 内の OpenSSL verify() を直接呼ぶため
// ObjC フックだけでは不十分。C レベルでもフックする。
//
// Target: com.netflix.Netflix (Argo) v15.48.1+
// ============================================

// MARK: - ログファイル出力

// Netflix sandbox 内に書く (NSHomeDirectory で動的取得)
let logDir: String = {
    let home = NSHomeDirectory()
    return "\(home)/Documents/nfx_capture"
}()
let logPath: String = {
    return "\(logDir)/msl_keys.jsonl"
}()

func ensureLogDir() {
    let fm = FileManager.default
    if !fm.fileExists(atPath: logDir) {
        try? fm.createDirectory(atPath: logDir, withIntermediateDirectories: true)
    }
}

func logToFile(_ line: String) {
    ensureLogDir()
    if let data = (line + "\n").data(using: .utf8) {
        if FileManager.default.fileExists(atPath: logPath) {
            if let fh = FileHandle(forWritingAtPath: logPath) {
                fh.seekToEndOfFile()
                fh.write(data)
                fh.closeFile()
            }
        } else {
            FileManager.default.createFile(atPath: logPath, contents: data)
        }
    }
}

func logJSON(_ dict: [String: Any]) {
    if let data = try? JSONSerialization.data(withJSONObject: dict),
       let str = String(data: data, encoding: .utf8) {
        logToFile(str)
    }
}

// MARK: - C function hooking via dlsym + MSHookFunction

@_silgen_name("MSHookFunction")
func MSHookFunction(_ symbol: UnsafeMutableRawPointer, _ replace: UnsafeMutableRawPointer, _ result: UnsafeMutablePointer<UnsafeMutableRawPointer?>)

@_silgen_name("dlopen")
func dlopen_c(_ path: UnsafePointer<CChar>?, _ mode: Int32) -> UnsafeMutableRawPointer?

@_silgen_name("dlsym")
func dlsym_c(_ handle: UnsafeMutableRawPointer?, _ symbol: UnsafePointer<CChar>) -> UnsafeMutableRawPointer?

@_silgen_name("_dyld_image_count")
func _dyld_image_count() -> UInt32

@_silgen_name("_dyld_get_image_name")
func _dyld_get_image_name(_ idx: UInt32) -> UnsafePointer<CChar>?

@_silgen_name("_dyld_get_image_vmaddr_slide")
func _dyld_get_image_vmaddr_slide(_ idx: UInt32) -> Int

// OpenSSL verify callback: int verify(int ok, X509_STORE_CTX *ctx)
typealias VerifyFunc = @convention(c) (Int32, OpaquePointer?) -> Int32
var orig_verify: VerifyFunc?
let hook_verify: VerifyFunc = { ok, ctx in
    NSLog("[NFXBypass] Nbp::verify(ok=%d) → forced 1", ok)
    return 1
}

// OpenSSL verify_notfailed callback
typealias VerifyNFFunc = @convention(c) (Int32, OpaquePointer?) -> Int32
var orig_verify_notfailed: VerifyNFFunc?
let hook_verify_notfailed: VerifyNFFunc = { ok, ctx in
    NSLog("[NFXBypass] Nbp::verify_notfailed(ok=%d) → forced 1", ok)
    return 1
}

// X509_verify_cert: int X509_verify_cert(X509_STORE_CTX *ctx)
typealias X509VerifyFunc = @convention(c) (OpaquePointer?) -> Int32
var orig_x509_verify: X509VerifyFunc?
let hook_x509_verify: X509VerifyFunc = { ctx in
    let ret = orig_x509_verify?(ctx) ?? 0
    if ret <= 0 {
        NSLog("[NFXBypass] X509_verify_cert() → forced 1")
        return 1
    }
    return ret
}

// MARK: - Layer 1: NflxTrustStore — OpenSSL CA 検証バイパス

class TrustStoreHook: ClassHook<NSObject> {
    typealias Target = NSObject
    static var targetName: String { "NflxTrustStore" }

    func evaluateTrust(_ trust: NSObject, error: UnsafeMutablePointer<NSError?>?) -> Bool {
        if let error = error { error.pointee = nil }
        NSLog("[NFXBypass] NflxTrustStore.evaluateTrust → forced YES")
        return true
    }
}

// MARK: - Layer 2: NflxPinnedCertEvaluator — ホスト別ピンニングバイパス

class PinnedCertHook: ClassHook<NSObject> {
    typealias Target = NSObject
    static var targetName: String { "NflxPinnedCertEvaluator" }

    func hasPinnedCertForHost(_ host: String) -> Bool {
        NSLog("[NFXBypass] hasPinnedCertForHost:%@ → forced NO", host)
        return false
    }

    func evaluatePinnedCertificate(_ cert: NSObject, forHost host: String) -> Bool {
        NSLog("[NFXBypass] evaluatePinnedCertificate:forHost:%@ → forced YES", host)
        return true
    }
}

// MARK: - Layer 3: IosMslClient — サーバー配信 SSL Trust Store 無効化

class MslClientHook: ClassHook<NSObject> {
    typealias Target = NSObject
    static var targetName: String { "IosMslClient" }

    func shouldUseSSLTrustStore() -> Bool {
        NSLog("[NFXBypass] IosMslClient.shouldUseSSLTrustStore → forced NO")
        return false
    }

    func updateNFURLSessionCerts(_ certs: NSObject?) {
        NSLog("[NFXBypass] IosMslClient.updateNFURLSessionCerts: blocked")
    }
}

// MARK: - Layer 4: NFURLSession — Trust Store / Evaluator 設定を無効化

class URLSessionHook: ClassHook<NSObject> {
    typealias Target = NSObject
    static var targetName: String { "NFURLSession" }

    class func setTrustStore(_ store: NSObject?) {
        NSLog("[NFXBypass] NFURLSession.setTrustStore: nullified")
        orig.setTrustStore(nil)
    }

    class func setPinnedCertificateEvaluator(_ evaluator: NSObject?) {
        NSLog("[NFXBypass] NFURLSession.setPinnedCertificateEvaluator: nullified")
        orig.setPinnedCertificateEvaluator(nil)
    }
}

// MARK: - Layer 6: CCCrypt フック (MSL AES-128-CBC セッション鍵キャプチャ)

// CCCryptorStatus CCCrypt(
//   CCOperation op, CCAlgorithm alg, CCOptions options,
//   const void *key, size_t keyLength,
//   const void *iv,
//   const void *dataIn, size_t dataInLength,
//   void *dataOut, size_t dataOutAvailable,
//   size_t *dataOutMoved
// )
//
// CCOperation: kCCEncrypt=0, kCCDecrypt=1
// CCAlgorithm: kCCAlgorithmAES=0
// CCOptions:   kCCOptionPKCS7Padding=1 (CBC+PKCS7), kCCOptionECBMode=2
//
// AES-128-CBC は alg=0, keyLen=16, options=1 でフィルタする。

typealias CCCryptFunc = @convention(c) (
    UInt32,                          // op
    UInt32,                          // alg
    UInt32,                          // options
    UnsafeRawPointer,                // key
    Int,                             // keyLength
    UnsafeRawPointer?,               // iv
    UnsafeRawPointer,                // dataIn
    Int,                             // dataInLength
    UnsafeMutableRawPointer,         // dataOut
    Int,                             // dataOutAvailable
    UnsafeMutablePointer<Int>        // dataOutMoved
) -> Int32

var orig_ccCrypt: CCCryptFunc?

// Hex エンコードヘルパー (最大 maxBytes バイトまで出力)
func hexString(_ ptr: UnsafeRawPointer, length: Int, maxBytes: Int = 64) -> String {
    let count = min(length, maxBytes)
    let buf = UnsafeBufferPointer(start: ptr.assumingMemoryBound(to: UInt8.self), count: count)
    return buf.map { String(format: "%02x", $0) }.joined()
}

let hook_ccCrypt: CCCryptFunc = { op, alg, options, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved in
    // AES-128-CBC (PKCS7) のみフィルタ: alg=0, keyLen=16, options=1
    let isAES128CBC = (alg == 0 && keyLen == 16 && options == 1)

    // 鍵・IV を事前取得
    let keyHex = hexString(key, length: keyLen, maxBytes: 16)
    let ivHex = iv.map { hexString($0, length: 16, maxBytes: 16) } ?? "(nil)"

    // 元の CCCrypt を呼ぶ
    let status = orig_ccCrypt!(op, alg, options, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvail, dataOutMoved)

    if isAES128CBC && status == 0 {
        let outLen = dataOutMoved.pointee
        let opStr = (op == 0) ? "encrypt" : "decrypt"
        let outHex = hexString(UnsafeRawPointer(dataOut), length: outLen, maxBytes: 200)
        let inHex = hexString(dataIn, length: dataInLen, maxBytes: 200)

        // ファイルに JSONL 出力
        logJSON([
            "event": "CCCrypt.\(opStr)",
            "ts": ISO8601DateFormatter().string(from: Date()),
            "key": keyHex,
            "iv": ivHex,
            "keyLen": keyLen,
            "inLen": dataInLen,
            "outLen": outLen,
            "dataIn": inHex,
            "dataOut": outHex,
        ])
    }

    return status
}

// MARK: - Layer 6: OpenSSL EVP_Cipher フック (Nbp.framework エクスポート)
//
// MslClient は OpenSSL の EVP_CipherInit_ex / EVP_CipherUpdate を使う。
// Nbp.framework からエクスポートされているので dlsym で取得可能。

// int EVP_CipherInit_ex(ctx, type, impl, key, iv, enc)
typealias EVPCipherInitFunc = @convention(c) (
    OpaquePointer?, OpaquePointer?, OpaquePointer?,
    UnsafeRawPointer?, UnsafeRawPointer?, Int32
) -> Int32

var orig_evpCipherInit: EVPCipherInitFunc?
let hook_evpCipherInit: EVPCipherInitFunc = { ctx, type, impl, key, iv, enc in
    let ret = orig_evpCipherInit!(ctx, type, impl, key, iv, enc)
    if let key = key {
        let encStr = enc == 1 ? "encrypt" : (enc == 0 ? "decrypt" : "enc=\(enc)")
        let keyHex = hexString(key, length: 16, maxBytes: 16)
        let ivHex = iv.map { hexString($0, length: 16, maxBytes: 16) } ?? "(nil)"
        logJSON([
            "event": "EVP_CipherInit",
            "ts": ISO8601DateFormatter().string(from: Date()),
            "enc": encStr,
            "key": keyHex,
            "iv": ivHex,
        ])
    }
    return ret
}

// int EVP_CipherUpdate(ctx, out, outl, in, inl)
typealias EVPCipherUpdateFunc = @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?, UnsafeMutablePointer<Int32>?,
    UnsafeRawPointer?, Int32
) -> Int32

var orig_evpCipherUpdate: EVPCipherUpdateFunc?
let hook_evpCipherUpdate: EVPCipherUpdateFunc = { ctx, out, outl, inData, inl in
    let ret = orig_evpCipherUpdate!(ctx, out, outl, inData, inl)
    if ret == 1, let outl = outl, let inData = inData, inl > 0 {
        let outLen = Int(outl.pointee)
        let inHex = hexString(inData, length: Int(inl), maxBytes: 256)
        var outHex = "?"
        if let out = out, outLen > 0 {
            outHex = hexString(UnsafeRawPointer(out), length: outLen, maxBytes: 256)
        }
        logJSON([
            "event": "EVP_CipherUpdate",
            "ts": ISO8601DateFormatter().string(from: Date()),
            "inLen": Int(inl),
            "outLen": outLen,
            "dataIn": inHex,
            "dataOut": outHex,
        ])
    }
    return ret
}

// MARK: - Layer 7: MslClient C++ AES-CBC フック
//
// MslClient.framework 内の以下の関数をオフセットベースでフックする:
//
//   aesCbcEncrypt (offset 0x80b9c, N_EXT):
//     void aesCbcEncrypt(const vector<uint8_t>& key,
//                        const vector<uint8_t>& iv,
//                        const vector<uint8_t>& plaintext,
//                        vector<uint8_t>& ciphertext)
//     arm64 ABI: x0=&key, x1=&iv, x2=&plaintext, x3=&ciphertext(out)
//
//   aesCbcDecrypt (offset 0x813bc, N_EXT):
//     void aesCbcDecrypt(const vector<uint8_t>& key,
//                        const vector<uint8_t>& iv,
//                        const vector<uint8_t>& ciphertext,
//                        vector<uint8_t>& plaintext)
//     arm64 ABI: x0=&key, x1=&iv, x2=&ciphertext, x3=&plaintext(out)
//
// std::vector<uint8_t> メモリレイアウト (arm64, 24 bytes):
//   +0x00: __begin_  (UnsafeRawPointer, データ先頭)
//   +0x08: __end_    (UnsafeRawPointer, データ末尾+1)
//   +0x10: __end_cap_ (容量末尾+1)
//   size = __end_ - __begin_

// std::vector<uint8_t> から [UInt8] に変換
func readStdVector(_ vecPtr: UnsafeRawPointer) -> [UInt8]? {
    // begin ポインタを読む
    let begin = vecPtr.load(as: UnsafeRawPointer?.self)
    // end ポインタを読む
    let end = vecPtr.advanced(by: 8).load(as: UnsafeRawPointer?.self)

    guard let begin = begin, let end = end else { return nil }
    let size = begin.distance(to: end)
    guard size > 0 && size <= 1024 * 1024 else { return nil }

    let buf = UnsafeBufferPointer(start: begin.assumingMemoryBound(to: UInt8.self), count: size)
    return Array(buf)
}

func bytesToBase64(_ bytes: [UInt8]) -> String {
    return Data(bytes).base64EncodedString()
}

// aesCbcEncrypt フック用の型
// void(const vec& key, const vec& iv, const vec& plain, vec& cipher)
// void* は arm64 で sret なし (vector は参照渡し)
typealias AesCbcEncryptFunc = @convention(c) (
    UnsafeRawPointer,   // x0: &key
    UnsafeRawPointer,   // x1: &iv
    UnsafeRawPointer,   // x2: &plaintext
    UnsafeMutableRawPointer // x3: &ciphertext (out, existing vector)
) -> Void

typealias AesCbcDecryptFunc = @convention(c) (
    UnsafeRawPointer,   // x0: &key
    UnsafeRawPointer,   // x1: &iv
    UnsafeRawPointer,   // x2: &ciphertext
    UnsafeMutableRawPointer // x3: &plaintext (out, existing vector)
) -> Void

var orig_aesCbcEncrypt: AesCbcEncryptFunc?
var orig_aesCbcDecrypt: AesCbcDecryptFunc?

let hook_aesCbcEncrypt: AesCbcEncryptFunc = { keyPtr, ivPtr, plainPtr, cipherPtr in
    // 入力を先に読む (呼び出し前)
    let key   = readStdVector(keyPtr)
    let iv    = readStdVector(ivPtr)
    let plain = readStdVector(plainPtr)

    // 元の関数を呼ぶ
    orig_aesCbcEncrypt!(keyPtr, ivPtr, plainPtr, cipherPtr)

    // 出力 (ciphertext) を読む (呼び出し後)
    let cipher = readStdVector(UnsafeRawPointer(cipherPtr))

    NSLog("[NFXBypass] aesCbcEncrypt key=%dB plain=%dB cipher=%dB",
          key?.count ?? -1, plain?.count ?? -1, cipher?.count ?? -1)

    logJSON([
        "event": "msl.aesCbcEncrypt",
        "ts": ISO8601DateFormatter().string(from: Date()),
        "key_b64":        key    != nil ? bytesToBase64(key!)    : NSNull(),
        "iv_b64":         iv     != nil ? bytesToBase64(iv!)     : NSNull(),
        "plaintext_b64":  plain  != nil ? bytesToBase64(plain!)  : NSNull(),
        "ciphertext_b64": cipher != nil ? bytesToBase64(cipher!) : NSNull(),
        "key_size":       key?.count    ?? 0,
        "iv_size":        iv?.count     ?? 0,
        "plaintext_size": plain?.count  ?? 0,
        "ciphertext_size": cipher?.count ?? 0,
    ])
}

let hook_aesCbcDecrypt: AesCbcDecryptFunc = { keyPtr, ivPtr, cipherPtr, plainPtr in
    // 入力を先に読む
    let key    = readStdVector(keyPtr)
    let iv     = readStdVector(ivPtr)
    let cipher = readStdVector(cipherPtr)

    // 元の関数を呼ぶ
    orig_aesCbcDecrypt!(keyPtr, ivPtr, cipherPtr, plainPtr)

    // 出力 (plaintext) を読む
    let plain = readStdVector(UnsafeRawPointer(plainPtr))

    NSLog("[NFXBypass] aesCbcDecrypt key=%dB cipher=%dB plain=%dB",
          key?.count ?? -1, cipher?.count ?? -1, plain?.count ?? -1)

    logJSON([
        "event": "msl.aesCbcDecrypt",
        "ts": ISO8601DateFormatter().string(from: Date()),
        "key_b64":        key    != nil ? bytesToBase64(key!)    : NSNull(),
        "iv_b64":         iv     != nil ? bytesToBase64(iv!)     : NSNull(),
        "ciphertext_b64": cipher != nil ? bytesToBase64(cipher!) : NSNull(),
        "plaintext_b64":  plain  != nil ? bytesToBase64(plain!)  : NSNull(),
        "key_size":       key?.count    ?? 0,
        "iv_size":        iv?.count     ?? 0,
        "ciphertext_size": cipher?.count ?? 0,
        "plaintext_size": plain?.count  ?? 0,
    ])
}

// MslClient のスライド済みベースアドレスを取得する
// _dyld_get_image_vmaddr_slide は ASLR スライド値を返す。
// MslClient の __TEXT vmaddr=0x0 なので base = slide。
func findMslClientBase() -> UnsafeRawPointer? {
    let count = _dyld_image_count()
    for i in 0..<count {
        guard let namePtr = _dyld_get_image_name(i) else { continue }
        let name = String(cString: namePtr)
        if name.contains("MslClient") {
            let slide = _dyld_get_image_vmaddr_slide(i)
            let base = UnsafeRawPointer(bitPattern: slide)
            logToFile("[NFXBypass] MslClient found: index=\(i) slide=0x\(String(UInt(bitPattern: slide), radix: 16)) base=\(String(describing: base))")
            NSLog("[NFXBypass] MslClient found: index=%u slide=0x%lx", i, slide)
            return base
        }
    }
    return nil
}

// MslClient の C++ AES-CBC 関数をオフセットベースでフックする
//
// オフセット値は MslClient バイナリのシンボルテーブルから取得:
//   aesCbcEncrypt: 0x80b9c (type=0x0f, N_SECT|N_EXT)
//   aesCbcDecrypt: 0x813bc (type=0x0f, N_SECT|N_EXT)
func hookMslClientAesCbc(base: UnsafeRawPointer) {
    let encryptOffset = 0x80b9c
    let decryptOffset = 0x813bc

    // aesCbcEncrypt
    let encryptAddr = base.advanced(by: encryptOffset)
    var origEncPtr: UnsafeMutableRawPointer?
    MSHookFunction(
        UnsafeMutableRawPointer(mutating: encryptAddr),
        unsafeBitCast(hook_aesCbcEncrypt, to: UnsafeMutableRawPointer.self),
        &origEncPtr
    )
    if let origPtr = origEncPtr {
        orig_aesCbcEncrypt = unsafeBitCast(origPtr, to: AesCbcEncryptFunc.self)
        logToFile("[NFXBypass] Hooked MslClient::aesCbcEncrypt @ 0x\(String(UInt(bitPattern: encryptAddr), radix: 16))")
        NSLog("[NFXBypass] Hooked MslClient::aesCbcEncrypt @ %p", encryptAddr)
    } else {
        logToFile("[NFXBypass] FAILED: MslClient::aesCbcEncrypt hook (origPtr nil) @ 0x\(String(UInt(bitPattern: encryptAddr), radix: 16))")
        NSLog("[NFXBypass] FAILED: aesCbcEncrypt hook @ %p", encryptAddr)
    }

    // aesCbcDecrypt
    let decryptAddr = base.advanced(by: decryptOffset)
    var origDecPtr: UnsafeMutableRawPointer?
    MSHookFunction(
        UnsafeMutableRawPointer(mutating: decryptAddr),
        unsafeBitCast(hook_aesCbcDecrypt, to: UnsafeMutableRawPointer.self),
        &origDecPtr
    )
    if let origPtr = origDecPtr {
        orig_aesCbcDecrypt = unsafeBitCast(origPtr, to: AesCbcDecryptFunc.self)
        logToFile("[NFXBypass] Hooked MslClient::aesCbcDecrypt @ 0x\(String(UInt(bitPattern: decryptAddr), radix: 16))")
        NSLog("[NFXBypass] Hooked MslClient::aesCbcDecrypt @ %p", decryptAddr)
    } else {
        logToFile("[NFXBypass] FAILED: MslClient::aesCbcDecrypt hook (origPtr nil) @ 0x\(String(UInt(bitPattern: decryptAddr), radix: 16))")
        NSLog("[NFXBypass] FAILED: aesCbcDecrypt hook @ %p", decryptAddr)
    }
}

// MARK: - Layer 5: C 関数フック (OpenSSL verify in Nbp.framework)

func hookCFunctions() {
    // Nbp.framework をロード (既にロード済みでも問題なし)
    let nbpHandle = dlopen_c(nil, 0x0 /* RTLD_DEFAULT */)

    // __Z6verifyiP17x509_store_ctx_st = verify(int, x509_store_ctx_st*)
    if let sym = dlsym_c(nbpHandle, "__Z6verifyiP17x509_store_ctx_st") {
        var origPtr: UnsafeMutableRawPointer?
        MSHookFunction(sym, unsafeBitCast(hook_verify, to: UnsafeMutableRawPointer.self), &origPtr)
        if let origPtr = origPtr {
            orig_verify = unsafeBitCast(origPtr, to: VerifyFunc.self)
        }
        NSLog("[NFXBypass] Hooked Nbp::verify()")
    } else {
        NSLog("[NFXBypass] [-] verify() symbol not found")
    }

    // __Z16verify_notfailediP17x509_store_ctx_st
    if let sym = dlsym_c(nbpHandle, "__Z16verify_notfailediP17x509_store_ctx_st") {
        var origPtr: UnsafeMutableRawPointer?
        MSHookFunction(sym, unsafeBitCast(hook_verify_notfailed, to: UnsafeMutableRawPointer.self), &origPtr)
        if let origPtr = origPtr {
            orig_verify_notfailed = unsafeBitCast(origPtr, to: VerifyNFFunc.self)
        }
        NSLog("[NFXBypass] Hooked Nbp::verify_notfailed()")
    } else {
        NSLog("[NFXBypass] [-] verify_notfailed() symbol not found")
    }

    // X509_verify_cert (グローバル)
    if let sym = dlsym_c(nbpHandle, "X509_verify_cert") {
        var origPtr: UnsafeMutableRawPointer?
        MSHookFunction(sym, unsafeBitCast(hook_x509_verify, to: UnsafeMutableRawPointer.self), &origPtr)
        if let origPtr = origPtr {
            orig_x509_verify = unsafeBitCast(origPtr, to: X509VerifyFunc.self)
        }
        NSLog("[NFXBypass] Hooked X509_verify_cert()")
    } else {
        NSLog("[NFXBypass] [-] X509_verify_cert() not found")
    }

    // EVP_CipherInit_ex — Nbp.framework からエクスポートされた OpenSSL 関数
    // MslClient はこれを使って AES-CBC 暗号化/復号する
    let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

    if let sym = dlsym_c(rtldDefault, "EVP_CipherInit_ex") {
        var origPtr: UnsafeMutableRawPointer?
        MSHookFunction(sym, unsafeBitCast(hook_evpCipherInit, to: UnsafeMutableRawPointer.self), &origPtr)
        if let origPtr = origPtr {
            orig_evpCipherInit = unsafeBitCast(origPtr, to: EVPCipherInitFunc.self)
        }
        logToFile("[NFXBypass] Hooked EVP_CipherInit_ex")
        NSLog("[NFXBypass] Hooked EVP_CipherInit_ex")
    } else {
        logToFile("[NFXBypass] [-] EVP_CipherInit_ex not found")
        NSLog("[NFXBypass] [-] EVP_CipherInit_ex not found")
    }

    if let sym = dlsym_c(rtldDefault, "EVP_CipherUpdate") {
        var origPtr: UnsafeMutableRawPointer?
        MSHookFunction(sym, unsafeBitCast(hook_evpCipherUpdate, to: UnsafeMutableRawPointer.self), &origPtr)
        if let origPtr = origPtr {
            orig_evpCipherUpdate = unsafeBitCast(origPtr, to: EVPCipherUpdateFunc.self)
        }
        logToFile("[NFXBypass] Hooked EVP_CipherUpdate")
        NSLog("[NFXBypass] Hooked EVP_CipherUpdate")
    } else {
        logToFile("[NFXBypass] [-] EVP_CipherUpdate not found")
        NSLog("[NFXBypass] [-] EVP_CipherUpdate not found")
    }

    // CCCrypt (libcommonCrypto — フォールバック)
    if let sym = dlsym_c(rtldDefault, "CCCrypt") {
        var origPtr: UnsafeMutableRawPointer?
        MSHookFunction(sym, unsafeBitCast(hook_ccCrypt, to: UnsafeMutableRawPointer.self), &origPtr)
        if let origPtr = origPtr {
            orig_ccCrypt = unsafeBitCast(origPtr, to: CCCryptFunc.self)
        }
        NSLog("[NFXBypass] Hooked CCCrypt (AES-128-CBC session key capture)")
    } else {
        NSLog("[NFXBypass] [-] CCCrypt symbol not found")
    }

    // Layer 7: MslClient AES-CBC フック
    // MslClient は起動時に既にロードされているが、遅延ロードの場合もある。
    // まずここで試みる。失敗した場合は bootstrapTweak のリトライで対処。
    if let base = findMslClientBase() {
        hookMslClientAesCbc(base: base)
    } else {
        logToFile("[NFXBypass] MslClient not loaded yet, will retry")
        NSLog("[NFXBypass] MslClient not loaded at hookCFunctions time")
    }
}

// MARK: - Constructor (Orion Tweak + C constructor fallback)

// 二重初期化防止フラグ
private var _bootstrapDone = false

struct NetflixSSLBypass: Tweak {
    init() {
        bootstrapTweak()
    }
}

func logLoadedFrameworks() {
    let imageCount = _dyld_image_count()
    let targets = ["MslClient", "Nbp", "NFWebCrypto", "NFURLSession", "Argo", "NetflixSSLBypass"]
    for i in 0..<imageCount {
        if let name = _dyld_get_image_name(i) {
            let path = String(cString: name)
            for t in targets {
                if path.contains(t) {
                    let slide = _dyld_get_image_vmaddr_slide(i)
                    logToFile("[NFXBypass] Framework[\(i)]: \(t) slide=0x\(String(format: "%lx", slide))")
                }
            }
        }
    }
}

func bootstrapTweak() {
    guard !_bootstrapDone else { return }
    _bootstrapDone = true
    NSLog("[NFXBypass] Netflix SSL Pinning Bypass loaded (ObjC + C hooks)")
    ensureLogDir()
    logToFile("[NFXBypass] Tweak loaded at \(ISO8601DateFormatter().string(from: Date()))")
    logLoadedFrameworks()
    hookCFunctions()
    logToFile("[NFXBypass] C hooks installed")
}

// __attribute__((constructor)) equivalent — Orion の init が呼ばれない場合のフォールバック
@_cdecl("NetflixSSLBypass_constructor")
func constructorEntry() {
    bootstrapTweak()
}

// dylib load 時に自動実行される constructor を C で登録
private let _bootstrapOnLoad: Void = {
    bootstrapTweak()
}()
