"""lldb Python plugin: BoringSSL RSA_sign breakpoint handler.

lldb にインポートされ、RSA_sign のブレークポイント時に
RSA 構造体から秘密鍵コンポーネントを読み取る。
"""

import lldb
import struct
import json
import os

OUTPUT_DIR = os.environ.get("RSA_DUMP_DIR", "/tmp/rsa_dump")
dump_count = 0


def read_mem(process, addr, size):
    error = lldb.SBError()
    data = process.ReadMemory(addr, size, error)
    if error.Success():
        return data
    return None


def read_ptr(process, addr):
    data = read_mem(process, addr, 8)
    if data:
        return struct.unpack("<Q", data)[0]
    return None


def read_bignum(process, bn_ptr):
    """BoringSSL BIGNUM: { BN_ULONG *d; int width; ... }"""
    if not bn_ptr or bn_ptr == 0:
        return None
    d_ptr = read_ptr(process, bn_ptr)
    width_data = read_mem(process, bn_ptr + 8, 4)
    if not d_ptr or not width_data:
        return None
    width = struct.unpack("<I", width_data)[0]
    if width <= 0 or width > 128:
        return None
    bn_data = read_mem(process, d_ptr, width * 8)
    if not bn_data:
        return None
    value = 0
    for i in range(width):
        word = struct.unpack("<Q", bn_data[i * 8 : (i + 1) * 8])[0]
        value |= word << (i * 64)
    return value


def on_rsa_sign_hit(frame, bp_loc, internal_dict):
    """RSA_sign breakpoint callback."""
    global dump_count
    dump_count += 1

    thread = frame.GetThread()
    process = thread.GetProcess()

    # arm64 calling convention: RSA_sign の第6引数 = x5 = RSA*
    rsa_ptr = frame.FindRegister("x5").GetValueAsUnsigned()

    if not rsa_ptr:
        print("[dump_rsa] #%d RSA_sign hit but x5=NULL" % dump_count)
        return False

    print("[dump_rsa] #%d RSA_sign hit, RSA* = 0x%x" % (dump_count, rsa_ptr))

    # BoringSSL RSA struct layout (arm64):
    #   +0x00: CRYPTO_refcount_t
    #   +0x08: BIGNUM *n
    #   +0x10: BIGNUM *e
    #   +0x18: BIGNUM *d
    #   +0x20: BIGNUM *p
    #   +0x28: BIGNUM *q
    n_bn = read_ptr(process, rsa_ptr + 0x08)
    e_bn = read_ptr(process, rsa_ptr + 0x10)
    d_bn = read_ptr(process, rsa_ptr + 0x18)
    p_bn = read_ptr(process, rsa_ptr + 0x20)
    q_bn = read_ptr(process, rsa_ptr + 0x28)

    n = read_bignum(process, n_bn)
    e = read_bignum(process, e_bn)
    d = read_bignum(process, d_bn)
    p = read_bignum(process, p_bn)
    q = read_bignum(process, q_bn)

    if n and e:
        print("  n = %d bits, e = %d" % (n.bit_length(), e))
        if d:
            print("  d = %d bits" % d.bit_length())
        if p:
            print("  p = %d bits" % p.bit_length())
        if q:
            print("  q = %d bits" % q.bit_length())

        result = {
            "dump": dump_count,
            "rsa_ptr": hex(rsa_ptr),
            "key_bits": n.bit_length(),
            "n": hex(n),
            "e": e,
        }
        if d:
            result["d"] = hex(d)
        if p:
            result["p"] = hex(p)
        if q:
            result["q"] = hex(q)

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        out_path = os.path.join(OUTPUT_DIR, "rsa_dump_%d.json" % dump_count)
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print("  Saved: %s" % out_path)

        if d and p and q:
            try:
                from cryptography.hazmat.primitives.asymmetric.rsa import (
                    RSAPrivateNumbers,
                    RSAPublicNumbers,
                    rsa_crt_dmp1,
                    rsa_crt_dmq1,
                    rsa_crt_iqmp,
                )
                from cryptography.hazmat.primitives.serialization import (
                    Encoding,
                    PrivateFormat,
                    NoEncryption,
                )

                dmp1 = rsa_crt_dmp1(d, p)
                dmq1 = rsa_crt_dmq1(d, q)
                iqmp = rsa_crt_iqmp(p, q)
                pub = RSAPublicNumbers(e, n)
                priv = RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
                key = priv.private_key()
                der = key.private_bytes(
                    Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                )
                der_path = os.path.join(OUTPUT_DIR, "private_key_%d.der" % dump_count)
                with open(der_path, "wb") as f:
                    f.write(der)
                print("  DER saved: %s (%d bytes)" % (der_path, len(der)))
            except Exception as ex:
                print("  DER build failed: %s" % ex)
    else:
        print("  Could not read RSA key components from 0x%x" % rsa_ptr)

    return False  # auto-continue


def setup_breakpoints(debugger, command, result, internal_dict):
    """Set breakpoints on BoringSSL RSA functions within libwidevinecdm."""
    target = debugger.GetSelectedTarget()

    cdm_module = None
    for module in target.module_iter():
        name = module.GetFileSpec().GetFilename()
        if name and "widevinecdm" in name:
            cdm_module = module
            break

    if not cdm_module:
        print("[!] libwidevinecdm.dylib not found in target")
        return

    print("[*] CDM module: %s" % cdm_module.GetFileSpec())

    found = False
    for symbol in cdm_module:
        sname = symbol.GetName()
        if not sname:
            continue

        if sname in ("RSA_sign", "_RSA_sign"):
            addr = symbol.GetStartAddress().GetLoadAddress(target)
            print("[+] Found %s at 0x%x" % (sname, addr))
            bp = target.BreakpointCreateByAddress(addr)
            bp.SetScriptCallbackFunction("lldb_rsa_hook.on_rsa_sign_hit")
            bp.SetAutoContinue(True)
            found = True

    if not found:
        print("[*] RSA_sign not found as symbol, searching broader...")
        for symbol in cdm_module:
            sname = symbol.GetName()
            if not sname:
                continue
            if any(
                k in sname.lower() for k in ["rsa", "sign", "private", "key", "digest"]
            ):
                addr = symbol.GetStartAddress().GetLoadAddress(target)
                st = symbol.GetType()
                print("  %s at 0x%x (type=%s)" % (sname, addr, st))

    print("[*] Breakpoints configured. Trigger a new license request in Chrome.")
