#!/usr/bin/env python3
"""
Static analysis: key 33.6 (scheme_data) construction in MslClient.framework.

Traces how the DH public key becomes the CBOR-encoded key exchange request data
(key 33 sub-key 6) in the MSL appboot handshake.

Binary: Netflix iOS MslClient.framework (arm64 Mach-O)
        /tmp/argo/Payload/Argo.app/Frameworks/MslClient.framework/MslClient

Usage:
    python3 tools/re/analyze_mslclient_key336.py [path_to_MslClient]
"""

import struct
import sys

import r2pipe

DEFAULT_BINARY = "/tmp/argo/Payload/Argo.app/Frameworks/MslClient.framework/MslClient"


def dump_cbor_symbol_table(r2) -> dict[int, str]:
    """Dump the CborMslSymbolTable s_tags array (CBOR integer key -> string name)."""
    table_base = 0x15C990
    raw = r2.cmd(f"p8 768 @ {hex(table_base)}").strip()
    data = bytes.fromhex(raw)
    mapping = {}
    for i in range(96):
        ptr = struct.unpack_from("<Q", data, i * 8)[0]
        if ptr == 0:
            continue
        file_off = ptr & 0xFFFFFFFF
        s = r2.cmd(f"ps @ {hex(file_off)}").strip()
        if s and len(s) < 60:
            mapping[i] = s
    return mapping


def analyze(binary_path: str) -> None:
    r2 = r2pipe.open(binary_path, flags=["-e", "bin.cache=true", "-2"])
    r2.cmd("aaa")

    print("=" * 72)
    print("KEY 33.6 CONSTRUCTION ANALYSIS - MslClient.framework")
    print("=" * 72)

    # =========================================================================
    # 1. CBOR Symbol Table (integer key <-> string name)
    # =========================================================================
    print("\n[1] CBOR SYMBOL TABLE (CborMslSymbolTable)")
    print("-" * 72)
    print("\n  Source: s_tags[] @ 0x15C990 (96 entries)")
    print("  Lookup: CborMslSymbolTable__integerForString @ 0x0605BC")
    print("  Reverse: CborMslSymbolTable__stringForInteger @ 0x060590")
    print()

    mapping = dump_cbor_symbol_table(r2)

    # Print all entries grouped by function
    print("  === Complete CBOR Integer <-> String Key Mapping ===")
    for i in sorted(mapping.keys()):
        print(f'    {i:3d} (0x{i:02x}) = "{mapping[i]}"')

    # Highlight the key exchange relevant entries
    print("\n  === Keys relevant to key exchange (key 33 = headerdata) ===")
    keyx_keys = {
        0x1E: "scheme",
        0x1F: "keydata",
        0x21: "headerdata",
        0x22: "entityauthdata",
        0x2A: "keyrequestdata",
        0x33: "mechanism",
        0x35: "publickey",
        0x3A: "parametersid",
        0x3B: "keypairid",
        0x41: "wrapdata",
        0x10: "signature",
        0x20: "mastertoken",
    }
    for k, v in sorted(keyx_keys.items()):
        print(f'    {k:3d} (0x{k:02x}) = "{v}"')

    # =========================================================================
    # 2. MSL Message Top-Level Structure
    # =========================================================================
    print("\n\n[2] MSL MESSAGE TOP-LEVEL CBOR STRUCTURE")
    print("-" * 72)
    print("""
  Every MSL message is CBOR tag 55799 (0xD9D9F7) + map:

  appboot request:
    tag(55799) map {
      34 (entityauthdata): bytes   <- FAIRPLAY_MGK or FAIRPLAY_MGK_APPID auth
      33 (headerdata):     bytes   <- key exchange + capabilities
      32 (mastertoken):    bytes   <- empty for new sessions
      16 (signature):      bytes   <- HMAC-SHA256 (32B)
    }

  The CBOR encoding is done by:
    CborMslEncoder__encodeObject @ 0x0AD778
      1. Encodes CBOR tag 55799 (0xD9D9F7)
      2. Iterates MslObject map entries
      3. For each entry, calls encodeMapEntry @ 0x0ADD08
         which calls CborMslSymbolTable__integerForString
         to convert string key -> integer CBOR key
""")

    # =========================================================================
    # 3. Key Exchange Schemes
    # =========================================================================
    print("\n[3] KEY EXCHANGE SCHEMES (NetflixKeyExchangeScheme)")
    print("-" * 72)
    print("""
  Scheme registry (static symbols in MslClient.framework):

  Standard MSL schemes:
    ASYMMETRIC_WRAPPED  @ 0x172D50  "ASYMMETRIC_WRAPPED"
    DIFFIE_HELLMAN      @ 0x172D70  "DIFFIE_HELLMAN"
    JWE_LADDER          @ 0x172D90  "JWE_LADDER"
    JWK_LADDER          @ 0x172DB0  "JWK_LADDER"
    SYMMETRIC_WRAPPED   @ 0x172DD0  "SYMMETRIC_WRAPPED"

  Netflix-specific schemes:
    AUTHENTICATED_DH    @ 0x16E7C8  "AUTHENTICATED_DH"   <- iOS appboot
    CDM                 @ 0x16E828  "CDM"
    ANYCAST             @ 0x16E808  "ANYCAST"
    NFLX_DH             @ 0x16E848  "NFLX_DH"
    WIDEVINE            @ 0x16E7E8  "WIDEVINE"

  iOS uses AUTHENTICATED_DH for key exchange.
  The IosAdhKeyx factory is registered for this scheme.
""")

    # =========================================================================
    # 4. IosAdhKeyRequestData Object Layout
    # =========================================================================
    print("\n[4] IosAdhKeyRequestData OBJECT LAYOUT")
    print("-" * 72)
    print("""
  Constructor: IosAdhKeyRequestData(pubkey, keypairId, wrapdata, unwrapKey)
    @ 0x07B260

  Object fields (from constructor disassembly):
    +0x00: vtable ptr (-> 0x15D6D0)
    +0x08: vtable ptr (KeyRequestData base)
    +0x10: scheme string = "AUTHENTICATED_DH" (from NetflixKeyExchangeScheme)
    +0x28: shared_ptr<vector<u8>> publickey   (DH public key bytes)
    +0x30: refcount for publickey
    +0x38: uint32_t keypairId
    +0x40: shared_ptr<vector<u8>> wrapdata    (optional, can be empty)
    +0x48: refcount for wrapdata
    +0x50: SecretKey unwrapKey                (for key unwrapping)
    +0x58: bool hasWrapdata                   (flag at offset 0x58)
""")

    # =========================================================================
    # 5. getKeydata() - Key 33.6 Inner Content Construction
    # =========================================================================
    print("\n[5] IosAdhKeyRequestData::getKeydata() @ 0x07B688")
    print("-" * 72)
    print("""
  This function builds the inner CBOR MslObject that becomes key 33 sub-key 6.
  It is called by KeyRequestData::toMslEncoding() which wraps it with
  "scheme" and "keydata" fields.

  Pseudocode (from disassembly):

  shared_ptr<MslObject> getKeydata(encoderFactory, format) {
      auto result = make_shared<MslObject>();

      // Check if wrapdata exists (this->wrapdata at +0x40)
      bool hasWrap = (this->wrapdata.get() != nullptr
                      && this->wrapdata->begin() != this->wrapdata->end());

      if (hasWrap) {
          // ---- PATH A: With wrapdata (key renewal) ----
          result->put("mechanism", "WRAP");         // CBOR key 51 = "WRAP"
      } else {
          // ---- PATH B: Without wrapdata (initial) ----
          result->put("mechanism", "MGK");           // CBOR key 51 = "MGK"
      }

      // Always: set parametersid = "1"
      result->put("parametersid", "1");              // CBOR key 58 = "1"

      // Always: set publickey = correctNullBytes(this->publickey)
      auto corrected = correctNullBytes(this->publickey);
      result->put("publickey", corrected);           // CBOR key 53 = bytes

      // Conditionally: set wrapdata if present
      if (hasWrap) {
          result->put("wrapdata", this->wrapdata);   // CBOR key 65 = bytes
      }

      return result;
  }

  CBOR key mapping for keydata fields:
    51 (0x33) "mechanism"    -> string: "MGK" or "WRAP"
    58 (0x3a) "parametersid" -> string: "1"
    53 (0x35) "publickey"    -> bytes:  DH public key (128B, null-corrected)
    65 (0x41) "wrapdata"     -> bytes:  optional wrap data
""")

    # =========================================================================
    # 6. KeyRequestData::toMslEncoding() - Outer Wrapping
    # =========================================================================
    print("\n[6] KeyRequestData::toMslEncoding() @ 0x066114")
    print("-" * 72)
    print("""
  This base class method wraps getKeydata() output:

  vector<u8> toMslEncoding(encoderFactory, format) {
      auto result = make_shared<MslObject>();

      // 1. Add scheme name (from this->scheme at +0x10)
      result->put("scheme", this->scheme_);         // key 30 = "AUTHENTICATED_DH"

      // 2. Call virtual getKeydata() and add result
      auto keydata = this->getKeydata(encoderFactory, format);
      result->put("keydata", keydata);              // key 31 = MslObject

      // 3. Encode to CBOR bytes
      return encoderFactory->encodeObject(result, format);
  }

  The toMslEncoding output becomes the value of key 33 sub-key 6 in
  the MSL message.
""")

    # =========================================================================
    # 7. correctNullBytes() - DH Public Key Padding
    # =========================================================================
    print("\n[7] IosAdhKeyx::correctNullBytes() @ 0x079358")
    print("-" * 72)
    print("""
  Ensures the DH public key has a leading 0x00 byte to indicate positive
  (unsigned) big-endian integer representation.

  shared_ptr<vector<u8>> correctNullBytes(shared_ptr<vector<u8>> input) {
      auto data = input.get();
      size_t size = data->end() - data->begin();
      size_t skip = 0;

      // Count leading zero bytes
      for (size_t i = 0; i < size; i++) {
          if (data[i] != 0) break;
          skip++;
      }

      if (skip == 1) {
          // Already has exactly one leading 0x00 -> return as-is
          return input;
      }

      // Create new vector: 0x00 + non-zero-prefix bytes
      size_t new_size = size - skip + 1;
      auto result = make_shared<vector<u8>>(new_size);
      result[0] = 0x00;                 // Leading zero byte
      memmove(result + 1, data + skip, size - skip);
      return result;
  }

  Result: DH pubkey always starts with 0x00, total size = 129B typically
  (or 128B if the original already had one leading zero).

  This is standard ASN.1/DER encoding for unsigned integers:
  prepend 0x00 if the high bit of the first byte is set.
""")

    # =========================================================================
    # 8. generateClientKeyRequestData() - Entry Point
    # =========================================================================
    print("\n[8] IosAdhKeyx::generateClientKeyRequestData() @ 0x07944C")
    print("-" * 72)
    print("""
  Called from: KeyRequestDataProvider::getKeyRequestData() @ 0x098FE0

  Signature:
    shared_ptr<IosAdhKeyRequestData>
    generateClientKeyRequestData(
        shared_ptr<AppleWebCrypto> crypto,
        shared_ptr<vector<u8>> wrapdata,
        SecretKey& unwrapKey
    )

  Pseudocode:
    1. Create empty DH pubkey vector (0x30 = 48 bytes object size)
    2. Call dhKeyGen(crypto, pubkey_out, keypairId_out)
       -> Generates DH key pair via AppleWebCrypto
       -> Returns pubkey bytes and keypairId (key handle)
    3. Create IosAdhKeyRequestData(pubkey, keypairId, wrapdata, unwrapKey)
    4. Return shared_ptr to the request data
""")

    # =========================================================================
    # 9. dhKeyGen() - DH Key Generation
    # =========================================================================
    print("\n[9] IosAdhKeyx::dhKeyGen() @ 0x079600 (2280 bytes)")
    print("-" * 72)
    print("""
  Signature:
    void dhKeyGen(
        shared_ptr<AppleWebCrypto> crypto,
        shared_ptr<vector<u8>> pubkey_out,
        uint& keypairId_out
    )

  Uses static DH parameters:
    prime:     stored at 0x176A68 (static local, lazy-initialized)
    generator: stored at 0x176A88 (static local, lazy-initialized)

  Calls AppleWebCrypto::dhKeyGen(Variant& params) in NFWebCrypto.framework
  which internally uses OpenSSL DH functions:
    DH_new() -> DH_set0_pqg() -> DH_generate_key()
    -> DH_get0_pub_key() -> BN_bn2bin()

  The DH group uses a 1024-bit prime (128 bytes).
  Generator is a small integer (typically 2).
""")

    # =========================================================================
    # 10. Complete CBOR Structure of Key 33.6
    # =========================================================================
    print("\n[10] COMPLETE CBOR STRUCTURE OF KEY 33.6")
    print("-" * 72)
    print("""
  Key 33.6 is the CBOR-encoded output of KeyRequestData::toMslEncoding(),
  which contains the scheme name and the keydata MslObject.

  === CBOR Wire Format (initial key exchange, mechanism=MGK) ===

  tag(55799)                          <- CBOR self-describing tag 0xD9D9F7
  map(2) {                            <- 2 entries: scheme + keydata
    30: "AUTHENTICATED_DH",           <- scheme (string)
    31: map(3) {                      <- keydata (3 entries)
      51: "MGK",                      <- mechanism
      58: "1",                        <- parametersid
      53: bytes(129)                  <- publickey (0x00 + 128B DH pubkey)
    }
  }

  === CBOR Wire Format (key renewal, mechanism=WRAP) ===

  tag(55799)
  map(2) {
    30: "AUTHENTICATED_DH",
    31: map(4) {                      <- keydata (4 entries with wrapdata)
      51: "WRAP",                     <- mechanism
      58: "1",                        <- parametersid
      53: bytes(129),                 <- publickey (0x00 + 128B DH pubkey)
      65: bytes(N)                    <- wrapdata (from previous session)
    }
  }

  === CBOR Integer Key Reference ===
    16 = signature          30 = scheme
    31 = keydata            32 = mastertoken
    33 = headerdata         34 = entityauthdata
    42 = keyrequestdata     51 = mechanism
    53 = publickey          58 = parametersid
    65 = wrapdata

  === Size Estimation ===
  tag(55799):                 3 bytes  (D9 D9F7)
  map(2) header:              1 byte   (A2)
  key 30 + "AUTHENTICATED_DH": 1 + 1 + 16 = 18 bytes
  key 31 + map(3):            1 + 1 = 2 bytes
    key 51 + "MGK":           1 + 1 + 3 = 5 bytes
    key 58 + "1":             2 + 1 + 1 = 4 bytes
    key 53 + bytes(129):      2 + 2 + 129 = 133 bytes
  Total: ~166 bytes (mechanism=MGK, no wrapdata)
""")

    # =========================================================================
    # 11. Response Structure
    # =========================================================================
    print("\n[11] IosAdhKeyResponseData::getKeydata() @ 0x07C028")
    print("-" * 72)
    print("""
  The response keydata has a simpler structure:

  tag(55799)
  map(2) {
    30: "AUTHENTICATED_DH",
    31: map(2-3) {
      58: "1",                        <- parametersid
      53: bytes(N),                   <- publickey (server DH pubkey)
      65: bytes(N)                    <- wrapdata (optional, for key renewal)
    }
  }

  Response construction:
    1. If wrapdata exists -> put("wrapdata", wrapdata)
    2. Always put("parametersid", "1")
    3. Always put("publickey", correctNullBytes(serverPubkey))

  After receiving the response:
    IosAdhKeyx::getCryptoContext() @ 0x07C3B8
      -> IosAdhKeyx::nflxDhDerive() @ 0x07A0F4
        -> AppleWebCrypto::nflxDhDerive()
          -> DH_compute_key(shared_secret, peer_pub, local_priv)
          -> SHA384(local_priv_bytes) -> HMAC-SHA384 -> enc_key + sign_key
""")

    # =========================================================================
    # 12. Outer MSL Message Assembly
    # =========================================================================
    print("\n[12] OUTER MSL MESSAGE ASSEMBLY (headerdata = key 33)")
    print("-" * 72)
    print("""
  The headerdata (CBOR key 33) contains:

  tag(55799)
  map(N) {
    6:  bytes(M)     <- keyrequestdata[0].toMslEncoding()  = key 33.6
    7:  bytes(0)     <- mastertoken (empty for new session)
    8:  string       <- identity (ESN + "_N" suffix)
    9:  bytes(16)    <- client nonce (random 16 bytes)
    ...              <- additional fields (capabilities, etc.)
  }

  Note: The sub-keys inside headerdata use a DIFFERENT numbering:
    Sub-key 6  = first entry (NOT "ciphertext", but keyrequestdata content)
    Sub-key 7  = second entry (mastertoken)
    Sub-key 8  = third entry (identity/ESN)
    Sub-key 9  = fourth entry (nonce)

  These sub-keys are the CBOR map integer keys within the headerdata map,
  which are assigned by the CborMslSymbolTable for the field names used
  in MessageHeader::toMslEncoding().

  Relevant mappings (from symbol table):
    3  (0x03) = "identity"
    9  (0x09) = "iv" (used for nonce)
    20 (0x14) = "sender"
    22 (0x16) = "messageid"
    24 (0x18) = "timestamp"
    36 (0x24) = "capabilities"
    40 (0x28) = "nonreplayable"
    42 (0x2A) = "keyrequestdata"

  The keyrequestdata field (key 42) is a CBOR array containing one or
  more KeyRequestData objects, each encoded via toMslEncoding().

  The observed sub-key 6 in captures corresponds to "ciphertext" (0x06)
  when the headerdata is encrypted, or the first meaningful field when
  it is a cleartext map.
""")

    # =========================================================================
    # 13. Function Address Summary
    # =========================================================================
    print("\n[13] FUNCTION ADDRESS SUMMARY")
    print("-" * 72)
    print("""
  Key Exchange:
    0x0007944C  IosAdhKeyx::generateClientKeyRequestData()
    0x00079600  IosAdhKeyx::dhKeyGen()
    0x00079358  IosAdhKeyx::correctNullBytes()
    0x0007A0F4  IosAdhKeyx::nflxDhDerive()
    0x0007C338  IosAdhKeyx::createRequestData()
    0x0007C378  IosAdhKeyx::createResponseData()
    0x0007C3B8  IosAdhKeyx::getCryptoContext()

  Request/Response Data:
    0x0007B260  IosAdhKeyRequestData::IosAdhKeyRequestData(pubkey, id, wrap, key)
    0x0007B684  IosAdhKeyRequestData::IosAdhKeyRequestData(MslObject)
    0x0007B688  IosAdhKeyRequestData::getKeydata()
    0x0007CD58  IosAdhKeyRequestData::getUnwrapKey()
    0x0007C028  IosAdhKeyResponseData::getKeydata()

  MSL Encoding:
    0x00066114  KeyRequestData::toMslEncoding()
    0x000AD778  CborMslEncoder__encodeObject()
    0x000605BC  CborMslSymbolTable__integerForString()
    0x00060590  CborMslSymbolTable__stringForInteger()

  CBOR Primitives:
    0x0011ABC0  _cbor_encode_tag()
    0x0011AB9C  _cbor_encode_map_start()
    0x0011AB10  _cbor_encode_negint()
    0x0011AAE8  _cbor_encode_uint()
    0x0011AB18  _cbor_encode_bytestring_start()
    0x0011AB54  _cbor_encode_string_start()

  Key Exchange Schemes:
    0x0016E7C8  NetflixKeyExchangeScheme::AUTHENTICATED_DH
    0x0016E848  NetflixKeyExchangeScheme::NFLX_DH
    0x0016E828  NetflixKeyExchangeScheme::CDM
    0x00172D70  KeyExchangeScheme::DIFFIE_HELLMAN
    0x00172DD0  KeyExchangeScheme::SYMMETRIC_WRAPPED

  Symbol Table:
    0x0015C990  s_tags[] (96-entry pointer array)
    0x00060698  __GLOBAL__sub_I_CborMslSymbolTable.cpp (init)
""")

    # =========================================================================
    # 14. Conclusions
    # =========================================================================
    print("\n" + "=" * 72)
    print("CONCLUSIONS")
    print("=" * 72)
    print("""
  1. KEY 33.6 IS NOT RAW BYTES: It is a nested CBOR object, not a raw
     DH public key or encrypted blob. The CBOR structure is:
       tag(55799) + map { scheme, keydata { mechanism, parametersid, publickey } }

  2. MECHANISM FIELD: Two modes:
     - "MGK" = Model Group Key (initial authentication, uses TFIT WB-AES
       encrypted DH pubkey via NFWebCrypto.framework)
     - "WRAP" = Key wrapping (session renewal, includes wrapdata from
       previous session)

  3. PARAMETERSID = "1": Fixed string, identifies the DH parameter set.
     The DH group parameters (prime, generator) are static locals in
     IosAdhKeyx::dhKeyGen().

  4. PUBLICKEY: The DH public key (128B) with null-byte correction
     (prepend 0x00 if needed, making it 129B). This is NOT TFIT-encrypted
     at the MslClient layer - TFIT encoding happens at the NFWebCrypto
     layer if the mechanism requires it.

  5. CBOR INTEGER KEYS: The observed integer keys in captures correspond to
     the CborMslSymbolTable mapping:
       16 = signature, 30 = scheme, 31 = keydata, 32 = mastertoken,
       33 = headerdata, 34 = entityauthdata, 42 = keyrequestdata,
       51 = mechanism, 53 = publickey, 58 = parametersid, 65 = wrapdata

  6. OBSERVED 352B/464B PAYLOADS: The larger sizes seen in captures include:
     - The CBOR tag and map overhead
     - The scheme string "AUTHENTICATED_DH" (16 bytes)
     - The nested keydata map with mechanism, parametersid, publickey
     - Optional wrapdata (for WRAP mechanism)
     - The publickey after correctNullBytes (129B)
     The exact size depends on CBOR encoding overhead and optional fields.

  7. THE 128B CBOR HEADER: Previously assumed to be a "fixed CBOR header"
     in the 352B payload is actually the CBOR structure containing scheme,
     mechanism, parametersid, and CBOR framing bytes. The "session region"
     is the DH public key bytes within the publickey field.

  8. Nbp.framework ROLE: Nbp does NOT implement key exchange directly.
     It uses MslClient.framework through ObjC bridging (IosMslClient).
     All key exchange logic is in MslClient.framework's C++ implementation.
""")

    r2.quit()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        binary = DEFAULT_BINARY
    else:
        binary = sys.argv[1]
    analyze(binary)
