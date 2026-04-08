# Work Plan: Phase 2 Initial Key Derivation Analysis

Date: 2026-04-08

## Goal

Analyze how the DH shared secret (128 bytes) is transformed into initial session keys (enc_key_0, sign_key_0) in Netflix iOS MSL protocol, and implement a pure Python simulation that eliminates the need for device-based key capture.

## Background

- Phase 3 KDF (key renewal) is solved: uses a non-standard HMAC-SHA256 chain, NOT standard HKDF
- 100+ HKDF parameter combinations already tested with no match
- Key 33.6 response (96 bytes) suspected structure: [IV:16B][CT:48B][HMAC:32B]
- PSK and nonce are known hardcoded constants from NFWebCrypto.framework
- The initial derivation likely also uses a non-standard construction

## Tasks

### Frida Engineer
- [ ] 1. Enumerate all crypto exports in NFWebCrypto.framework (`*HMAC*`, `*SHA*`, `*KDF*`, `*derive*`, `*PRF*`, `*expand*`, `*extract*`, `*HKDF*`) and hook them all during a fresh appboot session
- [ ] 2. Hook `AES_set_decrypt_key` / `EVP_DecryptInit` to capture the exact bytes used as decryption key for key 33.6, then trace backwards to identify which function produced those bytes
- [ ] 3. Hook CommonCrypto (`CC_SHA256`, `CCHmac`, `CCKeyDerivationPBKDF`) in system libraries to catch KDF calls outside bundled OpenSSL
- [ ] 4. Test MSL spec standard KDF: `HMAC-SHA384(pre_master_secret, "MASTER_SECRET" || PSK || nonce)` against live captured values
- [ ] 5. Identify and hook C++ orchestrator method in NFWebCrypto containing `appboot`, `session`, `derive`, or `master` in symbol name

### Tweak Engineer
- [ ] 6. Audit existing Tweak hook coverage — identify gaps in intermediate KDF state capture
- [ ] 7. Hook `dhDerive` export in NFWebCrypto.framework to capture raw 128-byte DH shared secret
- [ ] 8. Hook `HKDF` export in NFWebCrypto.framework with full parameter capture (IKM, salt, info, output length, output bytes)
- [ ] 9. Hook `aesCbc` with full context (key, IV, plaintext/ciphertext, direction) to identify wrapping step
- [ ] 10. Hook TFIT whitebox AES internals for MGK extraction — bridge between DH shared secret and wrapping key
- [ ] 11. Hook `IosMslClient -_handleAppbootResponse:error:timeoutMS:` to extract enc_key_0/sign_key_0 from parsed response object

### Python Engineer
- [ ] 12. Audit existing tools in `tools/` to catalogue exactly which KDF variants have been ruled out
- [ ] 13. Build `tools/find_phase2_hmac_chain.py`: test Phase 3 HMAC chain pattern applied to DH shared secret with varying truncation/ordering
- [ ] 14. Build `tools/find_phase2_kdf_variants.py`: test non-HKDF derivations (NIST SP 800-56C, ANSI X9.63, PBKDF2, raw SHA-256/SHA-1, PRF constructions)
- [ ] 15. Build `tools/decrypt_key_response.py`: attempt AES-CBC decryption of 96-byte key 33.6 blob under candidate keys, verify HMAC
- [ ] 16. Implement `derive_initial_session_keys()` in `src/netflix_msl/crypto.py` once algorithm is discovered
- [ ] 17. Write regression test `tools/verify_phase2_kdf.py` with known test vectors

## Execution Order

1. **Parallel — Runtime Analysis** (Tasks 1-5, 6-11):
   - Frida Engineer: Deploy comprehensive crypto hook script, capture full appboot session
   - Tweak Engineer: Deploy enhanced Tweak with HKDF/aesCbc/TFIT hooks, capture parallel data
2. **Parallel — Hypothesis Audit** (Task 12):
   - Python Engineer: Audit existing tool results while device analysis runs
3. **Sequential — Correlation** (after Step 1 completes):
   - Correlate Frida + Tweak logs to identify exact call chain: DH_compute_key → ??? → AES_set_decrypt_key
   - Determine if HKDF is used at all, or if it's another custom HMAC chain
4. **Sequential — Hypothesis Testing** (Tasks 13-15):
   - Python Engineer: Build and run targeted KDF search tools using parameters revealed by runtime analysis
5. **Sequential — Implementation** (Tasks 16-17):
   - Python Engineer: Implement and verify the discovered algorithm

## Deliverables

- `packages/frida/hook_phase2_kdf.js`: Comprehensive crypto tracer for appboot session
- `packages/tweak/<name>/Tweak.x.swift`: Enhanced hooks with HKDF/aesCbc/TFIT capture
- `tools/find_phase2_hmac_chain.py`: Phase 3 pattern applied to Phase 2
- `tools/find_phase2_kdf_variants.py`: Non-HKDF KDF variant tester
- `tools/decrypt_key_response.py`: Key 33.6 response decryptor
- `src/netflix_msl/crypto.py`: `derive_initial_session_keys()` implementation
- `tools/verify_phase2_kdf.py`: Regression test with known test vectors
- `docs/spec/msl_phase2_kdf_analysis.md`: Algorithm documentation

## Risks / Notes

- The derivation may involve TFIT whitebox crypto (Irdeto), making the key material opaque even to memory inspection — if so, we need to capture at the wrapping boundary, not inside the whitebox
- CommonCrypto vs bundled OpenSSL: KDF calls may span both libraries
- The 128-byte shared secret may be truncated or hashed before KDF input
- If the derivation uses device-specific material beyond PSK/nonce, pure Python simulation may not be fully portable
- Phase 3 KDF's non-standard nature strongly suggests Phase 2 is also non-standard — prioritize Netflix-custom HMAC chain hypotheses over standard KDF specs
