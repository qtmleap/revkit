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
- [x] 1. Enumerate all crypto exports in NFWebCrypto.framework — HKDF not found, DH_KDF_X9_42 found
- [x] 2. Hook `AES_set_decrypt_key` — captured exact key bytes, traced to HMAC-SHA384 output
- [x] 3. Hook CommonCrypto — confirmed not used for KDF
- [x] 4. Test MSL spec standard KDF — no match (algorithm is HMAC-SHA384 with TFIT key)
- [x] 5. Identified HMAC-SHA384 as the orchestrating function via HMAC_Init_ex hook

### Tweak Engineer
- [x] 6. Audit existing Tweak hook coverage — gaps in HMAC key capture identified
- [x] 7. Hook `DH_compute_key` — captured 128-byte shared secret
- [x] 8. Hook `HKDF` — confirmed not present in NFWebCrypto.framework
- [x] 9. Hook `AES_set_*_key` — captured all AES key material
- [ ] 10. Hook TFIT whitebox AES internals for MGK extraction — 48B TFIT key origin still opaque
- [x] 11. Hook HMAC — captured 48B TFIT key via HMAC_Init_ex

### Python Engineer
- [x] 12. Audit existing tools — 100+ HKDF variants ruled out
- [x] 13. Build `tools/find_phase2_hmac_chain.py` — Phase 3 pattern tested, no match
- [x] 14. Build `tools/find_phase2_kdf_variants.py` — all standard KDFs ruled out
- [x] 15. Build `tools/decrypt_key_response.py` — tested 66 candidate keys
- [x] 16. Implement `derive_initial_session_keys()` in `src/netflix_msl/crypto.py` — DONE
- [x] 17. Write regression test `tools/verify_phase2_kdf.py` — PASS

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
