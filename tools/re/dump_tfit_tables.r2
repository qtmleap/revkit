# radare2 script to dump TFIT tables from NFWebCrypto binary
# Usage: r2 -q -i dump_tfit_tables.r2 <NFWebCrypto_binary>

# Key schedules (224 bytes each)
echo "=== TFIT_key_iAES11_mgkATV (224 bytes) ==="
px 0xe0 @ 0x1acf28

echo "\n=== TFIT_key_iAES11_mgkiPad (224 bytes) ==="
px 0xe0 @ 0x1ad008

echo "\n=== TFIT_key_iAES11_mgkiPhone (224 bytes) ==="
px 0xe0 @ 0x1ad0e8

# Output S-boxes (first 2 for inspection)
echo "\n=== TFIT_out_iAES11_0 (256 bytes) ==="
px 0x100 @ 0x1ddba8

echo "\n=== TFIT_out_iAES11_1 (256 bytes) ==="
px 0x100 @ 0x1ddca8

# Round masks
echo "\n=== Round 9 masks ==="
px 24 @ 0x1adb70

echo "\n=== Round 10 masks ==="
px 32 @ 0x1adb88

# Functions
echo "\n=== genModelGroupKeys ==="
pd 40 @ 0x1db74

echo "\n=== encryptAes128Ecb ==="
pd 60 @ 0x1ddb8
