#!/usr/bin/env python3
import lief
b = lief.parse('/home/vscode/app/targets/znca_ios_3.4.1/Crew')

targets = [0x100c34fbc, 0x100c35004, 0x100c34470, 0x100c40240]

# Build reloc/bind map: address -> symbol name
# Use lief's dyld_info / chained fixups
print("=== bindings (dyld_chained_fixups) ===")
try:
    for b_ in b.dyld_chained_fixups.bindings:
        pass
except Exception as e:
    print("no chained_fixups bindings attr directly, trying alternate", e)

# Alternate: use imported functions / symbols with address
print("=== imported functions ===")
imp_addrs = {}
for f in b.imported_functions:
    imp_addrs[f.name] = f
print(len(b.imported_functions), "imported functions")

# use lief's Binary.get_function_address is for exported; try symtab search for STUBS section entries
print("=== sections named __stubs / __auth_stubs ===")
for seg in b.segments:
    for sec in seg.sections:
        if 'stub' in sec.name.lower():
            print(seg.name, sec.name, hex(sec.virtual_address), hex(sec.size))
