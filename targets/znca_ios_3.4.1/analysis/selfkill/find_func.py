#!/usr/bin/env python3
"""Locate the function containing a given VA using LC_FUNCTION_STARTS."""
import lief
import sys

BINARY = '/home/vscode/app/targets/znca_ios_3.4.1/Crew'
BASE = 0x100000000

b = lief.parse(BINARY)
print("format:", b.format)

fs = b.function_starts
print("function_starts object:", fs)
addrs = sorted(fs.functions) if fs is not None else []
print("num function starts:", len(addrs))

target = 0x10007D5B4
# functions are stored as offsets from base typically already VA in LIEF? check first few
print("first 5 raw:", addrs[:5])
print("last 5 raw:", addrs[-5:])
