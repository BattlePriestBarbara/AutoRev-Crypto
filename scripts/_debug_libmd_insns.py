#!/usr/bin/env python3
"""Throwaway debug: dump one libmd.so function's decoded call sites and literals.

Reuses libmd_symbols.py (the real tool) rather than re-implementing the decoder, so what
is printed here is exactly what the tool sees.

    python scripts\\_debug_libmd_insns.py Java_com_openssl_md_JniHand_paramJsonEncode
"""
from __future__ import annotations

import os
import struct
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import libmd_symbols as L  # noqa: E402

elf = L.Elf(open(L.DEFAULT_SO, "rb").read())
by_name = {n: (v, s) for n, v, s, _i, _x in elf.dynamic_symbols()}
addr_to_name = {v: n for n, (v, s) in by_name.items()}

for wanted in sys.argv[1:] or list(L.DEFAULT_FUNCTIONS):
    if wanted not in by_name:
        print("!! %s not in .dynsym" % wanted)
        continue
    vaddr, size = by_name[wanted]
    print("=" * 100)
    print("%s  vaddr=%#x size=%d (%#x)" % (wanted, vaddr, size, size))
    neighbours = sorted((v, n) for n, (v, s) in by_name.items() if abs(v - vaddr) < 0x2000)
    print("  nearby symbols: %s" % ", ".join("%s@%#x" % (n, v) for v, n in neighbours[:12]))
    info = L.analyse_function(elf, vaddr, size, wanted, addr_to_name)
    if info.get("error"):
        print("  ERROR %s" % info["error"])
        continue
    print("  slot_loads=%s slot_calls=%s distinct=%s counts=%s"
          % (info["slot_loads"], info["slot_calls"], info["distinct_slots"], info["slot_call_counts"]))
    for call in info["calls"]:
        line = "   +%s slot=%-4s imm=%#06x call@%s" % (
            call["load_offset"], call["slot"], call["imm"], call.get("call_offset"))
        print(line)
        for item in call["literal_args"]:
            print("        arg %s @%s -> %r" % (item["arg_reg"], item["vaddr"], item["text"]))
        if call["recent_literals"]:
            print("        recent: %s" % [(r["offset"], r["vaddr"], r["text"]) for r in call["recent_literals"]])
    if info.get("direct_calls"):
        print("  direct bl calls (resolved against .dynsym):")
        for item in info["direct_calls"]:
            print("   +%s -> %s %s" % (item["offset"], item["target"], item["name"]))
    print("  insns decoded=%s not_decoded=%s" % (info["insns_decoded"], info["insns_not_decoded"]))
