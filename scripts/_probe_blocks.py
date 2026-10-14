#!/usr/bin/env python3
"""Throwaway: show why a block window does or does not anchor, per start index."""
from __future__ import annotations

import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import libmd_symbols as L  # noqa: E402

elf = L.Elf(open(L.DEFAULT_SO, "rb").read())
by_name = {n: (v, s) for n, v, s, _i, _x in elf.dynamic_symbols()}
addr_to_name = {}
for name, (value, _s) in by_name.items():
    addr_to_name.setdefault(value, name)

name = "Java_com_openssl_md_JniHand_paramJsonEncode"
vaddr, size = by_name[name]
info = L.analyse_function(elf, vaddr, size, name, addr_to_name)
calls = info["calls"]
print("BLOCK_WIDTH=%d  n_calls=%d" % (L.BLOCK_WIDTH, len(calls)))
for index, call in enumerate(calls):
    lits = [it.get("text") for it in call["literal_args"] + call["recent_literals"]
            if it.get("text")]
    print("  %2d slot=%-4s call=%-6s lits=%s" % (index, call["slot"], call.get("call_offset"), lits))

print("\nwindow scan:")
for start in range(0, max(0, len(calls) - (L.BLOCK_WIDTH - 1))):
    window = calls[start:start + L.BLOCK_WIDTH]
    seen = {}
    for offset, call in enumerate(window):
        for item in call["literal_args"]:
            anchor = L.LITERAL_PROOF.get(item.get("text"))
            if anchor:
                seen.setdefault(anchor, offset)
    ok = (seen.get("FindClass") == 0 and seen.get("GetMethodID") == 1
          and seen.get("NewStringUTF") == L.BLOCK_WIDTH - 1)
    print("  start=%d slots=%s seen=%s -> %s"
          % (start, [c["slot"] for c in window], seen, "MATCH" if ok else "no"))
