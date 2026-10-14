#!/usr/bin/env python3
"""Static facts about the shipped libmd.so that the runtime capture needs, measured from the file.

Two questions this answers, both from bytes rather than from memory:

  1. WHERE the session key lives. libmd.so exports DATA symbols (shareKey, strApiPublicKey,
     keydata2, ecdh1, len1, len2). A data symbol's st_value is enough to find it at runtime as
     long as the module's load bias is known, and the load bias comes from /proc/<pid>/maps.
     No ptrace, no hook, no guess about which 32 bytes are the key.

  2. WHICH JNINativeInterface slot each JNI call uses. The wrapper's own AArch64 code says so:
     `env->functions` is `ldr Xd,[X0,#0]` at a JNI entry point, and a call is then a
     `ldr Xt,[Xd,#imm]` + `blr Xt`, so the slot index is imm/8. The literal string arguments the
     same code loads (ADRP+ADD into .rodata) name the calls that take a char* - "UTF-8" makes
     NewStringUTF unambiguous, "java/lang/String" makes FindClass unambiguous - so the index map
     is derived from this binary twice over instead of being copied from a table that may have
     been written for another API level.

Pure standard library, so it runs under whatever `python` the project already uses. Nothing here
executes the sample: the ELF is parsed and the ARM64 bytes are decoded in this process.

    python scripts\\libmd_symbols.py
    python scripts\\libmd_symbols.py --maps logs\\proc_5107_maps.txt   # resolve runtime addresses
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from datetime import datetime, timezone

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

DEFAULT_SO = r"D:\base\base\lib\arm64-v8a\libmd.so"

# Data symbols the runtime side reads. They are the module's own, not invented here: every name
# below appears in the file's .dynsym (libmd.so.exports.txt) and in the Ghidra decompilation
# (shareKey is the uchar* handed to aes_256_cbc_encode at 0x112ff0).
DEFAULT_DATA_SYMBOLS = ("shareKey", "strApiPublicKey", "keydata2", "ecdh1", "len1", "len2")

# The JNI wrappers plus two of the module's own helpers. jstringTostr/charTojstring are included
# because they are where GetStringUTFChars / NewStringUTF must appear, which is an independent
# second sighting of an index that paramJsonEncode also uses.
DEFAULT_FUNCTIONS = (
    "Java_com_openssl_md_JniHand_paramJsonEncode",
    "Java_com_openssl_md_JniHand_paramJsonDecode",
    "Java_com_openssl_md_JniHand_getAppPubKey",
    "Java_com_openssl_md_JniHand_setApiPubKey",
    "_Z12jstringTostrP7_JNIEnvP8_jstring",
    "_Z13charTojstringP7_JNIEnvPKc",
)

MAX_INSNS = 8000  # a wrapper is O(1000) bytes; this caps a runaway decode


# =====================================================================================
# ELF64 (little endian, AArch64): sections, PT_LOAD mapping, .dynsym
# =====================================================================================
class Elf:
    """Section + segment view of an ELF64 file, with vaddr <-> file offset mapping."""

    def __init__(self, blob: bytes) -> None:
        self.blob = blob
        if blob[:4] != b"\x7fELF" or blob[4] != 2 or blob[5] != 1:
            raise ValueError("not a little-endian ELF64 file")
        (self.e_machine,) = struct.unpack_from("<H", blob, 0x12)
        (self.e_phoff,) = struct.unpack_from("<Q", blob, 0x20)
        (e_shoff,) = struct.unpack_from("<Q", blob, 0x28)
        (e_phentsize,) = struct.unpack_from("<H", blob, 0x36)
        (e_phnum,) = struct.unpack_from("<H", blob, 0x38)
        (e_shentsize,) = struct.unpack_from("<H", blob, 0x3A)
        (e_shnum,) = struct.unpack_from("<H", blob, 0x3C)
        (e_shstrndx,) = struct.unpack_from("<H", blob, 0x3E)

        self.raw_sections = []
        for index in range(e_shnum):
            base = e_shoff + index * e_shentsize
            name, stype, flags, addr, offset, size, link, _info, _align, entsize = struct.unpack_from(
                "<IIQQQQIIQQ", blob, base)
            self.raw_sections.append({
                "index": index, "name_off": name, "type": stype, "flags": flags, "addr": addr,
                "offset": offset, "size": size, "link": link, "entsize": entsize,
            })

        self.segments = []
        for index in range(e_phnum):
            base = self.e_phoff + index * e_phentsize
            p_type, _flags, p_offset, p_vaddr = struct.unpack_from("<IIQQ", blob, base)
            _p_paddr, p_filesz, p_memsz, _align = struct.unpack_from("<QQQQ", blob, base + 24)
            if p_type == 1:  # PT_LOAD
                self.segments.append({"offset": p_offset, "vaddr": p_vaddr,
                                      "filesz": p_filesz, "memsz": p_memsz})

        shstr = self.raw_sections[e_shstrndx]
        self.shstrtab = blob[shstr["offset"]:shstr["offset"] + shstr["size"]]

    def sections(self):
        for item in self.raw_sections:
            item = dict(item)
            end = self.shstrtab.find(b"\x00", item["name_off"])
            item["name"] = self.shstrtab[item["name_off"]:end].decode("utf-8", "replace")
            yield item

    def section_by_name(self, name: str):
        for item in self.sections():
            if item["name"] == name:
                return item
        return None

    def dynamic_symbols(self):
        """(name, value, size, info, shndx) for every entry of .dynsym."""
        dynsym = self.section_by_name(".dynsym")
        dynstr = self.section_by_name(".dynstr")
        if not dynsym or not dynstr:
            return
        strings = self.blob[dynstr["offset"]:dynstr["offset"] + dynstr["size"]]
        for index in range(dynsym["size"] // 24):
            base = dynsym["offset"] + index * 24
            st_name, st_info, _st_other, st_shndx, st_value, st_size = struct.unpack_from(
                "<IBBHQQ", self.blob, base)
            end = strings.find(b"\x00", st_name)
            name = strings[st_name:end].decode("utf-8", "replace") if end >= 0 else ""
            if name:
                yield name, st_value, st_size, st_info, st_shndx

    def vaddr_to_offset(self, vaddr: int):
        for seg in self.segments:
            if seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
                return seg["offset"] + (vaddr - seg["vaddr"])
        return None

    def read_vaddr(self, vaddr: int, size: int):
        offset = self.vaddr_to_offset(vaddr)
        if offset is None:
            return None
        return self.blob[offset:offset + size]

    def read_cstring_vaddr(self, vaddr: int, cap: int = 256):
        raw = self.read_vaddr(vaddr, cap)
        if raw is None:
            return None
        end = raw.find(b"\x00")
        if end <= 0:
            return None
        try:
            text = raw[:end].decode("utf-8")
        except UnicodeDecodeError:
            return None
        return text if all(0x20 <= ord(ch) < 0x7F for ch in text) else None


# =====================================================================================
# Just enough AArch64 to read what libmd's own wrappers do with the JNIEnv table
# =====================================================================================
def decode_insn(word: int):
    """Return a small dict for the instruction forms this task needs, else None."""
    if (word & 0xFFC00000) == 0xF9400000:  # LDR Xt,[Xn,#imm]  (unsigned offset, 64-bit)
        return {"op": "ldr64", "rn": (word >> 5) & 31, "rt": word & 31, "imm": ((word >> 10) & 0xFFF) * 8}
    if (word & 0xFFC00000) == 0xF9000000:  # STR Xt,[Xn,#imm]
        return {"op": "str64", "rn": (word >> 5) & 31, "rt": word & 31, "imm": ((word >> 10) & 0xFFF) * 8}
    if (word & 0xFFE0FFE0) == 0xAA0003E0:  # MOV Xd,Xm  (ORR Xd,XZR,Xm)
        return {"op": "mov", "rd": word & 31, "rm": (word >> 16) & 31}
    if (word & 0x9F000000) == 0x90000000:  # ADRP Xd, page
        immlo = (word >> 29) & 0x3
        immhi = (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        return {"op": "adrp", "rd": word & 31, "imm": imm << 12}
    if (word & 0xFF800000) == 0x91000000:  # ADD Xd,Xn,#imm12
        return {"op": "add", "rd": word & 31, "rn": (word >> 5) & 31, "imm": (word >> 10) & 0xFFF}
    if (word & 0xFFFFFC1F) == 0xD63F0000:  # BLR Xn
        return {"op": "blr", "rn": (word >> 5) & 31}
    if (word & 0xFC000000) == 0x94000000:
        return {"op": "bl", "off": word & 0x3FFFFFF}
    return None


LITERAL_WINDOW = 6  # how many instructions back a materialised literal is still "the argument"


def analyse_function(elf: Elf, vaddr: int, size: int, name: str, addr_to_name: dict | None = None) -> dict:
    """Walk one function and report every JNIEnv slot it loads plus the char* literals it loads.

    X0 is JNIEnv* on entry, so `ldr Xd,[X0,#0]` yields env->functions and a call is a
    `ldr Xt,[Xd,#imm]` + `blr Xt`: the slot index is read out of imm rather than assumed. The
    literal arguments (ADRP+ADD into .rodata) say which of those calls take a char*, which is
    what makes a slot nameable without consulting a table written for some other API level.
    """
    raw = elf.read_vaddr(vaddr, size)
    if raw is None:
        return {"name": name, "error": "function vaddr is not inside a PT_LOAD segment"}
    count = min(len(raw) // 4, MAX_INSNS)
    regs = [None] * 32
    regs[0] = "env"
    spills = {}
    calls = []
    direct_calls = []
    recent = []
    decoded = 0

    for index in range(count):
        pc = vaddr + index * 4
        (word,) = struct.unpack_from("<I", raw, index * 4)
        insn = decode_insn(word)
        if not insn:
            continue
        decoded += 1
        op = insn["op"]
        if op == "ldr64":
            if insn["rn"] == 31:                                  # [SP,#imm]
                regs[insn["rt"]] = spills.get(insn["imm"])
                continue
            source = regs[insn["rn"]]
            if source == "env" and insn["imm"] == 0:
                regs[insn["rt"]] = "functions"
            elif source == "functions":
                slot = insn["imm"] // 8
                regs[insn["rt"]] = ("slot", slot)
                calls.append({"slot": slot, "imm": insn["imm"],
                              "load_offset": hex(pc - vaddr), "load_insn": "%08x" % word,
                              "literal_args": [], "recent_literals": []})
            elif isinstance(source, tuple) and source[0] == "slot":
                regs[insn["rt"]] = "callret"
            else:
                regs[insn["rt"]] = None
        elif op == "str64":
            if insn["rn"] == 31:
                spills[insn["imm"]] = regs[insn["rt"]]
            else:
                regs[insn["rt"]] = None
        elif op == "mov":
            regs[insn["rd"]] = regs[insn["rm"]]
        elif op == "adrp":
            # ADRP's immediate is relative to the 4 KiB page of the *ADRP itself*, so the page
            # base - not the raw immediate - is what the following ADD adds to. Dropping the PC
            # page here is what made every literal resolve to garbage: 0x64cee instead of the
            # real 0x74cee for "java/lang/String".
            regs[insn["rd"]] = ("page", (pc & ~0xFFF) + insn["imm"])
        elif op == "add":
            base = regs[insn["rn"]]
            if isinstance(base, tuple) and base[0] == "page":
                target = base[1] + insn["imm"]
                regs[insn["rd"]] = ("addr", target)
                recent = [item for item in recent if item["vaddr"] != target]
                recent.append({"vaddr": hex(target), "text": elf.read_cstring_vaddr(target),
                               "offset": hex(pc - vaddr)})
                recent = recent[-LITERAL_WINDOW:]
        elif op == "blr":
            origin = regs[insn["rn"]]
            if isinstance(origin, tuple) and origin[0] == "slot":
                for call in reversed(calls):
                    if call["slot"] == origin[1] and call.get("call_offset") is None:
                        call["call_offset"] = hex(pc - vaddr)
                        call["literal_args"] = [
                            {"arg_reg": "x%d" % r, "vaddr": hex(regs[r][1]),
                             "text": elf.read_cstring_vaddr(regs[r][1])}
                            for r in range(1, 4)
                            if isinstance(regs[r], tuple) and regs[r][0] == "addr"
                        ]
                        call["recent_literals"] = list(recent)
                        break
            for r in range(0, 19):        # caller-saved: a call clobbers these
                regs[r] = None
            regs[0] = "callret"
        elif op == "bl":
            # A direct call into this image. libmd reaches some JNI functions through its own
            # C++ wrappers (`_JNIEnv::NewObject`, `_JNIEnv::CallObjectMethod`) instead of
            # loading the table slot itself, so a JNI step can be one level away from the
            # `ldr Xt,[functions,#imm]` this walker looks for. Resolving the target against
            # .dynsym records that step by name rather than silently dropping it.
            offset = insn["off"]
            if offset & (1 << 25):
                offset -= 1 << 26
            target = pc + (offset << 2)
            if addr_to_name:
                direct_calls.append({"offset": hex(pc - vaddr), "target": hex(target),
                                     "name": addr_to_name.get(target)})

    called = [call for call in calls if call.get("call_offset")]
    counts = {}
    for call in called:
        key = str(call["slot"])
        counts[key] = counts.get(key, 0) + 1
    return {
        "name": name,
        "vaddr": hex(vaddr),
        "size": size,
        "slot_loads": len(calls),
        "slot_calls": len(called),
        "distinct_slots": len(counts),
        "slot_call_counts": counts,
        "calls": called,
        "direct_calls": direct_calls,
        "insns_decoded": decoded,
        "insns_not_decoded": max(0, count - decoded),
    }


# =====================================================================================
# Naming the slots: literal anchors, then the repeated block, then a cross-check
# =====================================================================================
# From the Ghidra decompilation of 0x112ff0 (libmd.so.targeted.c lines 276-333) each of the two
# paths calls the SAME five JNI table functions - FindClass("java/lang/String"),
# GetMethodID(cls, "<init>", "([BLjava/lang/String;)V"), NewByteArray, SetByteArrayRegion,
# NewStringUTF("UTF-8") - and GetStringLength is called once in the guard. That is 11 table calls
# over 6 indices. The constructor is then applied by `_JNIEnv::NewObject`, a C++ helper this file
# reaches with `bl`, so it owns no table slot here: an earlier 13-call/7-index guess counted it as
# one and was simply wrong against the file. The shape below is an expectation read back out of
# the file, re-checked on every run.
PARAMJSONENCODE_EXPECTED = {"distinct_slots": 6, "slot_calls": 11, "blocks": 2, "block_width": 5,
                            "guard_calls": 1}
BLOCK_NAMES = ("FindClass", "GetMethodID", "NewByteArray", "SetByteArrayRegion", "NewStringUTF")
BLOCK_WIDTH = len(BLOCK_NAMES)
# JNI's own signatures force these three: only FindClass takes a class name, only GetMethodID
# takes a constructor signature, and a bare "UTF-8" argument is the charset NewStringUTF makes.
LITERAL_PROOF = {"java/lang/String": "FindClass", "<init>": "GetMethodID", "UTF-8": "NewStringUTF"}
DIRECT_CALL_NOTE = "NewObject"  # a `bl` target, not a table slot (see name_slots)
# The JNIEnv function table layout is fixed by the JNI ABI (jni.h, JNINativeInterface_) and is
# identical on every Android ABI. Used ONLY as a third opinion to flag a disagreement for a human;
# it never names a slot - every slot this tool reports is still read from libmd's own `ldr`.
STANDARD_JNI_SLOTS = {
    "GetVersion": 4, "FindClass": 6, "GetMethodID": 33, "NewByteArray": 176,
    "SetByteArrayRegion": 208, "NewStringUTF": 167, "GetStringLength": 164,
    "GetArrayLength": 171, "GetByteArrayElements": 184, "ReleaseByteArrayElements": 192,
    "GetStringUTFChars": 169,
}


def parse_maps(text: str, needle: str) -> dict:
    """Load bias for `needle` out of a /proc/<pid>/maps dump (base - file offset of first map)."""
    result = {"needle": needle, "found": False, "maps": [], "base": None, "unknowns": []}
    for line in text.splitlines():
        if needle not in line:
            continue
        parts = line.split()
        if len(parts) < 6 or "-" not in parts[0]:
            continue
        try:
            start_text, end_text = parts[0].split("-")
            start = int(start_text, 16)
            end = int(end_text, 16)
            file_offset = int(parts[2], 16)
        except ValueError:
            result["unknowns"].append("unparsed maps line: %s" % line.strip())
            continue
        result["maps"].append({"start": hex(start), "end": hex(end),
                               "file_offset": hex(file_offset), "protection": parts[1]})
        if result["base"] is None and file_offset == 0:
            result["base"] = start - file_offset
    result["found"] = bool(result["maps"])
    if result["base"] is None and result["maps"]:
        result["unknowns"].append("no mapping with file_offset 0; load bias left unresolved")
    result["base"] = hex(result["base"]) if result["base"] is not None else None
    return result


def repo_index_table(path: str) -> dict:
    """Cross-check source: the JNI index table in an existing in-repo hook, if it has one."""
    table = {"path": os.path.normpath(path), "present": os.path.isfile(path), "entries": {},
             "unknowns": []}
    if not table["present"]:
        table["unknowns"].append("file not found")
        return table
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if ":" not in line or "=" in line:
                continue
            stripped = line.strip().rstrip(",")
            if not stripped or stripped.startswith("//"):
                continue
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip().rstrip(",").strip()
            if key.isidentifier() and value.isdigit():
                table["entries"][key] = int(value)
    if not table["entries"]:
        table["unknowns"].append("no `Name: <int>` entries recognised")
    return table


def name_slots(analysis: dict, repo: dict) -> dict:
    """Give every slot in paramJsonEncode a name, and only where this file supports it."""
    result = {"status": "NOT_ANCHORED", "names": {}, "evidence": {}, "unknowns": []}
    calls = analysis.get("calls") or []
    if not calls:
        result["unknowns"].append("no slot calls decoded for this function")
        return result

    # A block is BLOCK_WIDTH consecutive calls carrying the three proving literals at the
    # positions JNI's signatures require (class name first, constructor second, charset last).
    blocks = []
    for start in range(0, max(0, len(calls) - (BLOCK_WIDTH - 1))):
        window = calls[start:start + BLOCK_WIDTH]
        seen = {}
        for offset, call in enumerate(window):
            # literal_args are the x1..x3 registers still holding a materialised address at the
            # `blr`, i.e. the call's own arguments. recent_literals is deliberately NOT used here:
            # it is a lagging window, so the second path's calls still carry the first path's
            # literals and every anchor would collapse onto offset 0.
            for item in call["literal_args"]:
                name = LITERAL_PROOF.get(item.get("text"))
                if name:
                    seen.setdefault(name, offset)
        if (seen.get("FindClass") == 0 and seen.get("GetMethodID") == 1
                and seen.get("NewStringUTF") == BLOCK_WIDTH - 1):
            blocks.append({"start": start, "slots": [call["slot"] for call in window]})

    if not blocks:
        result["unknowns"].append("the three literal anchors were not at the expected positions; "
                                  "slots are reported but left unnamed")
        return result

    # Both paths must yield the SAME indices; if they do not, a block boundary was guessed wrong
    # and naming it would be fabrication.
    result["blocks"] = blocks
    distinct = {tuple(block["slots"]) for block in blocks}
    if len(distinct) != 1:
        result["unknowns"].append("the anchored blocks disagree on their slots: %s"
                                  % "; ".join(str(list(item)) for item in sorted(distinct)))
        return result

    for offset, slot in enumerate(blocks[0]["slots"]):
        name = BLOCK_NAMES[offset]
        result["names"][name] = slot
        result["evidence"][name] = {
            "confidence": "literal-anchored" if name in LITERAL_PROOF.values()
                          else "block-position",
            "slot": slot, "block_start_indices": [block["start"] for block in blocks],
            "offset_in_block": offset,
        }

    inside = set()
    for block in blocks:
        inside.update(range(block["start"], block["start"] + BLOCK_WIDTH))
    leftovers = [call for index, call in enumerate(calls) if index not in inside]
    if len(leftovers) == 1:
        result["names"]["GetStringLength"] = leftovers[0]["slot"]
        result["evidence"]["GetStringLength"] = {
            "confidence": "shape-only", "slot": leftovers[0]["slot"],
            "why": "the only slot call outside the anchored blocks, and the decompilation has "
                   "exactly one such call (the length guard)",
        }
    else:
        result["unknowns"].append("%d slot calls outside the anchored blocks, expected 1 "
                                  "(GetStringLength)" % len(leftovers))

    # The constructor call is a `bl` into libmd's own C++ `_JNIEnv::NewObject`, so it is real but
    # owns no table slot inside this function; say so instead of leaving a silent gap where a
    # reader would expect a sixth index.
    if analysis.get("direct_calls"):
        result["not_table_calls"] = {
            DIRECT_CALL_NOTE: {
                "reason": "reached by `bl` to a local _JNIEnv C++ wrapper; that wrapper's own "
                          "ldr Xt,[functions,#imm] lives inside the wrapper, not here",
                "direct_calls_decoded": len(analysis["direct_calls"]),
            }}

    for name, slot in result["names"].items():
        other = (repo.get("entries") or {}).get(name)
        if repo.get("present") and other is not None and other != slot:
            result["unknowns"].append("in-repo table disagrees about %s: %s here, %s in %s"
                                      % (name, slot, other, repo["path"]))
    result["status"] = "ANCHORED"
    result["expected_shape"] = PARAMJSONENCODE_EXPECTED
    return result


def string_reader_slots(analysis: dict) -> dict:
    """Name the slots jstringTostr uses to turn a jstring into bytes.

    Measured shape: FindClass("java/lang/String"), NewStringUTF("UTF-8"),
    GetMethodID(cls,"getBytes","(Ljava/lang/String;)[B") - the first and third literal-anchored -
    followed by three unnamed slots in call order. That is String.getBytes(charset) -> byte[] ->
    GetArrayLength -> GetByteArrayElements -> ReleaseByteArrayElements: libmd reads jstring
    CONTENT as UTF-8 bytes and never calls GetStringUTFChars. The three trailing slots take no
    char* literal, so they are named by position and then cross-checked, never assumed.
    """
    found = {"status": "NOT_FOUND", "names": {}, "evidence": {}, "unknowns": []}
    calls = analysis.get("calls") or []
    anchored = {}
    for index, call in enumerate(calls):
        # Only the call's own argument registers: recent_literals lags by up to six literals and
        # would let an earlier call's literals name a later one.
        for item in call["literal_args"]:
            text = item.get("text")
            if text == "java/lang/String":
                anchored.setdefault("FindClass", index)
            elif text == "getBytes":
                anchored.setdefault("GetMethodID", index)
            elif text == "UTF-8":
                anchored.setdefault("NewStringUTF", index)

    order = ("GetArrayLength", "GetByteArrayElements", "ReleaseByteArrayElements")
    trailing = [call for index, call in enumerate(calls)
                if index > anchored.get("GetMethodID", -1)]
    if anchored.get("FindClass") == 0 and "GetMethodID" in anchored and len(trailing) == len(order):
        for name, call in zip(order, trailing):
            found["names"][name] = call["slot"]
            found["evidence"][name] = {
                "confidence": "getbytes-shape", "slot": call["slot"],
                "call_offset": call.get("call_offset"),
                "why": "position in the measured getBytes path; takes no char* literal, so it is "
                       "cross-checked against the standard JNIEnv layout and the in-repo table",
            }
        found["status"] = "GETBYTES_SHAPE"
        found["anchored"] = anchored
        found["why"] = ("libmd reads a jstring via String.getBytes(\"UTF-8\"), not "
                        "GetStringUTFChars: the inbound plaintext surface is GetByteArrayElements, "
                        "so the capture must watch that (and GetArrayLength) rather than "
                        "GetStringUTFChars")
    else:
        found["unknowns"].append(
            "expected FindClass@0 + a getBytes GetMethodID + %d trailing slot calls, saw anchors=%s "
            "trailing=%d" % (len(order), anchored, len(trailing)))
    return found


# =====================================================================================
# Wiring
# =====================================================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Static facts (data symbols, JNIEnv slot indices) about libmd.so.")
    parser.add_argument("--so", default=DEFAULT_SO)
    parser.add_argument("--maps", default=None, help="saved /proc/<pid>/maps dump to resolve bases")
    parser.add_argument("--maps-needle", default="libmd.so")
    parser.add_argument("--repo-index-file", default=r"D:\frida\hooks\jni_boundary.js",
                        help="a second, independent source for the same indices")
    parser.add_argument("--data-symbols", default=",".join(DEFAULT_DATA_SYMBOLS))
    parser.add_argument("--functions", default=",".join(DEFAULT_FUNCTIONS))
    parser.add_argument("--json", default=os.path.join(ROOT, "data", "processed", "libmd_symbols.json"))
    parser.add_argument("--txt", default=os.path.join(ROOT, "logs", "libmd_symbols.txt"))
    return parser


def write_outputs(json_path: str, txt_path: str, document: dict, text: str) -> None:
    for path in (json_path, txt_path):
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    with open(txt_path, "w", encoding="utf-8") as handle:
        handle.write(text)


def collect_symbols(elf: Elf, wanted) -> tuple:
    section_names = {item["index"]: item["name"] for item in elf.sections()}
    found, missing = {}, []
    for name, value, size, info, shndx in elf.dynamic_symbols():
        if name in wanted:
            found[name] = {"st_value": hex(value), "vaddr_dec": value, "st_size": size,
                           "bind": info >> 4, "kind": info & 0xF,
                           "section": section_names.get(shndx), "shndx": shndx}
    for name in wanted:
        if name not in found:
            missing.append(name)
    return found, missing


def main() -> int:
    args = build_parser().parse_args()
    so_path = os.path.normpath(args.so)
    with open(so_path, "rb") as handle:
        blob = handle.read()
    sha256 = hashlib.sha256(blob).hexdigest()
    elf = Elf(blob)

    symbols, missing_symbols = collect_symbols(elf, set(args.data_symbols.split(",")))
    by_name = {name: (value, size) for name, value, size, _i, _s in elf.dynamic_symbols()}
    # Address -> symbol, for naming the `bl` targets libmd uses to reach its own JNI wrappers.
    # A shared address keeps the first name seen, which is enough to identify the wrapper.
    addr_to_name = {}
    for name, (value, _size) in by_name.items():
        addr_to_name.setdefault(value, name)

    functions = []
    for name in args.functions.split(","):
        if name not in by_name:
            functions.append({"name": name, "error": "not in .dynsym"})
            continue
        value, size = by_name[name]
        functions.append(analyse_function(elf, value, size, name, addr_to_name))

    repo = repo_index_table(args.repo_index_file)
    encoder = next((item for item in functions
                    if item["name"].endswith("paramJsonEncode") and "calls" in item), None)
    naming = name_slots(encoder, repo) if encoder else {"status": "NO_FUNCTION", "names": {},
                                                       "evidence": {}, "unknowns": ["wrapper missing"]}
    reader_helper = next((item for item in functions
                          if "jstringTostr" in item["name"] and "calls" in item), None)
    reader = string_reader_slots(reader_helper) if reader_helper else {
        "status": "NO_HELPER", "names": {}, "unknowns": ["jstringTostr not decoded"]}

    jni_index_map = {}
    for name, slot in naming.get("names", {}).items():
        jni_index_map[name] = {"slot": slot, "source": "paramJsonEncode",
                               **naming["evidence"].get(name, {})}
    for name, slot in reader.get("names", {}).items():
        jni_index_map[name] = {"slot": slot, "source": "jstringTostr",
                               **reader["evidence"].get(name, {"confidence": "getbytes-shape"})}

    maps = None
    if args.maps and os.path.isfile(args.maps):
        with open(args.maps, "r", encoding="utf-8", errors="replace") as handle:
            maps = parse_maps(handle.read(), args.maps_needle)
        if maps["base"]:
            base = int(maps["base"], 16)
            for item in symbols.values():
                item["runtime_address"] = hex(base + item["vaddr_dec"])
            maps["symbol_runtime_addresses"] = {
                name: item["runtime_address"] for name, item in sorted(symbols.items())}

    target = next((item for item in functions if item["name"].endswith("paramJsonEncode")), {})
    shape_ok = (target.get("distinct_slots") == PARAMJSONENCODE_EXPECTED["distinct_slots"]
                and target.get("slot_calls") == PARAMJSONENCODE_EXPECTED["slot_calls"])

    # Every slot this file actually asks for, across all decoded functions. Used only to make the
    # "libmd never requests a UTF-8 char*" claim measurable here instead of asserted.
    seen_slots = sorted({call["slot"] for item in functions if "calls" in item
                         for call in item["calls"]})
    utf8_chars_slot = STANDARD_JNI_SLOTS["GetStringUTFChars"]
    get_string_utf_chars_seen = utf8_chars_slot in seen_slots
    decoded_functions = [item for item in functions if "calls" in item]

    # Third opinions on indices the file gave us: the fixed JNI ABI, and the in-repo table. Neither
    # names a slot - they only raise a flag for a human when they disagree with the measurement.
    abi_conflicts = ["%s: this file says %s, the JNI ABI says %s"
                     % (name, item["slot"], STANDARD_JNI_SLOTS[name])
                     for name, item in sorted(jni_index_map.items())
                     if name in STANDARD_JNI_SLOTS and STANDARD_JNI_SLOTS[name] != item["slot"]]
    repo_entries = repo.get("entries") or {}
    repo_conflicts = ["%s: this file says %s, %s says %s"
                      % (name, item["slot"], repo["path"], repo_entries[name])
                      for name, item in sorted(jni_index_map.items())
                      if repo.get("present") and name in repo_entries
                      and repo_entries[name] != item["slot"]]

    checks = {
        "elf_is_aarch64": elf.e_machine == 0xB7,
        "sha256_recorded": len(sha256) == 64,
        "all_data_symbols_found": not missing_symbols,
        "paramjsonencode_slots_anchored": naming.get("status") == "ANCHORED",
        "paramjsonencode_shape_matches_decompilation": shape_ok,
        "jstringtostr_getbytes_shape_found": reader.get("status") == "GETBYTES_SHAPE",
        "index_map_covers_capture_surface":
            {"FindClass", "GetMethodID", "NewByteArray", "SetByteArrayRegion", "NewStringUTF",
             "GetStringLength", "GetArrayLength", "GetByteArrayElements",
             "ReleaseByteArrayElements"} <= set(jni_index_map),
        "measured_slots_agree_with_standard_jni_abi": not abi_conflicts,
        "repo_cross_check_has_no_conflict": not repo_conflicts,
        "getstringutfchars_absent_confirmed": not get_string_utf_chars_seen,
    }
    unknowns = []
    if missing_symbols:
        unknowns.append("data symbols absent from .dynsym: %s" % ", ".join(missing_symbols))
    unknowns += naming.get("unknowns", [])
    unknowns += reader.get("unknowns", [])
    for item in functions:
        if item.get("error"):
            unknowns.append("%s: %s" % (item["name"], item["error"]))
    if not maps:
        unknowns.append("no --maps dump given, so runtime addresses are not resolved in this run")
    unknowns += ["cross-check conflict: %s" % item for item in abi_conflicts + repo_conflicts]
    if not get_string_utf_chars_seen:
        unknowns.append(
            "slot %d (GetStringUTFChars) is never called by the %d decoded functions, so the "
            "inbound jstring content must be read through slot %s (GetByteArrayElements) with the "
            "length from slot %s; a capture that only hooks GetStringUTFChars would see nothing"
            % (utf8_chars_slot, len(decoded_functions),
               jni_index_map.get("GetByteArrayElements", {}).get("slot"),
               jni_index_map.get("GetArrayLength", {}).get("slot")))

    document = {
        "schema": "LibmdStaticFacts",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": os.path.abspath(__file__),
        "artifact": {"path": so_path, "sha256": sha256, "bytes": len(blob),
                     "e_machine": hex(elf.e_machine)},
        "data_symbols": symbols,
        "missing_data_symbols": missing_symbols,
        "functions": functions,
        "jni_index_map": jni_index_map,
        "jni_index_map_note": (
            "slot numbers are decoded from this binary's own code (ldr Xt,[functions,#imm]) and "
            "named by the char* literals the same code loads; the in-repo table is a cross-check, "
            "never the source"),
        "slot_naming": naming,
        "string_reader": reader,
        "repo_cross_check": repo,
        "cross_checks": {
            "standard_jni_abi_conflicts": abi_conflicts,
            "repo_conflicts": repo_conflicts,
            "getstringutfchars_slot_seen": get_string_utf_chars_seen,
        },
        "jni_slots_seen": seen_slots,
        "maps": maps,
        "checks": checks,
        "unknowns": unknowns,
        "verdict": {
            "headline": ("libmd.so exports its session-key globals and its JNI slot indices are "
                         "readable from the file itself"
                         if all(checks.values()) else "one or more static-fact checks did not hold"),
            "ok": all(checks.values()),
        },
    }

    lines = ["libmd.so static facts (data symbols + JNIEnv slot indices)",
             "generated_at : %s" % document["generated_at"],
             "artifact     : %s" % so_path,
             "sha256       : %s" % sha256,
             "",
             "data symbols (read at runtime as base + st_value):"]
    for name, item in sorted(symbols.items()):
        runtime = item.get("runtime_address", "unresolved (pass --maps)")
        lines.append("  %-16s st_value=%-12s size=%-4s section=%-10s runtime=%s"
                     % (name, item["st_value"], item["st_size"], item["section"], runtime))
    if missing_symbols:
        lines.append("  MISSING: %s" % ", ".join(missing_symbols))
    lines += ["", "JNIEnv slot calls per function:"]
    for item in functions:
        if item.get("error"):
            lines.append("  %-52s ERROR %s" % (item["name"], item["error"]))
            continue
        counts = ", ".join("%s:%s" % pair for pair in sorted(item["slot_call_counts"].items(),
                                                             key=lambda pair: int(pair[0])))
        lines.append("  %-52s calls=%-3s distinct=%-3s %s"
                     % (item["name"], item["slot_calls"], item["distinct_slots"], counts))
    lines += ["", "JNI index map (slot numbers measured here):"]
    for name in sorted(jni_index_map):
        item = jni_index_map[name]
        lines.append("  %-24s slot=%-4s confidence=%-15s source=%s"
                     % (name, item["slot"], item.get("confidence"), item.get("source")))
    for name, item in sorted((naming.get("not_table_calls") or {}).items()):
        lines.append("  note: %s carries no index here - %s" % (name, item["reason"]))
    if naming.get("unknowns"):
        lines += ["", "slot-naming notes:"]
        lines += ["  - %s" % item for item in naming["unknowns"]]
    if reader.get("unknowns"):
        lines += ["  - %s" % item for item in reader["unknowns"]]
    lines += ["", "cross-checks against independent sources (never the source of a slot):"]
    lines.append("  GetStringUTFChars(%s) called by this file: %s"
                 % (utf8_chars_slot, "yes" if get_string_utf_chars_seen
                    else "NO - inbound jstring content is read via GetByteArrayElements"))
    for item in abi_conflicts:
        lines.append("  CONFLICT vs the JNI ABI: %s" % item)
    for item in repo_conflicts:
        lines.append("  CONFLICT vs the in-repo table: %s" % item)
    if not abi_conflicts and not repo_conflicts:
        lines.append("  no disagreements")
    lines += ["", "checks:"]
    for name, value in sorted(checks.items()):
        lines.append("  %-45s %s" % (name, "PASS" if value else "FAIL"))
    lines += ["", "unknowns:"]
    lines += ["  - %s" % item for item in unknowns] or ["  - none"]
    lines += ["", "verdict: %s" % document["verdict"]["headline"]]
    write_outputs(args.json, args.txt, document, "\n".join(lines) + "\n")

    print("libmd.so %s" % sha256)
    for name, item in sorted(jni_index_map.items()):
        print("  %-24s slot %-4s %s" % (name, item["slot"], item.get("confidence")))
    print("checks: %d/%d PASS" % (sum(1 for value in checks.values() if value), len(checks)))
    for name, value in sorted(checks.items()):
        if not value:
            print("  FAIL %s" % name)
    print("json: %s" % os.path.normpath(args.json))
    print("txt : %s" % os.path.normpath(args.txt))
    return 0 if all(checks.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())






