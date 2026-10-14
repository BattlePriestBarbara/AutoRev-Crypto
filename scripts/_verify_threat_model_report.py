#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_verify_threat_model_report.py — 校验「威胁建模与攻击者视角评估报告」交付物

校验项
------
1. Markdown 主稿存在、UTF-8 可解码、结构完整（章节与证据等级标记）
2. 必备技术事实在 Markdown 中逐项存在
3. 禁用令牌（密钥材料 / 密文样本 / 应用侧公钥片段）在 Markdown 中零出现
4. 无可执行代码模式（Frida API、内存写入、命令片段等）
5. 跨文档一致性：本文件中的地址 / 偏移 / IV / 哈希与 build_disclosure_report.py 完全一致
6. .doc 为真 OLE2/CFB（魔数 d0cf11e0a1b11ae1）且体积合理
7. .doc 内部确实含有关键文本（UTF-16LE 落地）
8. 无残留 .tmp 中间文件
"""

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOCS = os.path.join(ROOT, "docs")

MD_PATH = os.path.join(DOCS, "threat_model_attacker_profile.md")
HTML_PATH = os.path.join(DOCS, "_threat_model_attacker_profile.html")
DISCLOSURE = os.path.join(HERE, "build_disclosure_report.py")

DOC_NAME = "国家反诈中心客户端_威胁建模与攻击者视角评估报告_20261014.doc"
DOC_DISCLOSURE_NAME = "国家反诈中心客户端_安全评估与负责任披露报告_20261014.doc"

_fail = []
_ok = []


def check(label, ok, detail=""):
    (_ok if ok else _fail).append(label)
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", label,
                         ("  -- " + detail) if detail else ""))


def _desktop_dir():
    for cand in [
        r"C:\Users\埃尔隆德\Desktop",
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
    ]:
        if cand and os.path.isdir(cand):
            return cand
    return None




# --------------------------------------------------------------------- 期望值
REQUIRED_FACTS = [
    "THREAT-2026-1014-MD-02", "DISC-2026-1014-MD-01", "com.hicorenational.antifraud",
    "Tier 1", "Tier 2", "Tier 3", "场景 A", "场景 B", "场景 C",
    "aes_256_cbc_encode @ 0x00111f0c", "4565722735503b3431743f3a3f6f2d3a", "0x74de0",
    "builtin_memcpy", "AES_set_encrypt_key(password, 0x100", "第 516 行",
    "第 529", "第 559", "0x00", "零填充",
    "genECDHsharedsecret @ 0x00111350", "pemString2key @ 0x00111164",
    "0x74c71", "0x500f1", "0x51085", "setApiPubKey @ 0x00112ac0",
    "strApiPublicKey", "shareKey", "0xad170", "0xad178",
    "a1a6e23aceb986331a3db34baa7c8557e1d944f1d4f4e80030eed0bad43f3072",
    "150781d39a9462169a0be86ed1fefd33c09f25c02301316a4d7a22a16d90a378",
    "paramJsonEncode @ 0x00112ff0", "GetStringUTFChars", "GetByteArrayElements",
    "SetByteArrayRegion", "jstringTostr",
    "libjiagu_vip_a64.so", "com/stub/StubApp", "com/tianyu/util/QHClassLoader",
    "FIPS-197", "raw", "HKDF", "AEAD", "AES-GCM",
    "预警失效", "隐私泄露", "信任滥用", "RASP", "服务端行为分析", "纵深防御",
    "NOT_TESTABLE", "REFUTED", "PROVEN",
    "e7ec1bfd7820317975340f0af97859635792030a017daad502f303118953eb48",
    "abca008ba600a9b1eee80660ef80aef0032dc341fead36cc2baea0443e452acc",
]

FORBIDDEN = [
    "fd33e6", "fd33e6814b7ef1da",
    "000102030405060708090a0b0c0d0e0f",
    "cb0ddae1", "421bc13c",
    "034d338d", "ebaa1fca", "66ofyv04",
    "b0bb3e9c", "73338c8c", "7ba7a9a6",
    "1f8c75ac",
    "E2E_CLOSURE_TEST",
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
]

CODE_PATTERNS = [
    "Java.perform", "Interceptor.attach", "Memory.write", "Memory.read",
    "NativeFunction", "Module.findBaseAddress", "Process.enumerateModules",
    "ptrace", "/proc/self/mem", "dd if=", "adb shell",
    "import frida", "from frida", "suspend_thread",
    "shellcode",
]

def read_text(path):
    with io.open(path, "r", encoding="utf-8") as fh:
        return fh.read()


# 允许出现的公开常量（随 APK 发布，先前文档已列出）：掩码后不应再有长块
ALLOWED_LONG = [
    "a1a6e23aceb986331a3db34baa7c8557e1d944f1d4f4e80030eed0bad43f3072",
    "150781d39a9462169a0be86ed1fefd33c09f25c02301316a4d7a22a16d90a378",
    "e7ec1bfd7820317975340f0af97859635792030a017daad502f303118953eb48",
    "abca008ba600a9b1eee80660ef80aef0032dc341fead36cc2baea0443e452acc",
    "e9c5fa2db6490fcce6b7da55acaa878c600ad2bc8c9ab9e12b297f8781d9c6aa",
    "17124c0280aa96c0fd0908661296b27c572891d0f7e7a84fa7abffc24df4375e",
]

TIER_MARKERS = ["【已验证·静态】", "【已验证·受控动态】", "【结论边界】",
                "【理论推演】", "【未验证假设】"]

SECTION_MARKERS = [
    "## 0. 文档元信息", "## 1. 阅读指南", "## 2. 攻击者能力分级",
    "## 3. 攻击面分析", "## 4. 攻击场景推演", "## 5. 业务影响评估",
    "## 6. 纵深防御建议", "## 7. 攻方视角总结",
    "附录 A", "附录 B", "附录 C", "附录 D",
]


# --------------------------------------------------------------------- 检查项
def check_markdown():
    check("markdown exists", os.path.isfile(MD_PATH), MD_PATH)
    md = read_text(MD_PATH)
    check("markdown non-trivial", len(md) > 20000,
          "%d chars / %d bytes" % (len(md), os.path.getsize(MD_PATH)))

    missing = [f for f in REQUIRED_FACTS if f not in md]
    check("required facts present (%d)" % len(REQUIRED_FACTS), not missing,
          ("missing=%r" % (missing[:8],)) if missing else "all present")

    leaked = [f for f in FORBIDDEN if f in md]
    check("no forbidden tokens (%d)" % len(FORBIDDEN), not leaked,
          ("leaked=%r" % (leaked,)) if leaked else "0 leaks")

    low = md.lower()
    bad = [p for p in CODE_PATTERNS if p.lower() in low]
    check("no executable-code patterns (%d)" % len(CODE_PATTERNS), not bad,
          ("found=%r" % (bad,)) if bad else "0 found")

    # 掩码已知公开常量后，不应再残留长十六进制 / 长 Base64 块
    masked = md
    for t in ALLOWED_LONG:
        masked = masked.replace(t, "")
    hex_hits = re.findall(r"[0-9a-fA-F]{40,}", masked)
    b64_hits = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", masked)
    check("no residual secret-like blobs", not (hex_hits or b64_hits),
          ("hex=%r b64=%r" % (hex_hits[:3], b64_hits[:3]))
          if (hex_hits or b64_hits) else "0 found")

    miss_t = [t for t in TIER_MARKERS if t not in md]
    check("all 5 evidence-tier markers used", not miss_t, repr(miss_t))

    miss_s = [s for s in SECTION_MARKERS if s not in md]
    check("all required sections present (%d)" % len(SECTION_MARKERS),
          not miss_s, repr(miss_s))

    check("no stray render artefacts",
          ("%%" not in md) and ("# @@APPEND@@" not in md))
    check("html intermediate exists", os.path.isfile(HTML_PATH),
          "%d bytes" % (os.path.getsize(HTML_PATH)
                        if os.path.isfile(HTML_PATH) else 0))
    return md


def check_cross_document_consistency(md):
    """本文件中的常量必须与披露报告生成器中的常量逐字一致。"""
    src = read_text(DISCLOSURE)
    consts = {}
    for name in ("APK_SHA", "LIBMD_SHA", "REPORT_NO", "REPORT_DATE"):
        m = re.search(r'^%s\s*=\s*"([^"]+)"' % name, src, re.M)
        consts[name] = m.group(1) if m else None

    check("disclosure REPORT_NO present in md",
          bool(consts["REPORT_NO"]) and consts["REPORT_NO"] in md,
          consts["REPORT_NO"])
    for name in ("APK_SHA", "LIBMD_SHA"):
        val = consts[name]
        check("hash %s matches disclosure" % name, bool(val) and val in md,
              (val or "")[:16] + "...")

    for needle, label in (
            ("4565722735503b3431743f3a3f6f2d3a", "IV hex"),
            ("0x74de0", "IV literal offset"),
            ("0x00111f0c", "encode function address"),
            ("0x00111350", "genECDHsharedsecret address"),
            ("0x00111164", "pemString2key address"),
            ("0x74c71", "peer key arm64-v8a offset"),
            ("0x500f1", "peer key armeabi-v7a offset"),
            ("0x51085", "peer key armeabi offset"),
            ("第 516 行", "IV load line"),
            ("第 529", "padding range"),
            ("第 559", "block-loop range"),
    ):
        check("constant consistency: %s" % label,
              (needle in md) and (needle in src), needle)


# --------------------------------------------------------------------- .doc
OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

DOC_NEEDLES = [
    "威胁建模与攻击者视角评估报告", "THREAT-2026-1014-MD-02",
    "DISC-2026-1014-MD-01", "攻击者能力分级",
    "aes_256_cbc_encode", "4565722735503b3431743f3a3f6f2d3a",
    "setApiPubKey", "paramJsonEncode", "纵深防御",
    "已验证", "NOT_TESTABLE",
]


def _needles_in_blob(blob, needles):
    found, missing = [], []
    for n in needles:
        if (n.encode("utf-16-le") in blob) or (n.encode("utf-8") in blob):
            found.append(n)
        else:
            missing.append(n)
    return found, missing


def check_doc():
    desk = _desktop_dir()
    check("desktop located", bool(desk), desk or "not found")
    if not desk:
        return

    doc_path = os.path.join(desk, DOC_NAME)
    check("threat-model .doc exists", os.path.isfile(doc_path), doc_path)
    if not os.path.isfile(doc_path):
        return

    size = os.path.getsize(doc_path)
    with open(doc_path, "rb") as fh:
        blob = fh.read()

    check("threat-model .doc is real OLE2/CFB",
          blob[:8] == OLE2_MAGIC,
          "magic=%s" % blob[:8].hex())
    check("threat-model .doc size sane", size > 100000, "%d bytes" % size)

    found, missing = _needles_in_blob(blob, DOC_NEEDLES)
    check("threat-model .doc carries key text (%d/%d)"
          % (len(found), len(DOC_NEEDLES)), not missing,
          ("missing=%r" % (missing,)) if missing else "all present")

    leaked = [f for f in FORBIDDEN
              if (f.encode("utf-16-le") in blob) or (f.encode("utf-8") in blob)]
    check("threat-model .doc has no forbidden tokens", not leaked,
          repr(leaked) if leaked else "0 leaks")

    doc2 = os.path.join(desk, DOC_DISCLOSURE_NAME)
    if os.path.isfile(doc2):
        with open(doc2, "rb") as fh:
            b2 = fh.read()
        check("disclosure .doc is real OLE2/CFB",
              b2[:8] == OLE2_MAGIC, "%d bytes" % len(b2))
        f2, m2 = _needles_in_blob(
            b2, ["负责任披露", "DISC-2026-1014-MD-01",
                 "4565722735503b3431743f3a3f6f2d3a"])
        check("disclosure .doc carries key text", not m2, repr(m2))
    else:
        check("disclosure .doc present (optional)", True, "not converted")


def check_no_temp():
    leftovers = []
    for d in (DOCS, HERE):
        for n in os.listdir(d):
            if n.endswith(".tmp"):
                leftovers.append(os.path.join(d, n))
    check("no residual .tmp files", not leftovers, repr(leftovers))


def main():
    md = check_markdown()
    check_cross_document_consistency(md)
    check_doc()
    check_no_temp()
    print("")
    print("checks passed : %d" % len(_ok))
    print("checks failed : %d" % len(_fail))
    for f in _fail:
        print("  FAILED -> %s" % f)
    print("RESULT: %s" % ("PASS" if not _fail else "FAIL"))
    return 0 if not _fail else 1


if __name__ == "__main__":
    sys.exit(main())
