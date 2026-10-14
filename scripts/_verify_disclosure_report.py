#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""_verify_disclosure_report.py - 校验生成的披露报告 .docx。

校验项：
  1. 包结构：必需的 OOXML part 是否齐全；
  2. XML 合法性：每个 .xml / .rels part 都必须是良构 XML；
  3. 结构约束：每个 w:tbl 后必须紧跟一个 w:p（Word 要求）；
  4. 单元格内容：不得出现因 run 规格误用而混入的字面量标记字符；
  5. 关键事实：IV、偏移、哈希、各发现编号必须真实出现在正文中；
  6. 边界约束：正文不得包含凭据类材料（Cookie / Authorization / 账号密码等）。

用法：python _verify_disclosure_report.py <path-to-docx>
"""

import os
import sys
import zipfile
import xml.etree.ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

REQUIRED_PARTS = [
    "[Content_Types].xml",
    "_rels/.rels",
    "docProps/core.xml",
    "docProps/app.xml",
    "word/_rels/document.xml.rels",
    "word/styles.xml",
    "word/document.xml",
]

# 必须出现的真实事实（均来自本次评估的一手证据）
REQUIRED_FACTS = [
    "4565722735503b3431743f3a3f6f2d3a",       # 固定 IV
    "0x74de0",                                 # IV 字面量偏移
    "0x00111f0c",                              # aes_256_cbc_encode 真身
    "0x00111350",                              # genECDHsharedsecret 真身
    "0x74c71",                                 # arm64 常量偏移
    "0x500f1",                                 # armeabi-v7a 常量偏移
    "0x51085",                                 # armeabi 常量偏移
    "a1a6e23aceb986331a3db34baa7c8557e1d944f1d4f4e80030eed0bad43f3072",
    "e7ec1bfd7820317975340f0af97859635792030a017daad502f303118953eb48",
    "abca008ba600a9b1eee80660ef80aef0032dc341fead36cc2baea0443e452acc",
    "F-01", "F-02", "F-03", "F-04",
    "零填充",
    "证据局限与未证实事项",
    "报告性质与边界声明",
]

# 必须出现的边界声明（本报告的核心约束，缺一不可）
REQUIRED_DISCLAIMERS = [
    "不构成任何攻击工具",
    "未获得任何真实会话密钥",
    "不主张实际通信已被解密或可被解密",
    "未与生产服务端发生任何交互",
    "并非通过窃取、截获或越权访问获得",
]

# 不得出现的攻击性 / 凭据性内容
# 注意：不要放入会在本报告自身的「否定句」里出现的词（例如「明文样本」会出现在
#       “不提供任何解密结果或明文样本”中），否则会产生误报。
FORBIDDEN = [
    "Cookie", "Set-Cookie", "Authorization:", "password=",
    "token=", "access_token", "session_key =",
    "高价值目标", "PRIVATE KEY", "-----BEGIN",
]

# 明确不得出现在报告中的材料：任何候选会话密钥与应用侧密钥数据。
# 本报告只允许出现「随 APK 公开发布」的出厂常量（见 REQUIRED_FACTS）。
MUST_NOT_APPEAR = [
    # 一次自洽性验算得到的派生值（非真实会话密钥，仍不纳入报告）
    "fd33e6814b7ef1da8e48a0adf5a1c5ab3fe4d9c692af63f144ba5b47e363c7a8",
    # 已知答案测试使用的固定测试密钥
    "000102030405060708090a0b0c0d0e0f",
    # 应用自身公钥材料（getAppPubKey 返回值片段）
    "cb0ddae1086a36b43471d259e66",
    "421bc13c609f7e76c536379dc43bae69",
]


def main(path):
    ok = True

    if not os.path.isfile(path):
        print("FAIL  file not found: %s" % path)
        return 1
    print("target : %s" % path)
    print("size   : %d bytes" % os.path.getsize(path))

    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())

        print("\n-- 1. package parts --")
        for part in REQUIRED_PARTS:
            present = part in names
            ok = ok and present
            print("  [%s] %s" % ("OK " if present else "MISS", part))

        print("\n-- 2. xml well-formedness --")
        for n in sorted(names):
            if n.endswith(".xml") or n.endswith(".rels"):
                try:
                    ET.fromstring(z.read(n))
                except Exception as exc:
                    ok = False
                    print("  [FAIL] %s : %s" % (n, exc))
        print("  all xml/rels parts parsed")

        doc = ET.fromstring(z.read("word/document.xml"))

    body = doc.find(W + "body")
    if body is None:
        print("FAIL  document.xml has no w:body")
        return 1

    print("\n-- 3. structure --")
    kids = list(body)
    tags = [el.tag for el in kids]
    paras = tables = 0
    for i, tag in enumerate(tags):
        if tag == W + "p":
            paras += 1
        elif tag == W + "tbl":
            tables += 1
            if i + 1 >= len(tags) or tags[i + 1] != W + "p":
                ok = False
                print("  [FAIL] w:tbl at index %d not followed by w:p" % i)
    print("  paragraphs=%d tables=%d" % (paras, tables))

    print("\n-- 4. run text sanity (kind markers must never leak as text) --")
    runs_total = 0
    leaked = []
    for r in doc.iter(W + "r"):
        runs_total += 1
        text = "".join(t.text or "" for t in r.iter(W + "t"))
        if text.strip() in ("c", "b", "bc", "i"):
            leaked.append(text)
    ok = ok and not leaked
    print("  runs=%d leaked-kind-markers=%d" % (runs_total, len(leaked)))
    for x in leaked[:10]:
        print("  [FAIL] leaked marker run: %r" % x)

    print("\n-- 4b. code-bearing cells (must carry no trailing marker) --")
    shown = 0
    total_code_cells = 0
    for tc in doc.iter(W + "tc"):
        text = "".join(t.text or "" for t in tc.iter(W + "t"))
        if ("0x" in text) or ("a1a6e23a" in text) or ("4565722735503b" in text):
            total_code_cells += 1
            if shown < 12:
                shown += 1
                print("  | %s" % text)
    print("  code-bearing cells: %d (showing %d)" % (total_code_cells, shown))

    # 全文（含表格）
    full = "".join(t.text or "" for t in doc.iter(W + "t"))

    print("\n-- 5. required facts --")
    for fact in REQUIRED_FACTS:
        hit = fact in full
        ok = ok and hit
        print("  [%s] %s" % ("OK " if hit else "MISS", fact))

    print("\n-- 6a. required boundary statements --")
    for need in REQUIRED_DISCLAIMERS:
        hit = need in full
        ok = ok and hit
        print("  [%s] %s" % ("OK " if hit else "MISS", need))

    print("\n-- 6b. forbidden technical material --")
    for bad in FORBIDDEN:
        hit = bad in full
        ok = ok and not hit
        print("  [%s] %s" % ("FAIL" if hit else "OK  ", bad))

    print("\n-- 6c. application-side key material must be absent --")
    for bad in MUST_NOT_APPEAR:
        hit = bad in full
        ok = ok and not hit
        print("  [%s] %s" % ("FAIL" if hit else "OK  ", bad[:34] + "..."))

    print("\n-- 7. text inventory (paragraph level, first 40) --")
    count = 0
    for el in body:
        if el.tag != W + "p":
            continue
        text = "".join(t.text or "" for t in el.iter(W + "t")).strip()
        if not text:
            continue
        count += 1
        if count <= 40:
            print("  %3d | %s" % (count, text[:110]))

    print("\ntotal characters in document : %d" % len(full))
    print("RESULT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else
                  os.path.join(os.path.expanduser("~"), "Desktop",
                               "report.docx")))
