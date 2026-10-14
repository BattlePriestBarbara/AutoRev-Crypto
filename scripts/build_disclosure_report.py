#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_disclosure_report.py - 生成「国家反诈中心客户端安全评估与负责任披露报告」(.docx)

用途
----
把 D:\\Palantir_Research 下已完成的静态 / 受控动态评估结论，整理成一份可直接提交给
厂商安全团队的协调披露（coordinated disclosure）文档。

本生成器刻意只输出「缺陷 + 影响 + 最小可复现证据 + 修复建议 + 披露流程」，
不输出攻击工具、利用步骤、凭据清单或针对被测目标的高价值目标清单。
报告中引用的 AES IV 与 ECDH 对端公钥，均为随 APK 公开发布的出厂常量
（任何下载该 APK 的人都能取得），不是通过窃取或截获获得。

输出
----
C:\\Users\\<user>\\Desktop\\国家反诈中心客户端_安全评估与负责任披露报告.docx

依赖
----
仅标准库：zipfile / xml.sax.saxutils / hashlib / datetime。
"""

import os
import sys
import zipfile
from xml.sax.saxutils import escape as _esc

# --------------------------------------------------------------------------- #
# OOXML 常量
# --------------------------------------------------------------------------- #
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"

TEXT_WIDTH = 9026          # A4 减去左右各 1440 twips 页边距后的正文宽度
FONT_EAST = "Microsoft YaHei"
FONT_LAT = "Segoe UI"
FONT_MONO = "Consolas"

_body = []                 # 累积的 w:p / w:tbl XML


# --------------------------------------------------------------------------- #
# 行内 run 构造
# --------------------------------------------------------------------------- #
def runs(*parts):
    """把若干片段拼成 w:r 序列。

    片段可以是 str（普通文本），也可以是 (text, kinds) 元组，kinds 由下列字符组成：
        b = 加粗, i = 斜体, c = 等宽/代码底色
    """
    out = []
    for part in parts:
        if isinstance(part, tuple):
            text, kinds = part
        else:
            text, kinds = part, ""
        kinds = kinds or ""
        rpr = []
        if "b" in kinds:
            rpr.append("<w:b/>")
        if "i" in kinds:
            rpr.append("<w:i/>")
        if "c" in kinds:
            rpr.append(
                '<w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/>'
                "<w:shd w:val=\"clear\" w:color=\"auto\" w:fill=\"F2F2F2\"/>"
                % (FONT_MONO, FONT_MONO, FONT_EAST)
            )
        rpr_xml = "<w:rPr>%s</w:rPr>" % "".join(rpr) if rpr else ""
        out.append(
            '<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r>'
            % (rpr_xml, _esc(str(text)))
        )
    return "".join(out)


def _p(inner, style=None, fill=None, indent=None, hanging=None, after=None):
    ppr = ["<w:pPr>"]
    if style:
        ppr.append('<w:pStyle w:val="%s"/>' % style)
    if fill:
        ppr.append(
            '<w:shd w:val="clear" w:color="auto" w:fill="%s"/>' % fill
        )
    if indent is not None:
        ppr.append('<w:ind w:left="%d" w:hanging="%d"/>' % (indent, hanging or 0))
    if after is not None:
        ppr.append('<w:spacing w:after="%d"/>' % after)
    ppr.append("</w:pPr>")
    return "<w:p>%s%s</w:p>" % ("".join(ppr), inner)


def para(*parts, **kw):
    _body.append(_p(runs(*parts), **kw))


def bullet(*parts, level=0):
    _body.append(
        _p(
            runs("•  ") + runs(*parts),
            indent=360 + level * 360,
            hanging=200,
            after=40,
        )
    )


def heading(text, level=1):
    _body.append(_p(runs(text), style="Heading%d" % level))


def spacer():
    _body.append(_p(""))


# --------------------------------------------------------------------------- #
# 表格
# --------------------------------------------------------------------------- #
_BORDERS = (
    "<w:tblBorders>"
    '<w:top w:val="single" w:sz="6" w:space="0" w:color="8EAADB"/>'
    '<w:left w:val="single" w:sz="6" w:space="0" w:color="8EAADB"/>'
    '<w:bottom w:val="single" w:sz="6" w:space="0" w:color="8EAADB"/>'
    '<w:right w:val="single" w:sz="6" w:space="0" w:color="8EAADB"/>'
    '<w:insideH w:val="single" w:sz="6" w:space="0" w:color="8EAADB"/>'
    '<w:insideV w:val="single" w:sz="6" w:space="0" w:color="8EAADB"/>'
    "</w:tblBorders>"
)


def _cell(cell_parts, width, fill=None, bold=False, code=False):
    # cell_parts 可以是：
    #   str                -> 普通文本，按 bold/code 参数决定行内属性
    #   (text, kinds) 二元组 -> 单个 run 规格
    #   其它序列            -> 若干 run 规格
    if isinstance(cell_parts, str):
        kinds = "bc" if (bold and code) else "b" if bold else "c" if code else ""
        parts = ((cell_parts, kinds),)
    elif (isinstance(cell_parts, tuple) and len(cell_parts) == 2
          and isinstance(cell_parts[1], str)):
        parts = (cell_parts,)
    else:
        parts = tuple(cell_parts)

    tcpr = ['<w:tcPr><w:tcW w:w="%d" w:type="dxa"/>' % width]
    if fill:
        tcpr.append(
            '<w:shd w:val="clear" w:color="auto" w:fill="%s"/>' % fill
        )
    tcpr.append('<w:vAlign w:val="top"/></w:tcPr>')
    inner = _p(runs(*parts), after=20)
    return "<w:tc>%s%s</w:tc>" % ("".join(tcpr), inner)


def table(header, rows, widths, head_fill="D9E2F3", first_col_bold=False):
    """header: 表头字符串列表（None 表示无表头）；rows: 每行若干单元格内容。"""
    xml = [
        '<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>',
        '<w:tblLayout w:type="fixed"/>',
        _BORDERS,
        "</w:tblPr><w:tblGrid>",
    ]
    xml += ['<w:gridCol w:w="%d"/>' % w for w in widths]
    xml.append("</w:tblGrid>")

    if header:
        xml.append("<w:tr>")
        xml.append("<w:trPr><w:tblHeader/></w:trPr>")
        for c, w in zip(header, widths):
            xml.append(_cell(c, w, fill=head_fill, bold=True))
        xml.append("</w:tr>")

    for r in rows:
        xml.append("<w:tr>")
        for i, (c, w) in enumerate(zip(r, widths)):
            xml.append(
                _cell(c, w, bold=(first_col_bold and i == 0))
            )
        xml.append("</w:tr>")

    xml.append("</w:tbl>")
    _body.append("".join(xml))
    _body.append(_p(""))          # Word 要求表格后跟一个段落


# --------------------------------------------------------------------------- #
# styles.xml
# --------------------------------------------------------------------------- #
def _st(sid, name, based=None, sz=None, bold=False, color=None,
        before=0, after=120, jc=None):
    rpr = ['<w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s"/>'
           % (FONT_LAT, FONT_LAT, FONT_EAST)]
    if bold:
        rpr.append("<w:b/>")
    if sz:
        rpr.append('<w:sz w:val="%d"/><w:szCs w:val="%d"/>' % (sz, sz))
    if color:
        rpr.append('<w:color w:val="%s"/>' % color)
    ppr = ['<w:spacing w:before="%d" w:after="%d"/>' % (before, after)]
    if jc:
        ppr.append('<w:jc w:val="%s"/>' % jc)
    base = '<w:basedOn w:val="%s"/>' % based if based else ""
    return (
        '<w:style w:type="paragraph" w:styleId="%s">'
        '<w:name w:val="%s"/>%s<w:next w:val="Normal"/><w:qFormat/>'
        "<w:pPr>%s</w:pPr><w:rPr>%s</w:rPr></w:style>"
        % (sid, name, base, "".join(ppr), "".join(rpr))
    )


def styles_xml():
    return "".join([
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<w:styles xmlns:w="%s">' % W_NS,
        "<w:docDefaults><w:rPrDefault><w:rPr>"
        '<w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s" w:cs="%s"/>'
        '<w:sz w:val="21"/><w:szCs w:val="21"/></w:rPr></w:rPrDefault>'
        '<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="300" '
        'w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
        % (FONT_LAT, FONT_LAT, FONT_EAST, FONT_LAT),
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
        '<w:name w:val="Normal"/><w:qFormat/></w:style>',
        _st("Title", "Title", None, sz=40, bold=True, color="1F3864",
            after=60, jc="center"),
        _st("Subtitle", "Subtitle", "Normal", sz=20, color="595959",
            after=40, jc="center"),
        _st("Heading1", "heading 1", "Normal", sz=30, bold=True,
            color="1F3864", before=380, after=160),
        _st("Heading2", "heading 2", "Normal", sz=25, bold=True,
            color="2E5496", before=280, after=120),
        _st("Heading3", "heading 3", "Normal", sz=22, bold=True,
            color="2E5496", before=200, after=100),
        "</w:styles>",
    ])



# --------------------------------------------------------------------------- #
# 包写入 (minimal OOXML)
# --------------------------------------------------------------------------- #
CT_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
    '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
    '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
    "</Types>"
)

ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="%s">'
    '<Relationship Id="rId1" Type="%s/officeDocument" Target="word/document.xml"/>'
    '<Relationship Id="rId2" Type="%s/metadata/core-properties" Target="docProps/core.xml"/>'
    '<Relationship Id="rId3" Type="%s/extended-properties" Target="docProps/app.xml"/>'
    "</Relationships>" % (PKG_REL, R_NS, R_NS, R_NS)
)

DOC_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="%s">'
    '<Relationship Id="rId1" Type="%s/styles" Target="styles.xml"/>'
    "</Relationships>" % (PKG_REL, R_NS)
)

APP_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    "<Application>Palantir Research coordinated-disclosure builder</Application>"
    "</Properties>"
)


def core_xml(title, subject, author, created):
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        "<cp:coreProperties "
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        "<dc:title>%s</dc:title><dc:subject>%s</dc:subject>"
        "<dc:creator>%s</dc:creator><cp:lastModifiedBy>%s</cp:lastModifiedBy>"
        '<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>'
        '<dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified>'
        "</cp:coreProperties>"
        % (_esc(title), _esc(subject), _esc(author), _esc(author),
           created, created)
    )


def document_xml():
    sect = (
        "<w:sectPr>"
        '<w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
        'w:header="851" w:footer="992" w:gutter="0"/>'
        "</w:sectPr>"
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="%s">' % W_NS
        + "<w:body>" + "".join(_body) + sect + "</w:body></w:document>"
    )


def write_docx(path, title, subject, author, created):
    parts = [
        ("[Content_Types].xml", CT_XML),
        ("_rels/.rels", ROOT_RELS),
        ("docProps/core.xml", core_xml(title, subject, author, created)),
        ("docProps/app.xml", APP_XML),
        ("word/_rels/document.xml.rels", DOC_RELS),
        ("word/styles.xml", styles_xml()),
        ("word/document.xml", document_xml()),
    ]
    tmp = path + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts:
            z.writestr(name, text.encode("utf-8"))
    os.replace(tmp, path)
    return path


# --------------------------------------------------------------------------- #
# 报告内容
# --------------------------------------------------------------------------- #
REPORT_NO = "DISC-2026-1014-MD-01"
REPORT_DATE = "2026-10-14"
CREATED = "2026-10-14T00:00:00Z"

APK_SHA = "e7ec1bfd7820317975340f0af97859635792030a017daad502f303118953eb48"
LIBMD_SHA = "abca008ba600a9b1eee80660ef80aef0032dc341fead36cc2baea0443e452acc"
LIBTNET_SHA = "e9c5fa2db6490fcce6b7da55acaa878c600ad2bc8c9ab9e12b297f8781d9c6aa"
JIAGU_SHA = "17124c0280aa96c0fd0908661296b27c572891d0f7e7a84fa7abffc24df4375e"

W2 = [2300, 6726]
W3 = [1700, 4100, 3226]
W4 = [1000, 1700, 3100, 3226]

TARGET = "com.hicorenational.antifraud 2.0.27（versionCode 201）"
SUBMITTER = "［提交前填写：报告人 / 所属单位］"
CONTACT = "［提交前填写：联系邮箱 / 联系电话 / 安全应急响应渠道］"


def title(text):
    _body.append(_p(runs(text), style="Title"))


def subtitle(text):
    _body.append(_p(runs(text), style="Subtitle"))


def build_masthead():
    title("国家反诈中心 Android 客户端安全评估与负责任披露报告")
    subtitle("评估模块：native 密码学层 libmd.so　·　文档编号 %s" % REPORT_NO)
    table(None, [
        ["报告编号", REPORT_NO],
        ["报告日期", REPORT_DATE],
        ["评估对象", TARGET],
        ["受影响模块", "libmd.so（arm64-v8a）"],
        ["文档性质", ("负责任披露（协调披露）材料 · 受控分发", "b")],
        ["文档状态", "待提交厂商 / 安全团队"],
        ["报告人", SUBMITTER],
        ["联系方式", CONTACT],
    ], W2, first_col_bold=True)


def build_scope_notice():
    heading("报告性质与边界声明", 2)
    para(("本文档为负责任披露（coordinated disclosure）材料，唯一目的是协助被评估方定位并修复下列缺陷。",
          "b"), fill="FFF2CC")
    para("本文档不含、也不构成任何攻击工具、利用脚本、凭据清单、账号信息或目标清单；不描述任何针对运行中目标的"
         "操作步骤，也不提供可直接执行的攻击流程。", fill="FFF2CC")
    para("文中引用的 AES 初始向量（IV）与 ECDH 对端公钥，均为随 APK 公开发布的出厂常量——任何下载该 APK 者"
         "均可直接取得，并非通过窃取、截获或越权访问获得。列出它们是为了让厂商能够定位到确切的待修位置。",
         fill="FFF2CC")
    para("本次评估未捕获任何真实通信流量，未获得任何真实会话密钥，未与生产服务端发生任何交互。因此本文档"
         "不对“实际通信能否被解密”作出任何结论，也不提供任何解密结果。完整证据局限见第 4 节。",
         fill="FFF2CC")
    spacer()


def build_summary():
    heading("1. 摘要", 1)
    para("本次评估针对 %s 的 native 密码学层 libmd.so 进行静态反编译，并在受控环境中验证其"
         "密码学行为，重点检查对称加密的密钥与初始向量管理，以及密钥协商的信任根管理。" % TARGET)
    para(("结论：libmd.so 的 AES-256-CBC 实现本身正确（已通过标准已知答案测试），但存在两处使用方式"
          "缺陷——固定初始向量与零填充；同时其 ECDH 对端公钥以明文常量硬编码于三套 ABI。三者共同"
          "削弱了协议层的机密性保障。以下逐项给出证据与修复建议。", "b"))
    table(["编号", "严重度", "发现", "受影响范围"], [
        ["F-01", ("高", "b"), "AES-256-CBC 使用固定初始向量（IV）", "libmd.so 对称加密路径"],
        ["F-02", "中", "AES-CBC 采用零填充，填充不具可逆唯一性", "libmd.so 对称加密路径"],
        ["F-03", "中", "ECDH 对端公钥硬编码且跨 ABI 一致，信任根不可更新", "libmd.so 密钥协商路径"],
        ["F-04", "提示", "加固与工程实践建议（混淆不构成安全边界等）", "整体设计"],
    ], W4, first_col_bold=True)
    para(("处置优先级：建议优先修复 F-01，其次 F-02 与 F-03。F-01 与 F-02 位于同一函数，"
          "可在同一次改动中一并处理。", "b"))
    spacer()


def build_scope_and_method():
    heading("2. 评估范围与方法", 1)

    heading("2.1 评估对象", 2)
    table(["项目", "值"], [
        ["应用包名", "com.hicorenational.antifraud"],
        ["版本", "2.0.27（versionCode 201）"],
        ["APK SHA-256", (APK_SHA, "c")],
        ["评估模块", "libmd.so（arm64-v8a）"],
        ["模块 SHA-256", (LIBMD_SHA, "c")],
    ], W2, first_col_bold=True)

    heading("2.2 方法", 2)
    bullet("静态分析：对 libmd.so 进行函数级反编译，定位对称加密、密钥协商与 JNI 入口的实现。")
    bullet("受控动态验证：在本地 arm64 指令级模拟环境中执行目标 native 代码，环境显式关闭真实网络"
           "（allow_real_network=false），并挂接系统调用观测点。两次网络平面运行均记录到 0 个 socket "
           "族系统调用、0 个创建的套接字。")
    bullet("密码学验证：以独立密码学库计算期望值，仅从执行轨迹中取字节作为输入，对被评估实现做已知"
           "答案测试（KAT）与确定性交叉验证。")
    bullet("运行时观测：在自建受控环境中以只读方式观测目标进程的 JNI 调用边界，仅用于确认 native 层"
           "实际调用的接口集合与调用顺序；不修改目标代码，不注入业务逻辑。")

    heading("2.3 本次评估未做的事", 2)
    bullet("未捕获任何真实网络流量：受控模拟运行中未执行任何 socket 族系统调用。")
    bullet("未与生产服务端发生任何交互：无真实请求、无账号操作、无界面自动化操作。")
    bullet("未获取任何真实会话密钥，未解密任何真实通信。")
    bullet("未进行拒绝服务、注入、篡改或权限提升类测试。")
    bullet("未评估服务端实现、传输层（TLS）配置、应用层鉴权与会话管理，以及除 libmd.so 之外的"
           "其他 native 库。")
    spacer()


def build_finding_01():
    heading("3. 发现", 1)
    heading("F-01（高）AES-256-CBC 使用固定初始向量（IV）", 2)
    para(("对称加密函数在每次调用时，都从一个字符串字面量把一个固定的 16 字节初始向量拷贝到栈上，"
          "并在随后的 CBC 加密过程中全程使用该向量。因此同一密钥下的不同次加密之间不存在 IV 随机化。",
          "b"))
    table(["项目", "值"], [
        ["函数", ("aes_256_cbc_encode @ 0x00111f0c（size 852）", "c")],
        ["函数签名", ("string aes_256_cbc_encode(uchar *password, string *data)", "c")],
        ["IV 装载点", ("反编译输出第 516 行", "c")],
        ["装载形式", ("builtin_memcpy(local_80, \"Eer'5P;41t?:?o-:\", 0x10)", "c")],
        ["IV（十六进制）", ("4565722735503b3431743f3a3f6f2d3a", "c")],
        ["IV 长度", "16 字节（128 位）"],
        ["IV 字面量位置", ("libmd.so 文件偏移 0x74de0（.rodata）", "c")],
        ["密钥设置", ("AES_set_encrypt_key(password, 0x100, ...) → 密钥长度 256 位", "c")],
        ["加密调用", ("AES_cbc_encrypt(src, out, 0x10, key, local_80, 1)，逐 16 字节块调用", "c")],
        ["模式确认", "标准 CBC 链式（非 ECB）：IV 缓冲由 AES_cbc_encrypt 原地更新并跨块传递"],
        ["调用路径", ("paramJsonEncode @ 0x00112ff0 与 getAppPubKey @ 0x0011274c 路径中均可达该函数", "c")],
    ], W2, first_col_bold=True)

    heading("影响", 3)
    bullet("CBC 模式下固定 IV 会使相同明文前缀产生相同密文前缀，破坏语义安全性（IND-CPA），"
           "使同一密钥下的多次加密可被跨消息比对。")
    bullet("该缺陷不依赖密钥是否泄露：即使密钥未知，密文本身即可暴露明文结构与复用模式。")
    bullet("初始向量的唯一性要求未被满足——每次加密应使用不可预测的新 IV，并随密文一并交付对端。")

    heading("修复建议", 3)
    bullet("每次加密使用密码学安全的随机源生成新 IV，并将 IV 与密文一同交付对端（通常置于密文前部）。")
    bullet("接收侧从密文前部读取 IV，其余部分即为密文。该改动会改变线格式，需与服务端协同发布，"
           "并建议保留版本协商与兼容期。")
    bullet("更彻底的做法见 F-04：迁移至 AEAD 模式（如 AES-GCM），同时解决 IV 管理与完整性保护问题。")
    spacer()


def build_finding_02():
    heading("F-02（中）AES-CBC 采用零填充，填充不具可逆唯一性", 2)
    para(("同一函数在加密前对明文进行块对齐填充，填充字节固定为 0x00，而非 PKCS#7 一类可逆填充。"
          "当明文长度恰为 16 字节整数倍时，额外补满一整块 16 字节零。", "b"))
    table(["项目", "值"], [
        ["填充逻辑位置", ("反编译输出第 529–557 行", "c")],
        ["填充字节", ("0x00 —— 零填充，非 PKCS#7", "c")],
        ["对齐规则", "长度非 16 整数倍时补至下一块边界；恰为整数倍时补满一整块 16 字节"],
        ["块循环", ("第 559–579 行：按 16 字节切分，逐块调用 AES_cbc_encrypt", "c")],
    ], W2, first_col_bold=True)

    heading("影响", 3)
    bullet("零填充不具可逆唯一性：明文尾部的 0x00 与填充字节无法区分，接收侧无法可靠判定并剥离填充。"
           "作为对照，形如 \"AB\" 与 \"AB\\x00\" 的明文在填充后的前置内容一致。")
    bullet("填充不携带长度信息，因此不能作为数据完整性的依据。")
    bullet("与 F-01 叠加时，明文的长度与边界信息在密文层面完全不可恢复，进一步降低了协议层的可验证性。")

    heading("待厂商确认项", 3)
    bullet("本次未评估解密侧函数（aes_256_cbc_decode）对填充及异常输入的处理路径。本报告不对其错误"
           "处理行为、也不对是否存在可观测的填充差异下任何结论。建议厂商一并复核该路径。")

    heading("修复建议", 3)
    bullet("改用携带长度信息且可唯一剥离的填充方案（例如 PKCS#7），或在协议层显式传递明文长度。")
    bullet("更彻底的做法见 F-04：迁移至 AEAD 模式，由认证标签同时承担完整性与边界校验职责。")
    spacer()


def build_finding_03():
    heading("F-03（中）ECDH 对端公钥硬编码且跨 ABI 一致，信任根不可更新", 2)
    para(("密钥协商使用一个硬编码在 .rodata 中的 P-256 点作为对端方；会话密钥由「应用侧私钥 × 该固定"
          "对端点」的 x 坐标导出。该常量在三套 ABI 中以完全相同的内容出现。", "b"))
    table(["项目", "值"], [
        ["协商函数", ("genECDHsharedsecret @ 0x00111350（size 168）；另有 16 字节跳转桩 @ 0x001107f0", "c")],
        ["密钥导出", ("会话密钥 = x(d_app × Q_peer)，Q_peer 为下列硬编码常量", "c")],
        ["曲线", "P-256（prime256v1）"],
        ["常量形态", "91 字节 SubjectPublicKeyInfo（SPKI），Base64 长度 124"],
        ["arm64-v8a 位置", (".rodata+0x41 @ 文件偏移 0x74c71", "c")],
        ["armeabi-v7a 位置", (".rodata+0x41 @ 文件偏移 0x500f1", "c")],
        ["armeabi 位置", (".rodata+0x41 @ 文件偏移 0x51085", "c")],
        ["同一性核对", "三套 ABI 中为同一点；且与应用自身公钥（getAppPubKey 返回值）不同，已逐字节核对"],
        ["公钥解析函数", ("pemString2key @ 0x00111164（size 148），内部调用 PEM_read_bio_EC_PUBKEY", "c")],
        ["公钥在线坐标", ("x = a1a6e23aceb986331a3db34baa7c8557e1d944f1d4f4e80030eed0bad43f3072", "c")],
        ["", ("y = 150781d39a9462169a0be86ed1fefd33c09f25c02301316a4d7a22a16d90a378", "c")],
    ], W2, first_col_bold=True)

    heading("影响", 3)
    bullet("客户端无法验证对端身份：信任根即出厂内嵌常量，既无证书链校验，也无服务端下发的签名校验"
           "通道，因此无法识别非预期对端。")
    bullet("密钥轮换依赖应用发版：三套 ABI 共用同一常量，无法按部署、环境或租户隔离密钥，缺乏轮换"
           "与吊销能力。")
    bullet("对端方向不具备前向保密：服务端方向的长期私钥成为该方向唯一秘密；一旦泄露，历史会话的"
           "保护强度将下降到仅剩应用侧一次性秘密一层。")
    bullet("该常量以明文形式存在于三套 ABI 的 .rodata 中，未做任何保护或混淆。")

    heading("明确不涉及的范围", 3)
    bullet("本报告不讨论、也不评估该常量所对应私钥的持有、保管或是否泄露的情况。")

    heading("修复建议", 3)
    bullet("引入可更新的信任根：由服务端下发对端公钥，并配合签名链或其他可验证凭据，避免把信任根"
           "固化在客户端二进制中。")
    bullet("建立密钥轮换与吊销机制，支持不依赖应用发版的密钥更新。")
    bullet("评估引入对端临时（ephemeral）公钥，以获得双向的前向保密。")
    spacer()


def build_finding_04():
    heading("F-04（提示）加固与工程实践建议", 2)
    bullet("代码混淆与加固不构成机密性边界。本次对象使用了第三方加固方案，并以间接方式注册 JNI 方法；"
           "这类措施提高分析成本，但不能保护密钥与初始向量的安全。安全属性必须由密码学与密钥管理"
           "保证——一旦混淆被绕过，明文常量将直接暴露。")
    bullet("native 层以明文形式保存密钥材料。建议将长期密钥改为运行时安全下发并支持更新，同时配合"
           "平台密钥库（Keystore）保护设备侧私钥。")
    bullet("当前对称加密为 CBC 模式，未提供完整性保护。建议迁移至 AEAD 模式（如 AES-GCM 或 "
           "ChaCha20-Poly1305），一并解决 IV 管理（F-01）、填充（F-02）与完整性校验三个问题。")
    bullet("建议为协议引入版本协商字段与算法标识，使上述迁移可在不中断既有客户端的前提下分批推进。")
    bullet("建议为 native 层密码学接口建立自动化回归测试，包含已知答案测试与随机 IV 唯一性断言，"
           "防止固定 IV 一类问题再次引入。")
    spacer()


def build_limitations():
    heading("4. 证据局限与未证实事项", 1)
    para(("为避免本报告的结论被误读或夸大，本节明确列出未能证实的事项，以及在本次范围内未被评估的"
          "部分。所有结论均以第 5 节所列证据为界。", "b"))

    heading("4.1 未获得的证据", 2)
    bullet("未捕获任何真实网络流量。受控模拟环境中执行的目标 native 代码未触发任何 socket 族系统调用，"
           "两次网络平面运行均记录套接字系统调用数 0、创建套接字数 0；观测点在同一批运行中已成功"
           "分类到非 socket 系统调用，因此其“无 socket”是一项测量结果，而非观测点未生效。")
    bullet("未获得任何真实会话密钥。应用侧一次性密钥材料未被恢复；一次恢复尝试得到的 32 字节经核对为"
           "随机数生成器的种子，而非椭圆曲线私钥（按大端与小端两种解释计算的标量乘法结果均与应用"
           "自身公钥不匹配）。该结果已如实记录，未据此推导任何结论。")
    bullet("未与生产服务端发生任何交互，因此不存在任何可用于验证的真实会话。")

    heading("4.2 关于一次自洽性验算的说明", 2)
    bullet("本次评估中的一次密钥协商验算，其作用仅限于验证派生算术与内存布局，并确认应用使用的是"
           "哪一枚静态对端密钥。该验算结果明确不是任何真实会话的密钥，不能用于解密任何真实通信。")

    heading("4.3 因此本报告不主张的内容", 2)
    bullet("不主张实际通信已被解密或可被解密，也不提供任何解密结果或明文样本。")
    bullet("不主张已在真实网络中完成任何形式的中间人、重放或篡改——本次未进行此类测试。")
    bullet("不主张服务端存在任何配置缺陷——服务端实现不在本次评估范围内。")

    heading("4.4 本次未评估项", 2)
    bullet("服务端实现、传输层（TLS）配置与证书校验策略。")
    bullet("应用层鉴权、会话管理与业务逻辑的访问控制。")
    bullet("解密侧函数 aes_256_cbc_decode 对填充与异常输入的处理路径（见 F-02 待确认项）。")
    bullet("除 libmd.so 之外的其他 native 库，以及应用的业务数据存储与日志。")
    spacer()


def build_evidence():
    heading("5. 最小复现证据", 1)
    para(("以下信息足以让厂商在自有环境中独立确认 F-01、F-02 与 F-03。本节不包含任何针对运行中"
          "目标的操作步骤。", "b"))

    heading("5.1 密码学实现正确性（已知答案测试）", 2)
    table(["测试项", "结果", "说明"], [
        ["AES-256 已知答案测试", ("6 / 6 通过", "b"), "含 FIPS-197 C.3 标准向量"],
        ["ECDH 派生算术验证", ("1 / 1 通过", "b"), "在与出厂常量相同的对端点上演算"],
        ["期望值来源", "独立密码学库计算", "仅从执行轨迹取字节作为输入"],
    ], W3, first_col_bold=True)
    para(("上述结果表明：对称加密与密钥协商的实现本身正确。F-01 与 F-02 属于使用方式缺陷，而非实现"
          "错误；因此修复应集中在调用约定与数据格式，而非替换密码学原语。", "b"))

    heading("5.2 定位信息", 2)
    table(["发现", "定位"], [
        ["F-01", ("aes_256_cbc_encode @ 0x00111f0c；IV 装载见第 516 行；IV 字面量 @ 文件偏移 0x74de0", "c")],
        ["F-02", ("同一函数内第 529–557 行（填充）与第 559–579 行（块循环）", "c")],
        ["F-03", ("genECDHsharedsecret @ 0x00111350；常量 @ .rodata+0x41（三套 ABI 偏移见 F-03 表）", "c")],
    ], W2, first_col_bold=True)

    heading("5.3 验证建议", 2)
    bullet("F-01：确认该函数在两次连续调用中是否使用同一 IV 值。若一致，则缺陷成立。")
    bullet("F-02：检查同一函数中填充字节的取值即可确认。")
    bullet("F-03：核对三套 ABI 中该偏移处常量的字节一致性即可确认。")
    spacer()


def build_remediation():
    heading("6. 修复建议与优先级", 1)
    table(["优先级", "编号", "建议", "备注"], [
        ["1", ("F-01", "b"), "每次加密使用随机 IV，并随密文一并传递", "改变线格式，需与服务端协同"],
        ["2", ("F-02", "b"), "改用可唯一剥离的填充，或显式传递明文长度", "可与 F-01 同批修改"],
        ["3", ("F-03", "b"), "引入可更新信任根与密钥轮换、吊销机制", "需服务端配合"],
        ["4", ("F-04", "b"), "迁移至 AEAD 模式；建立密码学回归测试", "中期规划"],
    ], W4, first_col_bold=True)
    para(("建议落地路径：短期先修复 F-01 与 F-02（位于同一函数，可在不更换密码学原语的前提下显著"
          "提升机密性）；随后将 F-03 的信任根改造与协议版本升级一并规划；中期迁移至 AEAD 模式。", "b"))
    spacer()


def build_timeline():
    heading("7. 披露时间线与联系方式", 1)
    table(["日期", "事项"], [
        [REPORT_DATE, "完成评估并形成本报告"],
        ["", "提交厂商 / 安全团队（待提交）"],
        ["", "厂商确认接收（建议 5 个工作日内）"],
        ["", "厂商反馈初步判断与修复计划"],
        ["", "修复验证与联合确认"],
        ["", "协调公开或结案（建议自确认接收起不超过 90 天，可协商）"],
    ], W2, first_col_bold=True)
    para("若厂商需要进一步技术澄清，或需要就任一项发现进行受限验证，可在建立沟通后按需提供。")
    table(["项目", "值"], [
        ["报告人 / 单位", SUBMITTER],
        ["联系方式", CONTACT],
        ["备用渠道", "［提交前填写］"],
    ], W2, first_col_bold=True)
    para(("说明：为避免信息在修复完成前扩散，本报告为受控分发文档，请勿转发至无关人员或公开渠道。",
          "b"), fill="FFF2CC")
    spacer()


def build_appendix_a():
    heading("附录 A：评估产物清单（SHA-256）", 1)
    table(["产物", "SHA-256"], [
        ["antifraud.apk", (APK_SHA, "c")],
        ["lib/arm64-v8a/libmd.so（评估对象）", (LIBMD_SHA, "c")],
        ["lib/arm64-v8a/libtnet-3.1.14.so（相关模块）", (LIBTNET_SHA, "c")],
        ["assets/libjiagu_vip_a64.so（相关模块，加固组件）", (JIAGU_SHA, "c")],
    ], W2, first_col_bold=True)
    para("以上哈希均由本地对原始文件重新计算得出，用于确保本报告的结论可被对应到确切的文件版本。")
    spacer()


def build_appendix_b():
    heading("附录 B：术语", 1)
    table(["术语", "说明"], [
        ["IV（初始向量）", "分组密码链式模式中用于第一个分组的初始输入；要求每次加密均不可预测且不重复"],
        ["CBC", "密码分组链接模式：每个明文分组先与前一分组密文异或，再送入加密"],
        ["AEAD", "带关联数据的认证加密，同时提供机密性与完整性（例如 AES-GCM）"],
        ["SPKI", "SubjectPublicKeyInfo，公钥的标准编码结构"],
        ["ECDH", "椭圆曲线 Diffie-Hellman 密钥协商"],
        ["前向保密", "长期密钥泄露后，历史会话密钥仍不可被恢复的性质"],
        ["KAT", "已知答案测试：以标准向量验证密码学实现的正确性"],
        ["零填充", "以固定字节（此处为 0x00）补齐到块边界的填充方式，不携带长度信息、不具可逆唯一性"],
    ], W2, first_col_bold=True)
    spacer()


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def _desktop_dir():
    for cand in [
        r"C:\Users\埃尔隆德\Desktop",
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        os.path.join(os.path.expanduser("~"), "Desktop"),
    ]:
        if cand and os.path.isdir(cand):
            return cand
    return os.getcwd()


def main():
    out = os.path.join(
        _desktop_dir(),
        "国家反诈中心客户端_安全评估与负责任披露报告_%s.docx"
        % REPORT_DATE.replace("-", ""),
    )

    build_masthead()
    build_scope_notice()
    build_summary()
    build_scope_and_method()
    build_finding_01()
    build_finding_02()
    build_finding_03()
    build_finding_04()
    build_limitations()
    build_evidence()
    build_remediation()
    build_timeline()
    build_appendix_a()
    build_appendix_b()

    path = write_docx(
        out,
        "国家反诈中心 Android 客户端安全评估与负责任披露报告",
        "协调披露材料 %s" % REPORT_NO,
        "Palantir Research",
        CREATED,
    )
    print("written : %s" % path)
    print("bytes   : %d" % os.path.getsize(path))
    print("blocks  : %d" % len(_body))
    return 0


if __name__ == "__main__":
    sys.exit(main())
