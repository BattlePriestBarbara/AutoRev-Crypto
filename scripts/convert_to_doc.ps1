# convert_to_doc.ps1 — 用本机 Office/WPS 的 COM 引擎把 .html / .docx 另存为
# 真正的 Word 97-2003 二进制 .doc（OLE2/CFB，而非改后缀）。
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File scripts\convert_to_doc.ps1 `
#       -Src <源文件> -Dst <目标.doc>
#
# 说明: wdFormatDocument = 0（Word 97-2003 二进制格式）。
#       转换后脚本会校验 OLE2 魔数 D0CF11E0A1B11AE1，非该魔数即判定失败。

param(
    [Parameter(Mandatory = $true)][string]$Src,
    [Parameter(Mandatory = $true)][string]$Dst
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Src)) { throw "source not found: $Src" }
$srcFull = (Resolve-Path -LiteralPath $Src).Path
$dstDir = Split-Path -Parent $Dst
if ($dstDir -and -not (Test-Path -LiteralPath $dstDir)) {
    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
}
if (Test-Path -LiteralPath $Dst) { Remove-Item -LiteralPath $Dst -Force }

$word = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    try { $word.Options.ConfirmConversions = $false } catch { }

    $doc = $word.Documents.Open($srcFull, $false, $true)
    $fmt = 0                      # wdFormatDocument (97-2003 binary)
    $doc.SaveAs([ref]$Dst, [ref]$fmt)
    $doc.Close([ref]0)
}
finally {
    if ($word -ne $null) {
        # 该 COM 引擎（WPS 仿真 Word 12.0）在 Quit() 阶段可能抛出
        # 0x800706BE / 0x800706BA —— 此时文档已保存完毕，不应让退出异常
        # 掩盖真正的转换结果，故此处吞掉退出异常并继续做魔数校验。
        try { $word.Quit() } catch { "note    : Quit() raised (ignored): 0x$('{0:X8}' -f $_.Exception.HResult)" }
        try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) } catch { }
    }
}

if (-not (Test-Path -LiteralPath $Dst)) { throw "conversion produced no output: $Dst" }

$bytes = [System.IO.File]::ReadAllBytes($Dst)
$magic = ($bytes[0..7] | ForEach-Object { $_.ToString('x2') }) -join ''
$ok = ($magic -eq 'd0cf11e0a1b11ae1')

"src     : $srcFull"
"dst     : $Dst"
"bytes   : $($bytes.Length)"
"magic   : $magic  (OLE2/CFB expected: d0cf11e0a1b11ae1)"
"verdict : $(if ($ok) { 'REAL_DOC_OK' } else { 'NOT_A_BINARY_DOC' })"

if (-not $ok) { exit 1 }
