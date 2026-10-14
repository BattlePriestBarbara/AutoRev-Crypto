<#
.SYNOPSIS
  ARM64 real-device native analysis pipeline for D:\base\antifraud.apk
  (360 jiagu VIP + DTC/dex2c).

.DESCRIPTION
  Why a real arm64 device: on the x86_64 LDPlayer instance the app's own libraries run inside
  the Native Bridge ARM guest space (/system/lib64/arm64/nb/*), so x86_64 Frida hooks observe
  nothing - only base.odex + libjiagu_vip_64.so are loaded natively and libc sees no app I/O.
  On arm64 everything is native, so the libc layer (open/read/write/mmap/socket/connect/send/
  recv) and the packer's JNI_OnLoad become observable.

  Phases
    0  preflight  : adb device present -> ABI gate (arm64-v8a ONLY) -> frida/server version pair
    1  frida-server: push -> chmod 755 -> start (su if available, else plain shell) -> verify
    2  install    : adb install -r <apk>
    3  root layer : hooks\root_bypass_arm64.js  (libc-level su/Magisk concealment)
    4  profile    : hooks\native_profile_arm64.js (native behaviour capture)
    5  capture    : both hooks loaded in ONE attach for $Seconds (run_native_session.py)
    6  extract    : JSONL -> apk_native_profile_arm64.json (aggregate_native_profile.py)

  Everything is teed to the transcript log. Nothing is written to the device except
  /data/local/tmp/frida-server and the installed package.

.EXAMPLE
  # dry run: show what would happen, touch nothing
  powershell -File D:\Palantir_Research\scripts\run_arm64_native_pipeline.ps1 -DryRun -Serial <serial>

.EXAMPLE
  # full 30 s capture with root concealment + maps scrubbing
  powershell -File D:\Palantir_Research\scripts\run_arm64_native_pipeline.ps1 -Serial <serial> -ScrubMaps

.NOTES
  The frida-mcp equivalent is: frida_push_server -> frida_run_hook(hook="native_profile_arm64").
  Use the MCP path when you want one hook in one session and the JSONL in D:\frida\out\scripts.
#>
[CmdletBinding()]
param(
    [string]$Serial = '',
    [string]$Apk = 'D:\base\antifraud.apk',
    [string]$Package = 'com.hicorenational.antifraud',
    [int]$Seconds = 30,
    [string]$Server = 'D:\frida\server\frida-server-17.18.0-android-arm64',
    [string]$LogFile = 'D:\Palantir_Research\logs\apk_native_analysis_arm64.txt',
    [string]$ProfileOut = 'D:\Palantir_Research\data\processed\apk_native_profile_arm64.json',
    [switch]$SkipInstall,
    [switch]$NoRootBypass,
    [switch]$ScrubMaps,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Adb = 'D:\frida\platform-tools\adb.exe'
$FridaExe = 'D:\frida\.venv\Scripts\frida.exe'
$FridaPs = 'D:\frida\.venv\Scripts\frida-ps.exe'
$Python = 'D:\frida\.venv\Scripts\python.exe'
$HooksDir = 'D:\frida\hooks'
$ScriptsDir = 'D:\Palantir_Research\scripts'
$OutDir = 'D:\frida\out\scripts'
$script:SelectedSerial = ''

function Step {
    param([string]$Text)
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
    $prefix = @()
    if ($script:SelectedSerial) { $prefix = @('-s', $script:SelectedSerial) }
    $all = $prefix + $Rest
    Write-Verbose ("adb " + ($all -join ' '))
    & $Adb @all
}

function Assert-File {
    param([string]$Path, [string]$What)
    if (-not (Test-Path -LiteralPath $Path)) { throw "$What not found: $Path" }
}

# ---------------------------------------------------------------------------------------
# Phase 0: preflight (adapter -> ABI gate -> version pairing)
# ---------------------------------------------------------------------------------------
Step 'Phase 0: preflight'

Assert-File $Adb 'adb'
Assert-File $FridaExe 'frida CLI'
Assert-File $Python 'venv python'
Assert-File $Server 'frida-server binary'
Assert-File $Apk 'target apk'

$deviceLines = & $Adb devices | Select-Object -Skip 1 | Where-Object { $_ -match "\sdevice\s*$" }
$serials = @()
foreach ($line in $deviceLines) {
    $trimmed = $line.Trim()
    if ($trimmed) { $serials += ($trimmed -split '\s+')[0] }
}
if (-not $serials) {
    throw "no adb device in 'device' state. Connect the arm64 phone over USB, enable USB debugging, accept the RSA prompt. (Emulator-only sessions must use the LDPlayer workflow instead.)"
}
if ($Serial) {
    if ($serials -notcontains $Serial) {
        throw "serial '$Serial' is not among the attached devices: $($serials -join ', ')"
    }
    $script:SelectedSerial = $Serial
} else {
    if ($serials.Count -gt 1) {
        Write-Warning "multiple devices attached ($($serials -join ', ')); using the first. Pass -Serial to be explicit."
    }
    $script:SelectedSerial = $serials[0]
}
Write-Host "[i] devices      : $($serials -join ', ')"
Write-Host "[i] selected     : $($script:SelectedSerial)"

$model = (Invoke-Adb shell getprop ro.product.model | Out-String).Trim()
$abi = (Invoke-Adb shell getprop ro.product.cpu.abi | Out-String).Trim()
$qemu = (Invoke-Adb shell getprop ro.kernel.qemu | Out-String).Trim()
$sdk = (Invoke-Adb shell getprop ro.build.version.sdk | Out-String).Trim()
Write-Host "[i] model/sdk    : $model / API $sdk"
Write-Host "[i] abi          : $abi (ro.kernel.qemu=$qemu)"

if ($abi -ne 'arm64-v8a') {
    throw "REFUSING to run: device '$($script:SelectedSerial)' reports ABI '$abi'. This pipeline is arm64-v8a only; on an x86_64/ARM-translation guest the app's libraries run inside the native-bridge guest space and Frida cannot observe them (see the earlier LDPlayer report, section 9.3). Use a real arm64 phone, or the x86_64 emulator workflow."
}
if ($qemu -eq '1') {
    Write-Warning 'ro.kernel.qemu=1: this looks like an emulator. Behaviour will differ from a physical device.'
}

$fridaVersion = (& $FridaExe --version | Out-String).Trim()
$serverVersion = ''
if ($Server -match '(\d+\.\d+\.\d+)') { $serverVersion = $Matches[1] }
if (-not $serverVersion) { throw "cannot read the version from the server filename: $Server" }
if ($fridaVersion -ne $serverVersion) {
    throw "version mismatch: frida CLI $fridaVersion vs frida-server $serverVersion. Mismatched versions fail with the misleading 'unable to communicate with remote frida-server'. Use the matching D:\frida\server\frida-server-$fridaVersion-android-arm64."
}
Write-Host "[i] frida        : CLI and server both $fridaVersion"

if ($DryRun) {
    Write-Host ''
    Write-Host '--- dry run: planned device actions ---' -ForegroundColor Yellow
    Write-Host "  adb -s $($script:SelectedSerial) push $Server /data/local/tmp/frida-server"
    Write-Host "  adb -s $($script:SelectedSerial) shell (su -c) 'chmod 755 /data/local/tmp/frida-server'"
    Write-Host "  adb -s $($script:SelectedSerial) shell (su -c) 'nohup /data/local/tmp/frida-server &'"
    if (-not $SkipInstall) {
        Write-Host "  adb -s $($script:SelectedSerial) install -r $Apk"
    }
    Write-Host "  adb -s $($script:SelectedSerial) shell \"monkey -p $Package -c android.intent.category.LAUNCHER 1\""
    Write-Host "  $Python $ScriptsDir\run_native_session.py --target <pid of $Package> --seconds $Seconds (hooks: root_bypass_arm64.js, native_profile_arm64.js)"
    Write-Host "  $Python $ScriptsDir\aggregate_native_profile.py --in $OutDir --out $ProfileOut"
    Write-Host ''
    Write-Host 'dry run complete - nothing was changed on the device.' -ForegroundColor Yellow
    return
}

$logDir = Split-Path -Parent $LogFile
if ($logDir -and -not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$outDir = $OutDir
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$profileDir = Split-Path -Parent $ProfileOut
if ($profileDir -and -not (Test-Path -LiteralPath $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force | Out-Null }

Start-Transcript -Path $LogFile -Append | Out-Null
$exitCode = 0
try {
    # -----------------------------------------------------------------------------------
    # Phase 1: frida-server
    # -----------------------------------------------------------------------------------
    Step 'Phase 1: frida-server (push -> chmod -> start -> verify)'
    $hasSu = $false
    try {
        $suProbe = (Invoke-Adb shell 'su -c id' | Out-String)
        if ($suProbe -match 'uid=0') { $hasSu = $true }
    } catch { $hasSu = $false }
    Write-Host "[i] su available : $hasSu"

    Invoke-Adb push $Server /data/local/tmp/frida-server | Out-String | Write-Host
    if ($hasSu) {
        Invoke-Adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'" | Out-String | Write-Host
        Invoke-Adb shell "su -c 'pkill -f /data/local/tmp/frida-server'" | Out-Null
        Invoke-Adb shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'" | Out-Null
    } else {
        Write-Warning 'no su: starting frida-server from the adb shell context (works on a userdebug/rooted-adb device, and universally on a Magisk device with adb-insecure)'
        Invoke-Adb shell 'chmod 755 /data/local/tmp/frida-server' | Out-String | Write-Host
        Invoke-Adb shell 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &' | Out-Null
    }
    Start-Sleep -Seconds 3
    $psOutput = (& $FridaPs -D $script:SelectedSerial 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -and $psOutput -notmatch 'PID') {
        throw "frida-server is not reachable: frida-ps -D $($script:SelectedSerial) failed -> $psOutput"
    }
    $procCount = ($psOutput -split "`n" | Where-Object { $_.Trim() }).Count
    Write-Host "[+] frida-server reachable ($procCount process lines)"

    # -----------------------------------------------------------------------------------
    # Phase 2: install the APK
    # -----------------------------------------------------------------------------------
    if ($SkipInstall) {
        Step 'Phase 2: install (skipped)'
    } else {
        Step 'Phase 2: install the APK'
        $install = Invoke-Adb install -r $Apk | Out-String
        Write-Host $install
        if ($install -notmatch 'Success') {
            Write-Warning 'adb install did not report Success - the app may already be the same version, or the install was refused (signature/space).'
        }
    }
    $installedPath = (Invoke-Adb shell "pm path $Package" | Out-String).Trim()
    if (-not $installedPath) { throw "$Package does not appear to be installed" }
    Write-Host "[i] installed    : $installedPath"

    # -----------------------------------------------------------------------------------
    # Phase 3+4: launch, then attach both hooks in one session
    # -----------------------------------------------------------------------------------
    Step 'Phase 3+4: launch and capture (root concealment + native profile, one attach)'
    Invoke-Adb shell 'input keyevent KEYCODE_WAKEUP' | Out-Null
    $launch = Invoke-Adb shell "monkey -p $Package -c android.intent.category.LAUNCHER 1" | Out-String
    Write-Host $launch
    $appPid = ''
    for ($i = 0; $i -lt 30; $i++) {
        $appPid = (Invoke-Adb shell "pidof $Package" | Out-String).Trim()
        if ($appPid) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $appPid) { throw "could not get a pid for $Package (the app may be crashing on startup - check 'adb logcat -d -b crash')" }
    $appPid = ($appPid -split '\s+')[0]
    Write-Host "[+] pid          : $appPid"
    Start-Sleep -Seconds 2

    $hooks = @()
    if (-not $NoRootBypass) {
        $hooks += '--js'
        $hooks += (Join-Path $HooksDir 'root_bypass_arm64.js')
    }
    $hooks += '--js'
    $hooks += (Join-Path $HooksDir 'native_profile_arm64.js')

    $sessionArgs = @(
        (Join-Path $ScriptsDir 'run_native_session.py'),
        '--target', $appPid,
        '--seconds', "$Seconds",
        '--label', 'native_profile_arm64',
        '--out', $OutDir,
        '--arg', "seconds=$Seconds",
        '--arg', "pkg=$Package",
        '--arg', "scrub_maps=$(if ($ScrubMaps) { 'true' } else { 'false' })"
    ) + $hooks
    Write-Host "[i] runner       : $Python $($sessionArgs -join ' ')"
    & $Python @sessionArgs
    $sessionExit = $LASTEXITCODE
    if ($sessionExit -ne 0) {
        Write-Warning "run_native_session.py exited with $sessionExit (no send() payload captured?)"
    }

    # -----------------------------------------------------------------------------------
    # Phase 5: extract the profile
    # -----------------------------------------------------------------------------------
    Step 'Phase 5: aggregate JSONL -> apk_native_profile_arm64.json'
    & $Python (Join-Path $ScriptsDir 'aggregate_native_profile.py') --in $OutDir --out $ProfileOut
    if ($LASTEXITCODE -ne 0) { Write-Warning 'aggregation failed - check the JSONL glob' }

    Step 'artifacts'
    Write-Host "log      : $LogFile"
    Write-Host "jsonl    : $OutDir"
    Write-Host "profile  : $ProfileOut"
} catch {
    $exitCode = 1
    Write-Host "`n[!] pipeline failed: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}

exit $exitCode
