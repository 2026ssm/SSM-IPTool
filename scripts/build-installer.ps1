# Builds the Windows installer in one command. Run from the repo root on a
# Windows machine with:
#   - Node.js 18+ (npm included)  - Python 3 on PATH (node-gyp uses it)
#   - Visual Studio C++ Build Tools (Desktop development with C++)
#   - the three vendor SDKs, whose paths go straight into node-gyp:
#       -UnvSdkDir   (include\ and lib\NetDEVSDK.lib - env UNV_SDK_DIR)
#       -TvtSdkDir   (include\ and Windows\bin_release\Release_vcx_x64\DVR_NET_SDK.lib - env TVT_SDK_DIR)
#       -DahuaSdkDir (Include\Common\, Lib\Win64\dhnetsdk.lib and a Bin\ folder of runtime DLLs - env DAHUA_SDK_DIR)
#
# .\scripts\build-installer.ps1 -UnvSdkDir C:\SDK\uniview -TvtSdkDir C:\SDK\tvt -DahuaSdkDir C:\SDK\dahua
#
# Output: release\Simplified IP-Tool-Setup-<version>.exe (from package.json's version).

param(
  [string]$UnvSdkDir = $env:UNV_SDK_DIR,
  [string]$TvtSdkDir = $env:TVT_SDK_DIR,
  [string]$DahuaSdkDir = $env:DAHUA_SDK_DIR
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function Step($msg) { Write-Host "`n== $msg ==" -ForegroundColor Cyan }

if (-not $UnvSdkDir)   { Fail "Uniview SDK path missing - pass -UnvSdkDir or set UNV_SDK_DIR." }
if (-not $TvtSdkDir)   { Fail "TVT SDK path missing - pass -TvtSdkDir or set TVT_SDK_DIR." }
if (-not $DahuaSdkDir) { Fail "Dahua SDK path missing - pass -DahuaSdkDir or set DAHUA_SDK_DIR." }

if (-not (Test-Path "$UnvSdkDir\include"))       { Fail "Uniview SDK has no include\ folder: $UnvSdkDir" }
if (-not (Test-Path "$UnvSdkDir\lib\NetDEVSDK.lib")) { Fail "Uniview SDK is missing lib\NetDEVSDK.lib: $UnvSdkDir" }
if (-not (Test-Path "$TvtSdkDir\include"))       { Fail "TVT SDK has no include\ folder: $TvtSdkDir" }
if (-not (Test-Path "$TvtSdkDir\Windows\bin_release\Release_vcx_x64\DVR_NET_SDK.lib")) { Fail "TVT SDK is missing Windows\bin_release\Release_vcx_x64\DVR_NET_SDK.lib: $TvtSdkDir" }
if (-not (Test-Path "$DahuaSdkDir\Include\Common")) { Fail "Dahua SDK has no Include\Common\ folder: $DahuaSdkDir" }
if (-not (Test-Path "$DahuaSdkDir\Lib\Win64\dhnetsdk.lib")) { Fail "Dahua SDK is missing Lib\Win64\dhnetsdk.lib: $DahuaSdkDir" }
if (-not (Test-Path "$DahuaSdkDir\Bin"))         { Fail "Dahua SDK has no Bin\ folder (the runtime DLLs are copied from there): $DahuaSdkDir" }

$env:UNV_SDK_DIR   = $UnvSdkDir
$env:TVT_SDK_DIR   = $TvtSdkDir
$env:DAHUA_SDK_DIR = $DahuaSdkDir

Step "Installing node dependencies"
npm ci
if ($LASTEXITCODE -ne 0) { Fail "npm ci failed." }

Step "Building native addons (Uniview, TVT, Dahua)"
npm run build:unv-native ; if ($LASTEXITCODE -ne 0) { Fail "Uniview addon build failed." }
npm run build:tvt-native ; if ($LASTEXITCODE -ne 0) { Fail "TVT addon build failed." }
npm run build:dahua-native ; if ($LASTEXITCODE -ne 0) { Fail "Dahua addon build failed." }

foreach ($node in @('uniview', 'tvt', 'dahua')) {
  $bin = "native/$node/build/Release"
  if (-not (Test-Path $bin)) { Fail "Expected addon output folder is missing: $bin" }
  $count = (Get-ChildItem $bin -File).Count
  if ($count -lt 2) { Fail "$bin has $count file(s) - the addon or its runtime DLLs didn't build/copy." }
  Write-Host "  $bin OK ($count files)"
}

Step "Building the app (main, preload, renderer)"
npm run build
if ($LASTEXITCODE -ne 0) { Fail "electron-vite build failed." }

Step "Packaging the Windows installer"
npx electron-builder --win
if ($LASTEXITCODE -ne 0) { Fail "electron-builder failed." }

$artifact = Get-ChildItem release -Filter "SSM-IPTool-Setup-*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $artifact) { Fail "No installer found in release\ ." }
Write-Host "`nInstaller ready:" -ForegroundColor Green
Write-Host "  $($artifact.FullName)"
Write-Host "`nTo test it on this PC, run the installer (it creates a desktop and start-menu shortcut), then scan the network."