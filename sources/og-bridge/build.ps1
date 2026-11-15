param(
    [Parameter(Mandatory=$true)][string]$BspPath,
    [Parameter(Mandatory=$true)][string]$PicoSdkPath,
    [Parameter(Mandatory=$true)][string]$PicotoolPath,
    [string]$ToolchainPath = $env:PICO_TOOLCHAIN_PATH,
    [ValidateRange(1,16)][int]$Jobs = 6
)
$ErrorActionPreference = 'Stop'
$resolvedBsp = (Resolve-Path -LiteralPath $BspPath).Path
$resolvedSdk = (Resolve-Path -LiteralPath $PicoSdkPath).Path
$resolvedPicotool = (Resolve-Path -LiteralPath $PicotoolPath).Path
if ($ToolchainPath) { $env:PICO_TOOLCHAIN_PATH = (Resolve-Path -LiteralPath $ToolchainPath).Path }
$bridgePython = (Get-Command python -ErrorAction Stop).Source
Get-Command cmake, ninja -ErrorAction Stop | Out-Null
& cmake -S $PSScriptRoot -B (Join-Path $PSScriptRoot 'build') -G Ninja `
    "-DFWOG_BSP=$resolvedBsp" "-DPICO_SDK_PATH=$resolvedSdk" `
    "-DPICOTOOL_EXECUTABLE=$resolvedPicotool" "-DPython3_EXECUTABLE=$bridgePython" `
    -DFWOG_LINK_BAUD=6250000
if ($LASTEXITCODE -ne 0) { throw 'Bridge configuration failed.' }
& cmake --build (Join-Path $PSScriptRoot 'build') --target bnbridge_main bl_display -j $Jobs
if ($LASTEXITCODE -ne 0) { throw 'Bridge build failed.' }
