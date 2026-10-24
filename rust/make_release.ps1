#!/usr/bin/env pwsh
# 打发布包。用法：pwsh rust\make_release.ps1 -Version 0.2.0
param(
    [string]$Version = "0.2.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$bin = "C:\rtools\rvpn-target\release"
$name = "RvpnKit-$Version-win32"
$out = Join-Path $root "dist\$name"

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Force -Path $out | Out-Null

# 1) 可执行文件
foreach ($exe in @("rvpnkit-gui.exe", "rvpnkit.exe")) {
    $src = Join-Path $bin $exe
    if (-not (Test-Path $src)) { throw "缺少 $src，请先 cargo build --release" }
    Copy-Item $src $out
    Write-Host "  + $exe ($([math]::Round((Get-Item $src).Length/1MB,2)) MB)"
}

# 2) 说明与协议
Copy-Item (Join-Path $root "dist\README.txt") $out
Copy-Item (Join-Path $root "dist\LICENSE.txt") $out

# 3) 打包
$zip = Join-Path $root "dist\$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$out\*" -DestinationPath $zip -CompressionLevel Optimal
Write-Host ""
Write-Host "发布包: $zip"
Write-Host "大小:   $([math]::Round((Get-Item $zip).Length/1KB,1)) KB"
