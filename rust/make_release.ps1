param(
    [ValidatePattern('^\d+\.\d+\.\d+([-.][A-Za-z0-9.-]+)?$')]
    [string]$Version = '0.4.0',
    [string]$TargetDirectory,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $TargetDirectory) {
    $TargetDirectory = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $PSScriptRoot 'target' }
}
$TargetDirectory = [System.IO.Path]::GetFullPath($TargetDirectory)
if (-not $SkipBuild) {
    Push-Location $PSScriptRoot
    try {
        cargo build --workspace --release --locked --target-dir $TargetDirectory
        if ($LASTEXITCODE -ne 0) { throw 'Cargo build failed.' }
    } finally { Pop-Location }
}
$name = "RvpnKit-$Version-windows-x64"
$out = Join-Path $root "dist\$name"
$zip = "$out.zip"
if ((Test-Path -LiteralPath $out) -or (Test-Path -LiteralPath $zip)) { throw "发布目录已存在：$out。请指定不同版本或自行归档旧文件。" }
# Validate sources before creating output.
foreach ($exe in @('rvpnkit-gui.exe','rvpnkit.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $TargetDirectory "release\$exe"))) { throw "缺少 $exe，请先完成 release 构建。" }
}
New-Item -ItemType Directory -Force -Path $out | Out-Null
foreach ($exe in @('rvpnkit-gui.exe','rvpnkit.exe')) { Copy-Item -LiteralPath (Join-Path $TargetDirectory "release\$exe") -Destination $out }
$readme = @"
RvpnKit $Version — Windows x64
=============================

这是 Radmin VPN 的非官方第三方客户端，不包含 VPN 驱动。
实际联机需要先安装并运行官方 Radmin VPN 服务。

快速运行
--------
rvpnkit-gui.exe       原生图形界面，双击即可启动。
rvpnkit.exe           本地 WebUI，启动后自动打开浏览器。
                     默认地址：http://127.0.0.1:8788

无服务预览（在当前目录的 PowerShell 中运行）
------------------------------------------
.\rvpnkit-gui.exe --demo
.\rvpnkit.exe --demo

演示模式使用内置示例数据，只读运行，不会发送真实 VPN 命令。
正常模式下服务暂时不可用时，界面仍会打开；启动官方服务后刷新即可。
WebUI 运行期间请保留控制台，按 Ctrl+C 停止服务。

可选参数
--------
.\rvpnkit.exe --no-open                  不自动打开浏览器。
.\rvpnkit.exe --addr 127.0.0.1:8789      修改监听地址。
.\rvpnkit-gui.exe --demo --page=members  预览成员页面。

界面支持网络收藏与搜索、成员筛选和导出、活动记录、浅深色主题。
加入、创建和成员管理操作以服务返回结果为准。
成员页会显示服务实际返回的虚拟地址、在线状态、角色、通道、延迟和产品版本；缺失字段显示为未知。
导出的 JSON 不包含密码令牌，但仍可能包含成员地址，请妥善保管。

源码与完整使用说明
------------------
https://github.com/block-fox/rvpnkit
https://github.com/block-fox/rvpnkit/blob/main/docs/README.md

本项目与 Famatech / Radmin VPN 无隶属关系。
请仅在你有权管理的网络中使用。协议变更可能影响兼容性。
"@
Set-Content -LiteralPath (Join-Path $out 'README.txt') -Value $readme -Encoding utf8
if (Test-Path -LiteralPath (Join-Path $root 'dist\LICENSE.txt')) { Copy-Item -LiteralPath (Join-Path $root 'dist\LICENSE.txt') -Destination $out }
Compress-Archive -Path (Join-Path $out '*') -DestinationPath $zip -CompressionLevel Optimal
Write-Host "发布包：$zip"
