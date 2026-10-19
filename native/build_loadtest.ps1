# Build the 32-bit loader test host (CRT-free style but standard link).
# Kept in a script so PowerShell can't mangle the linker arguments.
$ErrorActionPreference = 'Continue'
$zig = "C:\Users\冯乐潇\.zig\zig.exe"
$dir = "D:\工作区\workspace1\RvpnKit\native"
Set-Location $dir

Write-Output "=== 编译 loadtest32.exe ==="
& $zig cc -target x86-windows-gnu -O2 -o loadtest32.exe loadtest.c 2>&1
Write-Output "zig exit=$LASTEXITCODE"

if (Test-Path "$dir\loadtest32.exe") {
    Write-Output "`n=== 运行加载测试 ==="
    & "$dir\loadtest32.exe" 2>&1
    Write-Output "exit=$LASTEXITCODE"
} else {
    Write-Output "未生成可执行文件"
}
