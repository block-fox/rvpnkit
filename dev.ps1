param(
    [Parameter(Position=0)]
    [ValidateSet('build','test','web','gui','demo-web','demo-gui','package')]
    [string]$Action = 'build',
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$cargoPath = if ($cargo) { $cargo.Source } else { $null }
if (-not $cargo) {
    $candidate = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $candidate) { $cargoPath = $candidate }
    else { throw '找不到 cargo。请先安装 Rust stable，并重新打开终端。' }
}
# Optional compatibility with the existing Windows GNU installation.
if (Test-Path 'C:\rtools\binutils\mingw64\bin\as.exe') {
    $env:PATH = "C:\rtools\binutils\mingw64\bin;C:\rtools;$env:PATH"
}
Push-Location (Join-Path $PSScriptRoot 'rust')
try {
    $flags = @('--workspace', '--release', '--locked')
    if ($Offline) { $flags += '--offline' }
    if ($Action -eq 'test') {
        & $cargoPath test @flags
        if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed.' }
        & $cargoPath fmt --all -- --check
        if ($LASTEXITCODE -ne 0) { throw 'Formatting check failed.' }
        return
    }
    & $cargoPath build @flags
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed.' }
    $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $PWD 'target' }
    $target = [System.IO.Path]::GetFullPath($target)
    switch ($Action) {
        'web' { & (Join-Path $target 'release\rvpnkit.exe') }
        'gui' { & (Join-Path $target 'release\rvpnkit-gui.exe') }
        'demo-web' { & (Join-Path $target 'release\rvpnkit.exe') --demo }
        'demo-gui' { & (Join-Path $target 'release\rvpnkit-gui.exe') --demo }
        'package' { & (Join-Path $PWD 'make_release.ps1') -SkipBuild -TargetDirectory $target }
    }
} finally { Pop-Location }
