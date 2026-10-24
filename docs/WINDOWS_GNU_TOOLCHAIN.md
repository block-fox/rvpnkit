# windows-gnu 工具链修复（让 raw-dylib 能编译）

本机没有 MSVC，Rust 用的是 `x86_64-pc-windows-gnu`。这个目标下如果依赖里出现
`raw-dylib` 链接属性（`parking_lot_core`、`libloading`、`windows-sys` 都有），
rustc 会调用 `dlltool` **现场生成导入库**，而 Rust 自带的 dlltool 只差两样东西：

1. `as.exe`（dlltool 需要它汇编导入桩）
2. 几个运行库 DLL

症状长这样：

```
error calling dlltool 'dlltool.exe': program not found
# 或者
dlltool could not create import library with ... : C:\rtools\dlltool.exe: CreateProcess
```

## 修法

### 1. 链接参数

`rust/.cargo/config.toml` 里已经写好（缺了会在编 proc-macro 时报
`ld: cannot find -lkernel32`）：

```toml
[target.x86_64-pc-windows-gnu]
rustflags = ["-C", "linker=rust-lld", "-C", "link-self-contained=yes"]
```

### 2. 补齐 dlltool + as

Rust 自带的 dlltool 在：

```
%USERPROFILE%\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\
    x86_64-pc-windows-gnu\bin\self-contained\dlltool.exe
```

把它连同同目录的 `libwinpthread-1.dll` 一起拷到一个**纯 ASCII 路径**
（用户名是中文时，MinGW 程序处理非 ASCII 路径会出错），然后补上 `as.exe`：

```powershell
# 1) 建目录并拷 dlltool
New-Item -ItemType Directory -Force C:\rtools
$sc = "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained"
Copy-Item "$sc\*" C:\rtools -Force

# 2) 从 MSYS2 拉 binutils（拿到 as.exe）
#    https://repo.msys2.org/mingw/mingw64/mingw-w64-x86_64-binutils-*.pkg.tar.zst
tar -xf binutils.pkg.tar.zst -C C:\rtools\binutils

# 3) 补 as.exe 需要的运行库：libintl-8 / libzstd / zlib1 / libiconv-2
#    分别来自 MSYS2 的 gettext / libiconv / zstd / zlib 包
#    可以直接跑 rust/_fetch_binutils_dlls.py 自动下好并拷进去
python rust\_fetch_binutils_dlls.py
```

### 3. 构建时把工具目录放在 PATH 前面

```powershell
$env:PATH = "C:\rtools\binutils\mingw64\bin;C:\rtools;$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:CARGO_TARGET_DIR = "C:\rtools\rvpn-target"   # 也放 ASCII 路径更稳
cargo build -p rvpn-gui --release
```

验证：`as.exe --version` 与 `dlltool.exe --version` 都能正常输出。

## 排查过程中走过的弯路

| 尝试 | 结果 |
|---|---|
| 直接用 Rust 自带 dlltool | `CreateProcess` 失败 —— 找不到 `as` |
| 只把 dlltool 拷到 ASCII 路径 | `STATUS_DLL_NOT_FOUND` —— 缺 `libwinpthread-1.dll` |
| 降级 `parking_lot_core` 到 0.9.6 | `parking_lot 0.12.5` 要求 ≥0.9.12；降 `parking_lot` 后 `libloading`/`windows-sys` 照样要 raw-dylib |
| 只加 `-C link-self-contained=yes` | 能修好 serde 这类普通依赖，修不了 raw-dylib |
| 只装 `llvm-tools` | 里面没有 `llvm-dlltool` |
| 直接下 MSYS2 binutils 但没补 DLL | dlltool/as 都报 `STATUS_DLL_NOT_FOUND` |

**结论**：三样缺一不可 —— 正确的链接参数、能跑的 dlltool、能跑的 as（含其运行库）。
