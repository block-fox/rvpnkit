/* pipe_open.c —— 逐个试探管道访问权限组合。
 *
 * 背景：rvpnkit.exe 用 GENERIC_READ|GENERIC_WRITE 打开 Radmin 控制管道
 * 一律得到 ERROR_ACCESS_DENIED(5)，只读却能成功。为了判断到底是
 * 「写权限被 ACL 拒了」还是「读写组合被拒」，这里把各种掩码分别试一遍。
 *
 * 如果单写能成功，就可以「一个只读句柄 + 一个只写句柄」绕开问题。
 *
 * 编译：zig cc -target x86_64-windows-gnu -O2 -o pipe_open.exe pipe_open.c
 */
#include <windows.h>
#include <stdio.h>

static void try_open(const wchar_t *path, DWORD access, const char *label)
{
    HANDLE h;
    SetLastError(0);
    h = CreateFileW(path, access, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        printf("  %-22s 0x%08lx  失败 err=%d\n", label, access, (int)GetLastError());
    else {
        printf("  %-22s 0x%08lx  成功\n", label, access);
        CloseHandle(h);
    }
}

int main(void)
{
    const wchar_t *path = L"\\\\.\\pipe\\RadminVpnGuiChannel";

    printf("管道: %ls\n\n", path);
    try_open(path, GENERIC_READ | GENERIC_WRITE, "READ|WRITE");
    try_open(path, GENERIC_READ, "READ");
    try_open(path, GENERIC_WRITE, "WRITE");
    try_open(path, 0x00040000, "FILE_READ_DATA");
    try_open(path, 0x00000004, "FILE_WRITE_DATA");
    try_open(path, 0x00000002, "FILE_ADD_FILE");
    try_open(path, 0x0012019B, "FILE_ALL_ACCESS");
    try_open(path, 0x00120116, "FILE_GENERIC_WRITE");
    try_open(path, 0x00120089, "FILE_GENERIC_READ");
    try_open(path, 0x0012019F, "FILE_GENERIC_ALL");
    try_open(path, 0x00000002 | 0x00000004, "WRITE_DATA|ADD_FILE");
    try_open(path, 0x00000004 | 0x00100000, "WRITE_DATA|SYNCHRONIZE");
    return 0;
}
