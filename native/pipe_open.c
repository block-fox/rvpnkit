/* pipe_open.c —— 最小化的管道读写打开测试。
 *
 * 目的：判断「rvpnkit.exe 打开 Radmin 控制管道读写被拒（err=5）」到底是
 * 这个 exe 特有的问题，还是所有由当前 shell 派生的子进程都受同样的限制。
 *
 * 编译：zig cc -target x86_64-windows-gnu -O2 -o pipe_open.exe pipe_open.c
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    const wchar_t *path = L"\\\\.\\pipe\\RadminVpnGuiChannel";
    HANDLE h;
    int err;

    SetLastError(0);
    h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, 0, NULL);
    err = (int)GetLastError();
    if (h == INVALID_HANDLE_VALUE) {
        printf("RW  失败 err=%d\n", err);
    } else {
        printf("RW  成功\n");
        CloseHandle(h);
    }

    SetLastError(0);
    h = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    err = (int)GetLastError();
    if (h == INVALID_HANDLE_VALUE) {
        printf("RO  失败 err=%d\n", err);
    } else {
        printf("RO  成功\n");
        CloseHandle(h);
    }
    return 0;
}
