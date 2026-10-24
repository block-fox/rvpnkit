/* pipe_mask.c —— 用「具体权限位」而不是 GENERIC_* 来打开控制管道。
 *
 * 关键结论（由 pipe_open.c 的测试得出）：
 *   GENERIC_WRITE (0x40000000)        -> 拒绝访问(5)
 *   FILE_WRITE_DATA (0x00000004)      -> 通过(231=管道忙，说明 ACL 允许)
 *
 * 原因：GENERIC_WRITE 会被映射成 FILE_GENERIC_WRITE，其中包含
 * FILE_WRITE_ATTRIBUTES / FILE_WRITE_EA 等对命名管道不适用的位，
 * 管道的 ACL 没有授予这些位，于是整个请求被拒。
 * 直接请求「读写数据 + 同步」这几个真实需要的位就能通过。
 *
 * 编译：zig cc -target x86_64-windows-gnu -O2 -o pipe_mask.exe pipe_mask.c
 */
#include <windows.h>
#include <stdio.h>

#define FILE_READ_DATA   0x0001
#define FILE_WRITE_DATA  0x0004
#define SYNCHRONIZE_     0x00100000

int main(void)
{
    const wchar_t *path = L"\\\\.\\pipe\\RadminVpnGuiChannel";
    DWORD masks[] = {
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE_,   /* 0x00100005 */
        FILE_READ_DATA | FILE_WRITE_DATA,                   /* 0x00000005 */
        FILE_WRITE_DATA | SYNCHRONIZE_,                     /* 0x00100004 */
        FILE_WRITE_DATA,                                    /* 0x00000004 */
    };
    const char *names[] = {
        "R|W|SYNC", "R|W", "W|SYNC", "W"
    };
    int i, round, ok = 0;

    for (i = 0; i < 4; i++) {
        int success = 0, lastErr = 0;
        for (round = 0; round < 5; round++) {
            HANDLE h;
            SetLastError(0);
            h = CreateFileW(path, masks[i], 0, NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                success++;
                CloseHandle(h);
            } else {
                lastErr = (int)GetLastError();
            }
            Sleep(180);
        }
        printf("  %-10s 0x%08lx  5 次中成功 %d 次   最后错误=%d\n",
               names[i], masks[i], success, lastErr);
        if (success) ok++;
    }

    printf("\n结论: %s\n", ok ? "可以用具体权限位打开读写" : "全部失败");
    return 0;
}
