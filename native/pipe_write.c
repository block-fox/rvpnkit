/* pipe_write.c —— 找出「能真正 WriteFile 成功」的最小权限组合。
 *
 * 文件访问权限位（容易记错，这里列清楚）：
 *   FILE_READ_DATA      0x0001
 *   FILE_WRITE_DATA     0x0002     <- 写管道数据要的是这个
 *   FILE_APPEND_DATA    0x0004
 *   FILE_READ_ATTRIBUTES 0x0080
 *   SYNCHRONIZE         0x00100000
 *
 * 之前误把 FILE_APPEND_DATA(0x4) 当成 FILE_WRITE_DATA，所以能打开、
 * 但 WriteFile 仍然报错 5。
 *
 * 编译：zig cc -target x86_64-windows-gnu -O2 -o pipe_write.exe pipe_write.c
 */
#include <windows.h>
#include <stdio.h>

static const wchar_t *PATH = L"\\\\.\\pipe\\RadminVpnGuiChannel";

static void probe(DWORD access, const char *label)
{
    HANDLE h;
    DWORD wrote = 0;
    /* 一帧最小合法正文：长度前缀由 WriteFile 一起写，这里只写 4 字节长度 */
    BYTE buf[4] = { 4, 0, 0, 0 };
    BOOL ok;

    SetLastError(0);
    h = CreateFileW(PATH, access, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("  %-26s 打开失败 err=%d\n", label, (int)GetLastError());
        return;
    }

    SetLastError(0);
    ok = WriteFile(h, buf, 4, &wrote, NULL);
    printf("  %-26s 打开成功  WriteFile=%s err=%d wrote=%lu\n",
           label, ok ? "OK" : "失败", (int)GetLastError(), wrote);
    CloseHandle(h);
    Sleep(200);
}

int main(void)
{
    printf("测试各种掩码下的实际写入能力：\n\n");
    probe(0x00000001 | 0x00000002 | 0x00100000, "READ|WRITE_DATA|SYNC");
    probe(0x00000001 | 0x00000002 | 0x00000004 | 0x00100000, "R|WRITE|APPEND|SYNC");
    probe(0x00000002 | 0x00100000, "WRITE_DATA|SYNC");
    probe(0x00000002 | 0x00000004 | 0x00100000, "WRITE|APPEND|SYNC");
    probe(0x00000004 | 0x00100000, "APPEND|SYNC");
    probe(0x00000001 | 0x00000004 | 0x00100000, "READ|APPEND|SYNC");
    probe(0x00000001, "READ only");
    return 0;
}
