/* whoami_il.c —— 打印本进程令牌的完整性级别（Integrity Level）。
 *
 * 用来验证一个假设：从当前 shell 派生的子进程可能被降到 Low 完整性，
 * 而 Radmin 控制管道的强制完整性策略要求 Medium 才能写 —— 这能同时解释
 * 「能读不能写」「Python 能写（它不在降级范围内）」两个现象。
 *
 * 编译：zig cc -target x86_64-windows-gnu -O2 -o whoami_il.exe whoami_il.c
 */
#include <windows.h>
#include <stdio.h>

static const char *il_name(DWORD rid)
{
    switch (rid) {
    case 0x0000: return "Untrusted";
    case 0x1000: return "Low";
    case 0x2000: return "Medium";
    case 0x2100: return "Medium-Plus";
    case 0x3000: return "High";
    case 0x4000: return "System";
    default:     return "?";
    }
}

int main(void)
{
    HANDLE tok = NULL;
    DWORD len = 0;
    BYTE buf[256];
    TOKEN_MANDATORY_LABEL *tml;
    DWORD rid = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        printf("OpenProcessToken 失败 err=%lu\n", GetLastError());
        return 1;
    }

    if (!GetTokenInformation(tok, TokenIntegrityLevel, buf, sizeof(buf), &len)) {
        printf("GetTokenInformation 失败 err=%lu\n", GetLastError());
        CloseHandle(tok);
        return 1;
    }

    tml = (TOKEN_MANDATORY_LABEL *)buf;
    if (tml->Label.Sid) {
        BYTE *sid = (BYTE *)tml->Label.Sid;
        int count = sid[1];
        rid = *(DWORD *)(sid + 8 + (count - 1) * 4);
    }

    printf("完整性级别: %s (0x%lx)\n", il_name(rid), rid);
    printf("进程 pid  : %lu\n", GetCurrentProcessId());

    /* 顺带说明令牌是否被限制 */
    {
        DWORD restricted = 0;
        if (GetTokenInformation(tok, TokenIsRestricted, &restricted,
                                sizeof(restricted), &len))
            printf("受限令牌  : %s\n", restricted ? "是" : "否");
    }

    CloseHandle(tok);
    return 0;
}
