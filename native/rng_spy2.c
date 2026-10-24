// 第二版：除了记录调用者，还要记录随机缓冲区的**内容**和上层返回地址。
//
// 关键假设（已经被数据支持）：
//   RNG 产出 2*(n+1) 字节，令牌是 4*(n+1) 字节，
//   令牌前后两半的 u16 共享低字节。
// 只要拿到 RNG 实际填的那段字节，就能把拼装规则完全还原。
//
// 编译：
//   zig cc -target x86-windows-gnu -shared -O2 -o rng_spy2.dll rng_spy2.c -ladvapi32

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#define IAT_CRYPTGENRANDOM 0x1cf014u

typedef BOOL (WINAPI *PFN_CryptGenRandom)(uintptr_t hProv, DWORD cbBuffer, BYTE *pbBuffer);

static PFN_CryptGenRandom g_origCrypt = NULL;
static char        *g_base = NULL;
static char        *g_base_end = NULL;
static FILE        *g_log = NULL;
static CRITICAL_SECTION g_cs;
static int          g_depth = 0;

static void log_line(const char *fmt, ...)
{
    va_list ap;
    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
    LeaveCriticalSection(&g_cs);
}

// 在栈上找落在模块代码段里的返回地址，用来还原调用链
static void log_stack(const char *tag, unsigned char *sp)
{
    int found = 0;
    char buf[512];
    int n = 0;
    for (int i = 0; i < 256 && found < 6; i += 4) {
        char *v = *(char **)(sp + i);
        if (v > g_base && v < g_base_end) {
            n += sprintf(buf + n, " [%d]=rva0x%x", i, (unsigned)(v - g_base));
            found++;
            if (n > 400) break;
        }
    }
    if (found) log_line("  %s 栈上代码地址:%s", tag, buf);
}

static BOOL WINAPI Hook_CryptGenRandom(uintptr_t hProv, DWORD cbBuffer, BYTE *pbBuffer)
{
    void *ret = __builtin_return_address(0);
    BOOL ok;
    unsigned char *sp = (unsigned char *)__builtin_frame_address(0);
    unsigned char *buf_copy = NULL;

    if (g_depth > 0) return g_origCrypt(hProv, cbBuffer, pbBuffer);
    g_depth++;

    log_line("CryptGenRandom len=%lu caller_rva=0x%x", (unsigned long)cbBuffer,
             (unsigned)((char *)ret - g_base));

    if (pbBuffer && cbBuffer && cbBuffer <= 256) {
        buf_copy = (unsigned char *)malloc(cbBuffer);
        if (buf_copy) memcpy(buf_copy, pbBuffer, cbBuffer);
    }

    ok = g_origCrypt(hProv, cbBuffer, pbBuffer);

    if (ok && buf_copy) {
        char hex[700];
        DWORD i, n = 0;
        for (i = 0; i < cbBuffer && n < 640; i++)
            n += sprintf(hex + n, "%02x", buf_copy[i]);
        hex[n] = 0;
        log_line("  返回内容: %s", hex);
        free(buf_copy);
    }

    log_stack("上层", sp);
    g_depth--;
    return ok;
}

static void patch_slot(unsigned int rva, void *hook, void **saved)
{
    void **slot = (void **)(g_base + rva);
    DWORD old;
    if (saved) *saved = *slot;
    if (VirtualProtect(slot, sizeof(void *), PAGE_EXECUTE_READWRITE, &old)) {
        *slot = hook;
        VirtualProtect(slot, sizeof(void *), old, &old);
        log_line("patched IAT rva=0x%x old=%p", rva, *saved);
    } else {
        log_line("VirtualProtect 失败 rva=0x%x err=%lu", rva, GetLastError());
    }
}

static DWORD WINAPI worker(LPVOID param)
{
    char path[MAX_PATH];
    (void)param;
    InitializeCriticalSection(&g_cs);
    g_base = (char *)GetModuleHandleA(NULL);
    g_base_end = g_base + 0x00e00000;

    wsprintfA(path, "%s\\rng2_%lu.log",
              getenv("TEMP") ? getenv("TEMP") : ".", (unsigned long)GetCurrentProcessId());
    g_log = fopen(path, "wb");
    if (!g_log) return 1;

    log_line("=== rng_spy2 base=%p ===", g_base);
    patch_slot(IAT_CRYPTGENRANDOM, (void *)Hook_CryptGenRandom, (void **)&g_origCrypt);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}
