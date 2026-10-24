// 记录谁在调用随机数函数。
//
// 目的：令牌开头是 4 字节随机 IV，生成它的地方一定调用了随机源。
// 把 IAT 里的 CryptGenRandom / rand 换成我们的转发函数，记下返回地址，
// 就能得到「令牌函数」的准确位置。
//
// 编译（32 位目标，因为目标是 PE32）：
//   zig cc -target x86-windows-gnu -shared -O2 -o rng_spy.dll rng_spy.c

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#define IAT_CRYPTGENRANDOM 0x1cf014u   // RVA，对应 VA 0x5cf014
#define IAT_RAND           0x1d1778u   // RVA，对应 VA 0x5d1778

typedef BOOL (WINAPI *PFN_CryptGenRandom)(uintptr_t hProv, DWORD cbBuffer, BYTE *pbBuffer);
typedef int  (__cdecl *PFN_rand)(void);

static PFN_CryptGenRandom g_origCrypt = NULL;
static PFN_rand           g_origRand  = NULL;
static char              *g_base      = NULL;
static FILE              *g_log       = NULL;
static CRITICAL_SECTION   g_cs;
static int                g_ready     = 0;

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

static BOOL WINAPI Hook_CryptGenRandom(uintptr_t hProv, DWORD cbBuffer, BYTE *pbBuffer)
{
    void *ret = __builtin_return_address(0);
    log_line("CryptGenRandom len=%lu caller=%p  RVA=0x%x",
             (unsigned long)cbBuffer, ret,
             (unsigned)((char *)ret - g_base));
    return g_origCrypt(hProv, cbBuffer, pbBuffer);
}

static int __cdecl Hook_rand(void)
{
    void *ret = __builtin_return_address(0);
    log_line("rand caller=%p  RVA=0x%x", ret, (unsigned)((char *)ret - g_base));
    return g_origRand();
}

static void patch_slot(unsigned int rva, void *hook, void **saved)
{
    void **slot = (void **)(g_base + rva);
    DWORD old;
    if (saved) *saved = *slot;
    if (VirtualProtect(slot, sizeof(void *), PAGE_EXECUTE_READWRITE, &old)) {
        *slot = hook;
        VirtualProtect(slot, sizeof(void *), old, &old);
        log_line("patched IAT rva=0x%x  old=%p", rva, *saved);
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

    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    wsprintfA(path, "%s\\rng_spy_%lu_%lu.log",
              getenv("TEMP") ? getenv("TEMP") : ".", (unsigned long)pid, (unsigned long)tid);
    g_log = fopen(path, "wb");
    if (!g_log) return 1;

    log_line("=== rng_spy 启动  base=%p ===", g_base);

    patch_slot(IAT_CRYPTGENRANDOM, (void *)Hook_CryptGenRandom, (void **)&g_origCrypt);
    patch_slot(IAT_RAND,           (void *)Hook_rand,           (void **)&g_origRand);

    g_ready = 1;
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        // 不要在 DllMain 里做重活，开线程
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}
