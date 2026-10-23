/*
 * rvpipe_hook.c —— 抓取 Radmin VPN 控制管道的真实报文。
 *
 * 为什么要拦四个 API
 * ------------------
 * 最初只拦 TransactNamedPipe，结果装上后一条记录都没有 —— 说明 GUI 并不用
 * 它来发命令，而是走 WriteFile/ReadFile 的普通管道读写。因此这里同时拦截：
 *
 *     CreateFileW        —— 识别出控制管道的句柄，记住它
 *     WriteFile          —— 该句柄上的写入 = GUI → 服务的命令
 *     ReadFile           —— 该句柄上的读取 = 服务 → GUI 的响应/事件
 *     TransactNamedPipe  —— 少数场景仍可能使用
 *
 * 只对「CreateFileW 时看到路径含 RadminVpnGuiChannel」的句柄记录，避免把
 * 日志自身的写操作也录进去（否则会自我递归）。
 *
 * 编译（32 位，匹配目标进程）：
 *   zig cc -target x86-windows-gnu -shared -O2 -s -o rvpipe_hook.dll rvpipe_hook.c
 *
 * 配合「挂起启动」注入：CreateProcess(CREATE_SUSPENDED) → 注入 → ResumeThread，
 * 这样启动阶段的请求也能抓到。
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define MAXDUMP   4096
#define LOGCAP    (MAXDUMP * 4 + 4096)
#define MAXPIPES  16

static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_lock;
static BOOL g_lockReady = FALSE;

static volatile HANDLE g_pipes[MAXPIPES];
static volatile LONG g_pipeCount = 0;

static void *g_realCreate = NULL;
static void *g_realWrite = NULL;
static void *g_realRead = NULL;
static void *g_realTransact = NULL;

static volatile LONG g_patched = 0;

typedef HANDLE(WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                      DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *TransactNamedPipe_t)(HANDLE, LPVOID, DWORD, LPVOID, DWORD,
                                          LPDWORD, LPOVERLAPPED);

/* ---------------------------------------------------------------- logging */

static void log_text(const char *s)
{
    DWORD written = 0;
    if (g_log == INVALID_HANDLE_VALUE) return;
    /* 直接走 kernel32，绕开被 hook 的导入项 */
    WriteFile(g_log, s, (DWORD)strlen(s), &written, NULL);
}

static char g_buf[LOGCAP];

static void dump_to_buffer(const char *title, const void *data, DWORD len)
{
    const BYTE *p = (const BYTE *)data;
    DWORD shown = (len < MAXDUMP) ? len : MAXDUMP;
    size_t off = 0;
    DWORD i;

    off += (size_t)sprintf_s(g_buf + off, LOGCAP - off,
                             "\n=== %s len=%lu ===\nHEX:\n", title, len);

    for (i = 0; i < shown && off + 8 < LOGCAP; i++) {
        off += (size_t)sprintf_s(g_buf + off, LOGCAP - off, "%02x ", p[i]);
        if ((i & 15) == 15 && off + 2 < LOGCAP) {
            g_buf[off++] = '\n';
            g_buf[off] = 0;
        }
    }

    off += (size_t)sprintf_s(g_buf + off, LOGCAP - off, "\nASCII:\n");
    for (i = 0; i < shown && off + 2 < LOGCAP; i++) {
        g_buf[off++] = (p[i] >= 32 && p[i] < 127) ? (char)p[i] : '.';
        if ((i & 63) == 63 && off + 2 < LOGCAP) {
            g_buf[off++] = '\n';
            g_buf[off] = 0;
        }
    }
    if (off + 2 < LOGCAP) { g_buf[off++] = '\n'; g_buf[off] = 0; }

    log_text(g_buf);
}

/* ------------------------------------------------------- pipe bookkeeping */

static void remember_pipe(HANDLE h)
{
    LONG n = g_pipeCount;
    if (n >= MAXPIPES) return;
    g_pipes[n] = h;
    InterlockedIncrement(&g_pipeCount);
}

static BOOL is_pipe(HANDLE h)
{
    LONG n = g_pipeCount, i;
    if (!h || h == INVALID_HANDLE_VALUE) return FALSE;

    /* 先看是不是我们见过打开动作的句柄 */
    for (i = 0; i < n; i++)
        if (g_pipes[i] == h) return TRUE;

    /*
     * 关键补充：运行中注入时，目标进程往往**早就连上了管道**，
     * 我们根本没见到它的 CreateFileW。此时仅靠 g_pipes 判断会永远返回
     * FALSE，写入一条都抓不到（本项目实际踩过这个坑）。
     * 因此退回按句柄类型判断：命名管道一律视为候选。
     * 日志文件本身是磁盘句柄（FILE_TYPE_DISK），不会被误判、不会自我递归。
     */
    return GetFileType(h) == FILE_TYPE_PIPE;
}

/* ------------------------------------------------------------ the hooks */

/*
 * Radmin 控制帧的信封魔数。
 *
 * 只靠「是不是命名管道」过滤不够：放宽后会把系统其它管道的流量也录进来
 * （实测抓到大量 protobuf 遥测，payload 里甚至带 RvRvpnGui.exe 字样，
 *  极易误判为命令）。Radmin 的帧固定以这 6 字节开头，用它精确过滤。
 */
static const BYTE g_magic[6] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00 };

static BOOL looks_like_radmin(const void *buf, DWORD n)
{
    if (!buf || n < sizeof(g_magic)) return FALSE;
    return memcmp(buf, g_magic, sizeof(g_magic)) == 0;
}

static HANDLE WINAPI hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share,
                                      LPSECURITY_ATTRIBUTES sa, DWORD disp,
                                      DWORD flags, HANDLE tmpl)
{
    CreateFileW_t real = (CreateFileW_t)g_realCreate;
    HANDLE h = real(name, access, share, sa, disp, flags, tmpl);

    if (h != INVALID_HANDLE_VALUE && name && wcsstr(name, L"RadminVpnGuiChannel")) {
        char line[200];
        remember_pipe(h);
        sprintf_s(line, sizeof(line),
                  "\n### pipe handle opened: 0x%p (access=0x%lx flags=0x%lx)\n",
                  h, access, flags);
        log_text(line);
    }
    return h;
}

static BOOL WINAPI hook_WriteFile(HANDLE h, LPCVOID buf, DWORD n,
                                  LPDWORD written, LPOVERLAPPED ov)
{
    WriteFile_t real = (WriteFile_t)g_realWrite;
    BOOL ok;

    /* 长度用调用方给出的 n，天然安全 */
    if (buf && n <= 1024 * 1024 && is_pipe(h) && looks_like_radmin(buf, n)) {
        if (g_lockReady) EnterCriticalSection(&g_lock);
        dump_to_buffer("OUT (WriteFile)", buf, n);
        if (g_lockReady) LeaveCriticalSection(&g_lock);
    }
    ok = real(h, buf, n, written, ov);
    return ok;
}

/*
 * 注意：这里**故意不 hook ReadFile**。
 *
 * 早期版本 hook 了 ReadFile，进程会偶发崩溃。原因是 Qt 走的是重叠 I/O：
 * ReadFile 返回 TRUE 时 *got 可能仍是未定义值，甚至大于请求长度 n，
 * 按 *got 去读 buf 就会越界访问。
 * 而我们要的是「GUI 发出的命令」，那全在 WriteFile 上，读方向不必拦。
 */

static BOOL WINAPI hook_TransactNamedPipe(HANDLE h, LPVOID w, DWORD nw,
                                          LPVOID r, DWORD nr, LPDWORD got,
                                          LPOVERLAPPED ov)
{
    TransactNamedPipe_t real = (TransactNamedPipe_t)g_realTransact;
    DWORD cb = 0;
    BOOL ok;

    if (is_pipe(h) && w && nw && nw <= 1024 * 1024) {
        if (g_lockReady) EnterCriticalSection(&g_lock);
        dump_to_buffer("OUT (Transact)", w, nw);
        if (g_lockReady) LeaveCriticalSection(&g_lock);
    }

    ok = real(h, w, nw, r, nr, &cb, ov);

    /* 用 cb 与请求长度取小值，避免读到缓冲区之外 */
    if (is_pipe(h) && r && cb) {
        DWORD safe = (cb < nr) ? cb : nr;
        if (safe > 0 && safe <= 1024 * 1024) {
            if (g_lockReady) EnterCriticalSection(&g_lock);
            dump_to_buffer("IN (Transact)", r, safe);
            if (g_lockReady) LeaveCriticalSection(&g_lock);
        }
    }
    if (got) *got = cb;
    return ok;
}

/* --------------------------------------------------------- IAT patching */

static BOOL patch_one(HMODULE mod, const char *funcName, void *replacement,
                      void **origSlot)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *imp;
    IMAGE_IMPORT_DESCRIPTOR *desc;

    if (!base) return FALSE;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    imp = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp->VirtualAddress) return FALSE;

    desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp->VirtualAddress);
    for (; desc->Name; desc++) {
        const char *dll = (const char *)(base + desc->Name);
        IMAGE_THUNK_DATA *orig, *iat;

        if (_stricmp(dll, "KERNEL32.dll") != 0 &&
            _stricmp(dll, "KernelBase.dll") != 0)
            continue;

        orig = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
        iat = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
        if (!desc->OriginalFirstThunk) orig = iat;

        for (; orig->u1.AddressOfData; orig++, iat++) {
            DWORD oldProt = 0;
            IMAGE_IMPORT_BY_NAME *ibn;

            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            ibn = (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
            if (strcmp((const char *)ibn->Name, funcName) != 0) continue;

            if ((void *)iat->u1.Function == replacement) return TRUE;  /* 已补过 */
            if (origSlot && !*origSlot) *origSlot = (void *)iat->u1.Function;

            if (!VirtualProtect(&iat->u1.Function, sizeof(void *),
                                PAGE_READWRITE, &oldProt))
                return FALSE;
            iat->u1.Function = (ULONG_PTR)replacement;
            VirtualProtect(&iat->u1.Function, sizeof(void *), oldProt, &oldProt);
            InterlockedIncrement(&g_patched);
            return TRUE;
        }
    }
    return FALSE;
}

/* 给一个模块补需要拦截的 API，返回新补的数量 */
static int patch_module(HMODULE mod)
{
    int n = 0;
    n += patch_one(mod, "CreateFileW", (void *)hook_CreateFileW, &g_realCreate) ? 1 : 0;
    n += patch_one(mod, "WriteFile", (void *)hook_WriteFile, &g_realWrite) ? 1 : 0;
    n += patch_one(mod, "TransactNamedPipe", (void *)hook_TransactNamedPipe,
                   &g_realTransact) ? 1 : 0;
    return n;
}

static int patch_all_modules(void)
{
    HANDLE snap;
    MODULEENTRY32 me;
    int total = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return 0;

    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            total += patch_module((HMODULE)me.modBaseAddr);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return total;
}

/* ----------------------------------------------------------------- setup */

static BOOL open_log(void)
{
    wchar_t wpath[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, wpath);

    if (n == 0 || n >= MAX_PATH) wcscpy_s(wpath, MAX_PATH, L"C:\\Windows\\Temp\\");
    wcscat_s(wpath, MAX_PATH, L"rvpipe_hook.log");

    g_log = CreateFileW(wpath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    return g_log != INVALID_HANDLE_VALUE;
}

static DWORD WINAPI worker(LPVOID param)
{
    char line[200];
    int round;

    (void)param;
    for (round = 0; round < 600; round++) {
        int added = patch_all_modules();
        if (added > 0) {
            sprintf_s(line, sizeof(line), "rescan %d: patched %d import slot(s)\n",
                      round, added);
            log_text(line);
        }
        Sleep(150);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        char line[200];
        HANDLE th;

        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_lock);
        g_lockReady = TRUE;

        if (!open_log()) return TRUE;

        sprintf_s(line, sizeof(line), "rvpipe_hook attached pid=%lu\n",
                  GetCurrentProcessId());
        log_text(line);

        /*
         * 在 DllMain 返回前同步补齐主模块，确保「恢复运行后立刻发出的请求」
         * 也能被捕获；后台线程只负责后续加载的 DLL。
         */
        {
            int n = patch_module(GetModuleHandleW(NULL));
            sprintf_s(line, sizeof(line),
                      "main module: patched %d import slot(s)\n", n);
            log_text(line);
        }

        th = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
    return TRUE;
}
