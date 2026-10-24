/*
 * rvpn_capture.c —— 常驻命令抓取器（注入 RvRvpnGui.exe 后长期记录）
 *
 * 与 rvpipe_hook.c 的区别
 * ----------------------
 * 1. 日志用「追加 + 每次注入独立文件名」，不再 CREATE_ALWAYS 截断。
 *    早期版本每次注入都会把前面抓到的内容清掉，导致刚抓到的命令被下一次
 *    注入抹掉（实际踩过）。
 * 2. 每条帧带本地时间戳，便于和服务日志按时间对齐。
 * 3. 只记录 Radmin 控制帧（按信封魔数 00 00 00 04 01 00 过滤）。
 *    不这样过滤会混入系统其它命名管道的 protobuf 遥测流量。
 * 4. 不做无意义的 rescan 日志刷屏。
 *
 * 编译（32 位，匹配目标进程）：
 *   zig cc -target x86-windows-gnu -shared -O2 -s -o rvpn_capture32.dll rvpn_capture.c
 *
 * 使用：配合 capture.py 注入；日志写在 %TEMP%\rvpn_capture\ 下。
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#define MAXDUMP 8192
#define LOGPATH_MAX 512

static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_lock;
static BOOL g_lockReady = FALSE;
static void *g_realWrite = NULL;
static void *g_realTransact = NULL;
static volatile LONG g_frames = 0;
static volatile LONG g_is_reply = 0;

/* 前向声明：下面的 TransactNamedPipe 钩子先用到这几个，定义在后面 */
static BOOL is_radmin_frame(const void *buf, DWORD n);
static void dump_frame(const void *data, DWORD len);

typedef BOOL(WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *TransactNamedPipe_t)(HANDLE, LPVOID, DWORD, LPVOID, DWORD,
                                          LPDWORD, LPOVERLAPPED);

/*
 * 有些命令不走 WriteFile 而走 TransactNamedPipe（同步请求-应答）。
 * 实测：点界面上的电源开关触发了服务端 "Switched Off / Switched On"，
 * 但只 hook WriteFile 时一条都没抓到 —— 就是因为它走的是这个 API。
 */
static BOOL WINAPI hook_TransactNamedPipe(HANDLE h, LPVOID w, DWORD nw,
                                          LPVOID r, DWORD nr, LPDWORD got,
                                          LPOVERLAPPED ov)
{
    TransactNamedPipe_t real = (TransactNamedPipe_t)g_realTransact;
    DWORD cb = 0;
    BOOL ok;

    if (w && nw <= 1024 * 1024 && is_radmin_frame(w, nw)) {
        if (g_lockReady) EnterCriticalSection(&g_lock);
        dump_frame(w, nw);
        InterlockedIncrement(&g_frames);
        if (g_lockReady) LeaveCriticalSection(&g_lock);
    }

    ok = real(h, w, nw, r, nr, &cb, ov);

    if (ok && r && cb) {
        DWORD safe = (cb < nr) ? cb : nr;
        if (safe && is_radmin_frame(r, safe)) {
            if (g_lockReady) EnterCriticalSection(&g_lock);
            g_is_reply = 1;
            dump_frame(r, safe);
            g_is_reply = 0;
            if (g_lockReady) LeaveCriticalSection(&g_lock);
        }
    }
    if (got) *got = cb;
    return ok;
}

/* Radmin 控制帧的信封魔数，两个方向都一样 */
static const BYTE g_magic[6] = { 0x00, 0x00, 0x00, 0x04, 0x01, 0x00 };

static BOOL is_radmin_frame(const void *buf, DWORD n)
{
    const BYTE *p = (const BYTE *)buf;
    if (!buf || n < 8) return FALSE;

    /* 常规情况：信封魔数 */
    if (memcmp(buf, g_magic, sizeof(g_magic)) == 0) return TRUE;

    /*
     * 放宽判定。
     *
     * 早先只认魔数，结果点界面上的电源开关时一条都抓不到 —— 尽管服务端
     * 确实记录了 Switched Off/On。说明那种命令的首记录与常规命令不同。
     * 这里再接受「首 4 字节是大端的合理长度，且第 7 字节是记录里的 0x03」
     * 的形状，尽量不漏。宁可多记一点噪音，事后还能筛。
     */
    {
        DWORD size = ((DWORD)p[0] << 24) | ((DWORD)p[1] << 16)
                   | ((DWORD)p[2] << 8) | (DWORD)p[3];
        if (size <= n - 8 && p[6] == 0x03) return TRUE;
    }
    return FALSE;
}

static void timestamp(char *out, size_t cap)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(out, cap, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static void dump_frame(const void *data, DWORD len)
{
    static char buf[MAXDUMP * 4 + 1024];
    const BYTE *p = (const BYTE *)data;
    DWORD shown = (len < MAXDUMP) ? len : MAXDUMP;
    char ts[40];
    size_t off = 0;
    DWORD i;

    timestamp(ts, sizeof(ts));

    off += (size_t)sprintf_s(buf + off, sizeof(buf) - off,
                             "\\n=== %s %s len=%lu%s ===\\nHEX:\\n", ts, g_is_reply ? "IN " : "OUT", len, (len > shown) ? " TRUNCATED" : "");

    for (i = 0; i < shown && off + 8 < sizeof(buf); i++) {
        off += (size_t)sprintf_s(buf + off, sizeof(buf) - off, "%02x ", p[i]);
        if ((i & 15) == 15 && off + 2 < sizeof(buf)) {
            buf[off++] = '\n';
            buf[off] = 0;
        }
    }

    off += (size_t)sprintf_s(buf + off, sizeof(buf) - off, "\nASCII:\n");
    for (i = 0; i < shown && off + 2 < sizeof(buf); i++) {
        buf[off++] = (p[i] >= 32 && p[i] < 127) ? (char)p[i] : '.';
        if ((i & 63) == 63 && off + 2 < sizeof(buf)) {
            buf[off++] = '\n';
            buf[off] = 0;
        }
    }
    if (off + 2 < sizeof(buf)) { buf[off++] = '\n'; buf[off] = 0; }

    if (g_log != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(g_log, buf, (DWORD)strlen(buf), &written, NULL);
    }
}

static BOOL WINAPI hook_WriteFile(HANDLE h, LPCVOID buf, DWORD n,
                                  LPDWORD written, LPOVERLAPPED ov)
{
    WriteFile_t real = (WriteFile_t)g_realWrite;
    BOOL ok;

    if (n >= sizeof(g_magic) && n <= 1024 * 1024 && is_radmin_frame(buf, n)) {
        if (g_lockReady) EnterCriticalSection(&g_lock);
        dump_frame(buf, n);
        InterlockedIncrement(&g_frames);
        if (g_lockReady) LeaveCriticalSection(&g_lock);
    }

    ok = real(h, buf, n, written, ov);
    return ok;
}

/* 在一个模块的导入表里把 WriteFile 换掉。返回 2=新补 1=已补 0=无导入 */
static int patch_module(HMODULE mod)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *imp;
    IMAGE_IMPORT_DESCRIPTOR *desc;

    if (!base) return 0;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    imp = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp->VirtualAddress) return 0;

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
            if (strcmp((const char *)ibn->Name, "WriteFile") != 0) continue;

            if ((void *)iat->u1.Function == (void *)hook_WriteFile) return 1;
            if (!g_realWrite) g_realWrite = (void *)iat->u1.Function;

            if (!VirtualProtect(&iat->u1.Function, sizeof(void *),
                                PAGE_READWRITE, &oldProt))
                return 0;
            iat->u1.Function = (ULONG_PTR)hook_WriteFile;
            VirtualProtect(&iat->u1.Function, sizeof(void *), oldProt, &oldProt);
            return 2;
        }
    }
    return 0;
}

static BOOL open_log(void)
{
    wchar_t dir[LOGPATH_MAX], path[LOGPATH_MAX];
    char ts[64];
    DWORD n = GetTempPathW(LOGPATH_MAX, dir);

    if (n == 0 || n >= LOGPATH_MAX) wcscpy_s(dir, LOGPATH_MAX, L"C:\\Windows\\Temp\\");
    wcscat_s(dir, LOGPATH_MAX, L"rvpn_capture\\");
    CreateDirectoryW(dir, NULL);

    timestamp(ts, sizeof(ts));
    for (char *p = ts; *p; p++)
        if (*p == ':' || *p == ' ' || *p == '.') *p = '-';

    swprintf_s(path, LOGPATH_MAX, L"%ls%hs_pid%lu.log", dir, ts, GetCurrentProcessId());

    g_log = CreateFileW(path, FILE_APPEND_DATA,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    return g_log != INVALID_HANDLE_VALUE;
}

static DWORD WINAPI rescan(LPVOID p)
{
    int round;
    (void)p;

    /*
     * 主模块已在 DllMain 里同步补好，这里只补之后才加载进来的 DLL。
     * 这里用 Toolhelp32 而不是 EnumProcessModules，避免额外依赖 psapi。
     */
    for (round = 0; round < 1200; round++) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
                                               GetCurrentProcessId());
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me;
            me.dwSize = sizeof(me);
            if (Module32First(snap, &me)) {
                do {
                    patch_module((HMODULE)me.modBaseAddr);
                } while (Module32Next(snap, &me));
            }
            CloseHandle(snap);
        }
        Sleep(250);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE th;

        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_lock);
        g_lockReady = TRUE;

        if (!open_log()) return TRUE;

        /*
         * 必须在 DllMain 返回前同步补好主模块：调用方恢复线程后主线程会
         * 立刻发命令，若只交给后台线程会漏掉启动阶段的请求。
         */
        patch_module(GetModuleHandleW(NULL));

        th = CreateThread(NULL, 0, rescan, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
    return TRUE;
}
