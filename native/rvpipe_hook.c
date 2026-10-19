/*
 * rvpipe_hook.c — IAT hook for TransactNamedPipe in RvRvpnGui.exe
 *
 * Captures the Ground Truth of the Radmin VPN control pipe protocol: the GUI is
 * the only party that emits well-formed command messages, so logging its pipe
 * traffic reveals the exact command encoding.
 *
 * Deliberately CRT-free.  An earlier build that pulled in api-ms-win-crt-*
 * failed to load inside the target process, so every string and integer helper
 * is implemented here on top of kernel32 only.
 *
 * Build (32-bit, matching the GUI process):
 *   zig cc -target x86-windows-gnu -shared -O2 -o rvpipe_hook32.dll rvpipe_hook.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define MAXDUMP 8192             /* bytes dumped per direction */
#define LOGBUF  (MAXDUMP * 3)
#define LOGFILE L"rvpipe_hook.log"

static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_lock;
static BOOL g_lockReady = FALSE;
static void *g_real = NULL;

typedef BOOL(WINAPI *TransactNamedPipe_t)(HANDLE, LPVOID, DWORD, LPVOID, DWORD,
                                          LPDWORD, LPOVERLAPPED);

/* ------------------------------------------------------- tiny string lib */

static unsigned slen(const char *s)
{
    unsigned n = 0;
    while (s[n]) n++;
    return n;
}

static void scopy(char *d, const char *s, unsigned cap)
{
    unsigned i = 0;
    while (s[i] && i + 1 < cap) { d[i] = s[i]; i++; }
    d[i] = 0;
}

static void scat(char *d, const char *s, unsigned cap)
{
    unsigned n = slen(d);
    unsigned i = 0;
    while (s[i] && n + 1 < cap) { d[n++] = s[i++]; }
    d[n] = 0;
}

static int scmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int scmpi(const char *a, const char *b)
{
    for (;; a++, b++) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        if (!ca) return 0;
    }
}

/* append unsigned decimal */
static void sapp_u(char *d, unsigned v, unsigned cap)
{
    char tmp[16];
    int n = 0;
    if (v == 0) { scat(d, "0", cap); return; }
    while (v && n < 15) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n--) {
        char one[2];
        one[0] = tmp[n];
        one[1] = 0;
        scat(d, one, cap);
    }
}

/* append unsigned hex, fixed 2 digits */
static void sapp_hex2(char *d, unsigned v, unsigned cap)
{
    const char *digits = "0123456789abcdef";
    char one[2];
    one[0] = digits[(v >> 4) & 0xF];
    one[1] = 0;
    scat(d, one, cap);
    one[0] = digits[v & 0xF];
    scat(d, one, cap);
}

/* --------------------------------------------------------------- logging */

static void rawwrite(const char *s)
{
    DWORD written = 0;
    if (g_log == INVALID_HANDLE_VALUE) return;
    WriteFile(g_log, s, slen(s), &written, NULL);
}

/* hex + printable dump of a buffer, into a caller-provided static buffer */
static char g_scratch[LOGBUF + 512];

static void dump_buffer(const char *title, const BYTE *buf, DWORD len)
{
    char *p = g_scratch;
    unsigned i;

    scopy(p, "\n=== ", sizeof(g_scratch));
    scat(p, title, sizeof(g_scratch));
    scat(p, " len=", sizeof(g_scratch));
    sapp_u(p, len, sizeof(g_scratch));
    scat(p, " ===\nHEX:\n", sizeof(g_scratch));

    DWORD shown = (len < MAXDUMP) ? len : MAXDUMP;
    for (i = 0; i < shown; i++) {
        sapp_hex2(p, buf[i], sizeof(g_scratch));
        if (i + 1 < shown) scat(p, " ", sizeof(g_scratch));
        if ((i & 15) == 15) scat(p, "\n", sizeof(g_scratch));
    }
    scat(p, "\nASCII:\n", sizeof(g_scratch));

    for (i = 0; i < shown; i++) {
        char c = (buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.';
        char one[2];
        one[0] = c;
        one[1] = 0;
        scat(p, one, sizeof(g_scratch));
        if ((i & 63) == 63) scat(p, "\n", sizeof(g_scratch));
    }
    scat(p, "\n", sizeof(g_scratch));

    rawwrite(p);
}

/* ------------------------------------------------------------ the hook */

static BOOL WINAPI hook_TransactNamedPipe(HANDLE hPipe, LPVOID lpvWrite,
                                          DWORD nWrite, LPVOID lpvRead,
                                          DWORD nRead, LPDWORD lpcbRead,
                                          LPOVERLAPPED lpOverlapped)
{
    BOOL ok;
    DWORD cbRead = 0;
    TransactNamedPipe_t real = (TransactNamedPipe_t)g_real;

    if (g_lockReady) EnterCriticalSection(&g_lock);
    if (lpvWrite && nWrite) dump_buffer("OUT", (const BYTE *)lpvWrite, nWrite);
    if (g_lockReady) LeaveCriticalSection(&g_lock);

    ok = real(hPipe, lpvWrite, nWrite, lpvRead, nRead, &cbRead, lpOverlapped);
    if (!ok && !lpOverlapped) {
        /* a failed call still tells us the shape of the request */
        cbRead = 0;
    }

    if (g_lockReady) EnterCriticalSection(&g_lock);
    if (lpvRead && cbRead) {
        dump_buffer("IN", (const BYTE *)lpvRead, cbRead);
    } else {
        rawwrite("\n=== IN (no data) ===\n");
    }
    if (g_lockReady) LeaveCriticalSection(&g_lock);

    if (lpcbRead) *lpcbRead = cbRead;
    return ok;
}

/* --------------------------------------------------------- IAT patching */

static BOOL patch_iat(HMODULE mod, const char *dllName, const char *funcName,
                      void *replacement)
{
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *imp;
    IMAGE_IMPORT_DESCRIPTOR *desc;

    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    imp = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp->VirtualAddress) return FALSE;

    desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp->VirtualAddress);
    for (; desc->Name; desc++) {
        const char *name = (const char *)(base + desc->Name);
        IMAGE_THUNK_DATA *orig, *iat;

        if (scmpi(name, dllName) != 0) continue;

        orig = (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk);
        iat = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
        if (!desc->OriginalFirstThunk) orig = iat;

        for (; orig->u1.AddressOfData; orig++, iat++) {
            DWORD oldProt = 0;
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            if (scmp((const char *)((IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData))->Name,
                     funcName) != 0)
                continue;

            g_real = (void *)iat->u1.Function;
            if (!VirtualProtect(&iat->u1.Function, sizeof(void *), PAGE_READWRITE, &oldProt))
                return FALSE;
            iat->u1.Function = (ULONG_PTR)replacement;
            VirtualProtect(&iat->u1.Function, sizeof(void *), oldProt, &oldProt);
            return TRUE;
        }
    }
    return FALSE;
}

/* ----------------------------------------------------------------- setup */

/* wide-string helpers (kept CRT-free on purpose) */
static unsigned wlen(const wchar_t *s) { unsigned n = 0; while (s[n]) n++; return n; }

static void wcat(wchar_t *d, const wchar_t *s, unsigned cap)
{
    unsigned n = wlen(d), i = 0;
    while (s[i] && n + 1 < cap) { d[n++] = s[i++]; }
    d[n] = 0;
}

static void wcpy(wchar_t *d, const wchar_t *s, unsigned cap)
{
    unsigned i = 0;
    while (s[i] && i + 1 < cap) { d[i] = s[i]; i++; }
    d[i] = 0;
}

static DWORD WINAPI worker(LPVOID param)
{
    wchar_t wpath[MAX_PATH];
    char path[MAX_PATH];
    DWORD n;
    HMODULE kern, exe;
    void *target;

    (void)param;

    InitializeCriticalSection(&g_lock);
    g_lockReady = TRUE;

    /* Prefer %TEMP%: the install directory is not user-writable. */
    n = GetTempPathW(MAX_PATH, wpath);
    if (n == 0 || n >= MAX_PATH) {
        wcpy(wpath, L"C:\\Windows\\Temp\\", MAX_PATH);
    }
    wcat(wpath, LOGFILE, MAX_PATH);
    g_log = CreateFileW(wpath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_log == INVALID_HANDLE_VALUE) {
        /* fall back to beside the DLL */
        HMODULE self = NULL;
        wchar_t selfPath[MAX_PATH];
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)&worker, &self);
        GetModuleFileNameW(self, selfPath, MAX_PATH);
        n = wlen(selfPath);
        while (n && selfPath[n] != L'\\') n--;
        selfPath[n + 1] = 0;
        wcat(selfPath, LOGFILE, MAX_PATH);
        g_log = CreateFileW(selfPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        wcpy(wpath, selfPath, MAX_PATH);
    }

    if (g_log == INVALID_HANDLE_VALUE) return 0;

    /* convert the wide path to ascii just for the banner */
    {
        int i = 0;
        while (wpath[i] && i < MAX_PATH - 1) { path[i] = (char)wpath[i]; i++; }
        path[i] = 0;
    }

    scopy(g_scratch, "rvpipe_hook attached pid=", sizeof(g_scratch));
    sapp_u(g_scratch, GetCurrentProcessId(), sizeof(g_scratch));
    scat(g_scratch, " log=", sizeof(g_scratch));
    scat(g_scratch, path, sizeof(g_scratch));
    scat(g_scratch, "\n", sizeof(g_scratch));
    rawwrite(g_scratch);

    kern = GetModuleHandleA("kernel32.dll");
    if (!kern) kern = GetModuleHandleA("KernelBase.dll");
    if (!kern) { rawwrite("no kernel32\n"); return 0; }

    target = (void *)GetProcAddress(kern, "TransactNamedPipe");
    if (!target) { rawwrite("TransactNamedPipe not exported\n"); return 0; }
    g_real = target;

    exe = GetModuleHandleA(NULL);
    if (patch_iat(exe, "KERNEL32.dll", "TransactNamedPipe", (void *)hook_TransactNamedPipe) ||
        patch_iat(exe, "KERNEL32.DLL", "TransactNamedPipe", (void *)hook_TransactNamedPipe) ||
        patch_iat(exe, "kernel32.dll", "TransactNamedPipe", (void *)hook_TransactNamedPipe)) {
        rawwrite("IAT hook installed\n");
    } else {
        rawwrite("FAILED to patch IAT (TransactNamedPipe may be resolved dynamically)\n");
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    HANDLE th;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        th = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (th) CloseHandle(th);
    }
    return TRUE;
}
