/*
 * 32-bit host that LoadLibraryA's a DLL and prints the exact result.
 * No CRT, no windows.h — self-contained Win32 declarations only.
 *
 * Build:
 *   zig cc -target x86-windows-gnu -O2 -nostdlib -o loadtest32.exe loadtest.c \
 *       -Wl,--entry=RvMain
 */

typedef void          *HANDLE;
typedef void          *HMODULE;
typedef void          *LPVOID;
typedef unsigned long  DWORD;
typedef int            BOOL;
typedef unsigned char  BYTE;

#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)
#define MAX_PATH_ 260

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD which);
__declspec(dllimport) BOOL   __stdcall WriteFile(HANDLE h, const void *buf, DWORD n,
                                                 DWORD *written, LPVOID ov);
__declspec(dllimport) HMODULE __stdcall LoadLibraryA(const char *name);
__declspec(dllimport) DWORD  __stdcall GetLastError(void);
__declspec(dllimport) void   __stdcall ExitProcess(DWORD code);
__declspec(dllimport) char * __stdcall GetCommandLineA(void);
__declspec(dllimport) DWORD  __stdcall GetModuleFileNameA(HMODULE m, char *buf, DWORD n);

void *memcpy(void *dst, const void *src, unsigned long long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static void emit(const char *s)
{
    DWORD written = 0;
    BYTE *p = (BYTE *)s;
    DWORD n = 0;
    while (p[n]) n++;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), p, n, &written, (LPVOID)0);
}

static void emit_u(DWORD v)
{
    char tmp[16];
    int n = 0;
    char one[2];
    if (!v) { emit("0"); return; }
    while (v) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    while (n--) { one[0] = tmp[n]; one[1] = 0; emit(one); }
}

static void emit_hex(DWORD v)
{
    static const char dig[] = "0123456789abcdef";
    char tmp[16];
    int n = 0;
    char one[2];
    if (!v) { emit("0"); return; }
    while (v) { tmp[n++] = dig[v & 0xF]; v >>= 4; }
    while (n--) { one[0] = tmp[n]; one[1] = 0; emit(one); }
}

/* Pull the first argument out of the raw command line (skip argv[0]). */
static const char *first_arg(void)
{
    char *cl = (char *)GetCommandLineA();
    char *p = cl;

    if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p) p++; }
    else { while (*p && *p != ' ') p++; }
    while (*p == ' ') p++;
    return p;
}

void RvMain(void)
{
    const char *path = first_arg();
    HMODULE h;
    DWORD err;
    char self[MAX_PATH_];
    DWORD pid = 0;

    emit("host bitness: pointer size = ");
    emit_u((DWORD)sizeof(void *));
    emit("\n");

    GetModuleFileNameA((HMODULE)0, self, MAX_PATH_);
    emit("host exe: ");
    emit(self);
    emit("\n\ndll to load: ");
    if (!*path) { emit("(none given)\n"); ExitProcess(2); }
    emit(path);
    emit("\n");

    /* mark the loading process so we can confirm which pid loaded it */
    pid = 0;
    (void)pid;

    h = LoadLibraryA(path);
    err = GetLastError();

    if (h) {
        emit("RESULT: LOADED ok, base=0x");
        emit_hex((DWORD)(unsigned long long)(unsigned long long)h);
        emit("\n");
        ExitProcess(0);
    }

    emit("RESULT: LOAD FAILED, GetLastError=");
    emit_u(err);
    emit("  ");
    if (err == 126) emit("(ERROR_MOD_NOT_FOUND - missing dependency)\n");
    else if (err == 193) emit("(ERROR_BAD_EXE_FORMAT - bitness mismatch)\n");
    else if (err == 5) emit("(ERROR_ACCESS_DENIED)\n");
    else if (err == 127) emit("(ERROR_PROC_NOT_FOUND - missing symbol)\n");
    else if (err == 998) emit("(ERROR_NOACCESS - bad image)\n");
    else emit("(unknown)\n");

    ExitProcess(1);
}
