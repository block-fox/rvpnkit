/*
 * Absolute-minimum DLL: KERNEL32 imports only.  No CRT, no windows.h.
 *
 * Decides the open question: is the Zig CRT dependency what blocks loading
 * inside RvRvpnGui.exe, or does the target reject injection outright?
 *
 * Build:
 *   zig cc -target x86-windows-gnu -shared -O2 -nostdlib \
 *           -o tiny32.dll tiny.c -Wl,--entry=DllMainCRTStartup
 */

typedef void          *HANDLE;
typedef void          *HMODULE;
typedef void          *LPVOID;
typedef unsigned long  DWORD;
typedef int            BOOL;
typedef unsigned short wchar_t_;
typedef unsigned short WCHAR;

#define DLL_PROCESS_ATTACH 1
#define MAX_PATH_ 260
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)
#define FILE_APPEND_DATA 0x0004
#define FILE_SHARE_READ  0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define OPEN_ALWAYS      4
#define FILE_ATTRIBUTE_NORMAL 0x80

__declspec(dllimport) DWORD  __stdcall GetTempPathW(DWORD n, WCHAR *buf);
__declspec(dllimport) HANDLE __stdcall CreateFileW(const WCHAR *name, DWORD access,
                                                   DWORD share, LPVOID sec,
                                                   DWORD disp, DWORD flags, HANDLE tmpl);
__declspec(dllimport) BOOL   __stdcall WriteFile(HANDLE h, const void *buf, DWORD n,
                                                 DWORD *written, LPVOID ov);
__declspec(dllimport) BOOL   __stdcall CloseHandle(HANDLE h);
__declspec(dllimport) DWORD  __stdcall GetCurrentProcessId(void);
__declspec(dllimport) BOOL   __stdcall DisableThreadLibraryCalls(HMODULE m);

/* The compiler may synthesise a memcpy call for struct copies; -nostdlib
 * removes the CRT that would provide it, so supply one. */
void *memcpy(void *dst, const void *src, unsigned long long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static WCHAR g_path[MAX_PATH_];

static void append(WCHAR *dst, const WCHAR *src, DWORD cap)
{
    DWORD n = 0, i = 0;
    while (n < cap && dst[n]) n++;
    while (src[i] && n + 1 < cap) dst[n++] = src[i++];
    dst[n] = 0;
}

static void log_marker(void)
{
    static const WCHAR name[] = { 'r','v','t','i','n','y','.','l','o','g', 0 };
    char line[80];
    char *p = line;
    const char *pre = "tiny dll loaded, pid=";
    DWORD pid = GetCurrentProcessId();
    DWORD written = 0;
    HANDLE h;
    DWORD n = GetTempPathW(MAX_PATH_, g_path);

    if (n == 0 || n >= MAX_PATH_) return;
    append(g_path, name, MAX_PATH_);

    h = CreateFileW(g_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    (LPVOID)0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, (HANDLE)0);
    if (h == INVALID_HANDLE_VALUE) return;

    while (*pre) *p++ = *pre++;
    {
        char tmp[16];
        int k = 0;
        if (!pid) tmp[k++] = '0';
        while (pid) { tmp[k++] = (char)('0' + pid % 10); pid /= 10; }
        while (k--) *p++ = tmp[k];
    }
    *p++ = '\n';

    WriteFile(h, line, (DWORD)(p - line), &written, (LPVOID)0);
    CloseHandle(h);
}

BOOL __stdcall DllMainCRTStartup(HMODULE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        log_marker();
        DisableThreadLibraryCalls(inst);
    }
    return 1;
}

__declspec(dllexport) int TinyPing(void) { return 7; }
