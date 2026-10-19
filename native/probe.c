/*
 * Minimal CRT-free probe DLL.
 *
 * Purpose: isolate WHY the hook DLL failed to load inside RvRvpnGui.exe.
 * This file imports nothing but kernel32 and writes a marker file from
 * DllMain, so a successful marker proves the injection mechanism works and
 * that CRT-free DLLs load fine in the target.
 *
 * Build:
 *   zig cc -target x86-windows-gnu -shared -O2 -o probe32.dll probe.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

static void write_marker(const char *text)
{
    wchar_t path[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, path);
    if (n == 0 || n >= MAX_PATH) return;

    /* append "rvprobe.log" without CRT wide helpers */
    {
        const wchar_t *name = L"rvprobe.log";
        unsigned len = 0, i = 0;
        while (path[len]) len++;
        while (name[i] && len + 1 < MAX_PATH) path[len++] = name[i++];
        path[len] = 0;
    }

    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, text, (DWORD)strlen(text), &written, NULL);
    CloseHandle(h);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        char buf[128];
        char *p = buf;
        const char *pre = "probe attached, pid=";
        DWORD pid = GetCurrentProcessId();

        while (*pre) *p++ = *pre++;
        /* decimal pid */
        {
            char tmp[16];
            int n = 0;
            if (!pid) tmp[n++] = '0';
            while (pid) { tmp[n++] = (char)('0' + pid % 10); pid /= 10; }
            while (n--) *p++ = tmp[n];
        }
        *p++ = '\n';
        *p = 0;

        write_marker(buf);
        DisableThreadLibraryCalls(inst);
    }
    return TRUE;
}

__declspec(dllexport) int ProbePing(void) { return 42; }
