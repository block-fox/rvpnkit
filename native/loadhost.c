/*
 * Standard 32-bit host: LoadLibraryA's a given DLL and reports the exact error.
 * Uses normal CRT linking (no -nostdlib tricks), so it builds cleanly with Zig.
 *
 * Build:
 *   zig cc -target x86-windows-gnu -O2 -o loadhost32.exe loadhost.c
 */
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    HMODULE h;
    DWORD err;

    printf("host pointer size = %u\n", (unsigned)sizeof(void *));
    if (argc < 2) {
        printf("usage: loadhost32.exe <dll>\n");
        return 2;
    }

    printf("loading: %s\n", argv[1]);
    h = LoadLibraryA(argv[1]);
    err = GetLastError();

    if (h) {
        printf("RESULT: LOADED ok, base=%p\n", (void *)h);
        return 0;
    }

    printf("RESULT: LOAD FAILED, GetLastError=%lu (0x%lx)\n",
           (unsigned long)err, (unsigned long)err);
    switch (err) {
    case 126: printf("  ERROR_MOD_NOT_FOUND  -> a dependency DLL is missing\n"); break;
    case 193: printf("  ERROR_BAD_EXE_FORMAT -> bitness mismatch\n"); break;
    case 5:   printf("  ERROR_ACCESS_DENIED\n"); break;
    case 127: printf("  ERROR_PROC_NOT_FOUND -> a required symbol is missing\n"); break;
    case 998: printf("  ERROR_NOACCESS       -> bad/invalid image\n"); break;
    default: break;
    }
    return 1;
}
