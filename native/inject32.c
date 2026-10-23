/*
 * inject32.c —— 32 位注入器。
 *
 * 为什么必须用 32 位进程：目标 RvRvpnGui.exe 是 32 位（WOW64）。从 64 位进程
 * 调用 GetProcAddress(kernel32!LoadLibraryW) 得到的是 64 位 kernel32 里的地址
 * （形如 0x7ff8_xxxx_xxxx），这个地址在 32 位目标里无效。之前的注入尝试因此
 * 全部指向了垃圾地址。
 *
 * 本程序依次尝试三种注入机制，每个成功后都会等待 DLL 的 DllMain 写出标记文件：
 *   1. CreateRemoteThread(LoadLibraryW)
 *   2. QueueUserAPC(LoadLibraryW) 到所有线程
 *   3. SuspendThread + SetThreadContext 劫持线程入口
 *
 * 编译（32 位）：
 *   zig cc -target x86-windows-gnu -O2 -o inject32.exe inject32.c
 *
 * 用法：
 *   inject32.exe <dll路径> [进程名|pid]
 *   inject32.exe probe32.dll RvRvpnGui
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MARKER_NAME L"rvprobe.log"

static void get_temp_marker(wchar_t *out, DWORD cap)
{
    wchar_t tmp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n >= MAX_PATH) {
        wcscpy_s(out, cap, L"C:\\Windows\\Temp\\rvprobe.log");
        return;
    }
    wcscpy_s(out, cap, tmp);
    wcscat_s(out, cap, MARKER_NAME);
}

static BOOL marker_exists(void)
{
    wchar_t path[MAX_PATH];
    get_temp_marker(path, MAX_PATH);
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static void print_marker(void)
{
    wchar_t path[MAX_PATH];
    char buf[512] = {0};
    DWORD got = 0;
    HANDLE h;

    get_temp_marker(path, MAX_PATH);
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    ReadFile(h, buf, sizeof(buf) - 1, &got, NULL);
    CloseHandle(h);
    printf("    标记内容: %s\n", buf);
}

static DWORD find_pid(const char *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    DWORD pid = 0;
    char want[260];
    size_t i;

    if (snap == INVALID_HANDLE_VALUE) return 0;

    strncpy_s(want, sizeof(want), name, _TRUNCATE);
    for (i = 0; i < strlen(want); i++)
        want[i] = (char)tolower((unsigned char)want[i]);
    /* 若用户没写 .exe 后缀，补上 */
    if (strstr(want, ".exe") == NULL) {
        size_t len = strlen(want);
        if (len + 4 < sizeof(want)) {
            want[len] = '.';
            want[len + 1] = 'e';
            want[len + 2] = 'x';
            want[len + 3] = 'e';
            want[len + 4] = 0;
        }
    }

    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            char cur[260];
            for (i = 0; i < strlen(pe.szExeFile) && i < 259; i++)
                cur[i] = (char)tolower((unsigned char)pe.szExeFile[i]);
            cur[i] = 0;
            if (strcmp(cur, want) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* 把 DLL 路径写进目标进程，返回远端地址 */
static LPVOID push_path(HANDLE proc, const wchar_t *dllw)
{
    size_t bytes = (wcslen(dllw) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    SIZE_T written = 0;
    if (!remote) {
        printf("    VirtualAllocEx 失败: %lu\n", GetLastError());
        return NULL;
    }
    if (!WriteProcessMemory(proc, remote, dllw, bytes, &written)) {
        printf("    WriteProcessMemory 失败: %lu\n", GetLastError());
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        return NULL;
    }
    return remote;
}

static int wait_marker(int seconds)
{
    int i;
    for (i = 0; i < seconds * 4; i++) {
        if (marker_exists()) return 1;
        Sleep(250);
    }
    return 0;
}

/* ── 方式 1：CreateRemoteThread ── */
static int method_remote_thread(HANDLE proc, LPTHREAD_START_ROUTINE fn, LPVOID arg)
{
    HANDLE th;
    DWORD code = 0;
    printf("  [1] CreateRemoteThread ...\n");
    th = CreateRemoteThread(proc, NULL, 0, fn, arg, 0, NULL);
    if (!th) {
        printf("      创建失败: %lu\n", GetLastError());
        return 0;
    }
    WaitForSingleObject(th, 8000);
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    printf("      线程结束，返回码 0x%lx%s\n", code, code ? "" : "  (0 = 未执行)");
    if (wait_marker(6)) return 1;
    return 0;
}

/* ── 方式 2：APC 注入 ── */
static int method_apc(HANDLE proc, DWORD pid, PAPCFUNC fn, ULONG_PTR arg)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    int queued = 0, i;

    printf("  [2] QueueUserAPC 到所有线程 ...\n");
    if (snap == INVALID_HANDLE_VALUE) return 0;

    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE th;
            if (te.th32OwnerProcessID != pid) continue;
            th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (!th) continue;
            if (QueueUserAPC(fn, th, arg)) queued++;
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    printf("      已排队 %d 个线程\n", queued);
    /* 反复排队，提高命中 alertable 等待的机会 */
    for (i = 0; i < 12; i++) {
        if (wait_marker(1)) return 1;

        snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) {
                do {
                    HANDLE th;
                    if (te.th32OwnerProcessID != pid) continue;
                    th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (!th) continue;
                    QueueUserAPC(fn, th, arg);
                    CloseHandle(th);
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
    }
    return 0;
}

/* ── 方式 3：线程上下文劫持 ── */
static int method_hijack(HANDLE proc, DWORD pid, LPVOID load_lib, LPVOID arg)
{
    HANDLE snap;
    THREADENTRY32 te;
    int done = 0;

    printf("  [3] 线程上下文劫持 ...\n");
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE th;
            CONTEXT ctx;
            DWORD old;

            if (te.th32OwnerProcessID != pid) continue;
            th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (!th) continue;

            if (SuspendThread(th) == (DWORD)-1) {
                CloseHandle(th);
                continue;
            }

            ZeroMemory(&ctx, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(th, &ctx)) {
                /* 构造栈：返回地址 + 参数（stdcall：参数在返回地址之上） */
                DWORD sp = ctx.Esp;

                VirtualProtectEx(proc, (LPVOID)(sp - 8), 8, PAGE_READWRITE, &old);

                /* [sp-8] = 哨兵返回地址（Sleep 循环，避免崩溃） */
                DWORD sentinel = (DWORD)(ULONG_PTR)GetProcAddress(
                    GetModuleHandleW(L"kernel32.dll"), "Sleep");
                SIZE_T w = 0;
                WriteProcessMemory(proc, (LPVOID)(sp - 8), &sentinel, 4, &w);
                WriteProcessMemory(proc, (LPVOID)(sp - 4), &arg, 4, &w);

                ctx.Esp = sp - 8;
                ctx.Eip = (DWORD)(ULONG_PTR)load_lib;

                if (SetThreadContext(th, &ctx)) done++;
            }

            ResumeThread(th);
            CloseHandle(th);
            if (done) break;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    printf("      劫持了 %d 个线程\n", done);
    if (done && wait_marker(8)) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    const char *dll = argc > 1 ? argv[1] : "probe32.dll";
    const char *target = argc > 2 ? argv[2] : "RvRvpnGui";
    wchar_t dllw[MAX_PATH];
    HANDLE proc;
    DWORD pid;
    LPVOID remote;
    LPVOID load_lib;
    int ok = 0;

    /* 仅输出本进程（32 位）里 kernel32 的关键地址，供外部脚本使用。
     * 系统 DLL 的基址在同一次开机内对所有进程一致，因此这些地址在目标
     * 32 位进程里同样有效。 */
    if (argc > 1 && strcmp(argv[1], "--addr-only") == 0) {
        HMODULE k = GetModuleHandleW(L"kernel32.dll");
        printf("KERNEL32_BASE=0x%08lx\n", (unsigned long)(ULONG_PTR)k);
        printf("LOADLIBRARYW=0x%08lx\n",
               (unsigned long)(ULONG_PTR)GetProcAddress(k, "LoadLibraryW"));
        return 0;
    }

    if (argc > 1 && argv[1][0]) {
        /* 注意：argv 是 ANSI 代码页（中文系统为 GBK），不是 UTF-8。
         * 用 CP_UTF8 会把中文路径解成乱码并截断。 */
        if (MultiByteToWideChar(CP_ACP, 0, dll, -1, dllw, MAX_PATH) == 0)
            wcscpy_s(dllw, MAX_PATH, L"probe32.dll");
    } else {
        wcscpy_s(dllw, MAX_PATH, L"probe32.dll");
    }

    /* 目标可以是进程名或 pid */
    pid = (DWORD)atoi(target);
    if (pid == 0) pid = find_pid(target);
    if (pid == 0) {
        printf("找不到目标进程: %s\n", target);
        return 2;
    }

    printf("=== 32 位注入器 ===\n");
    printf("  本进程位数: %u\n", (unsigned)sizeof(void *) * 8);
    printf("  目标 pid  : %lu\n", pid);
    {
        wchar_t full[MAX_PATH];
        GetFullPathNameW(dllw, MAX_PATH, full, NULL);
        printf("  DLL       : %ls\n", full);
        wcscpy_s(dllw, MAX_PATH, full);
    }

    printf("  LoadLibraryW = 0x%08lx  (32 位地址)\n",
           (unsigned long)(ULONG_PTR)GetProcAddress(
               GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));

    proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) {
        DWORD e1 = GetLastError();
        /* PROCESS_ALL_ACCESS 常被安全软件单独拦截，退一步只要必需权限 */
        DWORD need = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                     PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
        printf("  OpenProcess(ALL_ACCESS) 失败: %lu，改用最小权限集重试\n", e1);
        proc = OpenProcess(need, FALSE, pid);
        if (!proc) {
            printf("  OpenProcess(最小权限) 也失败: %lu\n", GetLastError());
            return 3;
        }
        printf("  ✓ 以最小权限打开成功\n");
    }

    remote = push_path(proc, dllw);
    if (!remote) {
        CloseHandle(proc);
        return 4;
    }

    load_lib = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                      "LoadLibraryW");

    ok = method_remote_thread(proc, (LPTHREAD_START_ROUTINE)load_lib, remote);
    if (ok) printf("\n★ 成功（CreateRemoteThread）\n");
    else {
        ok = method_apc(proc, pid, (PAPCFUNC)load_lib, (ULONG_PTR)remote);
        if (ok) printf("\n★ 成功（APC）\n");
        else {
            ok = method_hijack(proc, pid, load_lib, remote);
            if (ok) printf("\n★ 成功（上下文劫持）\n");
        }
    }

    if (ok) print_marker();
    else printf("\n✗ 三种方式均未能让 DLL 载入\n");

    CloseHandle(proc);
    return ok ? 0 : 1;
}
