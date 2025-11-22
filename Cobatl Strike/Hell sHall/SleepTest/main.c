// hook_sleep_temp_unhook.c
// x64 only demo: temporary-uninstall Sleep hook -> call real Sleep -> reinstall
// Compile: cl /EHsc /W4 /MD hook_sleep_temp_unhook.c

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#ifdef _M_X64
#define TRAMPOLINE_SIZE 13   // mov r10, imm64 (10) + jmp r10 (3)
#else
#error "This demo is x64 only."
#endif

typedef struct _HookSt {
    BYTE  pOriginalBytes[TRAMPOLINE_SIZE];
    PVOID pFunctionToHook;
    PVOID pFunctionToRun;
    DWORD dwOldProtection;
    BOOL  installed;
} HookSt, * PHookSt;

static HookSt g_st = { 0 };
static CRITICAL_SECTION g_hookLock;

// page-aligned VirtualProtect wrapper
static BOOL VirtualProtectRange(PVOID address, SIZE_T len, DWORD newProt, DWORD* oldProtOut)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SIZE_T pageSize = si.dwPageSize;
    uintptr_t start = (uintptr_t)address & ~(pageSize - 1);
    uintptr_t end = ((uintptr_t)address + len + pageSize - 1) & ~(pageSize - 1);
    SIZE_T size = end - start;
    DWORD old = 0;
    BOOL ok = VirtualProtect((LPVOID)start, size, newProt, &old);
    if (oldProtOut) *oldProtOut = old;
    return ok;
}

// safe write memory helper (changes protection, writes, flushes, restores)
static BOOL WriteMemory(PVOID dst, const void* src, SIZE_T len)
{
    DWORD oldProt = 0;
    if (!VirtualProtectRange(dst, len, PAGE_EXECUTE_READWRITE, &oldProt)) {
        printf("[!] VirtualProtectRange failed: %u\n", GetLastError());
        return FALSE;
    }

    memcpy(dst, src, len);
    FlushInstructionCache(GetCurrentProcess(), dst, len);

    // restore original protection
    DWORD tmp = 0;
    if (!VirtualProtectRange(dst, len, oldProt, &tmp)) {
        // not fatal for demo but log
        printf("[!] Restore VirtualProtectRange failed: %u\n", GetLastError());
    }
    return TRUE;
}

// Resolve the real Sleep implementation from KernelBase.dll (modern Windows)
static PVOID ResolveRealSleep(void)
{
    HMODULE hKB = GetModuleHandleW(L"KernelBase.dll");
    if (!hKB) hKB = LoadLibraryW(L"KernelBase.dll");
    if (!hKB) return NULL;
    return (PVOID)GetProcAddress(hKB, "Sleep");
}

// Initialize hook struct: resolve target, save original bytes & protection
BOOL InitializeHookStruct(PHookSt Hook, PVOID pFunctionToRun)
{
    if (!Hook || !pFunctionToRun) return FALSE;

    Hook->pFunctionToRun = pFunctionToRun;

    Hook->pFunctionToHook = ResolveRealSleep();
    if (!Hook->pFunctionToHook) {
        printf("[!] ResolveRealSleep failed\n");
        return FALSE;
    }

    // Save original bytes
    memcpy(Hook->pOriginalBytes, Hook->pFunctionToHook, TRAMPOLINE_SIZE);

    // Save old protection (best effort)
    DWORD old = 0;
    if (!VirtualProtectRange(Hook->pFunctionToHook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READ, &old)) {
        // if this fails, still continue but set a plausible default
        Hook->dwOldProtection = PAGE_EXECUTE_READ;
    }
    else {
        Hook->dwOldProtection = old;
        // restore to original prot (we only queried, VirtualProtectRange already restored it)
        DWORD tmp; VirtualProtectRange(Hook->pFunctionToHook, TRAMPOLINE_SIZE, old, &tmp);
    }

    Hook->installed = FALSE;
    return TRUE;
}

// Install hook: write mov r10, imm64 ; jmp r10
BOOL InstallHook(PHookSt Hook)
{
    if (!Hook || !Hook->pFunctionToHook || !Hook->pFunctionToRun) return FALSE;
    if (Hook->installed) return TRUE;

    BYTE patch[TRAMPOLINE_SIZE];
    ZeroMemory(patch, sizeof(patch));
    // mov r10, imm64
    patch[0] = 0x49; patch[1] = 0xBA;
    uint64_t addr = (uint64_t)Hook->pFunctionToRun;
    memcpy(&patch[2], &addr, sizeof(addr));
    // jmp r10
    patch[10] = 0x41; patch[11] = 0xFF; patch[12] = 0xE2;

    if (!WriteMemory(Hook->pFunctionToHook, patch, TRAMPOLINE_SIZE)) {
        printf("[!] Install WriteMemory failed: %u\n", GetLastError());
        return FALSE;
    }

    Hook->installed = TRUE;
    return TRUE;
}

// Temporarily remove hook (restore original bytes) but keep Hook struct intact
BOOL TmpRemoveHook(PHookSt Hook)
{
    if (!Hook || !Hook->pFunctionToHook) return FALSE;
    if (!Hook->installed) return TRUE; // already removed

    if (!WriteMemory(Hook->pFunctionToHook, Hook->pOriginalBytes, TRAMPOLINE_SIZE)) {
        printf("[!] TmpRemoveHook WriteMemory failed: %u\n", GetLastError());
        return FALSE;
    }

    Hook->installed = FALSE;
    return TRUE;
}

// Final remove (same as tmp here; could free trampolines if allocated)
BOOL RemoveHook(PHookSt Hook)
{
    return TmpRemoveHook(Hook);
}

// Type for Sleep pointer (for debugging)
typedef VOID(WINAPI* Sleep_t)(DWORD);

// Hook handler
VOID WINAPI MySleep(DWORD dwMilliseconds)
{
    // Avoid recursion and races by serializing install/uninstall with critical section
    EnterCriticalSection(&g_hookLock);

    // Debug prints
    printf("\t[MySleep] called with %u ms\n", dwMilliseconds);

    // Temporarily unhook (restore original bytes). Do NOT NULL out Hook struct.
    if (!TmpRemoveHook(&g_st)) {
        printf("\t[MySleep] TmpRemoveHook failed inside MySleep\n");
        LeaveCriticalSection(&g_hookLock);
        return;
    }

    // Call the original Sleep (now unhooked): this will execute the real KernelBase!Sleep
    // Using direct Sleep() call is fine because we just restored the original prologue.
    Sleep(dwMilliseconds);
	// Run custom code here if needed

	MessageBoxA(NULL, "Slept for a while!", "Info", MB_OK);

    // Reinstall the hook (best-effort)
    if (!InstallHook(&g_st)) {
        printf("\t[MySleep] Reinstall InstallHook failed inside MySleep: %u\n", GetLastError());
        // We could decide to continue without hook; for demo we log and continue.
    }

    printf("\t[MySleep] Finished %u ms\n", dwMilliseconds);
    LeaveCriticalSection(&g_hookLock);
}

int main(){
    // initialize console
    SetConsoleOutputCP(CP_UTF8);
    InitializeCriticalSection(&g_hookLock);

	printf("[MAIN] START notepad.exe\n");
	//CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, NULL, NULL);

    // Initialize hook struct with pointer to our handler
    if (!InitializeHookStruct(&g_st, (PVOID)MySleep)) {
        printf("[MAIN] InitializeHookStruct failed\n");
        return 1;
    }

    // Install hook
    if (!InstallHook(&g_st)) {
        printf("[MAIN] InstallHook failed\n");
        return 1;
    }

    printf("[MAIN] Hook installed. Calling Sleep(2000) from main -> should hit MySleep.\n");
    Sleep(2000); 
    printf("[MAIN] returned from Sleep(2000)\n");


    // Cleanup: remove hook permanently
    if (!RemoveHook(&g_st)) {
        printf("[MAIN] RemoveHook failed\n");
    }
    else {
        printf("[MAIN] Hook removed permanently\n");
    }

    DeleteCriticalSection(&g_hookLock);
    return 0;
}
