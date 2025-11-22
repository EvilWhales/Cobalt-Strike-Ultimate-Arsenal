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
#include "tcg.h"
#include "memory.h"

#define GETRESOURCE(x) (char *)&x

#define memset(x, y, z) __stosb((unsigned char *)x, y, z);
#define memcpy(x, y, z) __movsb((unsigned char *)x, (unsigned char *)y, z);

#define GETRESOURCE(x) (char *)&x

__typeof__(GetModuleHandleA) * pGetModuleHandle __attribute__((section(".text")));
__typeof__(GetProcAddress)   * pGetProcAddress  __attribute__((section(".text")));

typedef struct {
    int   length;
    char  value[];
} RESOURCE;

typedef struct {
   char * start;
   DWORD  length;
   DWORD  offset;
} RDATA_SECTION;

typedef struct {
    char data[4096];
    char code[16384];
} PICO;

DECLSPEC_IMPORT NTSTATUS NTAPI   NTDLL$NtAllocateVirtualMemory (HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI   NTDLL$NtProtectVirtualMemory  (HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI   NTDLL$NtFreeVirtualMemory     (HANDLE, PVOID *, PSIZE_T, ULONG);
DECLSPEC_IMPORT int      WINAPIV MSVCRT$strncmp                (const char * string1, const char * string2, size_t count);

typedef void (*PICOHOOK_ENTRY)(IMPORTFUNCS *, MEMORY_LAYOUT *);

char * resolve(DWORD modHash, DWORD funcHash) {
    char * hModule = (char *)findModuleByHash(modHash);
    return findFunctionByHash(hModule, funcHash);
}