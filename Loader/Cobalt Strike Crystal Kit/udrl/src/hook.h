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
#include "hash.h"
#include "proxy.h"
#include "memory.h"

#define RBP_OP_INFO 0x5
#define draugrArg(i) (ULONG_PTR)functionCall->args[i]

#define memset(x, y, z) __stosb((unsigned char *)x, y, z);
#define memcpy(x, y, z) __movsb((unsigned char *)x, (unsigned char *)y, z);

DECLSPEC_IMPORT LPVOID            WINAPI KERNEL32$VirtualAlloc           (LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT LPVOID            WINAPI KERNEL32$VirtualAllocEx         (HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$VirtualProtect         (LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$VirtualProtectEx       (HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$VirtualFree            (LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT SIZE_T            WINAPI KERNEL32$VirtualQuery           (LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$GetThreadContext       (HANDLE, LPCONTEXT);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$SetThreadContext       (HANDLE, const CONTEXT *);
DECLSPEC_IMPORT DWORD             WINAPI KERNEL32$ResumeThread           (HANDLE);
DECLSPEC_IMPORT HANDLE            WINAPI KERNEL32$CreateThread           (LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT HANDLE            WINAPI KERNEL32$CreateRemoteThread     (HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT HANDLE            WINAPI KERNEL32$OpenProcess            (DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE            WINAPI KERNEL32$OpenThread             (DWORD, BOOL, DWORD);
DECLSPEC_IMPORT VOID              WINAPI KERNEL32$ExitThread             (DWORD);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$CloseHandle            (HANDLE);
DECLSPEC_IMPORT VOID              WINAPI KERNEL32$Sleep                  (DWORD);
DECLSPEC_IMPORT HANDLE            WINAPI KERNEL32$CreateFileMappingA     (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID            WINAPI KERNEL32$MapViewOfFile          (HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$UnmapViewOfFile        (LPCVOID);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$DuplicateHandle        (HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$ReadProcessMemory      (HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$WriteProcessMemory     (HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$CreateProcessA         (LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT HMODULE           WINAPI KERNEL32$GetModuleHandleA       (LPCSTR);
DECLSPEC_IMPORT PRUNTIME_FUNCTION WINAPI KERNEL32$RtlLookupFunctionEntry (DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
DECLSPEC_IMPORT HANDLE            WINAPI KERNEL32$CreateTimerQueue       ();
DECLSPEC_IMPORT BOOL              WINAPI KERNEL32$CreateTimerQueueTimer  (PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
DECLSPEC_IMPORT VOID              WINAPI KERNEL32$RtlCaptureContext      (PCONTEXT);
DECLSPEC_IMPORT HANDLE            WINAPI KERNEL32$GetProcessHeap         ();
DECLSPEC_IMPORT LPVOID            WINAPI KERNEL32$HeapAlloc              (HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT ULONG             NTAPI  NTDLL$RtlRandomEx               (PULONG);
DECLSPEC_IMPORT ULONG             NTAPI  NTDLL$NtContinue                (PCONTEXT, BOOLEAN);

/* the proxy pic */
DECLSPEC_IMPORT PVOID SpoofStub(PVOID, PVOID, PVOID, PVOID, PDRAUGR_PARAMETERS, PVOID, SIZE_T, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

// God Bless Vulcan Raven.
typedef struct _STACK_FRAME {
    LPCWSTR    DllPath;
    ULONG      Offset;
    ULONGLONG  TotalStackSize;
    BOOL       RequiresLoadLibrary;
    BOOL       SetsFramePointer;
    PVOID      ReturnAddress;
    BOOL       PushRbp;
    ULONG      CountOfCodes;
    BOOL       PushRbpIndex;
} STACK_FRAME, * PSTACK_FRAME;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

typedef unsigned char UBYTE;

typedef union _UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UBYTE Version : 3;
    UBYTE Flags   : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

typedef struct _FRAME_INFO {
    PVOID ModuleAddress;
    PVOID FunctionAddress;
    DWORD Offset;
} FRAME_INFO, * PFRAME_INFO;

typedef struct _SYNTHETIC_STACK_FRAME {
    FRAME_INFO Frame1;
    FRAME_INFO Frame2;
    PVOID      pGadget;
} SYNTHETIC_STACK_FRAME, * PSYNTHETIC_STACK_FRAME;

typedef struct {
    PVOID function;
    int argc;
    ULONG_PTR args[10];
} FUNCTION_CALL, * PFUNCTION_CALL;

typedef struct _DRAUGR_FUNCTION_CALL {
    PFUNCTION_CALL FunctionCall;
    PVOID StackFrame;
    PVOID SpoofCall;
} DRAUGR_FUNCTION_CALL, *PDRAUGR_FUNCTION_CALL;

SYNTHETIC_STACK_FRAME g_stackFrame;

void initFrameInfo()
{
    PVOID pModuleFrame1 = KERNEL32$GetModuleHandleA("kernel32.dll");
    PVOID pModuleFrame2 = KERNEL32$GetModuleHandleA("ntdll.dll");

    g_stackFrame.Frame1.ModuleAddress   = pModuleFrame1;
    g_stackFrame.Frame1.FunctionAddress = (PVOID)GetProcAddress((HMODULE)pModuleFrame1, "BaseThreadInitThunk");
    g_stackFrame.Frame1.Offset          = 0x17;

    g_stackFrame.Frame2.ModuleAddress   = pModuleFrame2;
    g_stackFrame.Frame2.FunctionAddress = (PVOID)GetProcAddress((HMODULE)pModuleFrame2, "RtlUserThreadStart");
    g_stackFrame.Frame2.Offset          = 0x2c;

    g_stackFrame.pGadget                = KERNEL32$GetModuleHandleA("KernelBase.dll");
}

BOOL getTextSectionSize(PVOID pModule, PDWORD pdwVirtualAddress, PDWORD pdwSize)
{
    PIMAGE_DOS_HEADER pImgDosHeader = (PIMAGE_DOS_HEADER)(pModule);
    
    if (pImgDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pImgNtHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pModule + pImgDosHeader->e_lfanew);
    
    if (pImgNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_SECTION_HEADER   pImgSectionHeader = IMAGE_FIRST_SECTION(pImgNtHeaders);
    
    for (int i = 0; i < pImgNtHeaders->FileHeader.NumberOfSections; i++)
    {
        DWORD h = hash((char*)pImgSectionHeader[i].Name);
        if (h == TEXT_HASH)
        {
            *pdwVirtualAddress = pImgSectionHeader[i].VirtualAddress;
            *pdwSize = pImgSectionHeader[i].SizeOfRawData;
            return TRUE;
        }
    }

    return FALSE;
}

PVOID calculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 imageBase)
{
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation    = 0;
    ULONG operationInfo      = 0;
    ULONG index              = 0;
    ULONG frameOffset        = 0;

    STACK_FRAME stackFrame;
    memset(&stackFrame, 0, sizeof(stackFrame));

    if (!pRuntimeFunction) {
        return NULL;
    }

    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + imageBase);
    
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;

        /* don't use switch as it produces jump tables */
        if (unwindOperation == UWOP_PUSH_NONVOL)
        {
            stackFrame.TotalStackSize += 8;
            if (RBP_OP_INFO == operationInfo) {
                stackFrame.PushRbp = TRUE;
                stackFrame.CountOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.PushRbpIndex = index + 1;
            }
        }
        else if (unwindOperation == UWOP_SAVE_NONVOL)
        {
            index += 1;
        }
        else if (unwindOperation == UWOP_ALLOC_SMALL)
        {
            stackFrame.TotalStackSize += ((operationInfo * 8) + 8);
        }
        else if (unwindOperation == UWOP_ALLOC_LARGE)
        {
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0) {
                frameOffset *= 8;
            }
            else {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.TotalStackSize += frameOffset;
        }
        else if (unwindOperation == UWOP_SET_FPREG)
        {
            stackFrame.SetsFramePointer = TRUE;
        }
        else if (unwindOperation == UWOP_SAVE_XMM128)
        {
            return NULL;
        }

        index += 1;
    }

    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1)) {
            index += 1;
        }

        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return calculateFunctionStackSize(pRuntimeFunction, imageBase);
    }

    stackFrame.TotalStackSize += 8;
    return (PVOID)(stackFrame.TotalStackSize);
}

PVOID calculateFunctionStackSizeWrapper(PVOID returnAddress)
{
    PRUNTIME_FUNCTION     pRuntimeFunction = NULL;
    DWORD64               ImageBase        = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable    = NULL;

    if (!returnAddress) {
        return NULL;
    }

    pRuntimeFunction = KERNEL32$RtlLookupFunctionEntry((DWORD64)returnAddress, &ImageBase, pHistoryTable);

    if (NULL == pRuntimeFunction) {
        return NULL;
    }

    return calculateFunctionStackSize(pRuntimeFunction, ImageBase);
}

PVOID findGadget(PVOID pModuleAddr)
{
    BOOL bFoundGadgets      = FALSE;
    DWORD dwTextSectionSize = 0;
    DWORD dwTextSectionVa   = 0;
    DWORD dwCounter         = 0;
    ULONG seed              = 0;
    ULONG randomNbr         = 0;
    PVOID pModTextSection   = NULL;

    PVOID pGadgetList[15];
    memset(&pGadgetList, 0, (sizeof(PVOID) * 8));

    if (!bFoundGadgets)
    {
        if (!getTextSectionSize(pModuleAddr, &dwTextSectionVa, &dwTextSectionSize)) {
            return NULL;
        }

        pModTextSection = (PBYTE)((UINT_PTR)pModuleAddr + dwTextSectionVa);

        for (int i = 0; i < (dwTextSectionSize - 2); i++)
        {
            // Searching for jmp rbx gadget
            if (((PBYTE)pModTextSection)[i] == 0xFF && ((PBYTE)pModTextSection)[i + 1] == 0x23)
            {
                pGadgetList[dwCounter] = (void*)((UINT_PTR)pModTextSection + i);
                dwCounter++;

                if (dwCounter == 15) {
                    break;
                }
            }
        }

        bFoundGadgets = TRUE;
    }

    seed = 0x1337;
    randomNbr = NTDLL$RtlRandomEx(&seed);
    randomNbr %= dwCounter;

    return pGadgetList[randomNbr];
}

ULONG_PTR draugrWrapper(PVOID pFunctionAddr, PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4, PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8, PVOID pArg9, PVOID pArg10, PVOID pArg11, PVOID pArg12)
{
    int attempts        = 0;
    PVOID returnAddress = NULL;

    DRAUGR_PARAMETERS draugrParameters;
    memset(&draugrParameters, 0, sizeof(DRAUGR_PARAMETERS));

    // configure BaseThreadInitThunk frame
    returnAddress = (void*)((UINT_PTR)g_stackFrame.Frame1.FunctionAddress + g_stackFrame.Frame1.Offset);
    draugrParameters.BaseThreadInitThunkStackSize = calculateFunctionStackSizeWrapper(returnAddress);
    draugrParameters.BaseThreadInitThunkReturnAddress = returnAddress;

    if (!draugrParameters.BaseThreadInitThunkStackSize || !draugrParameters.BaseThreadInitThunkReturnAddress) {
        return (ULONG_PTR)(NULL);
    }

    // configure RtlUserThreadStart frame.
    returnAddress = (void*)((UINT_PTR)g_stackFrame.Frame2.FunctionAddress + g_stackFrame.Frame2.Offset);
    draugrParameters.RtlUserThreadStartStackSize = calculateFunctionStackSizeWrapper(returnAddress);
    draugrParameters.RtlUserThreadStartReturnAddress = returnAddress;

    if (!draugrParameters.RtlUserThreadStartStackSize || !draugrParameters.RtlUserThreadStartReturnAddress) {
        return (ULONG_PTR)(NULL);
    }

    /*
    * Ensure that the gadget stack size is bigger than 0x80, which is min
    * required to hold 10 arguments, otherwise it will crash sporadically.
    */

    do {
        draugrParameters.Trampoline          = findGadget(g_stackFrame.pGadget);
        draugrParameters.TrampolineStackSize = calculateFunctionStackSizeWrapper(draugrParameters.Trampoline);
        
        attempts++;

        // quick sanity check for infinite loop
        if (attempts > 15) {
            return (ULONG_PTR)(NULL);
        }

    } while (draugrParameters.TrampolineStackSize == NULL || ((__int64)draugrParameters.TrampolineStackSize < 0x80));

    if (!draugrParameters.Trampoline || !draugrParameters.TrampolineStackSize) {
        return (ULONG_PTR)(NULL);
    }

    // make the call!
    return (ULONG_PTR)SpoofStub(pArg1, pArg2, pArg3, pArg4, &draugrParameters, pFunctionAddr, 8, pArg5, pArg6, pArg7, pArg8, pArg9, pArg10, pArg11, pArg12);
}

ULONG_PTR draugr(PFUNCTION_CALL functionCall)
{
    /* very inelegant */
    if (functionCall->argc == 0) {
        return draugrWrapper(functionCall->function, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 1) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 2) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 3) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 4) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 5) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 6) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), NULL, NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 7) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), NULL, NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 8) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), NULL, NULL, NULL, NULL);
    } else if (functionCall->argc == 9) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), NULL, NULL, NULL);
    } else if (functionCall->argc == 10) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), NULL, NULL);
    } else if (functionCall->argc == 11) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), (PVOID)draugrArg(10), NULL);
    } else if (functionCall->argc == 12) {
        return draugrWrapper(functionCall->function, (PVOID)draugrArg(0), (PVOID)draugrArg(1), (PVOID)draugrArg(2), (PVOID)draugrArg(3), (PVOID)draugrArg(4), (PVOID)draugrArg(5), (PVOID)draugrArg(6), (PVOID)draugrArg(7), (PVOID)draugrArg(8), (PVOID)draugrArg(9), (PVOID)draugrArg(10), (PVOID)draugrArg(11));
    }

    return (ULONG_PTR)(NULL);
}