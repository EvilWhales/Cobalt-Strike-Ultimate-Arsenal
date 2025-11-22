#include <windows.h>
 
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$IsWow64Process (HANDLE hProcess, PBOOL Wow64Process);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$GetCurrentProcess (VOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);


BOOL GetSyscallId(PVOID pModuleBase, DWORD* SyscallId, PCHAR fnctolookfor);
extern NTSTATUS __attribute__((naked)) executioner(HANDLE pHandle, ...);