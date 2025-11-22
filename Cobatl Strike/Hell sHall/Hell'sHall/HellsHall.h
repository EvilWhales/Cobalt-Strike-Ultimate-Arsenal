#include <Windows.h>


#ifndef HELLHALL_H
#define HELLHALL_H


typedef struct _NT_SYSCALL
{
    DWORD dwSSn;                    // syscall number
    DWORD dwSyscallHash;            // syscall hash value
    PVOID pSyscallAddress;          // syscall address
    PVOID pSyscallInstAddress;      // address of a random 'syscall' instruction in ntdll    

}NT_SYSCALL, * PNT_SYSCALL;


//unsigned int crc32b(char* str);
//#define HASH(API)	(crc32b((char*)API))

unsigned int Rs(char* str);
#define HASH(API)	(Rs((char*)API))


// from 'sc.c'
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);
FARPROC MyGetProcAddress(HMODULE hModule, LPCSTR funcName);
LPVOID FindETWbyHash(DWORD dwSysHash);

// from 'sc.asm'
extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern RunSyscall();


//  a macro to make calling 'SetSSn' easier
#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))


#endif // !HELLHALL_H







