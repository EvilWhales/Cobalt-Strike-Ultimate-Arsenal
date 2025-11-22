#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>
//#include "beacon.h"
#include "syscalls-asm.h"

#ifdef _WIN64
#define ULONGSIZE ULONG64
#else
#define ULONGSIZE ULONG32
#endif

#ifdef _WIN64
#define PEB_OFFSET 0x60
#define READ_MEMLOC __readgsqword
#else
#define PEB_OFFSET 0x30
#define READ_MEMLOC __readfsdword
#endif

#define SW2_SEED 0x655E97F3

#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

#define STATUS_SUCCESS 0x00000000

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
PVOID Reserved1[2];
LIST_ENTRY InMemoryOrderLinks;
PVOID Reserved2[2];
PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_SYSCALL_ENTRY
{
DWORD Hash;
DWORD Address;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
DWORD Count;
SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
BYTE Reserved1[8];
PVOID Reserved2[3];
LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_PEB {
BYTE Reserved1[2];
BYTE BeingDebugged;
BYTE Reserved2[1];
PVOID Reserved3[2];
PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef VOID(KNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        VOID*    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
    IN PVOID            ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG            Reserved);

EXTERN_C NTSTATUS NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL) asm("NtCreateSection");
    
EXTERN_C NTSTATUS NtQueueApcThread(
    IN HANDLE ThreadHandle,
    IN PKNORMAL_ROUTINE ApcRoutine,
    IN PVOID ApcArgument1 OPTIONAL,
    IN PVOID ApcArgument2 OPTIONAL,
    IN PVOID ApcArgument3 OPTIONAL) asm("NtQueueApcThread");
    
EXTERN_C NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL) asm("NtOpenProcess");
    
EXTERN_C NTSTATUS NtAlertThread(
    IN HANDLE ThreadHandle) asm("NtAlertThread");
    
EXTERN_C NTSTATUS NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress) asm("NtUnmapViewOfSection");
    
EXTERN_C NTSTATUS NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID BaseAddress,
    IN ULONG ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect) asm("NtMapViewOfSection");
    
EXTERN_C NTSTATUS NtResumeThread(
    IN HANDLE ThreadHandle,
    IN OUT PULONG PreviousSuspendCount OPTIONAL) asm("NtResumeThread");
    
EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL) asm("NtCreateThreadEx");
    
EXTERN_C NTSTATUS NtClose(
    IN HANDLE Handle) asm("NtClose");

#endif

void mymemcopy(char * dst, const char * src, int size) {
        int x;
        for (x = 0; x < size; x++) {
                *dst = *src;
                dst++;
                src++;
        }
}

DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);