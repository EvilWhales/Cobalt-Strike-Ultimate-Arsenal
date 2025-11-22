#pragma once

#include <windows.h>



#if _WIN64


#define ZwCreateSection NtCreateSection

__asm__("NtCreateSection: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0B8929801 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwMapViewOfSection NtMapViewOfSection

__asm__("NtMapViewOfSection: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x03F91DEC2 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwQueueApcThread NtQueueApcThread

__asm__("NtQueueApcThread: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0100F15A6 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwAlertThread NtAlertThread

__asm__("NtAlertThread: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x06BB897D7 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwResumeThread NtResumeThread

__asm__("NtResumeThread: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0103F5A11 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwUnmapViewOfSection NtUnmapViewOfSection

__asm__("NtUnmapViewOfSection: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x01CCC2661 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwClose NtClose

__asm__("NtClose: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x0C5592A11 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwOpenProcess NtOpenProcess

__asm__("NtOpenProcess: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x04DD14C44 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwCreateThreadEx NtCreateThreadEx

__asm__("NtCreateThreadEx: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x004B8C602 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#define ZwCreateUserProcess NtCreateUserProcess

__asm__("NtCreateUserProcess: \n\
mov [rsp +8], rcx \n\
mov [rsp+16], rdx \n\
mov [rsp+24], r8 \n\
mov [rsp+32], r9 \n\
sub rsp, 0x28 \n\
mov ecx, 0x049DE4A40 \n\
call SW2_GetSyscallNumber \n\
add rsp, 0x28 \n\
mov rcx, [rsp +8] \n\
mov rdx, [rsp+16] \n\
mov r8, [rsp+24] \n\
mov r9, [rsp+32] \n\
mov r10, rcx \n\
syscall \n\
ret \n\
");

#endif