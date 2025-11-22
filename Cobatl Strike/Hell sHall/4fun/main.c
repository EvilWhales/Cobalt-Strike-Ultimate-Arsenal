// test_shellcode_exec.c
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#pragma comment(lib, "kernel32.lib")

// Create hidden window to load the DLL into



int main(void) {
	HWND hWnd = GetConsoleWindow();
	if (hWnd != NULL) {
		ShowWindow(hWnd, SW_HIDE);
	}

    printf("[*] starting\n");
	HMODULE hMod = LoadLibraryA("test.dll");
	if (!hMod) {
		printf("[!] LoadLibraryA failed\n");
		return -1;
	}
	printf("[*] LoadLibraryA succeeded\n");

	PVOID pFunc = GetProcAddress(hMod, "RunPayload");
	if (!pFunc) {
		printf("[!] GetProcAddress failed\n");
		return -1;
	}
	printf("[*] GetProcAddress succeeded\n");
	typedef BOOL(*pRunPayload)();
	pRunPayload RunPayload = (pRunPayload)pFunc;
	if (!RunPayload) {
		printf("[!] Failed to cast RunPayload function\n");
		return -1;
	}

	if (!RunPayload()) {
		printf("[*] RunPayload succeeded\n");
	}
	else {
		printf("[!] RunPayload failed\n");
		return -1;
	}

	printf(">> Press to EXIT");
	getchar();
    return 0;
}
