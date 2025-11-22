#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include <dsgetdc.h>
#include "beacon.h"

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);
WINBASEAPI int __cdecl MSVCRT$printf(const char * __restrict__ _Format,...);
WINBASEAPI int __cdecl MSVCRT$wcscpy(wchar_t* dest, const wchar_t* src);

char* TestGlobalString = "This is a global string";
/* Can't do stuff like "int testvalue;" in a coff file, because it assumes that
 * the symbol is like any function, so you would need to allocate a section of bss
 * (without knowing the size of it), and then resolve the symbol to that. So safer
 * to just not support that */
int testvalue = 0;

int function1(void){
    MSVCRT$printf("Test String from function1\n");
    testvalue = 1;
    return 0;
}

int function2(void){
    MSVCRT$printf("Test String from function2\n");
    return 0;
}


void go(char * args, unsigned long alen) {
    BOOL compNameStatus = 0;
    PDOMAIN_CONTROLLER_INFO pdcInfo;
    BeaconPrintf(1, "Global CHAR* \"%s\"\n", TestGlobalString);
    MSVCRT$printf("Global Test INT: %d\n", testvalue);
    (void)function1();
    MSVCRT$printf("Test ValueBack: %d\n", testvalue);

    datap parser;
	BeaconDataParse(&parser, args, alen);
/* Arguments should be unpacked in the same order they were packed */
    int number = BeaconDataShort(&parser);

	BeaconPrintf(CALLBACK_OUTPUT, "Number passed: %i\n", number); 
    (void)function2();

    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    compNameStatus = KERNEL32$GetComputerNameA(computerName, &size);
    if (compNameStatus) {
        BeaconPrintf(1,"The computer name is: %s\n", computerName);
    }
}
