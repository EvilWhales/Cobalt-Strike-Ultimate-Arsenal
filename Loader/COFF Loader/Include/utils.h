#include <stdio.h>
#include <cstdint>
#include <Windows.h>
#include <iostream>

#ifdef _DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

typedef struct _Arg {
    char* value;
    size_t size;
    BOOL includeSize;
} Arg;


void PrintBanner();
void PrintUsage(char* ExecutableName);
void PackData(Arg* args, size_t numberOfArgs, char** output, size_t* size);
char* ReadFile(char* FilePath, DWORD* FileSize);