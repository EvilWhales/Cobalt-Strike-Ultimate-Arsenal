#pragma once
#include <stdio.h>
#include <Windows.h>
#include <cstdint>

extern "C" {
    #include "beacon_compatibility.h"
}

#ifdef _DEBUG
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

#if defined(__x86_64__) || defined(_WIN64)
#define PREPENDSYMBOLVALUE "__imp_"
#else
#define PREPENDSYMBOLVALUE "__imp__"
#endif

#define STR_EQUALS(str, substr) (strncmp(str, substr, strlen(substr)) == 0)

//https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
typedef struct coff_file_header {
    uint16_t Machine;		            
    uint16_t NumberOfSections;          
    uint32_t TimeDateStamp;             
    uint32_t PointerToSymbolTable;      
    uint32_t NumberOfSymbols;           
    uint16_t SizeOfOptionalHeader;      
    uint16_t Characteristics;           
} FileHeader_t;

#pragma pack(push,1)

//https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
typedef struct coff_sections_table {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} Section_t;

//https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-relocations-object-only
typedef struct coff_relocations {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} Relocation_t;

//https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table
typedef struct coff_symbols_table {
    union {
        char Name[8];
        uint32_t value[2];
    } first;
    uint32_t Value;
    uint16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} Symbol_t;


typedef struct COFF {
    char* FileBase;
    FileHeader_t* FileHeader;
    Relocation_t* Relocation;
    Symbol_t* SymbolTable;

    void* RawTextData;
    char* RelocationsTextPTR;
    int RelocationsCount;
    int FunctionMappingCount;
} COFF_t;

bool RunCOFF(char* FileData, DWORD* DataSize, char* EntryName, char* ArgumentData, unsigned long ArgumentSize);
