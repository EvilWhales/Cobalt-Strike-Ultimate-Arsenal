#include "../Include/coff_loader.h"

bool InternalFunctionMatch(char* StrippedSymbolName) {
    if (STR_EQUALS(StrippedSymbolName, "Beacon")  ||
        STR_EQUALS(StrippedSymbolName, "GetProcAddress") ||
        STR_EQUALS(StrippedSymbolName, "GetModuleHandleA") ||
        STR_EQUALS(StrippedSymbolName, "toWideChar") ||
        STR_EQUALS(StrippedSymbolName, "LoadLibraryA") ||
        STR_EQUALS(StrippedSymbolName, "FreeLibrary"))
    {
        return true;
    }
    return false;
}

void* ProcessBeaconSymbols(char* SymbolName, bool InternalFunction) {
    void* functionaddress = NULL;
    char localSymbolNameCopy[1024] = { 0 };
    InternalFunction = false;
    char* locallib = NULL;
    char* localfunc = SymbolName + sizeof(PREPENDSYMBOLVALUE) - 1;
    HMODULE llHandle = NULL;
    strncpy_s(localSymbolNameCopy, SymbolName, sizeof(localSymbolNameCopy) - 1);
    char* context = NULL;

    if (InternalFunctionMatch(SymbolName + sizeof(PREPENDSYMBOLVALUE) - 1)) {
        InternalFunction = true;

        localfunc = SymbolName + strlen(PREPENDSYMBOLVALUE);
        
        DEBUG_PRINT("\t\tInternalFunction: %s\n", localfunc);

        for (int tempcounter = 0; tempcounter < 30; tempcounter++) {
            if (InternalFunctions[tempcounter][0] != NULL) {
                if (STR_EQUALS(localfunc, (char*)(InternalFunctions[tempcounter][0]))) {
                    functionaddress = (void*)InternalFunctions[tempcounter][1];
                    return functionaddress;
                }
            }
        }
    }
    else {
        DEBUG_PRINT("\t\tExternal Symbol\n");
        locallib = strtok_s(localSymbolNameCopy + sizeof(PREPENDSYMBOLVALUE) - 1, "$", &context);
        llHandle = LoadLibraryA(locallib);

        DEBUG_PRINT("\t\tHandle: 0x%lx\n", llHandle);
        localfunc = strtok_s(NULL, "$", &context);
        localfunc = strtok_s(localfunc, "@", &context);
        functionaddress = GetProcAddress(llHandle, localfunc);
        DEBUG_PRINT("\t\tProcAddress: 0x%p\n", functionaddress);
        return functionaddress;
    }
}

BOOL ExecuteEntry(COFF_t* COFF, char* func, char* args, unsigned long argSize) {
    VOID(*foo)(char* in, uint32_t datalen) = NULL;

    if (!func || !COFF->FileBase)
        DEBUG_PRINT("No entry provided");

    for (UINT32 counter = 0; counter < COFF->FileHeader->NumberOfSymbols; counter++)
    {
        if (strcmp(COFF->SymbolTable[counter].first.Name, func) == 0) {
            foo = (void(*)(char*, uint32_t))((char*)COFF->RawTextData + COFF->SymbolTable[counter].Value);
            DEBUG_PRINT("Trying to run: 0x%p\n\n", foo);
        }
    }

    if (!foo)
        DEBUG_PRINT("Couldn't find entry point");

    foo((char*)args, argSize);
    return TRUE;
}

void RelocationTypeParse(COFF_t* COFF, void** SectionMapped, int SectionNumber, bool InternalFunction, void* FunctionAddrPTR, char* FunctionMapping) {
    uint32_t offsetAddr = 0;
    uint64_t longOffsetAddr = 0;
    unsigned int Type = COFF->Relocation->Type;

    if (Type == IMAGE_REL_AMD64_ADDR64) 
    {
        memcpy(&longOffsetAddr, (char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, sizeof(uint64_t));
        DEBUG_PRINT("\tReadin longOffsetValue : 0x%llX\n", longOffsetAddr);
        longOffsetAddr = (uint64_t)((char*)SectionMapped[COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].SectionNumber - 1] + (uint64_t)longOffsetAddr);
        longOffsetAddr += COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].Value;
        DEBUG_PRINT("\tModified longOffsetValue : 0x%llX Base Address: %p\n", longOffsetAddr, SectionMapped[COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].SectionNumber - 1]);
        memcpy((char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, &longOffsetAddr, sizeof(uint64_t));
    }
    else if (COFF->Relocation->Type == IMAGE_REL_AMD64_ADDR32NB) {
        memcpy(&offsetAddr, (char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, sizeof(int32_t));
        DEBUG_PRINT("\tReadin OffsetValue : 0x%0X\n", offsetAddr);
        DEBUG_PRINT("\t\tReferenced Section: 0x%X\n", (char*)SectionMapped[COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].SectionNumber - 1] + offsetAddr);
        DEBUG_PRINT("\t\tEnd of Relocation Bytes: 0x%X\n", (char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress + 4);
        offsetAddr = ((char*)((char*)SectionMapped[COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].SectionNumber - 1] + offsetAddr) - ((char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress + 4));
        offsetAddr += COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].Value;
        DEBUG_PRINT("\tSetting 0x%p to OffsetValue: 0x%X\n", (char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, offsetAddr);
        memcpy((char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, &offsetAddr, sizeof(uint32_t));
    }
    else if (Type == IMAGE_REL_AMD64_REL32) {
        if (FunctionAddrPTR != NULL) {
            memcpy(FunctionMapping + (COFF->FunctionMappingCount * 8), &FunctionAddrPTR, sizeof(uint64_t));
            offsetAddr = (int32_t)((FunctionMapping + (COFF->FunctionMappingCount * 8) ) - ((char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress + 4));
            offsetAddr += COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].Value;
            DEBUG_PRINT("\t\tSetting internal function at 0x%p to relative address: 0x%X\n", (char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, offsetAddr);
            memcpy((char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, &offsetAddr, sizeof(uint32_t));
            InternalFunction = false;
            COFF->FunctionMappingCount++;
        }
        else {
            // This should copy the relative offset for the specified data section into offsetAddr
            memcpy(&offsetAddr, (void*)((char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress), sizeof(uint32_t));
            DEBUG_PRINT("\tReadin Offset Value : 0x%llX\n", offsetAddr);
            // Getting the symbols section then adding the offset to get the value stored.
            offsetAddr += (uint32_t)((char*)SectionMapped[COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].SectionNumber - 1] - ((char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress + 4));
            // Since the StorageClass is going to be IMAGE_SYM_CLASS_STATIC or IMAGE_SYM_CLASS_EXTERNAL with a non-zero SymbolTableIndex
            offsetAddr += COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].Value;
            DEBUG_PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, offsetAddr);
            memcpy((char*)SectionMapped[SectionNumber] + COFF->Relocation->VirtualAddress, &offsetAddr, sizeof(uint32_t));
        }
    }
    else 
    {
        DEBUG_PRINT("[!] Relocation Type Not Implemented\n");
    }
    DEBUG_PRINT("\tValueNumber: 0x%X\n", COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].Value);
    DEBUG_PRINT("\tSectionNumber: 0x%X\n", COFF->SymbolTable[COFF->Relocation->SymbolTableIndex].SectionNumber);

}

bool RunCOFF(char* FileData, DWORD* DataSize, char* EntryName, char* argumentdata, unsigned long argumentsize) {

	COFF_t COFF;
    COFF.FileBase = FileData;
    COFF.FileHeader = (FileHeader_t*)COFF.FileBase;
    COFF.SymbolTable = (Symbol_t*)(COFF.FileBase + COFF.FileHeader->PointerToSymbolTable);
    COFF.FunctionMappingCount = 0;
    COFF.RelocationsCount = 0;
    
    char* functionMapping = NULL;
    void** sectionMapped = (void**)calloc(sizeof(char*) * (COFF.FileHeader->NumberOfSections + 1), 1);;

    if ((int)COFF.FileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
        DEBUG_PRINT("[!] This common object file format is not supported yet :)");
        delete FileData;
        return false;
    }

#pragma region "Print COFF Header"
    DEBUG_PRINT("********* COFF File Header *********\n");
    DEBUG_PRINT("Machine 0x%X\n", COFF.FileHeader->Machine);
    DEBUG_PRINT("Number of sections: %d\n", COFF.FileHeader->NumberOfSections);
    DEBUG_PRINT("TimeDateStamp : %X\n", COFF.FileHeader->TimeDateStamp);
    DEBUG_PRINT("PointerToSymbolTable : 0x%X\n", COFF.FileHeader->PointerToSymbolTable);
    DEBUG_PRINT("NumberOfSymbols: %u\n", COFF.FileHeader->NumberOfSymbols);
    DEBUG_PRINT("OptionalHeaderSize: %d\n", COFF.FileHeader->SizeOfOptionalHeader);
    DEBUG_PRINT("Characteristics: %d\n", COFF.FileHeader->Characteristics);
    DEBUG_PRINT("\n");
#pragma endregion

    for (byte i = 0; i < COFF.FileHeader->NumberOfSections; i++) {
        Section_t* section = (Section_t*)(COFF.FileBase + sizeof(FileHeader_t) + (i * sizeof(Section_t)));
        DEBUG_PRINT("********* COFF Section %d: \"%s\" *********\n", i, section->Name);

        sectionMapped[i] = (char*)VirtualAlloc(NULL, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
        DEBUG_PRINT("Allocated section %d at 0x%p\n", i, sectionMapped[i]);

        if (section->PointerToRawData != 0) {
            memcpy(sectionMapped[i], COFF.FileBase + section->PointerToRawData, section->SizeOfRawData);
        }
        else {
            memset(sectionMapped[i], 0, section->SizeOfRawData);
        }

        if (!strcmp(section->Name, ".text")) {
            COFF.RawTextData = sectionMapped[i];
        }

        COFF.RelocationsCount += section->NumberOfRelocations;

#pragma region "Print Section Table"
        DEBUG_PRINT("Name: %s\n", section->Name);
        DEBUG_PRINT("VirtualSize: 0x%X\n", section->VirtualSize);
        DEBUG_PRINT("VirtualAddress: 0x%X\n", section->VirtualAddress);
        DEBUG_PRINT("SizeOfRawData: 0x%X\n", section->SizeOfRawData);
        DEBUG_PRINT("PointerToRelocations: 0x%X\n", section->PointerToRelocations);
        DEBUG_PRINT("PointerToRawData: 0x%X\n", section->PointerToRawData);
        DEBUG_PRINT("NumberOfRelocations: %d\n", section->NumberOfRelocations);
        DEBUG_PRINT("Characteristics: %x\n\n", section->Characteristics);
#pragma endregion

    }

    DEBUG_PRINT("Total Relocations: %d\n", COFF.RelocationsCount);

    functionMapping = (char*)VirtualAlloc(NULL, COFF.RelocationsCount * 8, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
    int currentSection = 0;
    for (int s = 0; s < COFF.FileHeader->NumberOfSections; s++) {
        Section_t* section = (Section_t*)(COFF.FileBase + sizeof(FileHeader_t) + (s * sizeof(Section_t)));
        COFF.RelocationsTextPTR = COFF.FileBase + section->PointerToRelocations;
        DEBUG_PRINT("********* Performing Relocations for \"%s\" Section *********\n", section->Name);
        
        for (int i = 0; i < section->NumberOfRelocations; i++) {

            uint32_t symbolOffset = 0;
            void* funcptrlocation = NULL;
            COFF.Relocation = (Relocation_t*)(COFF.RelocationsTextPTR + (i * sizeof(Relocation_t)));

#pragma region "Print Relocation Struct"
            DEBUG_PRINT("********* COFF Relocation %d / %d *********\n", i, section->NumberOfRelocations);
            DEBUG_PRINT("VirtualAddress: 0x%X\n", COFF.Relocation->VirtualAddress);
            DEBUG_PRINT("SymbolTableIndex: 0x%X\n", COFF.Relocation->SymbolTableIndex);
            DEBUG_PRINT("Type: 0x%X\n\n", COFF.Relocation->Type);
#pragma endregion
            
            symbolOffset = COFF.SymbolTable[COFF.Relocation->SymbolTableIndex].first.value[1];

            // Check if the symbol name is more that 8 bytes. If so then the name is stored at the .first.value address
            // We can assume that if the name is longer than 8 bytes then it is probably an internal function and starts with "__imp_" and needs to be processed.
            // So if the name is 8 bytes then it points to a specific section.
            if (COFF.SymbolTable[COFF.Relocation->SymbolTableIndex].first.Name[0] != 0) {

#pragma region "Print Mapped Relocation Symbol"
                DEBUG_PRINT("\tSymPtr: 0x%X\n", symbolOffset);
                DEBUG_PRINT("\tSymName: %s\n", COFF.SymbolTable[COFF.Relocation->SymbolTableIndex].first.Name);
                DEBUG_PRINT("\tSectionNumber: 0x%X\n", COFF.SymbolTable[COFF.Relocation->SymbolTableIndex].SectionNumber);
#pragma endregion

                RelocationTypeParse(&COFF, sectionMapped, s, false, NULL, NULL);
            }
            else {
#pragma region "Print Mapped Relocation Symbol"
                DEBUG_PRINT("[!] Symbol Name is longer than 8 bytes\n");
                DEBUG_PRINT("\tSymPtr: 0x%X\n", symbolOffset);
                DEBUG_PRINT("\tSymName: %s\n", ((char*)(COFF.SymbolTable + COFF.FileHeader->NumberOfSymbols)) + symbolOffset);
                DEBUG_PRINT("\tSectionNumber: 0x%X\n", COFF.SymbolTable[COFF.Relocation->SymbolTableIndex].SectionNumber);
#pragma endregion

                bool internalFunctionCheck = false;
                funcptrlocation = ProcessBeaconSymbols(((char*)(COFF.SymbolTable + COFF.FileHeader->NumberOfSymbols)) + symbolOffset, &internalFunctionCheck);
                if (funcptrlocation == NULL && COFF.SymbolTable[COFF.Relocation->SymbolTableIndex].SectionNumber == 0) {
                    DEBUG_PRINT("[!] Failed to resolve symbol\n");
                }

                RelocationTypeParse(&COFF, sectionMapped, s, &internalFunctionCheck, funcptrlocation, functionMapping);
            }
        }
    }

    ExecuteEntry(&COFF, EntryName, argumentdata, argumentsize);

    return true;
}