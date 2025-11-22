#include "../Include/utils.h"
using namespace std;

void PrintBanner() {
#pragma region Banner
	printf("	 .o88b.  .d88b.  d88888b d88888b      db       .d88b.   .d8b.  d8888b. d88888b d8888b.\n");
	printf("	d8P  Y8 .8P  Y8. 88'     88'          88      .8P  Y8. d8' `8b 88  `8D 88'     88  `8D\n");
	printf("	8P      88    88 88ooo   88ooo        88      88    88 88ooo88 88   88 88ooooo 88oobY' \n");
	printf("	8b      88    88 88~~~   88~~~        88      88    88 88~~~88 88   88 88~~~~~ 88`8b\n");
	printf("	Y8b  d8 `8b  d8' 88      88           88booo. `8b  d8' 88   88 88  .8D 88.     88 `88.\n");
	printf("	 `Y88P'  `Y88P'  YP      YP           Y88888P  `Y88P'  YP   YP Y8888D' Y88888P 88   YD \n");
	printf("	Written by: Ap3x (https://github.com/Ap3x)\n\n");
#pragma endregion
}

void PrintUsage(char* ExecutableName) {
	printf("\nUsage:\n%s <Execute Function Name> <COFF Full Path> \n", ExecutableName);
}

void PackData(Arg* args, size_t numberOfArgs, char** output, size_t* size) {
	uint32_t fullSize = 0;
	for (size_t i = 0; i < numberOfArgs; i++) {
		Arg arg = args[i];
		fullSize += sizeof(uint32_t) + arg.size;
	}
	*output = (char*)malloc(sizeof(uint32_t) + fullSize);
	fullSize = 4;
	for (size_t i = 0; i < numberOfArgs; i++) {
		Arg arg = args[i];
		if (arg.includeSize == TRUE) {
			memcpy(*output + fullSize, &arg.size, sizeof(uint32_t));
			fullSize += sizeof(uint32_t);
		}
		memcpy(*output + fullSize, arg.value, arg.size);
		fullSize += arg.size;
	}
	memcpy(*output, &fullSize, sizeof(uint32_t));
	*size = fullSize;
}

char* ReadFile(char* FilePath, DWORD* FileSize) {
	HANDLE hFile = CreateFileA(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		DEBUG_PRINT("[!] Failed to open the file");
		return nullptr;
	}
	*FileSize = GetFileSize(hFile, NULL);
	if (*FileSize == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return nullptr;
	}

	char* coffData = new char[*FileSize];

	DWORD bytesRead;
	if (!ReadFile(hFile, coffData, *FileSize, &bytesRead, NULL)) {
		CloseHandle(hFile);
		delete[] coffData;
		return nullptr;
	}

	CloseHandle(hFile);

	return coffData;
}