#include "../Include/coff_loader.h"
#include "../Include/utils.h"

int main(int argc, char* argv[]){
	DWORD coffSize = 0;
	char* coffData = NULL;
	char* outdata = NULL;
	int outdataSize = 0;

	PrintBanner();

	if (argc < 3)
	{
		PrintUsage(argv[0]);
		return 1;
	}

	coffData = ReadFile((char*)argv[2], &coffSize);
	if (coffData == NULL) 
	{
		printf("");
		return 1;
	}

	Arg arg1;
	short testNum = 8;
	arg1.value = (char*)&testNum;
	arg1.size = sizeof(short);
	arg1.includeSize = FALSE;

	Arg args[1] = {arg1};

	char* argumentsString = NULL;
	size_t argumentsSize;
	PackData(args,1, &argumentsString, &argumentsSize);

	printf("\n[+] Executing COFF File\n");

	if (RunCOFF(coffData, &coffSize, (char*)argv[1], argumentsString, argumentsSize)) {
		printf("\n[+] SUCCESS - Executed COFF File\n");
	}

	outdata = BeaconGetOutputData(&outdataSize);
	if (outdata != NULL) {

		printf("\n[+] Outdata Below:\n\n%s\n", outdata);
	}

	return 0;
}