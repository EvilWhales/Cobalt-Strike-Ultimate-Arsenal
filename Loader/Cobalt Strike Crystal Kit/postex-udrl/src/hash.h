/*
 * Copyright 2025 Daniel Duggan, Zero-Point Security
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <windows.h>

#define KERNEL32DLL_HASH  0x6A4ABC5B
#define NTDLLDLL_HASH     0x3CFA685D

#define TEXT_HASH         0xEBC2F9B4

#define LOADLIBRARYA_HASH            0xEC0E4E8E
#define LOADLIBRARYW_HASH            0xEC0E4EA4
#define LOADLIBRARYEXW_HASH          0x753A512
#define GETPROCADDRESS_HASH          0x7C0DFCAA
#define RTLLOOKUPFUNCTIONENTRY_HASH  0xC1D846D9
#define GETMODULEHANDLEA_HASH        0xD3324904
#define VIRTUALALLOC_HASH            0x91AFCA54
#define VIRTUALALLOCEX_HASH          0x6E1A959C
#define VIRTUALPROTECT_HASH          0x7946C61B
#define VIRTUALPROTECTEX_HASH        0x53D98756
#define VIRTUALFREE_HASH             0x30633AC
#define GETTHREADCONTEXT_HASH        0x68A7C7D2
#define SETTHREADCONTEXT_HASH        0xE8A7C7D3
#define INTERNETOPENA_HASH           0x57E84429
#define INTERNETCONNECTA_HASH        0x1E4BE80E
#define RESUMETHREAD_HASH            0x9E4A3F88
#define CREATETHREAD_HASH            0xCA2BD06B
#define CREATEREMOTETHREAD_HASH      0x72BD9CDD
#define OPENPROCESS_HASH             0xEFE297C0
#define OPENTHREAD_HASH              0x58C91E6F
#define CLOSEHANDLE_HASH             0xFFD97FB
#define CREATEFILEMAPPINGA_HASH      0x56C61229
#define MAPVIEWOFFILE_HASH           0x7B073C59
#define UNMAPVIEWOFFILE_HASH         0xB2089259
#define VIRTUALQUERY_HASH            0xA3C8C8AA
#define DUPLICATEHANDLE_HASH         0xBD566724
#define READPROCESSMEMORY_HASH       0x579D1BE9
#define WRITEPROCESSMEMORY_HASH      0xD83D6AA1
#define EXITTHREAD_HASH              0x60E0CEEF
#define CREATEPROCESSA_HASH          0x16B3FE72
#define SLEEP_HASH                   0xDB2D49B0

#define HASH_KEY 13

#ifndef __MINGW32__
#pragma intrinsic( _rotr )
#endif

__forceinline DWORD ror( DWORD d ) {
    return _rotr( d, HASH_KEY );
}

__forceinline DWORD hash( char * c )
{
    register DWORD h = 0;
    do
    {
        h = ror( h );
        h += *c;
    } while( *++c );

    return h;
}