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

typedef struct _DRAUGR_PARAMETERS {
    PVOID       Fixup;                                 // 0
    PVOID       OriginalReturnAddress;                 // 8
    PVOID       Rbx;                                   // 16
    PVOID       Rdi;                                   // 24
    PVOID       BaseThreadInitThunkStackSize;          // 32
    PVOID       BaseThreadInitThunkReturnAddress;      // 40
    PVOID       TrampolineStackSize;                   // 48
    PVOID       RtlUserThreadStartStackSize;           // 56
    PVOID       RtlUserThreadStartReturnAddress;       // 64
    PVOID       Ssn;                                   // 72
    PVOID       Trampoline;                            // 80
    PVOID       Rsi;                                   // 88
    PVOID       R12;                                   // 96
    PVOID       R13;                                   // 104
    PVOID       R14;                                   // 112
    PVOID       R15;                                   // 120
} DRAUGR_PARAMETERS, * PDRAUGR_PARAMETERS;

typedef PVOID (*DRAUGR)(PVOID, PVOID, PVOID, PVOID, PDRAUGR_PARAMETERS, PVOID, SIZE_T, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);