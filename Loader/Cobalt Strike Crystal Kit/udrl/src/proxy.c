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

void * __attribute__((naked)) SpoofStub()
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "pop rax;"                       // Real return address in rax
        "mov r10, rdi;"                  // Store OG rdi in r10
        "mov r11, rsi;"                  // Store OG rsi in r11
        "mov rdi, [rsp + 32];"           // Storing struct in rdi
        "mov rsi, [rsp + 40];"           // Storing function to call
        
        // Storing our original registers
        "mov [rdi + 24], r10;"           // Storing OG rdi into param
        "mov [rdi + 88], r11;"           // Storing OG rsi into param
        "mov [rdi + 96], r12;"           // Storing OG r12 into param
        "mov [rdi + 104], r13;"          // Storing OG r13 into param
        "mov [rdi + 112], r14;"          // Storing OG r14 into param
        "mov [rdi + 120], r15;"          // Storing OG r15 into param
        "mov r12, rax;"                  // OG code used r12 for ret addr
        
        // Prepping to move stack args
        "xor r11, r11;"                  // r11 will hold the # of args that have been pushed
        "mov r13, [rsp + 0x30];"         // r13 will hold the # of args total that will be pushed
        "mov r14, 0x200;"                // r14 will hold the offset we need to push stuff
        "add r14, 8;"
        "add r14, [rdi + 56];"           // stack size of RtlUserStartThread
        "add r14, [rdi + 48];"           // stack size of BaseInitThreadThunk
        "add r14, [rdi + 32];"           // stack size of our gadget frame
        "sub r14, 0x20;"                 // first stack arg is located at + 0x28 from rsp, so we sub 0x20 from the offset. Loop will sub 0x8 each time.
        "mov r10, rsp;"
        "add r10, 0x30;"                 // offset of stack arg added to rsp
        "looping:;"
        "xor r15, r15;"                // r15 will hold the offset + rsp base
        "cmp r11d, r13d;"              // comparing # of stack args added vs # of stack args we need to add
        "je finish;"
        
        // Getting location to move the stack arg to
        "sub r14, 8;"                  // 1 arg means r11 is 0, r14 already 0x28 offset.
        "mov r15, rsp;"                // get current stack base
        "sub r15, r14;"                // subtract offset
        
        // Procuring the stack arg
        "add r10, 8;"
        "push qword ptr [r10];"
        "pop qword ptr [r15];"
        
        // Increment the counter and loop back in case we need more args
        "add r11, 1;"
        "jmp looping;"
        "finish:;"
        "sub rsp, 0x200;"              // Creating a large 320 byte frame for our fake call stack
        "push 0;"                      // Pushing a 0 to cut off the return addresses after RtlUserThreadStart
        "sub rsp, [rdi + 56];"         // RtlUserThreadStart + offset frame
        "mov r11, [rdi + 64];"
        "mov [rsp], r11;"
        "sub rsp, [rdi + 32];"         // BaseThreadInitThunk + offset frame
        "mov r11, [rdi + 40];"
        "mov [rsp], r11;"
        "sub rsp, [rdi + 48];"         // Gadget frame
        "mov r11, [rdi + 80];"
        "mov [rsp], r11;"
        // Adjusting the param struct for the fixup
        "mov r11, rsi;"                // Copying function to call into r11
        "mov [rdi + 8], r12;"          // Real return address is now moved into the "OriginalReturnAddress" member
        "mov [rdi + 16], rbx;"         // original rbx is stored into "Rbx" member
        "lea rbx, [rip + fixup];"      // Fixup address is moved into rbx
        "mov [rdi], rbx;"              // Fixup member now holds the address of Fixup
        "mov rbx, rdi;"                // Address of param struct (Fixup)is moved into rbx
        
        // For indirect syscall use. If you want to use it, make sure to set ssn
        // in param struct first.Otherwise, this is ignored by the callee.
        "mov r10, rcx;"
        "mov rax, [rdi + 72];"
        "jmp r11;"
        "fixup:;"
        "mov rcx, rbx;"
        "add rsp, 0x200;"                // Remove our large frame
        "add rsp, [rbx + 48];"           // Adjust back for our gadget frame
        "add rsp, [rbx + 32];"           // Adjust back for our BaseThreadInitThunk frame
        "add rsp, [rbx + 56];"           // Adjust back for our RtlUserThreadStart frame
        "mov rbx, [rcx + 16];"           // Restoring OG RBX
        "mov rdi, [rcx + 24];"           // Restoring OG rdi
        "mov rsi, [rcx + 88];"           // Restoring OG rsi
        "mov r12, [rcx + 96];"           // Restoring OG r12
        "mov r13, [rcx + 104];"          // Restoring OG r13
        "mov r14, [rcx + 112];"          // Restoring OG r14
        "mov r15, [rcx + 120];"          // Restoring OG r15
        "push rax;"
        "xor rax, rax;"
        "pop rax;"
        "jmp qword ptr [rcx + 8];"
        
        ".att_syntax prefix"
    );
}