;
; hyperv_asm.asm - Assembly implementations for Hyper-V hypercalls
;
.code

;
; BOOLEAN IsHyperVPresent(VOID)
; 
; Check if we're running under Hyper-V by using CPUID
;
IsHyperVPresent PROC
    push    rbx
    push    rcx
    push    rdx
    
    ; First check if hypervisor present bit is set
    mov     eax, 1
    cpuid
    test    ecx, 80000000h      ; Check bit 31 (hypervisor present)
    jz      not_present
    
    ; Check hypervisor vendor ID
    mov     eax, 40000000h
    cpuid
    
    ; Check for "Microsoft Hv" signature
    ; EBX should be 0x7263694D ("Micr")
    cmp     ebx, 7263694Dh
    jne     not_present
    
    ; ECX should be 0x666F736F ("osof") 
    cmp     ecx, 666F736Fh
    jne     not_present
    
    ; EDX should be 0x76482074 ("t Hv")
    cmp     edx, 76482074h
    jne     not_present
    
    ; Hyper-V is present
    mov     al, 1
    jmp     exit_proc
    
not_present:
    mov     al, 0
    
exit_proc:
    pop     rdx
    pop     rcx
    pop     rbx
    ret
IsHyperVPresent ENDP

;
; UINT64 HvReadMsr(UINT32 MsrIndex)
;
; Read a Model Specific Register
;
HvReadMsr PROC
    ; ECX = MSR index (from RCX parameter)
    mov     ecx, ecx            ; Clear upper 32 bits of ECX
    rdmsr                       ; Read MSR, result in EDX:EAX
    
    ; Combine EDX:EAX into RAX for 64-bit return value
    shl     rdx, 32
    or      rax, rdx
    
    ret
HvReadMsr ENDP

;
; VOID HvWriteMsr(UINT32 MsrIndex, UINT64 Value)
;
; Write to a Model Specific Register
;
HvWriteMsr PROC
    ; ECX = MSR index (from RCX parameter)
    ; RDX = Value (from RDX parameter)
    mov     ecx, ecx            ; Clear upper 32 bits of ECX
    mov     rax, rdx            ; Move value to RAX
    mov     rdx, rax            ; Copy for EDX
    shr     rdx, 32             ; Get upper 32 bits in EDX
    wrmsr                       ; Write MSR from EDX:EAX
    
    ret
HvWriteMsr ENDP

;
; UINT64 HvCallHypercall(
;     HYPERCALL_PROC HypercallProc,    ; RCX
;     UINT64 Control,                  ; RDX  
;     UINT64 InputParam,               ; R8
;     UINT64 OutputParam               ; R9
; )
;
; Call the hypercall function with proper register setup
;
HvCallHypercall PROC
    ; Save non-volatile registers
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; Save the hypercall procedure address
    mov     r10, rcx            ; Save hypercall proc in R10
    
    ; Set up registers for hypercall:
    ; RCX = Control (hypercall input)
    ; RDX = Input parameter address  
    ; R8  = Output parameter address
    mov     rcx, rdx            ; Control -> RCX
    mov     rdx, r8             ; InputParam -> RDX
    mov     r8, r9              ; OutputParam -> R8
    
    ; Call the hypercall procedure
    call    r10
    
    ; Result is already in RAX
    
    ; Restore non-volatile registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    
    ret
HvCallHypercall ENDP

;
; Alternative fast hypercall implementation using registers only
; UINT64 HvCallFastHypercall(UINT64 Control, UINT64 Input1, UINT64 Input2)
;
HvCallFastHypercall PROC
    ; Save registers that might be clobbered
    push    rbx
    push    rsi
    push    rdi
    
    ; Set up registers for fast hypercall:
    ; RCX = Control
    ; RDX = Input1  
    ; R8  = Input2
    ; (parameters are already in the correct registers)
    
    ; Execute hypercall via VMCALL instruction
    vmcall
    
    ; Result is in RAX
    
    ; Restore registers
    pop     rdi
    pop     rsi
    pop     rbx
    
    ret
HvCallFastHypercall ENDP

;
; Get processor information using CPUID
; VOID HvGetCpuInfo(UINT32 Function, UINT32* Eax, UINT32* Ebx, UINT32* Ecx, UINT32* Edx)
;
HvGetCpuInfo PROC
    ; Save registers
    push    rbx
    push    rsi
    push    rdi
    
    ; Save output pointers
    mov     rsi, rdx            ; EAX output pointer
    mov     rdi, r8             ; EBX output pointer  
    mov     r10, r9             ; ECX output pointer
    mov     r11, [rsp + 38h]    ; EDX output pointer (5th parameter on stack)
    
    ; Execute CPUID
    mov     eax, ecx            ; Function number
    cpuid
    
    ; Store results
    mov     [rsi], eax          ; Store EAX
    mov     [rdi], ebx          ; Store EBX
    mov     [r10], ecx          ; Store ECX
    mov     [r11], edx          ; Store EDX
    
    ; Restore registers
    pop     rdi
    pop     rsi
    pop     rbx
    
    ret
HvGetCpuInfo ENDP

END