; DNSASM - Ultra-Fast DNS Packet Processor
; x86_64 NASM Assembly - Question Section Parsing
;
; Parses DNS question section with optimized name decompression.

bits 64
default rel

section .data
    align 16

section .rodata
    align 16
    ; Lowercase conversion mask (for case-insensitive comparison)
    lowercase_mask: times 16 db 0x20

section .bss
    align 16

section .text
    global dnsasm_parse_question
    global dnsasm_decompress_name

; ============================================================================
; dnsasm_result_t dnsasm_parse_question(const uint8_t *packet, size_t len,
;                                        size_t offset, dnsasm_question_t *out)
;
; Arguments:
;   rdi = packet pointer
;   rsi = packet length
;   rdx = offset to start of question
;   rcx = output structure pointer
;
; Returns:
;   rax = result structure (error in low 32 bits, offset in high 32 bits)
;
; Performance: ~50 cycles for typical names (e.g., "www.example.com")
; ============================================================================
dnsasm_parse_question:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    
    mov     r12, rdi                ; packet
    mov     r13, rsi                ; len
    mov     r14, rdx                ; offset
    mov     r15, rcx                ; out
    
    ; Parse name into out->name
    lea     rdi, [r15]              ; out->name buffer
    mov     rsi, r12                ; packet
    mov     rdx, r13                ; len
    mov     rcx, r14                ; offset
    call    .decompress_name_internal
    
    ; Check for error
    test    eax, eax
    js      .error
    
    ; eax = decompressed name length
    ; edx = wire bytes consumed
    mov     word [r15 + 256], ax    ; out->name_len (at offset 256)
    
    ; Calculate new offset after name
    add     r14, rdx                ; offset += wire_len
    
    ; Check we have room for qtype + qclass (4 bytes)
    lea     rax, [r14 + 4]
    cmp     rax, r13
    ja      .too_short
    
    ; Read qtype (2 bytes, network order)
    movzx   eax, word [r12 + r14]
    xchg    al, ah                  ; byte swap
    mov     word [r15 + 258], ax    ; out->qtype
    
    ; Read qclass (2 bytes, network order)
    movzx   eax, word [r12 + r14 + 2]
    xchg    al, ah
    mov     word [r15 + 260], ax    ; out->qclass
    
    ; Calculate total wire length
    add     edx, 4                  ; name_wire_len + 4 (qtype + qclass)
    mov     word [r15 + 262], dx    ; out->wire_len
    
    ; Build result: offset in high 32 bits, error (0) in low 32 bits
    add     r14, 4                  ; final offset
    shl     r14, 32
    xor     eax, eax                ; error = 0
    or      rax, r14
    
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.too_short:
    mov     eax, -1                 ; DNSASM_ERR_SHORT
    jmp     .return_error

.error:
    ; eax already contains error code
.return_error:
    ; Return error with zero offset
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret


; ============================================================================
; Internal: decompress_name_internal
;
; Arguments:
;   rdi = output buffer (255+ bytes)
;   rsi = packet pointer
;   rdx = packet length
;   rcx = offset to start of name
;
; Returns:
;   eax = decompressed name length (negative on error)
;   edx = wire bytes consumed (for first name only, not following pointers)
; ============================================================================
.decompress_name_internal:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    
    mov     r8, rdi                 ; out buffer
    mov     r9, rsi                 ; packet
    mov     r10, rdx                ; len
    mov     r11, rcx                ; offset
    
    xor     r12d, r12d              ; out_len = 0
    xor     r13d, r13d              ; wire_len = 0 (only count first traversal)
    xor     r14d, r14d              ; pointer_count = 0 (loop detection)
    mov     r15d, 1                 ; counting_wire = 1 (stop after first pointer)
    
.label_loop:
    ; Check offset bounds
    cmp     r11, r10
    jae     .name_too_short
    
    ; Read label length byte
    movzx   eax, byte [r9 + r11]
    
    ; Check for compression pointer (top 2 bits = 11)
    mov     ecx, eax
    and     ecx, 0xC0
    cmp     ecx, 0xC0
    je      .compression_pointer
    
    ; Check for end of name (length = 0)
    test    eax, eax
    jz      .end_of_name
    
    ; Regular label
    ; Check label length is valid (1-63)
    cmp     eax, 63
    ja      .bad_name
    
    ; Check we won't overflow output buffer
    mov     ecx, r12d
    add     ecx, eax
    add     ecx, 1                  ; out_len + label_len + 1 (for length byte)
    cmp     ecx, 255
    ja      .name_overflow
    
    ; Check we have enough packet data
    lea     rcx, [r11 + rax + 1]
    cmp     rcx, r10
    ja      .name_too_short
    
    ; Copy label length byte
    mov     byte [r8 + r12], al
    inc     r12d
    
    ; Update wire length if still counting
    test    r15d, r15d
    jz      .skip_wire_count
    add     r13d, eax
    inc     r13d                    ; +1 for length byte
.skip_wire_count:
    
    ; Copy label bytes
    inc     r11                     ; skip length byte
    mov     ecx, eax                ; label length
    
.copy_label:
    movzx   eax, byte [r9 + r11]
    mov     byte [r8 + r12], al
    inc     r11
    inc     r12d
    dec     ecx
    jnz     .copy_label
    
    jmp     .label_loop

.compression_pointer:
    ; Compression pointer detected
    ; Format: 11xxxxxx xxxxxxxx (14-bit offset)
    
    ; Check we have the second byte
    lea     rcx, [r11 + 2]
    cmp     rcx, r10
    ja      .name_too_short
    
    ; Read 16-bit pointer and mask off top 2 bits
    movzx   eax, word [r9 + r11]
    xchg    al, ah                  ; byte swap
    and     eax, 0x3FFF             ; mask to 14 bits
    
    ; Update wire length if still counting
    test    r15d, r15d
    jz      .skip_ptr_wire
    add     r13d, 2                 ; pointer is 2 bytes
    xor     r15d, r15d              ; stop counting wire after pointer
.skip_ptr_wire:
    
    ; Loop detection
    inc     r14d
    cmp     r14d, 127               ; max reasonable pointer chain
    ja      .pointer_loop
    
    ; Check pointer doesn't point forward
    cmp     eax, r11d
    jae     .bad_pointer
    
    ; Follow the pointer
    mov     r11d, eax
    jmp     .label_loop

.end_of_name:
    ; Add null terminator
    mov     byte [r8 + r12], 0
    inc     r12d
    
    ; Update wire length for final null (if still counting)
    test    r15d, r15d
    jz      .done
    inc     r13d
    
.done:
    mov     eax, r12d               ; return name length
    mov     edx, r13d               ; return wire length
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.name_too_short:
    mov     eax, -1                 ; DNSASM_ERR_SHORT
    jmp     .error_return

.bad_name:
    mov     eax, -2                 ; DNSASM_ERR_NAME
    jmp     .error_return

.bad_pointer:
    mov     eax, -3                 ; DNSASM_ERR_POINTER
    jmp     .error_return

.pointer_loop:
    mov     eax, -4                 ; DNSASM_ERR_LOOP
    jmp     .error_return

.name_overflow:
    mov     eax, -5                 ; DNSASM_ERR_OVERFLOW
    
.error_return:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret


; ============================================================================
; dnsasm_result_t dnsasm_decompress_name(const uint8_t *packet, size_t len,
;                                         size_t offset, uint8_t *out,
;                                         uint16_t *out_len)
;
; Public wrapper for name decompression.
;
; Arguments:
;   rdi = packet pointer
;   rsi = packet length
;   rdx = offset
;   rcx = output buffer
;   r8  = out_len pointer
;
; Returns:
;   rax = result (error in low 32, wire_len in high 32)
; ============================================================================
dnsasm_decompress_name:
    push    rbx
    push    r12
    
    mov     r12, r8                 ; save out_len pointer
    
    ; Rearrange arguments for internal function
    mov     r8, rcx                 ; out buffer
    mov     rcx, rdx                ; offset
    mov     rdx, rsi                ; len
    mov     rsi, rdi                ; packet
    mov     rdi, r8                 ; out buffer
    
    ; Call internal
    push    r12
    call    dnsasm_parse_question.decompress_name_internal
    pop     r12
    
    ; Store out_len if successful
    test    eax, eax
    js      .decompress_error
    
    mov     word [r12], ax          ; *out_len = name_len
    
    ; Build result: wire_len in high 32, 0 (success) in low 32
    mov     ecx, edx
    shl     rcx, 32
    xor     eax, eax
    or      rax, rcx
    
    pop     r12
    pop     rbx
    ret

.decompress_error:
    ; eax already has error code
    pop     r12
    pop     rbx
    ret
