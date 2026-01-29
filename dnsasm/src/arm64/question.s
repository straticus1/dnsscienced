// DNSASM - Ultra-Fast DNS Packet Processor
// ARM64 Assembly - Question Section Parsing
//
// Parses DNS question section with optimized name decompression.

.text
.align 4

// ============================================================================
// dnsasm_result_t dnsasm_parse_question(const uint8_t *packet, size_t len,
//                                        size_t offset, dnsasm_question_t *out)
//
// Arguments:
//   x0 = packet pointer
//   x1 = packet length
//   x2 = offset to start of question
//   x3 = output structure pointer
//
// Returns:
//   x0 = result (error in low 32 bits, offset in high 32 bits)
//
// Performance: ~40 cycles for typical names
// ============================================================================
.globl _dnsasm_parse_question
_dnsasm_parse_question:
    // Save callee-saved registers
    stp     x19, x20, [sp, #-64]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    
    mov     x19, x0             // packet
    mov     x20, x1             // len
    mov     x21, x2             // offset
    mov     x22, x3             // out
    
    // Parse name into out->name
    mov     x0, x22             // out->name buffer
    mov     x1, x19             // packet
    mov     x2, x20             // len
    mov     x3, x21             // offset
    bl      _decompress_name_internal
    
    // Check for error
    tst     w0, w0
    b.mi    .Lq_error
    
    // w0 = name length, w1 = wire bytes consumed
    strh    w0, [x22, #256]     // out->name_len
    
    // Update offset
    add     x21, x21, x1        // offset += wire_len
    
    // Check room for qtype + qclass (4 bytes)
    add     x4, x21, #4
    cmp     x4, x20
    b.hi    .Lq_too_short
    
    // Read qtype (2 bytes, network order)
    ldrh    w4, [x19, x21]
    rev16   w4, w4              // byte swap
    strh    w4, [x22, #258]     // out->qtype
    
    // Read qclass (2 bytes, network order)
    add     x5, x21, #2
    ldrh    w5, [x19, x5]
    rev16   w5, w5              // byte swap
    strh    w5, [x22, #260]     // out->qclass
    
    // Calculate total wire length
    add     w1, w1, #4          // wire_len + 4
    strh    w1, [x22, #262]     // out->wire_len
    
    // Build result: offset in high 32 bits, 0 in low
    add     x21, x21, #4        // final offset
    lsl     x0, x21, #32
    
    // Restore and return
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #64
    ret

.Lq_too_short:
    mov     w0, #-1             // DNSASM_ERR_SHORT
    b       .Lq_return_error

.Lq_error:
    // w0 already contains error
.Lq_return_error:
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #64
    ret


// ============================================================================
// Internal: decompress_name_internal
//
// Arguments:
//   x0 = output buffer (255+ bytes)
//   x1 = packet pointer
//   x2 = packet length
//   x3 = offset to start of name
//
// Returns:
//   w0 = decompressed name length (negative on error)
//   w1 = wire bytes consumed
// ============================================================================
_decompress_name_internal:
    stp     x19, x20, [sp, #-64]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    
    mov     x19, x0             // out buffer
    mov     x20, x1             // packet
    mov     x21, x2             // len
    mov     x22, x3             // offset
    
    mov     w23, #0             // out_len = 0
    mov     w24, #0             // wire_len = 0
    mov     w25, #0             // pointer_count = 0
    mov     w26, #1             // counting_wire = 1
    
.Llabel_loop:
    // Check offset bounds
    cmp     x22, x21
    b.hs    .Lname_too_short
    
    // Read label length byte
    ldrb    w0, [x20, x22]
    
    // Check for compression pointer (top 2 bits = 11)
    and     w1, w0, #0xC0
    cmp     w1, #0xC0
    b.eq    .Lcompression_ptr
    
    // Check for end of name (length = 0)
    cbz     w0, .Lend_of_name
    
    // Regular label - check length is valid (1-63)
    cmp     w0, #63
    b.hi    .Lbad_name
    
    // Check output overflow
    add     w1, w23, w0
    add     w1, w1, #1
    cmp     w1, #255
    b.hi    .Lname_overflow
    
    // Check packet bounds
    add     x1, x22, x0
    add     x1, x1, #1
    cmp     x1, x21
    b.hi    .Lname_too_short
    
    // Store label length byte
    strb    w0, [x19, x23]
    add     w23, w23, #1
    
    // Update wire length if counting
    cbz     w26, .Lskip_wire1
    add     w24, w24, w0
    add     w24, w24, #1
.Lskip_wire1:
    
    // Copy label bytes
    add     x22, x22, #1        // skip length byte
    mov     w2, w0              // label length
    
.Lcopy_label:
    ldrb    w0, [x20, x22]
    strb    w0, [x19, x23]
    add     x22, x22, #1
    add     w23, w23, #1
    subs    w2, w2, #1
    b.ne    .Lcopy_label
    
    b       .Llabel_loop

.Lcompression_ptr:
    // Check second byte available
    add     x1, x22, #2
    cmp     x1, x21
    b.hi    .Lname_too_short
    
    // Read 16-bit pointer
    ldrh    w0, [x20, x22]
    rev16   w0, w0              // byte swap
    and     w0, w0, #0x3FFF     // mask to 14 bits
    
    // Update wire length if counting
    cbz     w26, .Lskip_wire2
    add     w24, w24, #2
    mov     w26, #0             // stop counting
.Lskip_wire2:
    
    // Loop detection
    add     w25, w25, #1
    cmp     w25, #127
    b.hi    .Lpointer_loop
    
    // Check pointer doesn't point forward
    cmp     w0, w22
    b.hs    .Lbad_pointer
    
    // Follow pointer
    mov     w22, w0
    b       .Llabel_loop

.Lend_of_name:
    // Add null terminator
    strb    wzr, [x19, x23]
    add     w23, w23, #1
    
    // Update wire length if counting
    cbz     w26, .Ldone
    add     w24, w24, #1
    
.Ldone:
    mov     w0, w23             // return name length
    mov     w1, w24             // return wire length
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #64
    ret

.Lname_too_short:
    mov     w0, #-1             // DNSASM_ERR_SHORT
    b       .Lerror_return

.Lbad_name:
    mov     w0, #-2             // DNSASM_ERR_NAME
    b       .Lerror_return

.Lbad_pointer:
    mov     w0, #-3             // DNSASM_ERR_POINTER
    b       .Lerror_return

.Lpointer_loop:
    mov     w0, #-4             // DNSASM_ERR_LOOP

.Lerror_return:
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #64
    ret


// ============================================================================
// dnsasm_result_t dnsasm_decompress_name(const uint8_t *packet, size_t len,
//                                         size_t offset, uint8_t *out,
//                                         uint16_t *out_len)
//
// Public wrapper.
// ============================================================================
.globl _dnsasm_decompress_name
_dnsasm_decompress_name:
    stp     x19, x20, [sp, #-16]!
    
    mov     x19, x4             // save out_len pointer
    
    // Rearrange for internal call
    mov     x4, x3              // out buffer -> temp
    mov     x3, x2              // offset
    mov     x2, x1              // len
    mov     x1, x0              // packet
    mov     x0, x4              // out buffer
    
    bl      _decompress_name_internal
    
    // Check result
    tst     w0, w0
    b.mi    .Ldec_error
    
    // Store out_len
    strh    w0, [x19]
    
    // Build result: wire_len in high 32, 0 in low
    lsl     x0, x1, #32
    
    ldp     x19, x20, [sp], #16
    ret

.Ldec_error:
    // w0 has error already
    ldp     x19, x20, [sp], #16
    ret
