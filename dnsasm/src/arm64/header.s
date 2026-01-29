// DNSASM - Ultra-Fast DNS Packet Processor
// ARM64 Assembly - Header Parsing
//
// Optimized for Apple Silicon (M1/M2/M3) and other ARM64 processors.
// Uses NEON for efficient 16-byte aligned operations.
//
// Calling Convention: AAPCS64 (ARM64 ABI)
//   - Arguments: x0-x7
//   - Return: x0 (int), d0 (float)
//   - Caller-saved: x0-x18, v0-v7, v16-v31
//   - Callee-saved: x19-x28, v8-v15

.text
.align 4

// ============================================================================
// int dnsasm_parse_header(const uint8_t *packet, size_t len, dnsasm_header_t *out)
//
// Arguments:
//   x0 = packet pointer
//   x1 = packet length
//   x2 = output structure pointer
//
// Returns:
//   0 on success, negative error code on failure
//
// Performance: ~8 cycles on Apple Silicon
// ============================================================================
.globl _dnsasm_parse_header
_dnsasm_parse_header:
    // Check minimum length (12 bytes for DNS header)
    cmp     x1, #12
    b.lo    .Ltoo_short

    // Load 16 bytes (we'll only use first 12)
    // Use SIMD for efficiency
    ldr     q0, [x0]

    // Reverse bytes in each 16-bit lane (network to host order)
    rev16   v1.16b, v0.16b

    // Store the first 12 bytes to output structure
    str     d1, [x2]            // Store bytes 0-7 (id, flags, qdcount, ancount)
    mov     x3, v1.d[1]         // Get upper 8 bytes
    str     w3, [x2, #8]        // Store bytes 8-11 (nscount, arcount)

    // Parse flags field (bytes 2-3, already byte-swapped)
    ldrh    w3, [x2, #2]        // Load flags
    
    // QR (bit 15)
    lsr     w4, w3, #15
    strb    w4, [x2, #12]       // qr
    
    // Opcode (bits 14-11)
    ubfx    w4, w3, #11, #4
    strb    w4, [x2, #13]       // opcode
    
    // AA (bit 10)
    ubfx    w4, w3, #10, #1
    strb    w4, [x2, #14]       // aa
    
    // TC (bit 9)
    ubfx    w4, w3, #9, #1
    strb    w4, [x2, #15]       // tc
    
    // RD (bit 8)
    ubfx    w4, w3, #8, #1
    strb    w4, [x2, #16]       // rd
    
    // RA (bit 7)
    ubfx    w4, w3, #7, #1
    strb    w4, [x2, #17]       // ra
    
    // RCODE (bits 3-0)
    and     w4, w3, #0x0F
    strb    w4, [x2, #18]       // rcode
    
    // Return success
    mov     w0, #0
    ret

.Ltoo_short:
    mov     w0, #-1             // DNSASM_ERR_SHORT
    ret


// ============================================================================
// size_t dnsasm_build_header(uint8_t *out, uint16_t id, uint16_t flags,
//                            uint16_t qdcount, uint16_t ancount,
//                            uint16_t nscount, uint16_t arcount)
//
// Arguments:
//   x0 = output buffer
//   w1 = id
//   w2 = flags
//   w3 = qdcount
//   w4 = ancount
//   w5 = nscount
//   w6 = arcount
//
// Returns:
//   12 (number of bytes written)
//
// Performance: ~12 cycles
// ============================================================================
.globl _dnsasm_build_header
_dnsasm_build_header:
    // Byte swap each field and store
    // Using REV16 for 16-bit byte swap
    
    // ID (bytes 0-1)
    rev16   w7, w1
    strh    w7, [x0]
    
    // Flags (bytes 2-3)
    rev16   w7, w2
    strh    w7, [x0, #2]
    
    // QDCOUNT (bytes 4-5)
    rev16   w7, w3
    strh    w7, [x0, #4]
    
    // ANCOUNT (bytes 6-7)
    rev16   w7, w4
    strh    w7, [x0, #6]
    
    // NSCOUNT (bytes 8-9)
    rev16   w7, w5
    strh    w7, [x0, #8]
    
    // ARCOUNT (bytes 10-11)
    rev16   w7, w6
    strh    w7, [x0, #10]
    
    // Return 12 bytes written
    mov     w0, #12
    ret
