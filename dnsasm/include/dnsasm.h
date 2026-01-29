/*
 * DNSASM - Ultra-Fast DNS Packet Processor
 * 
 * C header for FFI integration with assembly routines.
 * All functions use the System V AMD64 / ARM64 AAPCS calling conventions.
 */

#ifndef DNSASM_H
#define DNSASM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

/* DNS Header size */
#define DNS_HEADER_SIZE     12

/* Maximum DNS name length (including labels and null terminator) */
#define DNS_MAX_NAME_LEN    255

/* Maximum DNS packet size */
#define DNS_MAX_PACKET_SIZE 65535

/* DNS response codes */
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4
#define DNS_RCODE_REFUSED   5

/* DNS opcodes */
#define DNS_OPCODE_QUERY    0
#define DNS_OPCODE_IQUERY   1
#define DNS_OPCODE_STATUS   2

/* DNS record types */
#define DNS_TYPE_A          1
#define DNS_TYPE_NS         2
#define DNS_TYPE_CNAME      5
#define DNS_TYPE_SOA        6
#define DNS_TYPE_PTR        12
#define DNS_TYPE_MX         15
#define DNS_TYPE_TXT        16
#define DNS_TYPE_AAAA       28
#define DNS_TYPE_SRV        33
#define DNS_TYPE_OPT        41
#define DNS_TYPE_ANY        255

/* DNS classes */
#define DNS_CLASS_IN        1
#define DNS_CLASS_CH        3
#define DNS_CLASS_HS        4
#define DNS_CLASS_ANY       255

/* ============================================================================
 * Data Structures (cache-line aligned where beneficial)
 * ============================================================================ */

/*
 * Parsed DNS header (16 bytes, fits in one cache line with padding)
 * 
 * Wire format (12 bytes):
 *   0-1:   ID
 *   2-3:   Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
 *   4-5:   QDCOUNT
 *   6-7:   ANCOUNT
 *   8-9:   NSCOUNT
 *   10-11: ARCOUNT
 */
typedef struct __attribute__((aligned(16))) {
    uint16_t id;           /* Transaction ID */
    uint16_t flags;        /* Raw flags field */
    uint16_t qdcount;      /* Question count */
    uint16_t ancount;      /* Answer count */
    uint16_t nscount;      /* Authority count */
    uint16_t arcount;      /* Additional count */
    /* Parsed flags (set by parse_header) */
    uint8_t  qr;           /* Query (0) or Response (1) */
    uint8_t  opcode;       /* Operation code */
    uint8_t  aa;           /* Authoritative Answer */
    uint8_t  tc;           /* Truncated */
    uint8_t  rd;           /* Recursion Desired */
    uint8_t  ra;           /* Recursion Available */
    uint8_t  rcode;        /* Response code */
    uint8_t  _pad;         /* Padding for alignment */
} dnsasm_header_t;

/*
 * Parsed DNS question (variable size, but struct is fixed)
 */
typedef struct __attribute__((aligned(16))) {
    uint8_t  name[DNS_MAX_NAME_LEN + 1];  /* Decompressed name */
    uint16_t name_len;                     /* Length of name in bytes */
    uint16_t qtype;                        /* Query type */
    uint16_t qclass;                       /* Query class */
    uint16_t wire_len;                     /* Length consumed from wire */
} dnsasm_question_t;

/*
 * Parsed DNS resource record
 */
typedef struct __attribute__((aligned(32))) {
    uint8_t  name[DNS_MAX_NAME_LEN + 1];  /* Decompressed name */
    uint16_t name_len;                     /* Length of name in bytes */
    uint16_t rtype;                        /* Record type */
    uint16_t rclass;                       /* Record class */
    uint32_t ttl;                          /* Time to live */
    uint16_t rdlength;                     /* RDATA length */
    const uint8_t *rdata;                  /* Pointer to RDATA (in packet) */
    uint16_t wire_len;                     /* Length consumed from wire */
} dnsasm_rr_t;

/*
 * Parse result structure
 */
typedef struct {
    int32_t  error;        /* 0 = success, negative = error code */
    uint32_t offset;       /* Offset after parsed data */
} dnsasm_result_t;

/* Error codes */
#define DNSASM_OK               0
#define DNSASM_ERR_SHORT       -1   /* Packet too short */
#define DNSASM_ERR_NAME        -2   /* Invalid name format */
#define DNSASM_ERR_POINTER     -3   /* Invalid compression pointer */
#define DNSASM_ERR_LOOP        -4   /* Compression pointer loop */
#define DNSASM_ERR_OVERFLOW    -5   /* Name too long */

/* ============================================================================
 * Core Functions
 * ============================================================================ */

/*
 * Parse DNS header from packet.
 * 
 * @param packet    Pointer to raw DNS packet
 * @param len       Length of packet in bytes
 * @param out       Output header structure
 * @return          0 on success, negative error code otherwise
 * 
 * Performance: ~5 cycles on x86_64 with SSE2
 */
int dnsasm_parse_header(const uint8_t *packet, size_t len, dnsasm_header_t *out);

/*
 * Parse DNS question section.
 * 
 * @param packet    Pointer to raw DNS packet (full packet for decompression)
 * @param len       Length of packet in bytes
 * @param offset    Offset to start of question (typically 12)
 * @param out       Output question structure
 * @return          Result with error code and new offset
 * 
 * Performance: ~50 cycles for typical names
 */
dnsasm_result_t dnsasm_parse_question(const uint8_t *packet, size_t len, 
                                       size_t offset, dnsasm_question_t *out);

/*
 * Parse DNS resource record.
 * 
 * @param packet    Pointer to raw DNS packet
 * @param len       Length of packet
 * @param offset    Offset to start of RR
 * @param out       Output RR structure
 * @return          Result with error code and new offset
 */
dnsasm_result_t dnsasm_parse_rr(const uint8_t *packet, size_t len,
                                 size_t offset, dnsasm_rr_t *out);

/*
 * Decompress a DNS name.
 * 
 * @param packet    Pointer to raw DNS packet
 * @param len       Length of packet
 * @param offset    Offset to start of name
 * @param out       Output buffer (at least DNS_MAX_NAME_LEN + 1 bytes)
 * @param out_len   Output: length of decompressed name
 * @return          Result with error code and wire bytes consumed
 */
dnsasm_result_t dnsasm_decompress_name(const uint8_t *packet, size_t len,
                                        size_t offset, uint8_t *out, 
                                        uint16_t *out_len);

/* ============================================================================
 * Response Building Functions
 * ============================================================================ */

/*
 * Build DNS header for response.
 * 
 * @param out       Output buffer (at least DNS_HEADER_SIZE bytes)
 * @param id        Transaction ID
 * @param flags     Flags (or use helper macros)
 * @param qdcount   Question count
 * @param ancount   Answer count
 * @param nscount   Authority count
 * @param arcount   Additional count
 * @return          Number of bytes written (always 12)
 */
size_t dnsasm_build_header(uint8_t *out, uint16_t id, uint16_t flags,
                            uint16_t qdcount, uint16_t ancount,
                            uint16_t nscount, uint16_t arcount);

/*
 * Copy question section from request to response.
 * 
 * @param out       Output buffer
 * @param packet    Original packet
 * @param offset    Offset in original packet
 * @param qlen      Length of question section
 * @return          Number of bytes written
 */
size_t dnsasm_copy_question(uint8_t *out, const uint8_t *packet,
                             size_t offset, size_t qlen);

/*
 * Build an A record answer.
 * 
 * @param out       Output buffer
 * @param name      Name (compressed pointer or full name)
 * @param name_len  Length of name
 * @param ttl       TTL value
 * @param ip        IPv4 address (4 bytes, network order)
 * @return          Number of bytes written
 */
size_t dnsasm_build_a_record(uint8_t *out, const uint8_t *name, size_t name_len,
                              uint32_t ttl, const uint8_t *ip);

/* ============================================================================
 * SIMD-Optimized Functions (x86_64 AVX2 / ARM64 NEON)
 * ============================================================================ */

/*
 * Compare two DNS names (case-insensitive).
 * Uses SIMD for 16+ byte comparisons.
 * 
 * @param a         First name (raw wire format or decompressed)
 * @param a_len     Length of first name
 * @param b         Second name
 * @param b_len     Length of second name
 * @return          0 if equal, non-zero otherwise
 */
int dnsasm_name_equal(const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len);

/*
 * Find a name in a list (for zone lookups).
 * Uses SIMD for parallel comparison.
 * 
 * @param needle    Name to find
 * @param needle_len Length of needle
 * @param haystack  Array of names (pointers)
 * @param count     Number of names in haystack
 * @return          Index if found, -1 otherwise
 */
int dnsasm_name_find(const uint8_t *needle, size_t needle_len,
                      const uint8_t **haystack, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* DNSASM_H */
