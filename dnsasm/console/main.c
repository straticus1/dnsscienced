/*
 * DNSASM Console - Interactive DNS Packet Processor Test Client
 *
 * Usage:
 *   dnsasm-console                   - Interactive mode
 *   dnsasm-console --test            - Run test suite
 *   dnsasm-console --bench           - Run benchmarks
 *   dnsasm-console --parse <hexdata> - Parse hex-encoded DNS packet
 *   dnsasm-console --query <domain>  - Build and parse a query
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#include "dnsasm.h"

/* ANSI color codes */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

/* Sample DNS packets for testing */
static const uint8_t sample_query[] = {
    /* Header */
    0x12, 0x34,             /* ID */
    0x01, 0x00,             /* Flags: RD=1 */
    0x00, 0x01,             /* QDCOUNT */
    0x00, 0x00,             /* ANCOUNT */
    0x00, 0x00,             /* NSCOUNT */
    0x00, 0x00,             /* ARCOUNT */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,                   /* Root label */
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01              /* QCLASS: IN */
};

static const uint8_t sample_response[] = {
    /* Header */
    0x12, 0x34,             /* ID */
    0x81, 0x80,             /* Flags: QR=1, RD=1, RA=1 */
    0x00, 0x01,             /* QDCOUNT */
    0x00, 0x01,             /* ANCOUNT */
    0x00, 0x00,             /* NSCOUNT */
    0x00, 0x00,             /* ARCOUNT */
    /* Question: www.example.com A IN */
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,             /* QTYPE: A */
    0x00, 0x01,             /* QCLASS: IN */
    /* Answer: www.example.com A IN 300 93.184.216.34 */
    0xc0, 0x0c,             /* Name: pointer to offset 12 */
    0x00, 0x01,             /* TYPE: A */
    0x00, 0x01,             /* CLASS: IN */
    0x00, 0x00, 0x01, 0x2c, /* TTL: 300 */
    0x00, 0x04,             /* RDLENGTH: 4 */
    0x5d, 0xb8, 0xd8, 0x22  /* RDATA: 93.184.216.34 */
};

/* Get current time in nanoseconds */
static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Print hex dump */
static void hexdump(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) printf("\n");
        printf("%02x ", data[i]);
    }
    printf("\n");
}

/* Print parsed header */
static void print_header(const dnsasm_header_t *h) {
    printf(COLOR_CYAN "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_BOLD "DNS Header\n" COLOR_RESET);
    printf(COLOR_CYAN "═══════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("  ID:       0x%04x (%d)\n", h->id, h->id);
    printf("  Flags:    0x%04x\n", h->flags);
    printf("    QR:     %d (%s)\n", h->qr, h->qr ? "Response" : "Query");
    printf("    OPCODE: %d\n", h->opcode);
    printf("    AA:     %d\n", h->aa);
    printf("    TC:     %d\n", h->tc);
    printf("    RD:     %d\n", h->rd);
    printf("    RA:     %d\n", h->ra);
    printf("    RCODE:  %d (%s)\n", h->rcode, 
           h->rcode == 0 ? "NOERROR" :
           h->rcode == 1 ? "FORMERR" :
           h->rcode == 2 ? "SERVFAIL" :
           h->rcode == 3 ? "NXDOMAIN" :
           h->rcode == 5 ? "REFUSED" : "UNKNOWN");
    printf("  QDCOUNT:  %d\n", h->qdcount);
    printf("  ANCOUNT:  %d\n", h->ancount);
    printf("  NSCOUNT:  %d\n", h->nscount);
    printf("  ARCOUNT:  %d\n", h->arcount);
}

/* Print parsed question */
static void print_question(const dnsasm_question_t *q) {
    printf(COLOR_CYAN "───────────────────────────────────────────────────────────\n" COLOR_RESET);
    printf(COLOR_BOLD "Question Section\n" COLOR_RESET);
    printf(COLOR_CYAN "───────────────────────────────────────────────────────────\n" COLOR_RESET);
    
    /* Convert wire format name to dotted notation */
    char dotted[256];
    size_t di = 0;
    size_t i = 0;
    while (i < q->name_len && q->name[i] != 0) {
        uint8_t label_len = q->name[i];
        if (di > 0) dotted[di++] = '.';
        memcpy(dotted + di, q->name + i + 1, label_len);
        di += label_len;
        i += label_len + 1;
    }
    dotted[di] = '\0';
    
    printf("  Name:     %s\n", dotted);
    printf("  Type:     %d (%s)\n", q->qtype,
           q->qtype == 1 ? "A" :
           q->qtype == 28 ? "AAAA" :
           q->qtype == 5 ? "CNAME" :
           q->qtype == 15 ? "MX" :
           q->qtype == 2 ? "NS" :
           q->qtype == 16 ? "TXT" : "OTHER");
    printf("  Class:    %d (%s)\n", q->qclass,
           q->qclass == 1 ? "IN" : "OTHER");
    printf("  Wire len: %d bytes\n", q->wire_len);
}

/* Run test suite */
static int run_tests(void) {
    int passed = 0, failed = 0;
    
    printf(COLOR_BOLD "\n═══════════════════════════════════════════════════════════\n");
    printf("                    DNSASM Test Suite\n");
    printf("═══════════════════════════════════════════════════════════\n\n" COLOR_RESET);
    
    /* Test 1: Parse query header */
    {
        printf("Test 1: Parse query header... ");
        dnsasm_header_t h;
        int ret = dnsasm_parse_header(sample_query, sizeof(sample_query), &h);
        if (ret == 0 && h.id == 0x1234 && h.qr == 0 && h.rd == 1 && h.qdcount == 1) {
            printf(COLOR_GREEN "PASSED\n" COLOR_RESET);
            passed++;
        } else {
            printf(COLOR_RED "FAILED (ret=%d, id=0x%04x, qr=%d, rd=%d, qdcount=%d)\n" COLOR_RESET,
                   ret, h.id, h.qr, h.rd, h.qdcount);
            failed++;
        }
    }
    
    /* Test 2: Parse response header */
    {
        printf("Test 2: Parse response header... ");
        dnsasm_header_t h;
        int ret = dnsasm_parse_header(sample_response, sizeof(sample_response), &h);
        if (ret == 0 && h.id == 0x1234 && h.qr == 1 && h.ra == 1 && h.ancount == 1) {
            printf(COLOR_GREEN "PASSED\n" COLOR_RESET);
            passed++;
        } else {
            printf(COLOR_RED "FAILED (ret=%d, id=0x%04x, qr=%d, ra=%d, ancount=%d)\n" COLOR_RESET,
                   ret, h.id, h.qr, h.ra, h.ancount);
            failed++;
        }
    }
    
    /* Test 3: Parse question */
    {
        printf("Test 3: Parse question section... ");
        dnsasm_question_t q;
        dnsasm_result_t res = dnsasm_parse_question(sample_query, sizeof(sample_query), 12, &q);
        if (res.error == 0 && q.qtype == 1 && q.qclass == 1) {
            printf(COLOR_GREEN "PASSED\n" COLOR_RESET);
            passed++;
        } else {
            printf(COLOR_RED "FAILED (error=%d, qtype=%d, qclass=%d)\n" COLOR_RESET,
                   res.error, q.qtype, q.qclass);
            failed++;
        }
    }
    
    /* Test 4: Handle short packet */
    {
        printf("Test 4: Handle short packet... ");
        uint8_t short_pkt[] = {0x12, 0x34};
        dnsasm_header_t h;
        int ret = dnsasm_parse_header(short_pkt, sizeof(short_pkt), &h);
        if (ret == DNSASM_ERR_SHORT) {
            printf(COLOR_GREEN "PASSED\n" COLOR_RESET);
            passed++;
        } else {
            printf(COLOR_RED "FAILED (expected %d, got %d)\n" COLOR_RESET, DNSASM_ERR_SHORT, ret);
            failed++;
        }
    }
    
    /* Summary */
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("Results: ");
    if (failed == 0) {
        printf(COLOR_GREEN "%d passed, %d failed\n" COLOR_RESET, passed, failed);
    } else {
        printf(COLOR_RED "%d passed, %d failed\n" COLOR_RESET, passed, failed);
    }
    printf("═══════════════════════════════════════════════════════════\n");
    
    return failed;
}

/* Run benchmarks */
static void run_benchmarks(void) {
    printf(COLOR_BOLD "\n═══════════════════════════════════════════════════════════\n");
    printf("                    DNSASM Benchmarks\n");
    printf("═══════════════════════════════════════════════════════════\n\n" COLOR_RESET);
    
    const int iterations = 10000000;
    
    /* Benchmark: Header parsing */
    {
        printf("Benchmark: Header parsing (%d iterations)...\n", iterations);
        dnsasm_header_t h;
        
        uint64_t start = get_time_ns();
        for (int i = 0; i < iterations; i++) {
            dnsasm_parse_header(sample_query, sizeof(sample_query), &h);
        }
        uint64_t end = get_time_ns();
        
        double ns_per_op = (double)(end - start) / iterations;
        double ops_per_sec = 1e9 / ns_per_op;
        
        printf("  Time:     %.2f ns/op\n", ns_per_op);
        printf("  Rate:     %.2f M ops/sec\n", ops_per_sec / 1e6);
        printf("  (%.0f cycles @ 3GHz)\n", ns_per_op * 3.0);
    }
    
    /* Benchmark: Question parsing */
    {
        printf("\nBenchmark: Question parsing (%d iterations)...\n", iterations);
        dnsasm_question_t q;
        
        uint64_t start = get_time_ns();
        for (int i = 0; i < iterations; i++) {
            dnsasm_parse_question(sample_query, sizeof(sample_query), 12, &q);
        }
        uint64_t end = get_time_ns();
        
        double ns_per_op = (double)(end - start) / iterations;
        double ops_per_sec = 1e9 / ns_per_op;
        
        printf("  Time:     %.2f ns/op\n", ns_per_op);
        printf("  Rate:     %.2f M ops/sec\n", ops_per_sec / 1e6);
        printf("  (%.0f cycles @ 3GHz)\n", ns_per_op * 3.0);
    }
    
    /* Benchmark: Full packet parse (header + question) */
    {
        printf("\nBenchmark: Full packet parse (%d iterations)...\n", iterations);
        dnsasm_header_t h;
        dnsasm_question_t q;
        
        uint64_t start = get_time_ns();
        for (int i = 0; i < iterations; i++) {
            dnsasm_parse_header(sample_query, sizeof(sample_query), &h);
            dnsasm_parse_question(sample_query, sizeof(sample_query), 12, &q);
        }
        uint64_t end = get_time_ns();
        
        double ns_per_op = (double)(end - start) / iterations;
        double ops_per_sec = 1e9 / ns_per_op;
        
        printf("  Time:     %.2f ns/op\n", ns_per_op);
        printf("  Rate:     %.2f M packets/sec\n", ops_per_sec / 1e6);
        printf("  (%.0f cycles @ 3GHz)\n", ns_per_op * 3.0);
    }
    
    printf("\n═══════════════════════════════════════════════════════════\n");
}

/* Interactive mode */
static void interactive_mode(void) {
    printf(COLOR_BOLD "\n");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║           DNSASM Console - Interactive Mode               ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\nCommands:\n");
    printf("  parse <hex>  - Parse hex-encoded DNS packet\n");
    printf("  sample       - Parse sample query packet\n");
    printf("  response     - Parse sample response packet\n");
    printf("  test         - Run test suite\n");
    printf("  bench        - Run benchmarks\n");
    printf("  help         - Show this help\n");
    printf("  quit         - Exit\n\n");
    
    char line[1024];
    while (1) {
        printf(COLOR_GREEN "dnsasm> " COLOR_RESET);
        fflush(stdout);
        
        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }
        
        /* Remove newline */
        line[strcspn(line, "\n")] = '\0';
        
        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
            printf("Goodbye!\n");
            break;
        } else if (strcmp(line, "help") == 0) {
            printf("Commands: parse, sample, response, test, bench, quit\n");
        } else if (strcmp(line, "sample") == 0) {
            printf("\nSample query packet:\n");
            hexdump(sample_query, sizeof(sample_query));
            
            dnsasm_header_t h;
            if (dnsasm_parse_header(sample_query, sizeof(sample_query), &h) == 0) {
                print_header(&h);
                
                if (h.qdcount > 0) {
                    dnsasm_question_t q;
                    dnsasm_result_t res = dnsasm_parse_question(sample_query, sizeof(sample_query), 12, &q);
                    if (res.error == 0) {
                        print_question(&q);
                    }
                }
            }
            printf("\n");
        } else if (strcmp(line, "response") == 0) {
            printf("\nSample response packet:\n");
            hexdump(sample_response, sizeof(sample_response));
            
            dnsasm_header_t h;
            if (dnsasm_parse_header(sample_response, sizeof(sample_response), &h) == 0) {
                print_header(&h);
                
                if (h.qdcount > 0) {
                    dnsasm_question_t q;
                    dnsasm_result_t res = dnsasm_parse_question(sample_response, sizeof(sample_response), 12, &q);
                    if (res.error == 0) {
                        print_question(&q);
                    }
                }
            }
            printf("\n");
        } else if (strcmp(line, "test") == 0) {
            run_tests();
        } else if (strcmp(line, "bench") == 0) {
            run_benchmarks();
        } else if (strncmp(line, "parse ", 6) == 0) {
            /* Parse hex-encoded packet */
            const char *hex = line + 6;
            size_t hex_len = strlen(hex);
            if (hex_len % 2 != 0) {
                printf(COLOR_RED "Error: hex string must have even length\n" COLOR_RESET);
                continue;
            }
            
            size_t pkt_len = hex_len / 2;
            uint8_t *packet = malloc(pkt_len);
            
            for (size_t i = 0; i < pkt_len; i++) {
                unsigned int byte;
                sscanf(hex + i * 2, "%2x", &byte);
                packet[i] = (uint8_t)byte;
            }
            
            printf("\nParsed packet:\n");
            hexdump(packet, pkt_len);
            
            dnsasm_header_t h;
            if (dnsasm_parse_header(packet, pkt_len, &h) == 0) {
                print_header(&h);
            } else {
                printf(COLOR_RED "Error parsing header\n" COLOR_RESET);
            }
            
            free(packet);
        } else if (line[0] != '\0') {
            printf("Unknown command: %s\n", line);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "--test") == 0) {
            return run_tests();
        } else if (strcmp(argv[1], "--bench") == 0) {
            run_benchmarks();
            return 0;
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: %s [--test|--bench|--help]\n", argv[0]);
            return 0;
        }
    }
    
    interactive_mode();
    return 0;
}
