# DNSASM - Ultra-Fast DNS Packet Processor

**The world's fastest DNS packet processor, written in hand-optimized assembly.**

## Overview

DNSASM is a high-performance DNS packet parser and builder written in pure assembly language for both **x86_64** (using NASM) and **ARM64** architectures. It's designed to process millions of DNS packets per second with minimal latency.

## Performance Targets

| Operation | Target | Comparison |
|-----------|--------|------------|
| Header Parse | < 5 cycles | ~50x faster than typical |
| Question Parse | < 50 cycles | ~20x faster |
| Full Packet Parse | < 200 cycles | ~15x faster |
| Response Build | < 100 cycles | ~10x faster |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        DNSASM                               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   x86_64/AVX2   │    │   ARM64/NEON    │                │
│  │   (NASM)        │    │   (GNU AS)      │                │
│  └────────┬────────┘    └────────┬────────┘                │
│           │                      │                          │
│           └──────────┬───────────┘                          │
│                      ▼                                      │
│           ┌─────────────────────┐                          │
│           │   C ABI Interface   │                          │
│           └──────────┬──────────┘                          │
│                      ▼                                      │
│           ┌─────────────────────┐                          │
│           │    Go CGO Binding   │                          │
│           └─────────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
dnsasm/
├── README.md
├── Makefile
├── include/
│   └── dnsasm.h          # C header for FFI
├── src/
│   ├── x86_64/
│   │   ├── header.asm    # DNS header parsing
│   │   ├── question.asm  # Question section parsing
│   │   ├── answer.asm    # Answer section parsing
│   │   ├── name.asm      # Name compression/decompression
│   │   └── build.asm     # Response building
│   └── arm64/
│       ├── header.s      # DNS header parsing
│       ├── question.s    # Question section parsing
│       └── ...
├── go/
│   ├── dnsasm.go         # CGO bindings
│   └── dnsasm_test.go    # Benchmarks
└── test/
    └── packets/          # Test DNS packets
```

## Building

```bash
# Build for current architecture
make

# Build for x86_64
make ARCH=x86_64

# Build for ARM64
make ARCH=arm64

# Run benchmarks
make bench
```

## Usage (Go)

```go
import "github.com/dnsscience/dnsscienced/dnsasm/go"

// Parse a DNS packet (zero-copy)
header, err := dnsasm.ParseHeader(packet)
if err != nil {
    return err
}

// Parse question section
question, offset, err := dnsasm.ParseQuestion(packet, 12)

// Build a response
response := dnsasm.BuildResponse(header, answer)
```

## Key Optimizations

1. **SIMD Header Parsing**: Uses SSE2/AVX2 on x86_64 and NEON on ARM64 to parse the 12-byte DNS header in a single operation.

2. **Branchless Name Parsing**: Minimizes branch mispredictions in the hot path of name label parsing.

3. **Pointer Compression Cache**: Maintains a small cache of recently seen compression pointers.

4. **Zero-Copy Design**: Parses in-place without copying data.

5. **Cache-Line Alignment**: Critical data structures aligned to 64-byte boundaries.

## License

Apache 2.0 - Same as dnsscienced
