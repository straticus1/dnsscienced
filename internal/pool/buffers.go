package pool

import (
	"sync"

	"github.com/miekg/dns"
)

// DNS message and buffer pools to reduce GC pressure
// Critical for high-performance DNS servers processing millions of queries

const (
	// Buffer sizes for different use cases
	SmallBufferSize  = 512   // UDP DNS queries (most common)
	MediumBufferSize = 4096  // EDNS0 responses
	LargeBufferSize  = 65535 // Maximum DNS message size
)

// MessagePool is a sync.Pool for dns.Msg reuse
var MessagePool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}

// GetMessage gets a message from the pool
func GetMessage() *dns.Msg {
	return MessagePool.Get().(*dns.Msg)
}

// PutMessage returns a message to the pool
// IMPORTANT: Message is reset before returning to pool
func PutMessage(msg *dns.Msg) {
	if msg == nil {
		return
	}

	// Reset the message to prevent data leakage
	// This is critical for security - don't skip this!
	msg.Id = 0
	msg.Response = false
	msg.Opcode = 0
	msg.Authoritative = false
	msg.Truncated = false
	msg.RecursionDesired = false
	msg.RecursionAvailable = false
	msg.Zero = false
	msg.AuthenticatedData = false
	msg.CheckingDisabled = false
	msg.Rcode = 0

	// Clear slices but keep capacity
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]

	MessagePool.Put(msg)
}

// SmallBufferPool for UDP queries (512 bytes)
var SmallBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, SmallBufferSize)
		return &buf
	},
}

// GetSmallBuffer gets a 512-byte buffer
func GetSmallBuffer() []byte {
	bufPtr := SmallBufferPool.Get().(*[]byte)
	return (*bufPtr)[:SmallBufferSize]
}

// PutSmallBuffer returns a buffer to the pool
func PutSmallBuffer(buf []byte) {
	if cap(buf) < SmallBufferSize {
		return // Don't pool undersized buffers
	}
	buf = buf[:cap(buf)] // Reset length to capacity
	SmallBufferPool.Put(&buf)
}

// MediumBufferPool for EDNS0 responses (4096 bytes)
var MediumBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, MediumBufferSize)
		return &buf
	},
}

// GetMediumBuffer gets a 4096-byte buffer
func GetMediumBuffer() []byte {
	bufPtr := MediumBufferPool.Get().(*[]byte)
	return (*bufPtr)[:MediumBufferSize]
}

// PutMediumBuffer returns a buffer to the pool
func PutMediumBuffer(buf []byte) {
	if cap(buf) < MediumBufferSize {
		return
	}
	buf = buf[:cap(buf)]
	MediumBufferPool.Put(&buf)
}

// LargeBufferPool for large responses (65535 bytes)
var LargeBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, LargeBufferSize)
		return &buf
	},
}

// GetLargeBuffer gets a 65535-byte buffer
func GetLargeBuffer() []byte {
	bufPtr := LargeBufferPool.Get().(*[]byte)
	return (*bufPtr)[:LargeBufferSize]
}

// PutLargeBuffer returns a buffer to the pool
func PutLargeBuffer(buf []byte) {
	if cap(buf) < LargeBufferSize {
		return
	}
	buf = buf[:cap(buf)]
	LargeBufferPool.Put(&buf)
}

// GetBuffer intelligently selects the right buffer size
func GetBuffer(size int) []byte {
	switch {
	case size <= SmallBufferSize:
		return GetSmallBuffer()
	case size <= MediumBufferSize:
		return GetMediumBuffer()
	default:
		return GetLargeBuffer()
	}
}

// PutBuffer returns a buffer to the appropriate pool
func PutBuffer(buf []byte) {
	capacity := cap(buf)
	switch {
	case capacity == SmallBufferSize:
		PutSmallBuffer(buf)
	case capacity == MediumBufferSize:
		PutMediumBuffer(buf)
	case capacity == LargeBufferSize:
		PutLargeBuffer(buf)
	// else: don't pool weird sizes
	}
}

// WriterPool is for buffered writers
// Useful for bulk zone transfers or logging
var WriterPool = sync.Pool{
	New: func() interface{} {
		// Return a []byte that can be used as a write buffer
		buf := make([]byte, 8192)
		return &buf
	},
}

// GetWriterBuffer gets an 8KB writer buffer
func GetWriterBuffer() []byte {
	bufPtr := WriterPool.Get().(*[]byte)
	return *bufPtr
}

// PutWriterBuffer returns writer buffer to pool
func PutWriterBuffer(buf []byte) {
	if cap(buf) >= 8192 {
		WriterPool.Put(&buf)
	}
}

// Stats tracks pool allocation statistics
// Useful for monitoring and tuning
type Stats struct {
	Gets uint64
	Puts uint64
	News uint64 // Allocations (pool miss)
}

// We could add atomic counters here for production monitoring,
// but sync.Pool doesn't expose this by default.
// In production, you'd instrument with prometheus or similar.

// ResetPools clears all pools (useful for testing or memory pressure)
func ResetPools() {
	MessagePool = sync.Pool{
		New: func() interface{} {
			return new(dns.Msg)
		},
	}

	SmallBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, SmallBufferSize)
			return &buf
		},
	}

	MediumBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, MediumBufferSize)
			return &buf
		},
	}

	LargeBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, LargeBufferSize)
			return &buf
		},
	}
}

// Example usage patterns:

// Pattern 1: DNS message processing
// msg := pool.GetMessage()
// defer pool.PutMessage(msg)
// msg.SetQuestion("example.com.", dns.TypeA)
// // ... process message ...

// Pattern 2: Buffer for packing
// buf := pool.GetSmallBuffer()
// defer pool.PutSmallBuffer(buf)
// packed, err := msg.PackBuffer(buf)

// Pattern 3: Intelligent buffer sizing
// expectedSize := 1024
// buf := pool.GetBuffer(expectedSize)
// defer pool.PutBuffer(buf)
