package packet

import (
	"encoding/binary"
	"errors"
	"testing"
)

// Test basic parsing of well-formed DNS messages
func TestParseSimpleQuery(t *testing.T) {
	// DNS query for example.com A
	msg := []byte{
		// Header
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: standard query, RD=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0

		// Question: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // null terminator
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	p := NewParser(msg)
	m, err := p.Parse()
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if m.Header.ID != 0x1234 {
		t.Errorf("ID = %x, want 0x1234", m.Header.ID)
	}

	if !m.Header.RD {
		t.Error("RD should be true")
	}

	if len(m.Question) != 1 {
		t.Fatalf("got %d questions, want 1", len(m.Question))
	}

	q := m.Question[0]
	if q.Name != "example.com." {
		t.Errorf("Name = %q, want %q", q.Name, "example.com.")
	}
	if q.Type != 1 {
		t.Errorf("Type = %d, want 1 (A)", q.Type)
	}
}

// Test compression pointer handling
func TestParseCompression(t *testing.T) {
	// DNS message with compression pointer
	msg := []byte{
		// Header
		0x12, 0x34, // ID
		0x81, 0x80, // Flags: response, RD=1, RA=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x01, // ANCOUNT = 1
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0

		// Question: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // null terminator
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN

		// Answer: compression pointer to example.com
		0xC0, 0x0C, // Pointer to offset 12 (example.com)
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x00, 0x3C, // TTL = 60
		0x00, 0x04, // RDLENGTH = 4
		192, 0, 2, 1, // 192.0.2.1
	}

	p := NewParser(msg)
	m, err := p.Parse()
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(m.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(m.Answer))
	}

	if m.Answer[0].Name != "example.com." {
		t.Errorf("Answer name = %q, want %q", m.Answer[0].Name, "example.com.")
	}
}

// Test detection of compression bomb (pointer loop)
func TestCompressionBomb_Loop(t *testing.T) {
	// Malicious message with pointer loop
	msg := []byte{
		// Header
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0

		// Question with pointer loop
		0xC0, 0x0C, // Pointer to itself (offset 12)
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	p := NewParser(msg)
	_, err := p.Parse()
	if !errors.Is(err, ErrCompressionBomb) && !errors.Is(err, ErrInvalidOffset) {
		t.Errorf("expected ErrCompressionBomb or ErrInvalidOffset, got %v", err)
	}
}

// Test detection of excessive compression depth
func TestCompressionBomb_Depth(t *testing.T) {
	// Create message with deep pointer chain
	msg := make([]byte, 0, 512)

	// Header
	header := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	msg = append(msg, header...)

	// Create chain of 25 pointers (exceeds maxCompressionDepth=20)
	startOffset := len(msg)
	for i := 0; i < 25; i++ {
		// Each iteration adds a pointer
		ptr := make([]byte, 2)
		if i == 0 {
			// First pointer points to final label
			binary.BigEndian.PutUint16(ptr, uint16(startOffset+25*2)|0xC000)
		} else {
			// Point to previous pointer
			binary.BigEndian.PutUint16(ptr, uint16(startOffset+(i-1)*2)|0xC000)
		}
		msg = append(msg, ptr...)
	}

	// Final label
	msg = append(msg, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00)

	// Question type/class
	msg = append(msg, 0x00, 0x01, 0x00, 0x01)

	p := NewParser(msg)
	_, err := p.Parse()
	if !errors.Is(err, ErrCompressionBomb) && !errors.Is(err, ErrInvalidOffset) {
		t.Errorf("expected ErrCompressionBomb or ErrInvalidOffset for deep chain, got %v", err)
	}
}

// Test detection of too many RRs
func TestTooManyRRs(t *testing.T) {
	msg := make([]byte, 0, 8192)

	// Header with 150 answers (exceeds maxRRsPerName=100)
	header := []byte{
		0x12, 0x34, // ID
		0x81, 0x80, // Response
		0x00, 0x01, // QDCOUNT = 1
		0x00, 150,  // ANCOUNT = 150 (too many)
		0x00, 0x00, 0x00, 0x00,
	}
	msg = append(msg, header...)

	// Question
	msg = append(msg, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00)
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A IN

	// Add 150 A records
	for i := 0; i < 150; i++ {
		msg = append(msg, 0xC0, 0x0C) // Compression pointer
		msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A IN
		msg = append(msg, 0x00, 0x00, 0x00, 0x3C) // TTL
		msg = append(msg, 0x00, 0x04) // RDLENGTH
		msg = append(msg, 192, 0, 2, byte(i)) // IP
	}

	p := NewParser(msg)
	_, err := p.Parse()
	if !errors.Is(err, ErrTooManyRRs) {
		t.Errorf("expected ErrTooManyRRs, got %v", err)
	}
}

// Test detection of RRset too large
func TestRRsetTooLarge(t *testing.T) {
	msg := make([]byte, 0, 65536)

	// Header
	header := []byte{
		0x12, 0x34, // ID
		0x81, 0x80, // Response
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x02, // ANCOUNT = 2
		0x00, 0x00, 0x00, 0x00,
	}
	msg = append(msg, header...)

	// Question
	msg = append(msg, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00)
	msg = append(msg, 0x00, 0x10, 0x00, 0x01) // TXT IN

	// Add 2 huge TXT records (total > 32KB)
	for i := 0; i < 2; i++ {
		msg = append(msg, 0xC0, 0x0C) // Compression pointer
		msg = append(msg, 0x00, 0x10, 0x00, 0x01) // TXT IN
		msg = append(msg, 0x00, 0x00, 0x00, 0x3C) // TTL

		// RDLENGTH = 20KB
		msg = append(msg, 0x4E, 0x20) // 20000 bytes

		// RDATA: huge TXT record
		rdata := make([]byte, 20000)
		for j := range rdata {
			rdata[j] = 'A'
		}
		msg = append(msg, rdata...)
	}

	p := NewParser(msg)
	_, err := p.Parse()
	if !errors.Is(err, ErrRRsetTooLarge) {
		t.Errorf("expected ErrRRsetTooLarge, got %v", err)
	}
}

// Test invalid pointer (points outside message)
func TestInvalidPointer(t *testing.T) {
	msg := []byte{
		// Header
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

		// Question with pointer beyond message
		0xC0, 0xFF, // Pointer to offset 255 (beyond end)
		0x00, 0x01, 0x00, 0x01,
	}

	p := NewParser(msg)
	_, err := p.Parse()
	if !errors.Is(err, ErrInvalidOffset) {
		t.Errorf("expected ErrInvalidOffset, got %v", err)
	}
}

// Test label too long
func TestLabelTooLong(t *testing.T) {
	msg := make([]byte, 0, 256)

	// Header
	header := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	msg = append(msg, header...)

	// Label with length 64 (max is 63)
	msg = append(msg, 64)
	label := make([]byte, 64)
	for i := range label {
		label[i] = 'a'
	}
	msg = append(msg, label...)
	msg = append(msg, 0x00) // null terminator
	msg = append(msg, 0x00, 0x01, 0x00, 0x01) // A IN

	p := NewParser(msg)
	_, err := p.Parse()
	if err == nil {
		t.Error("expected error for label too long")
	}
}

// Benchmark parsing simple query
func BenchmarkParseSimpleQuery(b *testing.B) {
	msg := []byte{
		0x12, 0x34, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := NewParser(msg)
		_, err := p.Parse()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark parsing response with compression
func BenchmarkParseCompressedResponse(b *testing.B) {
	msg := []byte{
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	// Add 5 A records with compression
	for i := 0; i < 5; i++ {
		msg = append(msg,
			0xC0, 0x0C, // Pointer
			0x00, 0x01, 0x00, 0x01, // A IN
			0x00, 0x00, 0x00, 0x3C, // TTL
			0x00, 0x04, // RDLENGTH
			192, 0, 2, byte(i), // IP
		)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := NewParser(msg)
		_, err := p.Parse()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Fuzz test for parser
func FuzzParser(f *testing.F) {
	// Seed corpus with valid messages
	seeds := [][]byte{
		// Simple query
		{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
			0x00, 0x01, 0x00, 0x01},

		// Response with answer
		{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
			0x00, 0x01, 0x00, 0x01,
			0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C,
			0x00, 0x04, 192, 0, 2, 1},
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parser should never panic on any input
		p := NewParser(data)
		_, _ = p.Parse() // Ignore errors, just ensure no panic
	})
}

// Test HashQuery function
func TestHashQuery(t *testing.T) {
	h1 := HashQuery("example.com.", 1, 1)
	h2 := HashQuery("example.com.", 1, 1)
	h3 := HashQuery("example.org.", 1, 1)

	if h1 != h2 {
		t.Error("same query should hash to same value")
	}

	if h1 == h3 {
		t.Error("different queries should hash to different values")
	}
}
