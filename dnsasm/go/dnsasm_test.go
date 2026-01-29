package dnsasm

import (
	"testing"
)

// Sample DNS query packet
var sampleQuery = []byte{
	// Header
	0x12, 0x34, // ID
	0x01, 0x00, // Flags: RD=1
	0x00, 0x01, // QDCOUNT
	0x00, 0x00, // ANCOUNT
	0x00, 0x00, // NSCOUNT
	0x00, 0x00, // ARCOUNT
	// Question: www.example.com A IN
	0x03, 'w', 'w', 'w',
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,       // Root label
	0x00, 0x01, // QTYPE: A
	0x00, 0x01, // QCLASS: IN
}

func TestParseHeader(t *testing.T) {
	h, err := ParseHeader(sampleQuery)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}

	if h.ID != 0x1234 {
		t.Errorf("ID = %04x, want 0x1234", h.ID)
	}
	if h.QR != false {
		t.Errorf("QR = %v, want false (query)", h.QR)
	}
	if h.RD != true {
		t.Errorf("RD = %v, want true", h.RD)
	}
	if h.QDCount != 1 {
		t.Errorf("QDCount = %d, want 1", h.QDCount)
	}
}

func TestParseQuestion(t *testing.T) {
	q, offset, err := ParseQuestion(sampleQuery, 12)
	if err != nil {
		t.Fatalf("ParseQuestion failed: %v", err)
	}

	if q.Name != "www.example.com" {
		t.Errorf("Name = %q, want %q", q.Name, "www.example.com")
	}
	if q.Type != TypeA {
		t.Errorf("Type = %d, want %d (A)", q.Type, TypeA)
	}
	if q.Class != ClassIN {
		t.Errorf("Class = %d, want %d (IN)", q.Class, ClassIN)
	}
	if offset != len(sampleQuery) {
		t.Errorf("offset = %d, want %d", offset, len(sampleQuery))
	}
}

func TestParseHeaderShort(t *testing.T) {
	_, err := ParseHeader([]byte{0x12, 0x34})
	if err != ErrShort {
		t.Errorf("expected ErrShort, got %v", err)
	}
}

func BenchmarkParseHeader(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseHeader(sampleQuery)
	}
}

func BenchmarkParseQuestion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseQuestion(sampleQuery, 12)
	}
}

func BenchmarkParsePacket(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseHeader(sampleQuery)
		_, _, _ = ParseQuestion(sampleQuery, 12)
	}
}
