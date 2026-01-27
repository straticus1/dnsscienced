package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
)

var (
	// ErrCompressionBomb indicates recursive pointer loops or excessive depth
	ErrCompressionBomb = errors.New("compression bomb detected")

	// ErrInvalidOffset indicates pointer outside message bounds
	ErrInvalidOffset = errors.New("invalid compression pointer offset")

	// ErrMessageTooShort indicates malformed DNS message
	ErrMessageTooShort = errors.New("message too short")

	// ErrRRsetTooLarge indicates RRset exceeds size limits
	ErrRRsetTooLarge = errors.New("rrset too large")

	// ErrTooManyRRs indicates too many records in RRset
	ErrTooManyRRs = errors.New("too many resource records")
)

const (
	// Security limits based on Unbound CVE-2024-8508 mitigation
	maxCompressionDepth = 20      // Maximum pointer chain length
	maxRRsPerName       = 100     // Maximum RRs per qname
	maxRRsetSize        = 32 * 1024 // 32KB max per RRset
	maxMessageSize      = 65535   // DNS message size limit

	// DNS header constants
	headerSize = 12

	// Label constraints (RFC 1035)
	maxLabelLength = 63
	maxDomainLength = 255
)

// Header represents DNS message header (RFC 1035 Section 4.1.1)
type Header struct {
	ID      uint16
	QR      bool   // Query (false) or Response (true)
	Opcode  uint8  // 4 bits
	AA      bool   // Authoritative Answer
	TC      bool   // Truncated
	RD      bool   // Recursion Desired
	RA      bool   // Recursion Available
	Z       uint8  // Reserved (3 bits)
	Rcode   uint8  // Response code (4 bits)
	QDCount uint16 // Question count
	ANCount uint16 // Answer count
	NSCount uint16 // Authority count
	ARCount uint16 // Additional count
}

// Message represents a DNS message
type Message struct {
	Header     Header
	Question   []Question
	Answer     []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord

	// Security metadata
	CompressedSize int  // Wire format size
	DecompressOps  int  // Number of decompression operations
}

// Question represents a DNS question section entry
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord represents a DNS resource record
type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

// Parser provides secure DNS message parsing with attack mitigation
type Parser struct {
	msg    []byte
	offset int

	// Anti-DOS counters
	decompressionOps int
	totalRRSize      int
	rrCount          int
}

// NewParser creates a parser for the given DNS message
func NewParser(msg []byte) *Parser {
	return &Parser{
		msg:    msg,
		offset: 0,
	}
}

// Parse parses a complete DNS message with security checks
func (p *Parser) Parse() (*Message, error) {
	if len(p.msg) < headerSize {
		return nil, ErrMessageTooShort
	}

	m := &Message{}

	// Parse header
	if err := p.parseHeader(&m.Header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	// Parse question section
	m.Question = make([]Question, m.Header.QDCount)
	for i := 0; i < int(m.Header.QDCount); i++ {
		q, err := p.parseQuestion()
		if err != nil {
			return nil, fmt.Errorf("parse question %d: %w", i, err)
		}
		m.Question[i] = q
	}

	// Parse answer section
	var err error
	m.Answer, err = p.parseRRSection(int(m.Header.ANCount))
	if err != nil {
		return nil, fmt.Errorf("parse answer: %w", err)
	}

	// Parse authority section
	m.Authority, err = p.parseRRSection(int(m.Header.NSCount))
	if err != nil {
		return nil, fmt.Errorf("parse authority: %w", err)
	}

	// Parse additional section
	m.Additional, err = p.parseRRSection(int(m.Header.ARCount))
	if err != nil {
		return nil, fmt.Errorf("parse additional: %w", err)
	}

	m.CompressedSize = len(p.msg)
	m.DecompressOps = p.decompressionOps

	return m, nil
}

// parseHeader parses DNS message header (12 bytes)
func (p *Parser) parseHeader(h *Header) error {
	if len(p.msg) < headerSize {
		return ErrMessageTooShort
	}

	h.ID = binary.BigEndian.Uint16(p.msg[0:2])

	flags := binary.BigEndian.Uint16(p.msg[2:4])
	h.QR = (flags & 0x8000) != 0
	h.Opcode = uint8((flags >> 11) & 0x0F)
	h.AA = (flags & 0x0400) != 0
	h.TC = (flags & 0x0200) != 0
	h.RD = (flags & 0x0100) != 0
	h.RA = (flags & 0x0080) != 0
	h.Z = uint8((flags >> 4) & 0x07)
	h.Rcode = uint8(flags & 0x0F)

	h.QDCount = binary.BigEndian.Uint16(p.msg[4:6])
	h.ANCount = binary.BigEndian.Uint16(p.msg[6:8])
	h.NSCount = binary.BigEndian.Uint16(p.msg[8:10])
	h.ARCount = binary.BigEndian.Uint16(p.msg[10:12])

	p.offset = headerSize
	return nil
}

// parseQuestion parses a question section entry
func (p *Parser) parseQuestion() (Question, error) {
	q := Question{}

	name, err := p.parseName()
	if err != nil {
		return q, fmt.Errorf("parse name: %w", err)
	}
	q.Name = name

	if p.offset+4 > len(p.msg) {
		return q, ErrMessageTooShort
	}

	q.Type = binary.BigEndian.Uint16(p.msg[p.offset : p.offset+2])
	q.Class = binary.BigEndian.Uint16(p.msg[p.offset+2 : p.offset+4])
	p.offset += 4

	return q, nil
}

// parseRRSection parses a section of resource records with security limits
func (p *Parser) parseRRSection(count int) ([]ResourceRecord, error) {
	if count > maxRRsPerName {
		return nil, ErrTooManyRRs
	}

	rrs := make([]ResourceRecord, 0, count)
	sectionSize := 0

	for i := 0; i < count; i++ {
		rr, size, err := p.parseRR()
		if err != nil {
			return nil, fmt.Errorf("parse RR %d: %w", i, err)
		}

		sectionSize += size
		if sectionSize > maxRRsetSize {
			return nil, ErrRRsetTooLarge
		}

		rrs = append(rrs, rr)
	}

	return rrs, nil
}

// parseRR parses a single resource record
func (p *Parser) parseRR() (ResourceRecord, int, error) {
	rr := ResourceRecord{}
	startOffset := p.offset

	name, err := p.parseName()
	if err != nil {
		return rr, 0, fmt.Errorf("parse name: %w", err)
	}
	rr.Name = name

	if p.offset+10 > len(p.msg) {
		return rr, 0, ErrMessageTooShort
	}

	rr.Type = binary.BigEndian.Uint16(p.msg[p.offset : p.offset+2])
	rr.Class = binary.BigEndian.Uint16(p.msg[p.offset+2 : p.offset+4])
	rr.TTL = binary.BigEndian.Uint32(p.msg[p.offset+4 : p.offset+8])
	rdlength := binary.BigEndian.Uint16(p.msg[p.offset+8 : p.offset+10])
	p.offset += 10

	if p.offset+int(rdlength) > len(p.msg) {
		return rr, 0, ErrMessageTooShort
	}

	// Copy RDATA to prevent holding large backing array
	rr.RData = make([]byte, rdlength)
	copy(rr.RData, p.msg[p.offset:p.offset+int(rdlength)])
	p.offset += int(rdlength)

	size := p.offset - startOffset
	return rr, size, nil
}

// parseName parses a domain name with compression pointer protection
// This is the critical function that prevents CVE-2024-8508 style attacks
func (p *Parser) parseName() (string, error) {
	var labels []string
	visited := make(map[int]bool) // Track visited offsets to detect loops
	depth := 0
	offset := p.offset
	jumped := false
	origOffset := p.offset

	for {
		// Check compression depth limit (Unbound-style mitigation)
		if depth > maxCompressionDepth {
			return "", ErrCompressionBomb
		}

		if offset >= len(p.msg) {
			return "", ErrInvalidOffset
		}

		length := int(p.msg[offset])

		// Check for compression pointer (0xC0)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(p.msg) {
				return "", ErrMessageTooShort
			}

			// Extract pointer offset
			ptr := int(binary.BigEndian.Uint16(p.msg[offset:offset+2]) & 0x3FFF)

			// Detect loops by checking if we've visited this offset
			if visited[ptr] {
				return "", ErrCompressionBomb
			}
			visited[ptr] = true

			// Validate pointer is within message and points backwards
			if ptr >= len(p.msg) || ptr >= origOffset {
				return "", ErrInvalidOffset
			}

			if !jumped {
				p.offset = offset + 2
				jumped = true
			}

			offset = ptr
			depth++
			p.decompressionOps++
			continue
		}

		// End of name (null label)
		if length == 0 {
			if !jumped {
				p.offset = offset + 1
			}
			break
		}

		// Validate label length
		if length > maxLabelLength {
			return "", fmt.Errorf("label too long: %d", length)
		}

		offset++
		if offset+length > len(p.msg) {
			return "", ErrMessageTooShort
		}

		// Copy label to prevent holding large backing array
		label := make([]byte, length)
		copy(label, p.msg[offset:offset+length])
		labels = append(labels, string(label))

		offset += length
	}

	// Construct FQDN
	if len(labels) == 0 {
		return ".", nil
	}

	// Check total domain length
	name := ""
	for i, label := range labels {
		name += label
		if i < len(labels)-1 {
			name += "."
		}
	}
	name += "."

	if len(name) > maxDomainLength {
		return "", fmt.Errorf("domain too long: %d", len(name))
	}

	return name, nil
}

// HashQuery creates a cache key hash for a query (DOS-resistant)
// Uses FNV-1a which is fast and has good distribution
func HashQuery(qname string, qtype, qclass uint16) uint64 {
	h := fnv.New64a()
	h.Write([]byte(qname))
	binary.Write(h, binary.BigEndian, qtype)
	binary.Write(h, binary.BigEndian, qclass)
	return h.Sum64()
}
