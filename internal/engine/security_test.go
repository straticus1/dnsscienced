package engine

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestApply0x20Encoding(t *testing.T) {
	// Run multiple times to ensure randomness doesn't break functionality
	for i := 0; i < 10; i++ {
		name := "www.example.com."
		encoded := Apply0x20Encoding(name)

		// Should be same length
		assert.Equal(t, len(name), len(encoded))

		// Should be equal when compared case-insensitively
		assert.True(t, strings.EqualFold(name, encoded), "0x20 encoded name should be DNS-equal to original")
	}
}

func TestValidate0x20Response(t *testing.T) {
	// Exact match should pass
	assert.True(t, Validate0x20Response("WwW.ExAmPlE.cOm.", "WwW.ExAmPlE.cOm."))

	// Different case should fail (this catches spoofing)
	assert.False(t, Validate0x20Response("WwW.ExAmPlE.cOm.", "www.example.com."))
}

func TestScrubResponse(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("www.example.com.", dns.TypeA)

	// Add in-bailiwick authority
	msg.Ns = append(msg.Ns, &dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns1.example.com.",
	})

	// Add out-of-bailiwick authority (should be removed)
	msg.Ns = append(msg.Ns, &dns.NS{
		Hdr: dns.RR_Header{Name: "attacker.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns1.attacker.com.",
	})

	// Add in-bailiwick glue
	msg.Extra = append(msg.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   []byte{192, 0, 2, 1},
	})

	// Add out-of-bailiwick glue (should be removed)
	msg.Extra = append(msg.Extra, &dns.A{
		Hdr: dns.RR_Header{Name: "ns1.attacker.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   []byte{192, 0, 2, 53},
	})

	ScrubResponse(msg, "example.com.")

	// Should only have in-bailiwick records left
	assert.Len(t, msg.Ns, 1)
	assert.Equal(t, "example.com.", msg.Ns[0].Header().Name)

	assert.Len(t, msg.Extra, 1)
	assert.Equal(t, "ns1.example.com.", msg.Extra[0].Header().Name)
}

func TestApplyQNAMEMinimization(t *testing.T) {
	tests := []struct {
		fullName    string
		currentZone string
		expected    string
	}{
		// Querying www.example.com at the .com zone should ask for example.com
		{"www.example.com.", "com.", "example.com."},
		// Querying www.example.com at the example.com zone should ask for www.example.com
		{"www.example.com.", "example.com.", "www.example.com."},
		// Querying a.b.c.example.com at the .com zone should ask for example.com
		{"a.b.c.example.com.", "com.", "example.com."},
		// Querying a.b.c.example.com at the example.com zone should ask for c.example.com
		{"a.b.c.example.com.", "example.com.", "c.example.com."},
		// Querying example.com at the .com zone should ask for example.com
		{"example.com.", "com.", "example.com."},
		// Root zone case
		{"example.com.", ".", "com."},
	}

	for _, tt := range tests {
		result := ApplyQNAMEMinimization(tt.fullName, tt.currentZone)
		assert.Equal(t, tt.expected, result, "QNAME minimization failed for %s at zone %s", tt.fullName, tt.currentZone)
	}
}

func TestIsInBailiwick(t *testing.T) {
	assert.True(t, IsInBailiwick("www.example.com.", "example.com."))
	assert.True(t, IsInBailiwick("example.com.", "example.com."))
	assert.True(t, IsInBailiwick("a.b.c.example.com.", "example.com."))
	assert.False(t, IsInBailiwick("example.com.", "www.example.com."))
	assert.False(t, IsInBailiwick("attacker.com.", "example.com."))
}
