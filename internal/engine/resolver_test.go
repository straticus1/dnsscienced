package engine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolver_Resolve(t *testing.T) {
	// Start a local mock DNS server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()

	server := &dns.Server{PacketConn: pc}

	// Handler that returns a fixed A record
	dns.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{1, 2, 3, 4}, // 1.2.3.4
		})
		w.WriteMsg(m)
	})
	defer dns.HandleRemove("example.com.")

	go func() {
		server.ActivateAndServe()
	}()
	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Create our resolver pointing to this mock server
	r := NewResolver(pc.LocalAddr().String())

	// Test Resolve
	res, err := r.Resolve(context.Background(), "example.com.", "A", "IN", false, true, false)
	require.NoError(t, err)
	assert.Equal(t, int32(dns.RcodeSuccess), res.RCode)
	assert.Len(t, res.Answer, 1)
	assert.Equal(t, "example.com.", res.Answer[0].Name)
	assert.Equal(t, "A", res.Answer[0].Type)
	assert.Equal(t, "1.2.3.4", res.Answer[0].Data)
}
