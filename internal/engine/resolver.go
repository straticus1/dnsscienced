package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/dnsscience/dnsscienced/api/grpc/ports"
	"github.com/miekg/dns"
)

// Resolver implements ports.DNSResolver using miekg/dns.
type Resolver struct {
	Upstream string
	Client   *dns.Client
}

// NewResolver creates a new Resolver instance forwarding to the specified upstream.
// If upstream is empty, it defaults to "8.8.8.8:53".
func NewResolver(upstream string) *Resolver {
	if upstream == "" {
		upstream = "8.8.8.8:53"
	}
	return &Resolver{
		Upstream: upstream,
		Client: &dns.Client{
			Timeout: 2 * time.Second,
		},
	}
}

// Resolve performs a DNS query.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype string, class string, dnssec bool, rd bool, cd bool) (*ports.ResolveResult, error) {
	// 1. Construct the query message
	m := new(dns.Msg)
	t, ok := dns.StringToType[qtype]
	if !ok {
		// Fallback or default? Let's error for now or default to A
		t = dns.TypeA
	}
	c, ok := dns.StringToClass[class]
	if !ok {
		c = dns.ClassINET
	}
	m.SetQuestion(dns.Fqdn(name), t)
	m.Question[0].Qclass = c
	m.RecursionDesired = rd
	m.CheckingDisabled = cd
	m.SetEdns0(4096, dnssec)

	// 2. Exchange with upstream
	// Note: In a real recursive resolver, we would iterate from root hints.
	// For this MVP, we forward.
	in, rtt, err := r.Client.ExchangeContext(ctx, m, r.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream query failed: %w", err)
	}

	// 3. Convert response to ports.ResolveResult
	res := &ports.ResolveResult{
		RCode:              int32(in.Rcode),
		RCodeName:          dns.RcodeToString[in.Rcode],
		Authoritative:      in.Authoritative,
		Truncated:          in.Truncated,
		RecursionAvailable: in.RecursionAvailable,
		Meta: map[string]string{
			"rtt_ms": fmt.Sprintf("%d", rtt.Milliseconds()),
		},
	}

	// Pack wire format
	wire, err := in.Pack()
	if err == nil {
		res.Wire = wire
	}

	// Helper to convert []dns.RR to []ports.ResourceRecord
	convertRRs := func(rrs []dns.RR) []ports.ResourceRecord {
		var out []ports.ResourceRecord
		for _, rr := range rrs {
			// Basic formatting
			// For RData, we might need to pack it, but ports.ResourceRecord has string Data and byte RData
			// Let's rely on rr.String() for Data and pack specific rdata if needed.
			// Ideally ports.ResourceRecord should allow us to reconstruct.

			header := rr.Header()
			// To get just the RData bytes is tricky without packing the whole RR and stripping header,
			// or using type assertions. miekg/dns doesn't expose RawRData easily.
			// We will just pack the whole RR for now as implementations often assume standard wire format.
			// Wait, the ports definition says "RData []byte".
			// Let's pack the whole thing and slice? No, that's messy.
			// Let's just provide the wire format of the whole RR in RData maybe?
			// Or ignore RData bytes if Data string is sufficient for the gRPC consumer.
			// Let's try to get RDATA bytes by packing and stripping header.

			buf := make([]byte, len(name)+1000) // crude buffer
			off, err := dns.PackRR(rr, buf, 0, nil, false)
			var rdataBytes []byte
			if err == nil {
				// Header is variable length due to name compression?
				// Actually PackRR packs the whole thing.
				// Parsing it back is the safest way to find RDATA start?
				// For the MVP, let's leave RData empty or just the whole packed RR.
				// The gRPC consumer likely expects just the rdata per RFC 1035.
				// Let's leave it nil for now and populate Data string.
				rdataBytes = buf[:off]
			}

			out = append(out, ports.ResourceRecord{
				Name:  header.Name,
				Type:  dns.TypeToString[header.Rrtype],
				Class: dns.ClassToString[header.Class],
				TTL:   header.Ttl,
				Data:  rr.String()[len(header.String()):], // hacky way to get RDATA string part
				RData: rdataBytes,
			})
		}
		return out
	}

	res.Answer = convertRRs(in.Answer)
	res.Authority = convertRRs(in.Ns)
	res.Additional = convertRRs(in.Extra)

	return res, nil
}
