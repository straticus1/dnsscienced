package cache

import (
	"context"
	"testing"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
)

func TestEnrichEntry(t *testing.T) {
	scorer := NewThreatScorer("")

	tests := []struct {
		name      string
		domain    string
		wantScore int32
		wantRep   string
	}{
		{
			name:      "Benign Domain",
			domain:    "google.com",
			wantScore: 0,
			wantRep:   "benign",
		},
		{
			name:      "Malicious Domain",
			domain:    "bad-site.org",
			wantScore: 100,
			wantRep:   "malicious",
		},
		{
			name:      "Suspicious Domain",
			domain:    "suspicious-domain.xyz",
			wantScore: 50,
			wantRep:   "suspicious",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &Entry{
				QName: tt.domain,
			}
			scorer.EnrichEntry(entry)

			if entry.ThreatScore != tt.wantScore {
				t.Errorf("EnrichEntry() ThreatScore = %v, want %v", entry.ThreatScore, tt.wantScore)
			}
			if entry.Reputation != tt.wantRep {
				t.Errorf("EnrichEntry() Reputation = %v, want %v", entry.Reputation, tt.wantRep)
			}
			if entry.FirstSeen.IsZero() {
				t.Error("EnrichEntry() FirstSeen should not be zero")
			}
		})
	}
}

func TestEnrich(t *testing.T) {
	scorer := NewThreatScorer("")

	entry := &pb.CacheEntry{
		Name: "bad-site.org",
	}

	scorer.Enrich(context.Background(), entry)

	if entry.ThreatScore != 100 {
		t.Errorf("Enrich() ThreatScore = %v, want 100", entry.ThreatScore)
	}
}
