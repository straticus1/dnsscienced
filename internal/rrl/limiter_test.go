package rrl

import (
	"net"
	"testing"
	"time"
)

func TestNewLimiter(t *testing.T) {
	cfg := DefaultConfig()
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	if !limiter.cfg.Enabled {
		t.Error("limiter should be enabled by default")
	}
}

func TestCheck_Allow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 10
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// First few queries should be allowed
	for i := 0; i < 5; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action != ActionAllow {
			t.Errorf("query %d: action = %v, want ActionAllow", i, action)
		}
	}

	stats := limiter.GetStats()
	if stats.Allowed != 5 {
		t.Errorf("allowed = %d, want 5", stats.Allowed)
	}
}

func TestCheck_RateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 2
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust tokens (2 tokens for 1 second window)
	for i := 0; i < 2; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action != ActionAllow {
			t.Errorf("initial query %d should be allowed", i)
		}
	}

	// Next query should be rate limited
	action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	if action == ActionAllow {
		t.Error("query should be rate limited")
	}

	stats := limiter.GetStats()
	if stats.Dropped+stats.Slipped == 0 {
		t.Error("should have dropped or slipped at least one query")
	}
}

func TestCheck_Refill(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 5
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust tokens
	for i := 0; i < 5; i++ {
		limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	}

	// Should be rate limited now
	action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	if action == ActionAllow {
		t.Error("should be rate limited")
	}

	// Wait for refill
	time.Sleep(1200 * time.Millisecond)

	// Should be allowed again
	action = limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	if action != ActionAllow {
		t.Error("should be allowed after refill")
	}
}

func TestCheck_Exempt(t *testing.T) {
	_, exemptNet, _ := net.ParseCIDR("192.0.2.0/24")

	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 1
	cfg.ExemptPrefixes = []*net.IPNet{exemptNet}
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.100")

	// Exempt IPs should never be rate limited
	for i := 0; i < 100; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action != ActionAllow {
			t.Errorf("exempt client should always be allowed, got %v", action)
		}
	}
}

func TestCheck_DifferentCategories(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 2
	cfg.NXDOMAINsPerSecond = 2
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust response tokens
	for i := 0; i < 2; i++ {
		limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	}

	// NXDOMAIN should still be allowed (different bucket)
	action := limiter.Check(clientIP, "notfound.com", 1, CategoryNXDOMAIN)
	if action != ActionAllow {
		t.Error("NXDOMAIN should use separate bucket")
	}
}

func TestCheck_Slip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 1
	cfg.Window = 1
	cfg.Slip = 2 // 50% slip rate
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Exhaust tokens
	limiter.Check(clientIP, "example.com", 1, CategoryResponse)

	// Generate many rate-limited queries
	var slipped, dropped int
	for i := 0; i < 100; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action == ActionSlip {
			slipped++
		} else if action == ActionDrop {
			dropped++
		}
	}

	// Should have both slips and drops
	if slipped == 0 {
		t.Error("should have some slipped responses")
	}
	if dropped == 0 {
		t.Error("should have some dropped responses")
	}

	// Roughly 50/50 split (allow some variance)
	ratio := float64(slipped) / float64(slipped+dropped)
	if ratio < 0.3 || ratio > 0.7 {
		t.Errorf("slip ratio = %.2f, expected ~0.5", ratio)
	}
}

func TestCheck_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Should always allow when disabled
	for i := 0; i < 1000; i++ {
		action := limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		if action != ActionAllow {
			t.Error("disabled limiter should always allow")
		}
	}
}

func TestCategorizeResponse(t *testing.T) {
	tests := []struct {
		rcode       int
		answerCount int
		nsCount     int
		want        int
	}{
		{0, 1, 0, CategoryResponse},    // NOERROR with answer
		{0, 0, 1, CategoryReferral},    // NOERROR with NS
		{0, 0, 0, CategoryNodata},      // NOERROR without answer or NS
		{3, 0, 0, CategoryNXDOMAIN},    // NXDOMAIN
		{2, 0, 0, CategoryError},       // SERVFAIL
		{1, 0, 0, CategoryError},       // FORMERR
	}

	for _, tt := range tests {
		got := CategorizeResponse(tt.rcode, tt.answerCount, tt.nsCount)
		if got != tt.want {
			t.Errorf("CategorizeResponse(%d, %d, %d) = %d, want %d",
				tt.rcode, tt.answerCount, tt.nsCount, got, tt.want)
		}
	}
}

func TestGetStats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ResponsesPerSecond = 2
	cfg.Window = 1
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	// Generate some traffic
	for i := 0; i < 10; i++ {
		limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	}

	stats := limiter.GetStats()
	if stats.Total != 10 {
		t.Errorf("total = %d, want 10", stats.Total)
	}
	if stats.Allowed+stats.Dropped+stats.Slipped != stats.Total {
		t.Error("stats don't add up")
	}
	if stats.DropRate < 0 || stats.DropRate > 1 {
		t.Errorf("dropRate = %.2f, should be between 0 and 1", stats.DropRate)
	}
}

func BenchmarkCheck(b *testing.B) {
	cfg := DefaultConfig()
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Check(clientIP, "example.com", 1, CategoryResponse)
	}
}

func BenchmarkCheckConcurrent(b *testing.B) {
	cfg := DefaultConfig()
	limiter := NewLimiter(cfg)
	defer limiter.Close()

	clientIP := net.ParseIP("192.0.2.1")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			limiter.Check(clientIP, "example.com", 1, CategoryResponse)
		}
	})
}
