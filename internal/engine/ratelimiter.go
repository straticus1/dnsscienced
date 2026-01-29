package engine

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides per-client rate limiting for DNS queries.
// It uses a token bucket algorithm to limit queries per second.
type RateLimiter struct {
	mu              sync.RWMutex
	limitersByIP    map[string]*rate.Limiter
	queriesPerSec   rate.Limit
	burstSize       int
	cleanupInterval time.Duration
	lastCleanup     time.Time
	exemptNets      []*net.IPNet
}

// RateLimiterConfig holds configuration for the rate limiter.
type RateLimiterConfig struct {
	QueriesPerSecond float64       // Maximum queries per second per client
	BurstSize        int           // Maximum burst size
	CleanupInterval  time.Duration // How often to clean up stale limiters
}

// DefaultRateLimiterConfig returns sensible defaults.
func DefaultRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		QueriesPerSecond: 100, // 100 QPS per client
		BurstSize:        200, // Allow bursts up to 200
		CleanupInterval:  5 * time.Minute,
	}
}

// NewRateLimiter creates a new RateLimiter with the given configuration.
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	return &RateLimiter{
		limitersByIP:    make(map[string]*rate.Limiter),
		queriesPerSec:   rate.Limit(cfg.QueriesPerSecond),
		burstSize:       cfg.BurstSize,
		cleanupInterval: cfg.CleanupInterval,
		lastCleanup:     time.Now(),
		exemptNets:      make([]*net.IPNet, 0),
	}
}

// Allow checks if a query from the given IP should be allowed.
// Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow(ip net.IP) bool {
	// Check if IP is exempt
	if rl.isExempt(ip) {
		return true
	}

	ipStr := ip.String()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Periodic cleanup of stale limiters
	if time.Since(rl.lastCleanup) > rl.cleanupInterval {
		rl.cleanup()
	}

	// Get or create limiter for this IP
	limiter, ok := rl.limitersByIP[ipStr]
	if !ok {
		limiter = rate.NewLimiter(rl.queriesPerSec, rl.burstSize)
		rl.limitersByIP[ipStr] = limiter
	}

	return limiter.Allow()
}

// AllowString is a convenience wrapper that parses an IP string.
func (rl *RateLimiter) AllowString(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return rl.Allow(ip)
}

// AddExempt adds a network that is exempt from rate limiting.
func (rl *RateLimiter) AddExempt(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return err
		}
		if ip.To4() != nil {
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.exemptNets = append(rl.exemptNets, ipnet)
	return nil
}

// isExempt checks if an IP is in the exempt list.
func (rl *RateLimiter) isExempt(ip net.IP) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	for _, exempt := range rl.exemptNets {
		if exempt.Contains(ip) {
			return true
		}
	}
	return false
}

// cleanup removes limiters that haven't been used recently.
// Must be called with lock held.
func (rl *RateLimiter) cleanup() {
	// Simple cleanup: just clear all limiters periodically
	// A more sophisticated approach would track last access time
	rl.limitersByIP = make(map[string]*rate.Limiter)
	rl.lastCleanup = time.Now()
}

// Stats returns current statistics about the rate limiter.
func (rl *RateLimiter) Stats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return RateLimiterStats{
		TrackedClients: len(rl.limitersByIP),
		ExemptNets:     len(rl.exemptNets),
	}
}

// RateLimiterStats holds statistics about the rate limiter.
type RateLimiterStats struct {
	TrackedClients int
	ExemptNets     int
}
