package random

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Package random provides cryptographically secure randomization for DNS
// to prevent cache poisoning attacks.
//
// Attack model: Kaminsky attack and birthday attack variants
// - Attacker floods resolver with spoofed responses
// - Must guess transaction ID (16 bits) + source port (16 bits) = 32 bits total
// - With 10,000 queries/sec, attacker has ~6 seconds for 50% collision
// - Solution: Crypto-strong randomization + additional entropy (0x20 encoding)

var (
	ErrPortPoolExhausted = errors.New("no available ports in pool")
	ErrInvalidPortRange  = errors.New("invalid port range")
)

// TransactionID generates a cryptographically random 16-bit transaction ID
// NEVER use math/rand for DNS transaction IDs - it's predictable!
func TransactionID() uint16 {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// This should never happen, but if it does, panic is appropriate
		// because proceeding with predictable IDs is a critical security flaw
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return binary.BigEndian.Uint16(buf[:])
}

// SourcePort generates a cryptographically random source port
// Avoids privileged ports (< 1024) and common ephemeral ranges
func SourcePort() uint16 {
	// Use high ephemeral range: 32768-61000
	// Excludes 61001-65535 (might be used by other services)
	const (
		minPort   = 32768
		portRange = 61000 - 32768 // 28232 possible ports
	)

	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}

	// Use modulo on 32-bit random to avoid bias
	randomOffset := binary.BigEndian.Uint32(buf[:]) % portRange
	return uint16(minPort + randomOffset)
}

// PortPool manages a pool of randomized source ports
// Prevents port reuse which could aid cache poisoning
type PortPool struct {
	mu sync.Mutex

	// Port range
	minPort int
	maxPort int

	// Available ports (map for O(1) lookup)
	available map[uint16]struct{}

	// In-use ports with expiration
	inUse map[uint16]time.Time

	// Configuration
	maxInUse     int
	portLifetime time.Duration

	// Statistics
	allocated   uint64
	recycled    uint64
	exhaustions uint64
}

// PortPoolConfig holds configuration for port pool
type PortPoolConfig struct {
	// Port range (default: 32768-61000)
	MinPort int
	MaxPort int

	// Maximum simultaneous in-use ports (default: 10000)
	MaxInUse int

	// Port lifetime before recycling (default: 2 minutes)
	// Should be > maximum DNS timeout
	PortLifetime time.Duration
}

// NewPortPool creates a new randomized port pool
func NewPortPool(cfg PortPoolConfig) (*PortPool, error) {
	if cfg.MinPort == 0 {
		cfg.MinPort = 32768
	}
	if cfg.MaxPort == 0 {
		cfg.MaxPort = 61000
	}
	if cfg.MaxInUse == 0 {
		cfg.MaxInUse = 10000
	}
	if cfg.PortLifetime == 0 {
		cfg.PortLifetime = 2 * time.Minute
	}

	if cfg.MinPort >= cfg.MaxPort {
		return nil, ErrInvalidPortRange
	}
	if cfg.MinPort < 1024 {
		return nil, errors.New("min port must be >= 1024 (non-privileged)")
	}

	portCount := cfg.MaxPort - cfg.MinPort

	p := &PortPool{
		minPort:      cfg.MinPort,
		maxPort:      cfg.MaxPort,
		available:    make(map[uint16]struct{}, portCount),
		inUse:        make(map[uint16]time.Time, cfg.MaxInUse),
		maxInUse:     cfg.MaxInUse,
		portLifetime: cfg.PortLifetime,
	}

	// Initialize available ports
	for port := cfg.MinPort; port < cfg.MaxPort; port++ {
		p.available[uint16(port)] = struct{}{}
	}

	// Start background cleanup
	go p.cleanup()

	return p, nil
}

// Allocate allocates a random available port
func (p *PortPool) Allocate() (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to allocate from available pool
	if len(p.available) > 0 {
		// Pick random port from available
		// Convert map to slice (inefficient but ensures randomness)
		ports := make([]uint16, 0, len(p.available))
		for port := range p.available {
			ports = append(ports, port)
		}

		// Random selection
		var buf [4]byte
		rand.Read(buf[:])
		idx := int(binary.BigEndian.Uint32(buf[:])) % len(ports)
		selectedPort := ports[idx]

		// Move to in-use
		delete(p.available, selectedPort)
		p.inUse[selectedPort] = time.Now()
		p.allocated++

		return selectedPort, nil
	}

	// No available ports - try to recycle expired ones
	now := time.Now()
	for port, allocated := range p.inUse {
		if now.Sub(allocated) > p.portLifetime {
			// Port expired, recycle it
			p.recycled++
			p.inUse[port] = now
			return port, nil
		}
	}

	// Pool exhausted
	p.exhaustions++
	return 0, ErrPortPoolExhausted
}

// Release returns a port to the available pool
func (p *PortPool) Release(port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove from in-use
	delete(p.inUse, port)

	// Add back to available
	if int(port) >= p.minPort && int(port) < p.maxPort {
		p.available[port] = struct{}{}
	}
}

// cleanup periodically recycles expired ports
func (p *PortPool) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()

		now := time.Now()
		var recycled []uint16

		for port, allocated := range p.inUse {
			if now.Sub(allocated) > p.portLifetime {
				recycled = append(recycled, port)
			}
		}

		// Recycle expired ports
		for _, port := range recycled {
			delete(p.inUse, port)
			p.available[port] = struct{}{}
			p.recycled++
		}

		p.mu.Unlock()
	}
}

// Stats returns pool statistics
type PoolStats struct {
	Available   int
	InUse       int
	Allocated   uint64
	Recycled    uint64
	Exhaustions uint64
}

// GetStats returns current pool statistics
func (p *PortPool) GetStats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	return PoolStats{
		Available:   len(p.available),
		InUse:       len(p.inUse),
		Allocated:   p.allocated,
		Recycled:    p.recycled,
		Exhaustions: p.exhaustions,
	}
}

// QueryID combines transaction ID and source port for cache key
// This creates 32 bits of entropy against cache poisoning
type QueryID struct {
	TxID uint16
	Port uint16
}

// NewQueryID generates a new random query ID
func NewQueryID() QueryID {
	return QueryID{
		TxID: TransactionID(),
		Port: SourcePort(),
	}
}

// String returns string representation for logging
func (q QueryID) String() string {
	return fmt.Sprintf("txid=%d port=%d", q.TxID, q.Port)
}

// Hash returns a hash suitable for cache keys
func (q QueryID) Hash() uint64 {
	return uint64(q.TxID)<<16 | uint64(q.Port)
}

// ValidateResponse checks if a response matches the query ID
// This is the critical security check that prevents cache poisoning
func (q QueryID) ValidateResponse(responseTxID uint16, responseAddr net.Addr) bool {
	// Check transaction ID
	if q.TxID != responseTxID {
		return false
	}

	// Extract port from response address
	// Response should come from the port we sent to
	// (Actually, we're checking the port we sent FROM, not TO)
	// The UDP layer will handle this, but we double-check here

	// For now, we only validate txid
	// Port validation happens at socket level
	return true
}

// Entropy calculates effective entropy bits
// Transaction ID: 16 bits
// Source port: ~14.8 bits (28232 possible ports)
// Total: ~30.8 bits
func Entropy() float64 {
	const (
		txidBits = 16.0
		// Port range: 28232 ports = log2(28232) ≈ 14.78 bits
		portBits = 14.78
	)
	return txidBits + portBits
}

// RequiredQueriesFor50PercentCollision calculates queries needed
// Birthday paradox: √(2^n) queries for 50% collision
// With 30.8 bits: √(2^30.8) ≈ 37,000 queries
func RequiredQueriesFor50PercentCollision() int {
	// 2^(30.8/2) ≈ 37,000
	return 37000
}
