package random

import (
	"testing"
	"time"
)

func TestTransactionID(t *testing.T) {
	// Generate multiple IDs and check uniqueness
	seen := make(map[uint16]bool)
	const iterations = 10000

	for i := 0; i < iterations; i++ {
		id := TransactionID()

		if seen[id] {
			// Collision is possible but should be rare
			// With 10k iterations and 65k possible values,
			// collision probability is ~60% (birthday paradox)
			// So we just check that we get mostly unique values
			continue
		}
		seen[id] = true
	}

	uniqueCount := len(seen)
	if uniqueCount < iterations*9/10 {
		t.Errorf("too many collisions: got %d unique IDs from %d iterations", uniqueCount, iterations)
	}
}

func TestSourcePort(t *testing.T) {
	const (
		minPort = 32768
		maxPort = 61000
	)

	// Generate multiple ports and check range
	for i := 0; i < 1000; i++ {
		port := SourcePort()

		if port < minPort || port >= maxPort {
			t.Errorf("port %d out of range [%d, %d)", port, minPort, maxPort)
		}
	}
}

func TestSourcePort_Distribution(t *testing.T) {
	// Check that ports are well-distributed
	const iterations = 10000
	buckets := make(map[int]int)

	for i := 0; i < iterations; i++ {
		port := SourcePort()
		// Divide into 10 buckets
		bucket := (int(port) - 32768) / 2824 // (61000-32768)/10
		buckets[bucket]++
	}

	// Each bucket should have roughly 1000 samples
	// Allow 20% deviation
	expectedPerBucket := iterations / 10
	minExpected := expectedPerBucket * 8 / 10
	maxExpected := expectedPerBucket * 12 / 10

	for bucket, count := range buckets {
		if count < minExpected || count > maxExpected {
			t.Errorf("bucket %d has %d samples, expected ~%d", bucket, count, expectedPerBucket)
		}
	}
}

func TestNewQueryID(t *testing.T) {
	id1 := NewQueryID()
	id2 := NewQueryID()

	// IDs should be different (highly likely)
	if id1.TxID == id2.TxID && id1.Port == id2.Port {
		t.Error("consecutive query IDs should be different")
	}

	// Hash should be consistent
	if id1.Hash() != id1.Hash() {
		t.Error("hash should be deterministic")
	}
}

func TestQueryID_String(t *testing.T) {
	id := QueryID{TxID: 0x1234, Port: 54321}
	s := id.String()

	if s == "" {
		t.Error("string representation should not be empty")
	}

	// Should contain both values
	expected := "txid=4660 port=54321"
	if s != expected {
		t.Errorf("String() = %q, want %q", s, expected)
	}
}

func TestQueryID_ValidateResponse(t *testing.T) {
	id := QueryID{TxID: 0x1234, Port: 54321}

	// Valid response
	if !id.ValidateResponse(0x1234, nil) {
		t.Error("should validate matching txid")
	}

	// Invalid transaction ID
	if id.ValidateResponse(0x5678, nil) {
		t.Error("should reject mismatched txid")
	}
}

func TestNewPortPool(t *testing.T) {
	cfg := PortPoolConfig{
		MinPort:      40000,
		MaxPort:      50000,
		MaxInUse:     1000,
		PortLifetime: 1 * time.Minute,
	}

	pool, err := NewPortPool(cfg)
	if err != nil {
		t.Fatalf("NewPortPool() error: %v", err)
	}

	if pool.minPort != 40000 {
		t.Errorf("minPort = %d, want 40000", pool.minPort)
	}
	if pool.maxPort != 50000 {
		t.Errorf("maxPort = %d, want 50000", pool.maxPort)
	}

	stats := pool.GetStats()
	expectedAvailable := 50000 - 40000
	if stats.Available != expectedAvailable {
		t.Errorf("available = %d, want %d", stats.Available, expectedAvailable)
	}
}

func TestNewPortPool_Defaults(t *testing.T) {
	cfg := PortPoolConfig{} // Use defaults

	pool, err := NewPortPool(cfg)
	if err != nil {
		t.Fatalf("NewPortPool() error: %v", err)
	}

	if pool.minPort == 0 {
		t.Error("should have default minPort")
	}
	if pool.maxPort == 0 {
		t.Error("should have default maxPort")
	}
}

func TestNewPortPool_InvalidRange(t *testing.T) {
	cfg := PortPoolConfig{
		MinPort: 50000,
		MaxPort: 40000, // Invalid: min > max
	}

	_, err := NewPortPool(cfg)
	if err == nil {
		t.Error("NewPortPool() should fail with invalid range")
	}
}

func TestNewPortPool_PrivilegedPort(t *testing.T) {
	cfg := PortPoolConfig{
		MinPort: 80, // Privileged port
		MaxPort: 1000,
	}

	_, err := NewPortPool(cfg)
	if err == nil {
		t.Error("NewPortPool() should fail with privileged port")
	}
}

func TestPortPool_Allocate(t *testing.T) {
	cfg := PortPoolConfig{
		MinPort:  40000,
		MaxPort:  40010, // Small range for testing
		MaxInUse: 10,
	}

	pool, err := NewPortPool(cfg)
	if err != nil {
		t.Fatalf("NewPortPool() error: %v", err)
	}

	// Allocate a port
	port, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}

	if port < 40000 || port >= 40010 {
		t.Errorf("port %d out of range", port)
	}

	stats := pool.GetStats()
	if stats.InUse != 1 {
		t.Errorf("inUse = %d, want 1", stats.InUse)
	}
	if stats.Allocated != 1 {
		t.Errorf("allocated = %d, want 1", stats.Allocated)
	}
}

func TestPortPool_Release(t *testing.T) {
	cfg := PortPoolConfig{
		MinPort:  40000,
		MaxPort:  40010,
		MaxInUse: 10,
	}

	pool, err := NewPortPool(cfg)
	if err != nil {
		t.Fatalf("NewPortPool() error: %v", err)
	}

	// Allocate and release
	port, err := pool.Allocate()
	if err != nil {
		t.Fatalf("Allocate() error: %v", err)
	}

	pool.Release(port)

	stats := pool.GetStats()
	if stats.InUse != 0 {
		t.Errorf("inUse = %d, want 0 after release", stats.InUse)
	}
}

func TestPortPool_Exhaustion(t *testing.T) {
	cfg := PortPoolConfig{
		MinPort:      40000,
		MaxPort:      40005, // Only 5 ports
		MaxInUse:     5,
		PortLifetime: 10 * time.Second, // Long lifetime
	}

	pool, err := NewPortPool(cfg)
	if err != nil {
		t.Fatalf("NewPortPool() error: %v", err)
	}

	// Allocate all ports
	for i := 0; i < 5; i++ {
		_, err := pool.Allocate()
		if err != nil {
			t.Fatalf("Allocate() %d error: %v", i, err)
		}
	}

	// Next allocation should fail
	_, err = pool.Allocate()
	if err != ErrPortPoolExhausted {
		t.Errorf("Allocate() error = %v, want ErrPortPoolExhausted", err)
	}

	stats := pool.GetStats()
	if stats.Exhaustions != 1 {
		t.Errorf("exhaustions = %d, want 1", stats.Exhaustions)
	}
}

func TestPortPool_Recycling(t *testing.T) {
	cfg := PortPoolConfig{
		MinPort:      40000,
		MaxPort:      40005,
		MaxInUse:     5,
		PortLifetime: 50 * time.Millisecond, // Short lifetime for testing
	}

	pool, err := NewPortPool(cfg)
	if err != nil {
		t.Fatalf("NewPortPool() error: %v", err)
	}

	// Allocate all ports
	for i := 0; i < 5; i++ {
		_, err := pool.Allocate()
		if err != nil {
			t.Fatalf("Allocate() %d error: %v", i, err)
		}
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be able to allocate again (recycled)
	port, err := pool.Allocate()
	if err != nil {
		t.Errorf("Allocate() after recycling error: %v", err)
	}

	if port < 40000 || port >= 40005 {
		t.Errorf("recycled port %d out of range", port)
	}

	stats := pool.GetStats()
	if stats.Recycled == 0 {
		t.Error("recycled count should be non-zero")
	}
}

func TestPortPool_Randomness(t *testing.T) {
	cfg := PortPoolConfig{
		MinPort:  40000,
		MaxPort:  40100,
		MaxInUse: 100,
	}

	pool, err := NewPortPool(cfg)
	if err != nil {
		t.Fatalf("NewPortPool() error: %v", err)
	}

	// Allocate ports and check distribution
	ports := make(map[uint16]bool)
	for i := 0; i < 50; i++ {
		port, err := pool.Allocate()
		if err != nil {
			t.Fatalf("Allocate() error: %v", err)
		}
		ports[port] = true
	}

	// Should get diverse ports (at least 40 unique from 50 allocations)
	if len(ports) < 40 {
		t.Errorf("poor randomness: only %d unique ports from 50 allocations", len(ports))
	}
}

func TestEntropy(t *testing.T) {
	entropy := Entropy()

	// Should be around 30-31 bits
	if entropy < 30 || entropy > 32 {
		t.Errorf("entropy = %.2f, expected ~30-31 bits", entropy)
	}
}

func TestRequiredQueriesFor50PercentCollision(t *testing.T) {
	required := RequiredQueriesFor50PercentCollision()

	// Should be in tens of thousands
	if required < 30000 || required > 50000 {
		t.Errorf("required queries = %d, expected ~37000", required)
	}
}

// Benchmark transaction ID generation
func BenchmarkTransactionID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		TransactionID()
	}
}

// Benchmark source port generation
func BenchmarkSourcePort(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SourcePort()
	}
}

// Benchmark query ID generation
func BenchmarkNewQueryID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewQueryID()
	}
}

// Benchmark port pool allocation
func BenchmarkPortPool_Allocate(b *testing.B) {
	cfg := PortPoolConfig{
		MinPort:  40000,
		MaxPort:  50000,
		MaxInUse: 10000,
	}

	pool, _ := NewPortPool(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		port, err := pool.Allocate()
		if err == nil {
			pool.Release(port)
		}
	}
}
