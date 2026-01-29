package engine

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestACL_DefaultAllow(t *testing.T) {
	acl := NewACL(true) // Default allow

	// Any IP should be allowed by default
	assert.True(t, acl.IsAllowedString("192.168.1.1"))
	assert.True(t, acl.IsAllowedString("10.0.0.1"))
	assert.True(t, acl.IsAllowedString("1.2.3.4"))

	// Deny a network
	require.NoError(t, acl.DenyNet("10.0.0.0/8"))

	// Denied network should be blocked
	assert.False(t, acl.IsAllowedString("10.0.0.1"))
	assert.False(t, acl.IsAllowedString("10.255.255.255"))

	// Other networks still allowed
	assert.True(t, acl.IsAllowedString("192.168.1.1"))
}

func TestACL_DefaultDeny(t *testing.T) {
	acl := NewACL(false) // Default deny

	// All IPs should be denied by default
	assert.False(t, acl.IsAllowedString("192.168.1.1"))
	assert.False(t, acl.IsAllowedString("10.0.0.1"))

	// Allow a network
	require.NoError(t, acl.AllowNet("192.168.0.0/16"))

	// Allowed network should pass
	assert.True(t, acl.IsAllowedString("192.168.1.1"))
	assert.True(t, acl.IsAllowedString("192.168.255.255"))

	// Other networks still denied
	assert.False(t, acl.IsAllowedString("10.0.0.1"))
}

func TestACL_DenyOverridesAllow(t *testing.T) {
	acl := NewACL(true)

	// Allow all, but deny a specific subnet
	require.NoError(t, acl.AllowNet("10.0.0.0/8"))
	require.NoError(t, acl.DenyNet("10.0.1.0/24"))

	// General network allowed
	assert.True(t, acl.IsAllowedString("10.0.0.1"))
	assert.True(t, acl.IsAllowedString("10.0.2.1"))

	// Specific subnet denied
	assert.False(t, acl.IsAllowedString("10.0.1.1"))
	assert.False(t, acl.IsAllowedString("10.0.1.254"))
}

func TestACL_SingleIP(t *testing.T) {
	acl := NewACL(false)

	// Allow a single IP
	require.NoError(t, acl.AllowNet("192.168.1.100"))

	assert.True(t, acl.IsAllowedString("192.168.1.100"))
	assert.False(t, acl.IsAllowedString("192.168.1.101"))
}

func TestACL_IPv6(t *testing.T) {
	acl := NewACL(false)

	require.NoError(t, acl.AllowNet("2001:db8::/32"))

	assert.True(t, acl.IsAllowed(net.ParseIP("2001:db8::1")))
	assert.True(t, acl.IsAllowed(net.ParseIP("2001:db8:ffff::1")))
	assert.False(t, acl.IsAllowed(net.ParseIP("2001:db9::1")))
}

func TestRateLimiter_Basic(t *testing.T) {
	cfg := RateLimiterConfig{
		QueriesPerSecond: 10,
		BurstSize:        10,
		CleanupInterval:  1 * time.Minute,
	}
	rl := NewRateLimiter(cfg)

	ip := net.ParseIP("192.168.1.1")

	// First 10 queries should be allowed (burst)
	for i := 0; i < 10; i++ {
		assert.True(t, rl.Allow(ip), "Query %d should be allowed", i)
	}

	// 11th query should be rate limited
	assert.False(t, rl.Allow(ip), "Query 11 should be rate limited")
}

func TestRateLimiter_DifferentClients(t *testing.T) {
	cfg := RateLimiterConfig{
		QueriesPerSecond: 5,
		BurstSize:        5,
		CleanupInterval:  1 * time.Minute,
	}
	rl := NewRateLimiter(cfg)

	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	// Exhaust ip1's burst
	for i := 0; i < 5; i++ {
		rl.Allow(ip1)
	}
	assert.False(t, rl.Allow(ip1))

	// ip2 should still have full burst available
	for i := 0; i < 5; i++ {
		assert.True(t, rl.Allow(ip2), "ip2 query %d should be allowed", i)
	}
}

func TestRateLimiter_Exempt(t *testing.T) {
	cfg := RateLimiterConfig{
		QueriesPerSecond: 1,
		BurstSize:        1,
		CleanupInterval:  1 * time.Minute,
	}
	rl := NewRateLimiter(cfg)

	// Add localhost to exempt list
	require.NoError(t, rl.AddExempt("127.0.0.0/8"))

	ip := net.ParseIP("127.0.0.1")

	// Exempt IPs should never be rate limited
	for i := 0; i < 100; i++ {
		assert.True(t, rl.Allow(ip), "Exempt IP should always be allowed")
	}
}
