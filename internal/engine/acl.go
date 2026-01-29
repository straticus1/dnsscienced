package engine

import (
	"net"
	"sync"
)

// ACL represents an Access Control List for DNS queries.
// It defines which clients are allowed or denied access.
type ACL struct {
	mu           sync.RWMutex
	allowedNets  []*net.IPNet
	deniedNets   []*net.IPNet
	defaultAllow bool // If true, allow by default; if false, deny by default
}

// NewACL creates a new ACL with a default policy.
// If defaultAllow is true, all clients are allowed unless explicitly denied.
// If false, all clients are denied unless explicitly allowed.
func NewACL(defaultAllow bool) *ACL {
	return &ACL{
		defaultAllow: defaultAllow,
		allowedNets:  make([]*net.IPNet, 0),
		deniedNets:   make([]*net.IPNet, 0),
	}
}

// AllowNet adds a network to the allow list.
// The cidr should be in CIDR notation, e.g., "192.168.0.0/24" or "10.0.0.1/32".
func (a *ACL) AllowNet(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try parsing as a single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return err
		}
		// Convert to /32 or /128
		if ip.To4() != nil {
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allowedNets = append(a.allowedNets, ipnet)
	return nil
}

// DenyNet adds a network to the deny list.
func (a *ACL) DenyNet(cidr string) error {
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
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deniedNets = append(a.deniedNets, ipnet)
	return nil
}

// IsAllowed checks if the given IP is allowed by the ACL.
// The evaluation order is: deny list first, then allow list, then default policy.
func (a *ACL) IsAllowed(ip net.IP) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Check deny list first (explicit deny takes precedence)
	for _, denied := range a.deniedNets {
		if denied.Contains(ip) {
			return false
		}
	}

	// Check allow list
	for _, allowed := range a.allowedNets {
		if allowed.Contains(ip) {
			return true
		}
	}

	// Fall back to default policy
	return a.defaultAllow
}

// IsAllowedString is a convenience wrapper that parses an IP string.
func (a *ACL) IsAllowedString(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return a.IsAllowed(ip)
}

// Clear removes all entries from the ACL.
func (a *ACL) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.allowedNets = make([]*net.IPNet, 0)
	a.deniedNets = make([]*net.IPNet, 0)
}
