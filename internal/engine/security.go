package engine

import (
	"crypto/rand"
	"math/big"
	"strings"

	"github.com/miekg/dns"
)

// Apply0x20Encoding randomizes the case of letters in a DNS name.
// This is used to detect cache poisoning attacks per the 0x20 bit encoding technique.
// See: https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00
func Apply0x20Encoding(name string) string {
	var result strings.Builder
	result.Grow(len(name))

	for _, c := range name {
		if c >= 'a' && c <= 'z' {
			// Randomly decide to uppercase
			if randomBool() {
				result.WriteRune(c - 32) // Convert to uppercase
			} else {
				result.WriteRune(c)
			}
		} else if c >= 'A' && c <= 'Z' {
			// Randomly decide to lowercase
			if randomBool() {
				result.WriteRune(c + 32) // Convert to lowercase
			} else {
				result.WriteRune(c)
			}
		} else {
			result.WriteRune(c)
		}
	}
	return result.String()
}

// Validate0x20Response checks if the response preserves the case of the query name.
// Returns true if the case is preserved (valid response), false otherwise (potential spoofing).
func Validate0x20Response(queryName string, responseName string) bool {
	return queryName == responseName
}

// randomBool returns a cryptographically random boolean.
func randomBool() bool {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return false // Fallback to false on error
	}
	return n.Int64() == 1
}

// ScrubResponse removes out-of-bailiwick records from a DNS response.
// This hardens against cache poisoning via glue records.
// The zone parameter is the expected zone of the response (e.g., "example.com.").
func ScrubResponse(msg *dns.Msg, zone string) {
	if msg == nil || zone == "" {
		return
	}

	zone = dns.Fqdn(strings.ToLower(zone))

	// Filter Authority section
	msg.Ns = filterInBailiwick(msg.Ns, zone)

	// Filter Additional section (glue records)
	msg.Extra = filterInBailiwick(msg.Extra, zone)
}

// filterInBailiwick filters RRs to only include those in the specified zone's bailiwick.
func filterInBailiwick(rrs []dns.RR, zone string) []dns.RR {
	var filtered []dns.RR
	for _, rr := range rrs {
		name := strings.ToLower(rr.Header().Name)
		// A record is in-bailiwick if it's a subdomain of (or equal to) the zone
		if dns.IsSubDomain(zone, name) {
			filtered = append(filtered, rr)
		}
		// Always keep OPT records (EDNS0)
		if rr.Header().Rrtype == dns.TypeOPT {
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

// IsInBailiwick checks if a name is within the bailiwick of a zone.
func IsInBailiwick(name, zone string) bool {
	name = strings.ToLower(dns.Fqdn(name))
	zone = strings.ToLower(dns.Fqdn(zone))
	return dns.IsSubDomain(zone, name)
}

// ApplyQNAMEMinimization returns a minimized query name for a given target zone.
// For example, querying "www.example.com." when at the ".com." zone level
// should only ask for "example.com." (not the full name).
// This implements RFC 7816 Query Name Minimisation.
func ApplyQNAMEMinimization(fullName string, currentZone string) string {
	fullName = dns.Fqdn(strings.ToLower(fullName))
	currentZone = dns.Fqdn(strings.ToLower(currentZone))

	// If fullName is already at or shorter than the currentZone, return as-is
	if !dns.IsSubDomain(currentZone, fullName) || fullName == currentZone {
		return fullName
	}

	// Count labels
	fullLabels := dns.SplitDomainName(fullName)
	zoneLabels := dns.SplitDomainName(currentZone)

	// We want to reveal only one more label than the current zone
	if len(fullLabels) <= len(zoneLabels) {
		return fullName
	}

	// Calculate how many labels to take from full name
	// We want len(zoneLabels) + 1 labels
	targetLabelCount := len(zoneLabels) + 1
	if targetLabelCount > len(fullLabels) {
		return fullName
	}

	// Take the last targetLabelCount labels
	minimizedLabels := fullLabels[len(fullLabels)-targetLabelCount:]
	return dns.Fqdn(strings.Join(minimizedLabels, "."))
}

// HardenGlue validates glue records to ensure they only contain addresses
// for nameservers that are within the delegated zone.
// Returns only the valid glue records.
func HardenGlue(glueRecords []dns.RR, delegatedZone string, nsNames []string) []dns.RR {
	delegatedZone = dns.Fqdn(strings.ToLower(delegatedZone))

	// Build a set of expected NS names (lowercased)
	nsSet := make(map[string]bool)
	for _, ns := range nsNames {
		nsSet[strings.ToLower(dns.Fqdn(ns))] = true
	}

	var hardened []dns.RR
	for _, rr := range glueRecords {
		name := strings.ToLower(rr.Header().Name)

		// Glue is only valid if:
		// 1. The name is in the nsSet (it's a nameserver for the delegation)
		// 2. The name is within the delegated zone (in-bailiwick)
		if nsSet[name] && dns.IsSubDomain(delegatedZone, name) {
			hardened = append(hardened, rr)
		}
	}
	return hardened
}
