# DNSScienced Licensing Module

## Overview

This document specifies the licensing system for DNSScienced, integrating with the After Dark Systems licensing platform at `licensing.afterdarksys.com`. The licensing module enables feature gating, seat management, and tiered product offerings.

---

## Licensing Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LICENSING ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       DNSScienced Server                             │   │
│  │                                                                      │   │
│  │   ┌─────────────────────────────────────────────────────────────┐   │   │
│  │   │                    Licensing Module                          │   │   │
│  │   │                                                              │   │   │
│  │   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │   │   │
│  │   │  │   License    │  │   Feature    │  │    Seat      │      │   │   │
│  │   │  │   Manager    │  │   Gate       │  │   Manager    │      │   │   │
│  │   │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │   │   │
│  │   │         │                 │                 │               │   │   │
│  │   │         └─────────────────┼─────────────────┘               │   │   │
│  │   │                           │                                 │   │   │
│  │   │  ┌────────────────────────▼────────────────────────────┐   │   │   │
│  │   │  │              License Validator                       │   │   │   │
│  │   │  │                                                      │   │   │   │
│  │   │  │  • Signature verification                            │   │   │   │
│  │   │  │  • Expiration check                                  │   │   │   │
│  │   │  │  • Feature entitlement                               │   │   │   │
│  │   │  │  • Hardware binding                                  │   │   │   │
│  │   │  └────────────────────────┬────────────────────────────┘   │   │   │
│  │   │                           │                                 │   │   │
│  │   └───────────────────────────┼─────────────────────────────────┘   │   │
│  │                               │                                     │   │
│  └───────────────────────────────┼─────────────────────────────────────┘   │
│                                  │                                          │
│                    ┌─────────────▼─────────────┐                           │
│                    │   Local License Cache     │                           │
│                    │   (/var/lib/dnsscienced/  │                           │
│                    │    license.json)          │                           │
│                    └─────────────┬─────────────┘                           │
│                                  │                                          │
│                         ┌────────▼────────┐                                │
│                         │                 │                                │
│                         ▼                 ▼                                │
│          ┌──────────────────┐   ┌──────────────────┐                      │
│          │  Offline Mode    │   │  Online Mode     │                      │
│          │  (Cached License)│   │  (API Refresh)   │                      │
│          └──────────────────┘   └────────┬─────────┘                      │
│                                          │                                 │
└──────────────────────────────────────────┼─────────────────────────────────┘
                                           │
                                           │ HTTPS
                                           │
┌──────────────────────────────────────────▼─────────────────────────────────┐
│                                                                            │
│                    licensing.afterdarksys.com                              │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                     After Dark Systems                               │  │
│  │                     Licensing Server                                 │  │
│  │                                                                      │  │
│  │  • License generation                                                │  │
│  │  • License validation                                                │  │
│  │  • Seat management                                                   │  │
│  │  • Usage analytics                                                   │  │
│  │  • Billing integration                                               │  │
│  │                                                                      │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## License Format (ADS License v1.0)

### Cryptographic License Model

The licensing system uses an RSA-based approach inspired by enterprise licensing systems like Symantec:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CRYPTOGRAPHIC LICENSE FLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PROVISIONING (Server-Side)                                                 │
│  ══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│  1. Customer purchases license                                              │
│     └── Order ID: ord_12345                                                 │
│                                                                             │
│  2. Server generates unique RSA keypair for customer                        │
│     ┌─────────────────────────────────────────────────────────┐            │
│     │  MYPASS="$(openssl rand -base64 32)"                    │            │
│     │  openssl genrsa -out customer.pem -aes256 \             │            │
│     │          -passout pass:$MYPASS 4096                     │            │
│     │  openssl rsa -in customer.pem -pubout -out customer.pub │            │
│     └─────────────────────────────────────────────────────────┘            │
│                                                                             │
│  3. Server stores:                                                          │
│     • customer.pem (encrypted private key)                                  │
│     • MYPASS (encryption passphrase)                                        │
│     • customer.pub (public key)                                             │
│     • License metadata                                                      │
│                                                                             │
│  4. Server creates one-time pickup URL                                      │
│     └── https://licensing.afterdarksys.com/pickup/tkn_abc123xyz            │
│         (Valid for 72 hours, single use)                                    │
│                                                                             │
│  PICKUP & ACTIVATION (Client-Side)                                          │
│  ══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│  5. Customer downloads license via pickup URL                               │
│     └── Receives: license.json (contains public key + metadata)             │
│                                                                             │
│  6. Client validates license signature                                      │
│     • License JSON is signed with server's master key                       │
│     • Embedded customer public key is authenticated                         │
│                                                                             │
│  RUNTIME VALIDATION                                                         │
│  ══════════════════════════════════════════════════════════════════════════ │
│                                                                             │
│  7. Periodic license check (online):                                        │
│     ┌─────────────────────────────────────────────────────────┐            │
│     │  Client → Server: "Validate license {license_id}"       │            │
│     │  Server: Signs challenge with customer's private key    │            │
│     │  Server → Client: Signed challenge                      │            │
│     │  Client: Verifies with embedded public key              │            │
│     │  Result: License is authentic and active                │            │
│     └─────────────────────────────────────────────────────────┘            │
│                                                                             │
│  WHY THIS IS NEARLY UNCRACKABLE:                                            │
│  • Private key never leaves the server                                      │
│  • Public key is useless without server signing challenges                  │
│  • One-time pickup URLs prevent URL sharing                                 │
│  • Challenge-response prevents replay attacks                               │
│  • Hardware binding adds another layer                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Server-Side Key Generation

```bash
#!/bin/bash
# /opt/licensing/scripts/generate_customer_key.sh

CUSTOMER_ID="$1"
KEY_DIR="/var/lib/licensing/keys"

# Generate strong random passphrase
PASSPHRASE=$(openssl rand -base64 32)

# Generate 4096-bit RSA keypair with AES-256 encryption
openssl genrsa -out "${KEY_DIR}/${CUSTOMER_ID}.pem" \
    -aes256 -passout "pass:${PASSPHRASE}" 4096

# Extract public key
openssl rsa -in "${KEY_DIR}/${CUSTOMER_ID}.pem" \
    -passin "pass:${PASSPHRASE}" \
    -pubout -out "${KEY_DIR}/${CUSTOMER_ID}.pub"

# Store passphrase securely (encrypted in database or HSM)
vault kv put secret/licensing/keys/${CUSTOMER_ID} \
    passphrase="${PASSPHRASE}"

echo "Keys generated for customer: ${CUSTOMER_ID}"
```

### JSON Structure

```json
{
  "ads_license_version": "1.0",
  "ads_license_id": "lic_dnsscienced_12345678",
  "ads_license_tier": "enterprise",
  "ads_license_seats": 100,
  "ads_license_arch": ["x86_64", "arm64"],
  "ads_license_software": "dnsscienced",
  "ads_license_software_version": ">=1.0.0,<3.0.0",

  "ads_license_features": [
    "core_authoritative",
    "core_recursive",
    "dnssec_signing",
    "dnssec_validation",
    "dot",
    "doh",
    "doq",
    "zone_transfer",
    "rate_limiting",
    "rpz",
    "web3_ens",
    "web3_sns",
    "web3_unstoppable",
    "web3_freename",
    "web3_itz",
    "dip_sampling",
    "dip_ai_engine",
    "dip_threat_feeds",
    "dip_intelligent_routing",
    "dip_service_provider",
    "dip_cdn_edition",
    "dip_finserv_edition",
    "multi_tenant",
    "cluster_mode",
    "geo_routing",
    "api_access",
    "webhook_events",
    "custom_plugins"
  ],

  "ads_license_enabled": [
    "core_authoritative",
    "core_recursive",
    "dnssec_signing",
    "dnssec_validation",
    "dot",
    "doh",
    "doq",
    "zone_transfer",
    "rate_limiting",
    "rpz",
    "api_access"
  ],

  "ads_license_limits": {
    "max_zones": 1000,
    "max_qps": 1000000,
    "max_cache_size_gb": 64,
    "max_workers": 32
  },

  "ads_license_issued_at": "2024-01-01T00:00:00Z",
  "ads_license_expires_at": "2025-01-01T00:00:00Z",
  "ads_license_limit_threshold": 24,

  "ads_license_customer": {
    "id": "cust_12345",
    "name": "Example Corporation",
    "email": "admin@example.com"
  },

  "ads_license_binding": {
    "type": "hardware",
    "machine_id": "a1b2c3d4e5f6",
    "hostname": "dns*.example.com"
  },

  "ads_license_signature": "BASE64_ENCODED_SIGNATURE"
}
```

### License Tiers

```yaml
tiers:
  free:
    name: "Free / Community"
    seats: 1
    features:
      - core_authoritative
      - core_recursive
      - dnssec_validation
    limits:
      max_zones: 10
      max_qps: 10000
      max_cache_size_gb: 1
    support: "Community forums"
    price: "$0"

  student:
    name: "Student"
    seats: 1
    features:
      - core_authoritative
      - core_recursive
      - dnssec_signing
      - dnssec_validation
      - dot
      - doh
    limits:
      max_zones: 25
      max_qps: 25000
      max_cache_size_gb: 2
    support: "Email (48h response)"
    price: "$0 (verified students)"
    requirements:
      - "Valid .edu email"
      - "Student ID verification"

  education:
    name: "Education"
    seats: 50
    features:
      - core_authoritative
      - core_recursive
      - dnssec_signing
      - dnssec_validation
      - dot
      - doh
      - zone_transfer
      - api_access
    limits:
      max_zones: 100
      max_qps: 100000
      max_cache_size_gb: 8
    support: "Email (24h response)"
    price: "$99/year"
    requirements:
      - "Educational institution"
      - "Non-commercial use"

  professional:
    name: "Professional"
    seats: 10
    features:
      - core_authoritative
      - core_recursive
      - dnssec_signing
      - dnssec_validation
      - dot
      - doh
      - doq
      - zone_transfer
      - rate_limiting
      - rpz
      - api_access
      - webhook_events
    limits:
      max_zones: 500
      max_qps: 500000
      max_cache_size_gb: 32
    support: "Email (8h response), Phone"
    price: "$499/month"

  enterprise:
    name: "Enterprise"
    seats: 100
    features:
      - ALL_CORE_FEATURES
      - web3_ens
      - web3_sns
      - web3_unstoppable
      - dip_sampling
      - dip_threat_feeds
      - multi_tenant
      - cluster_mode
      - geo_routing
      - custom_plugins
    limits:
      max_zones: 5000
      max_qps: 2000000
      max_cache_size_gb: 128
    support: "24/7 Phone, Dedicated TAM"
    price: "$2,999/month"

  government:
    name: "Government / Defense"
    seats: 500
    features:
      - ALL_FEATURES
      - fips_compliance
      - audit_logging
      - air_gap_support
    limits:
      max_zones: 10000
      max_qps: 5000000
      max_cache_size_gb: 256
    support: "24/7, On-site available"
    price: "Contact sales"
    requirements:
      - "Government entity verification"
      - "Security clearance process"

  custom:
    name: "Custom / OEM"
    seats: "Negotiable"
    features: "Negotiable"
    limits: "Negotiable"
    support: "Custom SLA"
    price: "Contact sales"
```

---

## Feature Catalog

### Core Features

```yaml
features:
  # --- Core DNS ---
  core_authoritative:
    id: "core_authoritative"
    name: "Authoritative DNS"
    description: "Serve authoritative DNS zones"
    tier_minimum: "free"
    component: "dnsscience-authd"

  core_recursive:
    id: "core_recursive"
    name: "Recursive Resolution"
    description: "Full iterative DNS resolution"
    tier_minimum: "free"
    component: "dnsscience-cached"

  # --- DNSSEC ---
  dnssec_validation:
    id: "dnssec_validation"
    name: "DNSSEC Validation"
    description: "Validate DNSSEC signatures on responses"
    tier_minimum: "free"
    component: "dnsscience-cached"

  dnssec_signing:
    id: "dnssec_signing"
    name: "DNSSEC Signing"
    description: "Sign zones with DNSSEC"
    tier_minimum: "student"
    component: "dnsscience-authd"
    tools:
      - "dnsscience-keygen"
      - "dnsscience-signzone"

  # --- Encrypted Transports ---
  dot:
    id: "dot"
    name: "DNS over TLS (DoT)"
    description: "Encrypted DNS over TLS (RFC 7858)"
    tier_minimum: "student"

  doh:
    id: "doh"
    name: "DNS over HTTPS (DoH)"
    description: "Encrypted DNS over HTTPS (RFC 8484)"
    tier_minimum: "student"

  doq:
    id: "doq"
    name: "DNS over QUIC (DoQ)"
    description: "Encrypted DNS over QUIC (RFC 9250)"
    tier_minimum: "professional"

  # --- Zone Management ---
  zone_transfer:
    id: "zone_transfer"
    name: "Zone Transfers"
    description: "AXFR/IXFR zone transfers with TSIG"
    tier_minimum: "education"

  dynamic_updates:
    id: "dynamic_updates"
    name: "Dynamic DNS Updates"
    description: "RFC 2136 dynamic updates"
    tier_minimum: "professional"

  # --- Security ---
  rate_limiting:
    id: "rate_limiting"
    name: "Response Rate Limiting"
    description: "RRL for DDoS mitigation"
    tier_minimum: "professional"

  rpz:
    id: "rpz"
    name: "Response Policy Zones"
    description: "DNS firewall with RPZ"
    tier_minimum: "professional"

  dns_cookies:
    id: "dns_cookies"
    name: "DNS Cookies"
    description: "RFC 7873 DNS Cookies"
    tier_minimum: "professional"

  # --- Web3 Integration ---
  web3_ens:
    id: "web3_ens"
    name: "ENS Resolution"
    description: "Ethereum Name Service (.eth)"
    tier_minimum: "enterprise"

  web3_sns:
    id: "web3_sns"
    name: "SNS Resolution"
    description: "Solana Name Service (.sol)"
    tier_minimum: "enterprise"

  web3_unstoppable:
    id: "web3_unstoppable"
    name: "Unstoppable Domains"
    description: "Resolve Unstoppable Domain TLDs"
    tier_minimum: "enterprise"

  web3_freename:
    id: "web3_freename"
    name: "Freename Domains"
    description: "Freename Web3 DNS integration"
    tier_minimum: "enterprise"

  web3_itz:
    id: "web3_itz"
    name: "ITZ.agency Integration"
    description: "Multi-chain wallet DNS resolution"
    tier_minimum: "enterprise"

  # --- DNS Intelligence Platform ---
  dip_sampling:
    id: "dip_sampling"
    name: "Traffic Sampling"
    description: "DNS traffic sampling and analysis"
    tier_minimum: "enterprise"

  dip_ai_engine:
    id: "dip_ai_engine"
    name: "AI/ML Engine"
    description: "DGA detection, anomaly detection"
    tier_minimum: "enterprise"

  dip_threat_feeds:
    id: "dip_threat_feeds"
    name: "Threat Intelligence"
    description: "DNSScience.io threat feed integration"
    tier_minimum: "enterprise"

  dip_intelligent_routing:
    id: "dip_intelligent_routing"
    name: "Intelligent Routing"
    description: "Geo, latency, health-based routing"
    tier_minimum: "enterprise"

  dip_service_provider:
    id: "dip_service_provider"
    name: "Service Provider Edition"
    description: "Multi-tenant ISP features"
    tier_minimum: "enterprise"
    addon_price: "$1,000/month"

  dip_cdn_edition:
    id: "dip_cdn_edition"
    name: "CDN Edition"
    description: "Edge routing, cache control"
    tier_minimum: "enterprise"
    addon_price: "$1,000/month"

  dip_finserv_edition:
    id: "dip_finserv_edition"
    name: "Financial Services Edition"
    description: "Ultra-low latency, compliance"
    tier_minimum: "enterprise"
    addon_price: "$2,500/month"

  # --- Infrastructure ---
  multi_tenant:
    id: "multi_tenant"
    name: "Multi-Tenancy"
    description: "Tenant isolation, per-tenant policies"
    tier_minimum: "enterprise"

  cluster_mode:
    id: "cluster_mode"
    name: "Cluster Mode"
    description: "Distributed cluster deployment"
    tier_minimum: "enterprise"

  geo_routing:
    id: "geo_routing"
    name: "Geographic Routing"
    description: "Geo-based query routing"
    tier_minimum: "enterprise"

  # --- Management ---
  api_access:
    id: "api_access"
    name: "REST API"
    description: "Full management REST API"
    tier_minimum: "professional"

  webhook_events:
    id: "webhook_events"
    name: "Webhook Events"
    description: "Event notifications via webhooks"
    tier_minimum: "professional"

  custom_plugins:
    id: "custom_plugins"
    name: "Custom Plugins"
    description: "Load custom Go plugins"
    tier_minimum: "enterprise"

  # --- Compliance ---
  fips_compliance:
    id: "fips_compliance"
    name: "FIPS 140-2 Compliance"
    description: "FIPS-validated cryptography"
    tier_minimum: "government"

  audit_logging:
    id: "audit_logging"
    name: "Audit Logging"
    description: "Comprehensive audit trail"
    tier_minimum: "government"

  air_gap_support:
    id: "air_gap_support"
    name: "Air-Gap Deployment"
    description: "Offline/air-gapped operation"
    tier_minimum: "government"
```

---

## License Manager Implementation

### Configuration

```yaml
# /etc/dnsscienced/dnsscienced.conf
licensing:
  # License file location
  license_file: /var/lib/dnsscienced/license.json

  # Licensing server
  server:
    url: "https://licensing.afterdarksys.com/api/v1"
    timeout: 30s
    retry:
      max_attempts: 3
      backoff: exponential

  # Refresh settings
  refresh:
    enabled: true
    interval: 24h
    on_startup: true
    on_feature_check: false  # Don't call API on every feature check

  # Offline mode
  offline:
    enabled: true
    grace_period: 7d  # Allow operation after license expires
    cache_license: true

  # Hardware binding
  binding:
    type: "machine_id"  # machine_id, hostname, mac_address, none
    allow_virtualization: true

  # Telemetry (opt-in)
  telemetry:
    enabled: false
    metrics:
      - queries_total
      - zones_count
      - features_used
```

### Go Implementation

```go
package licensing

import (
    "context"
    "crypto"
    "crypto/rsa"
    "encoding/json"
    "errors"
    "sync"
    "time"
)

// License represents an ADS license
type License struct {
    Version        string    `json:"ads_license_version"`
    ID             string    `json:"ads_license_id"`
    Tier           Tier      `json:"ads_license_tier"`
    Seats          int       `json:"ads_license_seats"`
    Architectures  []string  `json:"ads_license_arch"`
    Software       string    `json:"ads_license_software"`
    SoftwareVersion string   `json:"ads_license_software_version"`

    Features       []string  `json:"ads_license_features"`
    EnabledFeatures []string `json:"ads_license_enabled"`

    Limits         Limits    `json:"ads_license_limits"`

    IssuedAt       time.Time `json:"ads_license_issued_at"`
    ExpiresAt      time.Time `json:"ads_license_expires_at"`
    LimitThreshold int       `json:"ads_license_limit_threshold"`

    Customer       Customer  `json:"ads_license_customer"`
    Binding        Binding   `json:"ads_license_binding"`
    Signature      string    `json:"ads_license_signature"`
}

// Tier represents license tier
type Tier string

const (
    TierFree         Tier = "free"
    TierStudent      Tier = "student"
    TierEducation    Tier = "education"
    TierProfessional Tier = "professional"
    TierEnterprise   Tier = "enterprise"
    TierGovernment   Tier = "government"
    TierCustom       Tier = "custom"
)

// Limits represents license limits
type Limits struct {
    MaxZones       int   `json:"max_zones"`
    MaxQPS         int64 `json:"max_qps"`
    MaxCacheSizeGB int   `json:"max_cache_size_gb"`
    MaxWorkers     int   `json:"max_workers"`
}

// Customer represents license holder
type Customer struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

// Binding represents hardware binding
type Binding struct {
    Type      string `json:"type"`
    MachineID string `json:"machine_id,omitempty"`
    Hostname  string `json:"hostname,omitempty"`
}

// Manager handles license operations
type Manager struct {
    config     *Config
    license    *License
    publicKey  *rsa.PublicKey
    client     *LicenseClient
    mu         sync.RWMutex

    // Feature cache
    enabledFeatures map[string]bool

    // Metrics
    featureChecks   map[string]int64
    lastRefresh     time.Time
}

// NewManager creates a new license manager
func NewManager(config *Config) (*Manager, error) {
    m := &Manager{
        config:          config,
        enabledFeatures: make(map[string]bool),
        featureChecks:   make(map[string]int64),
    }

    // Load public key for signature verification
    if err := m.loadPublicKey(); err != nil {
        return nil, err
    }

    // Create API client
    m.client = NewLicenseClient(config.Server.URL)

    // Load license
    if err := m.loadLicense(); err != nil {
        return nil, err
    }

    // Start refresh goroutine
    if config.Refresh.Enabled {
        go m.refreshLoop()
    }

    return m, nil
}

// IsFeatureEnabled checks if a feature is enabled
func (m *Manager) IsFeatureEnabled(featureID string) bool {
    m.mu.RLock()
    defer m.mu.RUnlock()

    // Track feature check
    m.featureChecks[featureID]++

    // Check cache
    if enabled, ok := m.enabledFeatures[featureID]; ok {
        return enabled
    }

    return false
}

// RequireFeature panics if feature is not enabled (for init)
func (m *Manager) RequireFeature(featureID string) error {
    if !m.IsFeatureEnabled(featureID) {
        return &FeatureNotLicensedError{Feature: featureID}
    }
    return nil
}

// CheckLimit verifies a limit is not exceeded
func (m *Manager) CheckLimit(limitType string, value int64) error {
    m.mu.RLock()
    defer m.mu.RUnlock()

    if m.license == nil {
        return ErrNoLicense
    }

    switch limitType {
    case "zones":
        if value > int64(m.license.Limits.MaxZones) {
            return &LimitExceededError{
                Limit:   "max_zones",
                Current: value,
                Max:     int64(m.license.Limits.MaxZones),
            }
        }
    case "qps":
        if value > m.license.Limits.MaxQPS {
            return &LimitExceededError{
                Limit:   "max_qps",
                Current: value,
                Max:     m.license.Limits.MaxQPS,
            }
        }
    case "cache_size_gb":
        if value > int64(m.license.Limits.MaxCacheSizeGB) {
            return &LimitExceededError{
                Limit:   "max_cache_size_gb",
                Current: value,
                Max:     int64(m.license.Limits.MaxCacheSizeGB),
            }
        }
    case "workers":
        if value > int64(m.license.Limits.MaxWorkers) {
            return &LimitExceededError{
                Limit:   "max_workers",
                Current: value,
                Max:     int64(m.license.Limits.MaxWorkers),
            }
        }
    }

    return nil
}

// GetLicense returns current license info (safe copy)
func (m *Manager) GetLicense() *License {
    m.mu.RLock()
    defer m.mu.RUnlock()

    if m.license == nil {
        return nil
    }

    // Return copy
    copy := *m.license
    return &copy
}

// Validate validates the current license
func (m *Manager) Validate() error {
    m.mu.RLock()
    defer m.mu.RUnlock()

    if m.license == nil {
        return ErrNoLicense
    }

    // Check expiration
    if time.Now().After(m.license.ExpiresAt) {
        // Check grace period
        gracePeriod := m.config.Offline.GracePeriod
        if time.Now().After(m.license.ExpiresAt.Add(gracePeriod)) {
            return ErrLicenseExpired
        }
        // In grace period - log warning
    }

    // Verify signature
    if err := m.verifySignature(); err != nil {
        return err
    }

    // Check hardware binding
    if err := m.checkBinding(); err != nil {
        return err
    }

    // Check software version
    if err := m.checkSoftwareVersion(); err != nil {
        return err
    }

    return nil
}

// loadLicense loads license from file
func (m *Manager) loadLicense() error {
    data, err := os.ReadFile(m.config.LicenseFile)
    if err != nil {
        if os.IsNotExist(err) {
            // No license file - use free tier
            m.setFreeTier()
            return nil
        }
        return err
    }

    var license License
    if err := json.Unmarshal(data, &license); err != nil {
        return err
    }

    m.mu.Lock()
    m.license = &license
    m.rebuildFeatureCache()
    m.mu.Unlock()

    return m.Validate()
}

// rebuildFeatureCache rebuilds enabled features cache
func (m *Manager) rebuildFeatureCache() {
    m.enabledFeatures = make(map[string]bool)
    for _, feature := range m.license.EnabledFeatures {
        m.enabledFeatures[feature] = true
    }
}

// setFreeTier sets free tier defaults
func (m *Manager) setFreeTier() {
    m.license = &License{
        Version:         "1.0",
        Tier:            TierFree,
        Seats:           1,
        Software:        "dnsscienced",
        EnabledFeatures: []string{
            "core_authoritative",
            "core_recursive",
            "dnssec_validation",
        },
        Limits: Limits{
            MaxZones:       10,
            MaxQPS:         10000,
            MaxCacheSizeGB: 1,
            MaxWorkers:     2,
        },
        ExpiresAt: time.Now().AddDate(100, 0, 0), // Never expires
    }
    m.rebuildFeatureCache()
}

// verifySignature verifies license signature
func (m *Manager) verifySignature() error {
    // Create hash of license data (excluding signature)
    licenseCopy := *m.license
    licenseCopy.Signature = ""

    data, _ := json.Marshal(licenseCopy)
    hash := crypto.SHA256.New()
    hash.Write(data)
    hashed := hash.Sum(nil)

    // Decode signature
    signature, err := base64.StdEncoding.DecodeString(m.license.Signature)
    if err != nil {
        return ErrInvalidSignature
    }

    // Verify
    if err := rsa.VerifyPKCS1v15(m.publicKey, crypto.SHA256, hashed, signature); err != nil {
        return ErrInvalidSignature
    }

    return nil
}

// checkBinding verifies hardware binding
func (m *Manager) checkBinding() error {
    if m.license.Binding.Type == "" || m.license.Binding.Type == "none" {
        return nil
    }

    switch m.license.Binding.Type {
    case "machine_id":
        machineID, err := getMachineID()
        if err != nil {
            return err
        }
        if !matchWildcard(machineID, m.license.Binding.MachineID) {
            return ErrHardwareMismatch
        }

    case "hostname":
        hostname, _ := os.Hostname()
        if !matchWildcard(hostname, m.license.Binding.Hostname) {
            return ErrHardwareMismatch
        }
    }

    return nil
}

// refreshLoop periodically refreshes license
func (m *Manager) refreshLoop() {
    ticker := time.NewTicker(m.config.Refresh.Interval)
    defer ticker.Stop()

    for range ticker.C {
        if err := m.refresh(); err != nil {
            // Log error but continue with cached license
        }
    }
}

// refresh refreshes license from server
func (m *Manager) refresh() error {
    ctx, cancel := context.WithTimeout(context.Background(), m.config.Server.Timeout)
    defer cancel()

    newLicense, err := m.client.GetLicense(ctx, m.license.ID)
    if err != nil {
        return err
    }

    m.mu.Lock()
    m.license = newLicense
    m.rebuildFeatureCache()
    m.lastRefresh = time.Now()
    m.mu.Unlock()

    // Save to cache
    return m.saveLicense()
}

// Errors
var (
    ErrNoLicense        = errors.New("no license installed")
    ErrLicenseExpired   = errors.New("license has expired")
    ErrInvalidSignature = errors.New("invalid license signature")
    ErrHardwareMismatch = errors.New("hardware binding mismatch")
)

type FeatureNotLicensedError struct {
    Feature string
}

func (e *FeatureNotLicensedError) Error() string {
    return fmt.Sprintf("feature not licensed: %s", e.Feature)
}

type LimitExceededError struct {
    Limit   string
    Current int64
    Max     int64
}

func (e *LimitExceededError) Error() string {
    return fmt.Sprintf("license limit exceeded: %s (current: %d, max: %d)",
        e.Limit, e.Current, e.Max)
}
```

### Feature Gate Integration

```go
// Feature gate decorator for handler functions
func (m *Manager) FeatureGate(featureID string, handler Handler) Handler {
    return func(ctx context.Context, w ResponseWriter, r *dns.Message) {
        if !m.IsFeatureEnabled(featureID) {
            // Log and return REFUSED
            w.WriteError(dns.RcodeRefused)
            return
        }
        handler(ctx, w, r)
    }
}

// Usage example in server setup
func setupHandlers(licMgr *licensing.Manager) {
    // DoT handler - requires "dot" feature
    server.RegisterHandler("tls", licMgr.FeatureGate("dot", tlsHandler))

    // DoH handler - requires "doh" feature
    server.RegisterHandler("https", licMgr.FeatureGate("doh", httpsHandler))

    // Web3 ENS - requires "web3_ens" feature
    server.RegisterPlugin("ens", func() Plugin {
        if err := licMgr.RequireFeature("web3_ens"); err != nil {
            return nil
        }
        return NewENSPlugin()
    })
}
```

---

## After Dark Systems Central Auth Integration

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 AFTER DARK SYSTEMS CENTRAL AUTH                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                          auth.afterdarksys.com                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     Central Identity Provider                        │   │
│  │                                                                      │   │
│  │  • OAuth 2.0 / OpenID Connect                                        │   │
│  │  • SAML 2.0 (Enterprise SSO)                                         │   │
│  │  • Multi-Factor Authentication                                       │   │
│  │  • User/Org Management                                               │   │
│  │  • Role-Based Access Control                                         │   │
│  │  • Audit Logging                                                     │   │
│  │                                                                      │   │
│  └───────────────────────────────┬─────────────────────────────────────┘   │
│                                  │                                          │
│                    ┌─────────────┼─────────────┐                           │
│                    │             │             │                           │
│                    ▼             ▼             ▼                           │
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐         │
│  │   Licensing      │  │   Support        │  │   Other ADS      │         │
│  │   Portal         │  │   Portal         │  │   Services       │         │
│  │                  │  │                  │  │                  │         │
│  │ licensing.       │  │ support.         │  │ *.afterdarksys   │         │
│  │ afterdarksys.com │  │ afterdarksys.com │  │ .com             │         │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Central Auth Configuration

```yaml
# Central Auth Server Configuration
# /etc/ads-central-auth/config.yaml

server:
  domain: "auth.afterdarksys.com"
  listen: ":443"
  tls:
    certificate: /etc/ssl/certs/auth.afterdarksys.com.crt
    key: /etc/ssl/private/auth.afterdarksys.com.key

# Identity Providers
identity:
  # Local accounts
  local:
    enabled: true
    password_policy:
      min_length: 12
      require_uppercase: true
      require_lowercase: true
      require_number: true
      require_special: true
      max_age_days: 90

  # OAuth 2.0 providers
  oauth:
    google:
      enabled: true
      client_id: "${GOOGLE_CLIENT_ID}"
      client_secret: "${GOOGLE_CLIENT_SECRET}"
      allowed_domains:
        - "*"  # Or restrict to specific domains

    github:
      enabled: true
      client_id: "${GITHUB_CLIENT_ID}"
      client_secret: "${GITHUB_CLIENT_SECRET}"

    microsoft:
      enabled: true
      client_id: "${MS_CLIENT_ID}"
      client_secret: "${MS_CLIENT_SECRET}"
      tenant: "common"

  # Enterprise SAML
  saml:
    enabled: true
    providers:
      - name: "okta"
        entity_id: "https://auth.afterdarksys.com/saml"
        sso_url: "https://company.okta.com/app/xxx/sso/saml"
        certificate: /etc/ads-central-auth/saml/okta.crt

# Multi-Factor Authentication
mfa:
  required: true
  methods:
    - totp           # Time-based OTP (Google Authenticator, etc.)
    - webauthn       # Hardware keys (YubiKey, etc.)
    - sms            # SMS codes (fallback)
    - email          # Email codes (fallback)

# Session Management
session:
  lifetime: 8h
  idle_timeout: 30m
  max_concurrent: 5
  secure_cookie: true
  same_site: strict

# Organizations
organizations:
  enabled: true
  features:
    - teams
    - roles
    - invitations
    - api_keys

# Role-Based Access Control
rbac:
  roles:
    # Global roles
    - name: "admin"
      description: "Full administrative access"
      permissions:
        - "*"

    - name: "billing_admin"
      description: "Billing and subscription management"
      permissions:
        - "billing:*"
        - "licenses:view"
        - "licenses:purchase"

    - name: "user"
      description: "Standard user access"
      permissions:
        - "licenses:view"
        - "licenses:download"
        - "support:create_ticket"

    # Product-specific roles
    - name: "dnsscience_admin"
      description: "DNS Science product administrator"
      permissions:
        - "dnsscience:*"

    - name: "dnsscience_operator"
      description: "DNS Science operator"
      permissions:
        - "dnsscience:view"
        - "dnsscience:configure"
```

### Licensing Portal Authentication

```yaml
# Licensing Portal Configuration
# /etc/licensing-portal/config.yaml

server:
  domain: "licensing.afterdarksys.com"
  listen: ":443"

# Central Auth Integration
auth:
  provider: "ads-central-auth"
  config:
    issuer: "https://auth.afterdarksys.com"
    client_id: "${LICENSING_CLIENT_ID}"
    client_secret: "${LICENSING_CLIENT_SECRET}"
    redirect_uri: "https://licensing.afterdarksys.com/auth/callback"

    # Required scopes
    scopes:
      - openid
      - profile
      - email
      - organizations

    # Token validation
    token:
      audience: "licensing.afterdarksys.com"
      required_claims:
        - sub
        - email
        - org_id

# Authorization rules
authorization:
  # Map Central Auth roles to portal permissions
  role_mapping:
    admin:
      - "licenses:*"
      - "customers:*"
      - "reports:*"
      - "settings:*"

    billing_admin:
      - "licenses:view"
      - "licenses:purchase"
      - "licenses:renew"
      - "billing:*"

    user:
      - "licenses:view"
      - "licenses:download"
      - "licenses:activate"

  # Resource-based access
  resource_rules:
    licenses:
      - action: "view"
        condition: "resource.org_id == user.org_id"
      - action: "download"
        condition: "resource.org_id == user.org_id"
      - action: "activate"
        condition: "resource.org_id == user.org_id && resource.seats_remaining > 0"
```

### OAuth 2.0 / OIDC Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AUTHENTICATION FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. User visits licensing.afterdarksys.com                                  │
│     └── No session found                                                    │
│                                                                             │
│  2. Redirect to auth.afterdarksys.com/authorize                             │
│     ┌─────────────────────────────────────────────────────────────┐        │
│     │  GET /authorize?                                            │        │
│     │    client_id=licensing.afterdarksys.com                     │        │
│     │    redirect_uri=https://licensing.afterdarksys.com/callback │        │
│     │    response_type=code                                       │        │
│     │    scope=openid profile email organizations                 │        │
│     │    state=random_state_value                                 │        │
│     └─────────────────────────────────────────────────────────────┘        │
│                                                                             │
│  3. User authenticates (login + MFA)                                        │
│     └── auth.afterdarksys.com handles authentication                        │
│                                                                             │
│  4. Authorization callback                                                  │
│     ┌─────────────────────────────────────────────────────────────┐        │
│     │  GET /callback?                                             │        │
│     │    code=authorization_code                                  │        │
│     │    state=random_state_value                                 │        │
│     └─────────────────────────────────────────────────────────────┘        │
│                                                                             │
│  5. Exchange code for tokens                                                │
│     ┌─────────────────────────────────────────────────────────────┐        │
│     │  POST /token                                                │        │
│     │  Response:                                                  │        │
│     │  {                                                          │        │
│     │    "access_token": "eyJ...",                                │        │
│     │    "id_token": "eyJ...",                                    │        │
│     │    "refresh_token": "...",                                  │        │
│     │    "expires_in": 3600                                       │        │
│     │  }                                                          │        │
│     └─────────────────────────────────────────────────────────────┘        │
│                                                                             │
│  6. Validate ID token and extract claims                                    │
│     ┌─────────────────────────────────────────────────────────────┐        │
│     │  ID Token Claims:                                           │        │
│     │  {                                                          │        │
│     │    "sub": "user_12345",                                     │        │
│     │    "email": "admin@example.com",                            │        │
│     │    "name": "John Admin",                                    │        │
│     │    "org_id": "org_67890",                                   │        │
│     │    "org_name": "Example Corp",                              │        │
│     │    "roles": ["admin", "dnsscience_admin"],                  │        │
│     │    "mfa_verified": true                                     │        │
│     │  }                                                          │        │
│     └─────────────────────────────────────────────────────────────┘        │
│                                                                             │
│  7. Create portal session, user accesses licenses                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### API Authentication

```yaml
# API Authentication Methods

# Method 1: Bearer Token (from Central Auth)
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# Token claims include:
# - sub: User ID
# - org_id: Organization ID
# - scope: Granted permissions
# - exp: Expiration timestamp

# Method 2: API Key (for automation/CI)
X-API-Key: ads_api_key_live_abc123xyz789

# API keys are:
# - Generated in Central Auth portal
# - Scoped to specific permissions
# - Bound to organization
# - Rotatable without affecting user access

# Method 3: License Key (for DNSScienced daemon)
X-License-Key: lic_dnsscienced_12345678
X-Machine-ID: a1b2c3d4e5f6

# Used by the DNS server itself for:
# - License validation
# - License refresh
# - Usage reporting
```

### Central Auth Database Schema

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255),  -- NULL for SSO-only users
    name VARCHAR(255),
    avatar_url VARCHAR(512),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active'  -- active, suspended, deleted
);

-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    billing_email VARCHAR(255),
    plan VARCHAR(50) DEFAULT 'free',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Organization memberships
CREATE TABLE org_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, org_id)
);

-- API keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,  -- Hashed API key
    key_prefix VARCHAR(20) NOT NULL,  -- For identification (ads_api_key_live_abc)
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    revoked_at TIMESTAMP
);

-- OAuth connections (for social login)
CREATE TABLE oauth_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,  -- google, github, microsoft
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255),
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

-- Sessions
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    last_active TIMESTAMP DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    org_id UUID REFERENCES organizations(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_org_memberships_user ON org_memberships(user_id);
CREATE INDEX idx_org_memberships_org ON org_memberships(org_id);
CREATE INDEX idx_api_keys_org ON api_keys(org_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_org ON audit_log(org_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);
```

### Portal Features Behind Auth

```yaml
licensing_portal_features:
  # Public (no auth required)
  public:
    - Landing page
    - Pricing page
    - Documentation
    - Status page

  # Authenticated (any valid user)
  authenticated:
    - Dashboard
    - View own licenses
    - Download license files
    - Activate/deactivate seats
    - View usage statistics
    - Support ticket creation

  # Billing Admin role
  billing_admin:
    - Purchase new licenses
    - Upgrade/downgrade licenses
    - Renew licenses
    - View invoices
    - Update payment methods
    - View billing history

  # Admin role
  admin:
    - Manage organization users
    - Generate API keys
    - View audit logs
    - Transfer licenses
    - Cancel licenses

  # Super Admin (ADS staff)
  super_admin:
    - View all organizations
    - Generate custom licenses
    - Override limits
    - System administration
    - Analytics dashboard
```

---

## Licensing Server API

### Endpoints

```yaml
base_url: https://licensing.afterdarksys.com/api/v1

endpoints:
  # License retrieval
  GET /licenses/{license_id}:
    description: "Get license by ID"
    authentication: "License key or API key"
    response:
      type: "License JSON"

  # License validation
  POST /licenses/{license_id}/validate:
    description: "Validate license"
    authentication: "License key"
    request:
      machine_id: string
      hostname: string
      software_version: string
    response:
      valid: bool
      errors: []string
      warnings: []string

  # License activation
  POST /licenses/{license_id}/activate:
    description: "Activate license on machine"
    authentication: "License key"
    request:
      machine_id: string
      hostname: string
    response:
      activated: bool
      seats_remaining: int

  # Seat management
  GET /licenses/{license_id}/seats:
    description: "List activated seats"
    authentication: "API key"
    response:
      seats:
        - machine_id: string
          hostname: string
          activated_at: timestamp
          last_seen: timestamp

  DELETE /licenses/{license_id}/seats/{machine_id}:
    description: "Deactivate a seat"
    authentication: "API key"

  # Usage reporting
  POST /licenses/{license_id}/usage:
    description: "Report usage metrics"
    authentication: "License key"
    request:
      period: string
      metrics:
        queries_total: int
        zones_count: int
        features_used: []string

  # License portal
  GET /portal/licenses:
    description: "List customer's licenses"
    authentication: "Portal token"

  POST /portal/licenses:
    description: "Purchase new license"
    authentication: "Portal token"
```

---

## Branding Configuration

### White-Label Support

```yaml
# Branding configuration for OEM/white-label
branding:
  # Company branding
  company:
    name: "DNS Science"
    logo_url: "https://licensing.afterdarksys.com/assets/dnsscience-logo.png"
    favicon_url: "https://licensing.afterdarksys.com/assets/favicon.ico"
    website: "https://dnsscience.io"

  # Color scheme
  colors:
    primary: "#1a73e8"        # Primary brand color
    secondary: "#34a853"      # Secondary color
    accent: "#fbbc04"         # Accent color
    background: "#ffffff"     # Background
    surface: "#f8f9fa"        # Surface color
    text_primary: "#202124"   # Primary text
    text_secondary: "#5f6368" # Secondary text
    error: "#ea4335"          # Error color
    warning: "#fbbc04"        # Warning color
    success: "#34a853"        # Success color

  # UI text customization
  text:
    product_name: "DNSScienced"
    tagline: "DNS Data, Management, Analytics, and Security"
    footer: "Copyright 2024 DNS Science, a division of After Dark Systems"

  # License portal branding
  portal:
    title: "DNS Science License Portal"
    support_email: "support@dnsscience.io"
    support_url: "https://support.dnsscience.io"
    docs_url: "https://docs.dnsscience.io"

  # Email templates
  email:
    from_name: "DNS Science Licensing"
    from_address: "licensing@dnsscience.io"
    template_dir: "/etc/dnsscienced/branding/email-templates"
```

### OEM Customization

```yaml
# For OEM partners
oem:
  partner_id: "partner_12345"
  partner_name: "Acme Networks"

  # Override branding
  branding:
    company:
      name: "Acme DNS"
      logo_url: "https://acme.com/assets/logo.png"

    colors:
      primary: "#ff6600"
      secondary: "#333333"

    text:
      product_name: "Acme DNS Server"
      tagline: "Enterprise DNS by Acme Networks"
      footer: "Powered by DNS Science"

  # Feature restrictions (can't exceed base license)
  feature_restrictions:
    - dip_service_provider
    - dip_finserv_edition

  # Pricing (partner sets their own)
  pricing:
    currency: "USD"
    professional_monthly: 299
    enterprise_monthly: 1999
```

---

## CLI Commands

### License Management

```bash
# View current license
dnssciencectl license info

# Output:
# License: lic_dnsscienced_12345678
# Tier: Enterprise
# Customer: Example Corporation
# Seats: 100 (15 active)
# Expires: 2025-01-01
# Features: 45 enabled
#
# Enabled Features:
#   Core: authoritative, recursive, dnssec_signing, dnssec_validation
#   Transport: dot, doh, doq
#   Security: rate_limiting, rpz, dns_cookies
#   Web3: ens, sns, unstoppable
#   DIP: sampling, ai_engine, threat_feeds
#
# Limits:
#   Max Zones: 5,000 (current: 150)
#   Max QPS: 2,000,000 (current avg: 50,000)
#   Max Cache: 128 GB (current: 16 GB)

# Check specific feature
dnssciencectl license feature web3_ens
# Output: Feature 'web3_ens' is ENABLED

dnssciencectl license feature dip_finserv_edition
# Output: Feature 'dip_finserv_edition' is NOT ENABLED
#         Upgrade to Enterprise tier with FinServ addon

# Activate license
dnssciencectl license activate LICENSE_KEY

# Refresh license from server
dnssciencectl license refresh

# Deactivate license
dnssciencectl license deactivate

# Show usage report
dnssciencectl license usage --period 30d
```

---

## Integration Points

### Server Startup

```go
func main() {
    // Initialize license manager
    licMgr, err := licensing.NewManager(config.Licensing)
    if err != nil {
        log.Fatal("Failed to initialize licensing:", err)
    }

    // Validate license
    if err := licMgr.Validate(); err != nil {
        switch {
        case errors.Is(err, licensing.ErrNoLicense):
            log.Info("No license found, running in free tier mode")
        case errors.Is(err, licensing.ErrLicenseExpired):
            log.Warn("License expired, some features disabled")
        default:
            log.Fatal("License validation failed:", err)
        }
    }

    // Log license info
    lic := licMgr.GetLicense()
    log.Info("License loaded",
        "tier", lic.Tier,
        "features", len(lic.EnabledFeatures),
        "expires", lic.ExpiresAt,
    )

    // Configure features based on license
    setupFeatures(licMgr)

    // Start server
    server.Start()
}
```

### Feature-Gated Plugins

```go
// Web3 module registration
func registerWeb3Modules(reg *plugin.Registry, licMgr *licensing.Manager) {
    // ENS
    if licMgr.IsFeatureEnabled("web3_ens") {
        reg.Register("ens", NewENSModule())
    }

    // SNS
    if licMgr.IsFeatureEnabled("web3_sns") {
        reg.Register("sns", NewSNSModule())
    }

    // Unstoppable Domains
    if licMgr.IsFeatureEnabled("web3_unstoppable") {
        reg.Register("unstoppable", NewUnstoppableModule())
    }

    // Freename
    if licMgr.IsFeatureEnabled("web3_freename") {
        reg.Register("freename", NewFreenameModule())
    }

    // ITZ
    if licMgr.IsFeatureEnabled("web3_itz") {
        reg.Register("itz", NewITZModule())
    }
}

// DIP module registration
func registerDIPModules(reg *plugin.Registry, licMgr *licensing.Manager) {
    if licMgr.IsFeatureEnabled("dip_sampling") {
        reg.Register("dip_sampler", NewSamplerModule())
    }

    if licMgr.IsFeatureEnabled("dip_ai_engine") {
        reg.Register("dip_ai", NewAIEngineModule())
    }

    if licMgr.IsFeatureEnabled("dip_threat_feeds") {
        reg.Register("dip_feeds", NewThreatFeedModule())
    }

    if licMgr.IsFeatureEnabled("dip_intelligent_routing") {
        reg.Register("dip_routing", NewRoutingModule())
    }

    // Edition-specific
    if licMgr.IsFeatureEnabled("dip_service_provider") {
        reg.Register("dip_provider", NewServiceProviderModule())
    }

    if licMgr.IsFeatureEnabled("dip_cdn_edition") {
        reg.Register("dip_cdn", NewCDNModule())
    }

    if licMgr.IsFeatureEnabled("dip_finserv_edition") {
        reg.Register("dip_finserv", NewFinServModule())
    }
}
```

---

## Error Messages and UX

### User-Friendly Messages

```yaml
error_messages:
  no_license:
    title: "No License Installed"
    message: "DNSScienced is running in Free tier mode. Some features are limited."
    action: "Visit https://dnsscience.io/pricing to upgrade."

  license_expired:
    title: "License Expired"
    message: "Your license expired on {expiry_date}. Running with limited features."
    action: "Renew your license at https://portal.dnsscience.io"
    grace_period_message: "Grace period ends in {days} days."

  feature_not_licensed:
    title: "Feature Not Available"
    message: "The '{feature_name}' feature requires {required_tier} tier or higher."
    action: "Upgrade at https://portal.dnsscience.io/upgrade"

  limit_exceeded:
    title: "License Limit Exceeded"
    message: "You have exceeded the {limit_type} limit ({current}/{max})."
    action: "Upgrade your license or reduce usage."

  hardware_mismatch:
    title: "Hardware Binding Failed"
    message: "This license is bound to different hardware."
    action: "Contact support@dnsscience.io to transfer your license."

  seat_limit_reached:
    title: "Seat Limit Reached"
    message: "All {max_seats} seats are in use."
    action: "Deactivate unused seats or purchase additional seats."
```

---

*Document Version: 1.0*
*Licensing Module Design*
