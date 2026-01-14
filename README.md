# DNSScienced

**Enterprise-grade DNS Server Platform with Intelligence Integration**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-dnsscience.io-667eea)](https://dnsscience.io/docs/server)

DNSScienced is a modern, high-performance DNS server platform written in Go. It provides both **authoritative** and **recursive** DNS services with deep integration into the [DNSScience.io](https://dnsscience.io) intelligence platform.

## Features

### Core Capabilities

- **Authoritative DNS** (`dnsscience_authd`) - Enterprise zone hosting with DNSSEC signing
- **Recursive Resolver** (`dnsscience_cached`) - Full caching resolver with DNSSEC validation
- **Modern Transports** - Native DoT, DoH, and DoQ support
- **DNSRPZ** - Response Policy Zones for threat blocking
- **Plugin System** - Extend with Go plugins or Lua/Starlark scripts

### Security & Protection

- **DNSSEC** - Full signing and validation with algorithm agility
- **DDoS Mitigation** - Multi-layer protection (RRL, DNS Cookies, rate limiting)
- **Threat Intelligence** - DNSScience.io feed integration
- **Query Logging** - Structured logging with multiple outputs

### Web3 DNS Integration

- ENS (.eth) - Ethereum Name Service
- SNS (.sol) - Solana Name Service
- Unstoppable Domains (.crypto, .x, .wallet, .nft, .blockchain, .888, .dao)
- Freename (.fn)
- ITZ (.itz)

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/dnsscience/dnsscienced.git
cd dnsscienced

# Build all binaries
make build

# Install to system
sudo make install
```

### Using Go Install

```bash
go install github.com/dnsscience/dnsscienced/cmd/...@latest
```

### Docker

```bash
# Recursive resolver
docker run -d --name dns-cached \
  -p 53:53/udp -p 53:53/tcp \
  -p 853:853/tcp \
  dnsscience/dnsscienced:cached

# Authoritative server
docker run -d --name dns-authd \
  -p 5353:53/udp -p 5353:53/tcp \
  -v /var/lib/dnsscienced/zones:/zones \
  dnsscience/dnsscienced:authd
```

### Start the Resolver

```bash
# Start recursive resolver
sudo dnsscience-cached -c /etc/dnsscienced/cached.conf

# Test it
dig @127.0.0.1 example.com
```

### Start Authoritative Server

```bash
# Start authoritative server
sudo dnsscience-authd -c /etc/dnsscienced/authd.conf

# Test zone
dig @127.0.0.1 example.com SOA
```

## Architecture

```
+---------------------------------------------------------------+
|                     DNSScience Ecosystem                       |
+---------------------------------------------------------------+
|                                                                |
|  +------------------+          +------------------------+      |
|  | dnsscience_cached|<-------->|    dnsscience_authd    |      |
|  |   (Recursive)    |          |    (Authoritative)     |      |
|  +--------+---------+          +-----------+------------+      |
|           |                                |                   |
|           +---------------+----------------+                   |
|                           |                                    |
|            +--------------v---------------+                    |
|            |    libdnsscience (core)      |                    |
|            +------------------------------+                    |
|                                                                |
|  +----------------------------------------------------------+  |
|  |                     CLI Utilities                         |  |
|  |  dnsscience-checkzone  dnsscience-convert                |  |
|  |  dnsscience-keygen     dnsscience-signzone               |  |
|  |  dnsscience-dig        dnsscience-ctl                    |  |
|  +----------------------------------------------------------+  |
+----------------------------------------------------------------+
```

## Configuration

### Recursive Resolver (`/etc/dnsscienced/cached.conf`)

```yaml
server {
    listen = ["0.0.0.0:53", "[::]:53"]
    listen-tls = ["0.0.0.0:853"]
    listen-https = ["0.0.0.0:443"]
}

cache {
    backend = "memory"  # or "redis"
    size = "512MB"
    serve-stale = yes
}

dnssec {
    validation = yes
    trust-anchor-file = "/etc/dnsscienced/root.key"
}

rpz {
    zone "dnsscience-threat" {
        url = "https://rpz.dnsscience.io/threat.rpz"
        refresh = 3600
    }
}
```

### Zone File Format (`.dnszone`)

DNSScienced uses a modern, YAML-like zone format:

```yaml
zone: example.com
serial: auto
ttl: 3600

nameservers:
  - ns1.example.com
  - ns2.example.com

mx:
  - priority: 10
    host: mail.example.com

records:
  "@":
    A: 192.0.2.1
    AAAA: 2001:db8::1
    TXT: "v=spf1 mx -all"

  www:
    CNAME: "@"
```

## CLI Tools

| Tool | Description |
|------|-------------|
| `dnsscience-cached` | Recursive resolver daemon |
| `dnsscience-authd` | Authoritative server daemon |
| `dnsscience-ctl` | Runtime control (reload, flush, stats) |
| `dnsscience-dig` | Enhanced dig with DoH/DoT support |
| `dnsscience-checkzone` | Zone file validation |
| `dnsscience-convert` | Zone format conversion |
| `dnsscience-keygen` | DNSSEC key generation |
| `dnsscience-signzone` | Zone signing |

### Examples

```bash
# Enhanced dig with DNSSEC
dnsscience-dig +dnssec example.com A

# DNS over HTTPS query
dnsscience-dig +https @cloudflare-dns.com example.com A

# Validate zone file
dnsscience-checkzone example.com example.com.dnszone

# Convert BIND zone to DNSScienced format
dnsscience-convert bind2dnszone example.com.zone -o example.com.dnszone

# Generate DNSSEC keys
dnsscience-keygen -a ED25519 -f KSK example.com
dnsscience-keygen -a ED25519 example.com

# Runtime control
dnsscience-ctl reload
dnsscience-ctl flush
dnsscience-ctl stats
```

## Transport Support

| Protocol | Port | RFC | Description |
|----------|------|-----|-------------|
| UDP/TCP | 53 | RFC 1035 | Traditional DNS |
| DoT | 853 | RFC 7858 | DNS over TLS |
| DoH | 443 | RFC 8484 | DNS over HTTPS |
| DoQ | 853/UDP | RFC 9250 | DNS over QUIC |

## DNSSEC

Supported algorithms (RFC 8624 compliant):

| Algorithm | ID | Recommendation |
|-----------|----|-----------------|
| ECDSAP256SHA256 | 13 | **Recommended** |
| ED25519 | 15 | **Best Performance** |
| RSASHA256 | 8 | Legacy compatibility |
| RSASHA512 | 10 | Legacy compatibility |
| ED448 | 16 | Highest security |

## Plugin System

Extend DNSScienced with custom functionality:

- **Native Go Plugins** (`.so`) - Highest performance
- **Lua Scripts** (`.lua`) - Quick customization, hot reload
- **Starlark Scripts** (`.star`) - Sandboxed execution

### Hook Points

- `PreQuery` / `PostResponse` - Query processing
- `OnZoneLoad` / `OnZoneUpdate` - Zone events
- `OnCacheHit` / `OnCacheMiss` - Cache events
- `OnStart` / `OnStop` / `OnReload` - Lifecycle

### Built-in Modules

- DNS Intelligence Platform (DIP) - AI/ML threat detection
- GeoIP Routing - Geographic load balancing
- Web3 DNS - Blockchain name resolution
- Blocklist Plugin - Domain filtering

## DNSScience.io Integration

Connect to the DNSScience.io cloud platform for:

- **Threat Intelligence Feeds** - Real-time RPZ updates
- **Anonymous Analytics** - Query pattern insights
- **Reputation Data** - Domain/IP scoring
- **Monitoring** - Centralized dashboard

```yaml
dnsscience-cloud {
    enabled = yes
    api-key = "${DNSSCIENCE_API_KEY}"
    threat-feeds = yes
    telemetry = yes
}
```

## Documentation

- **Full Documentation**: [dnsscience.io/docs/server](https://dnsscience.io/docs/server)
- **Design Document**: [DESIGN.md](DESIGN.md)
- **API Reference**: [docs/API_SPECIFICATIONS.md](docs/API_SPECIFICATIONS.md)
- **Deployment Guide**: [docs/DEPLOYMENT_OPERATIONS.md](docs/DEPLOYMENT_OPERATIONS.md)

## RFC Compliance

DNSScienced implements comprehensive RFC compliance:

**Core DNS**: RFC 1034/1035, RFC 2181, RFC 2308, RFC 6891, RFC 7766, RFC 8020

**DNSSEC**: RFC 4033/4034/4035, RFC 5155, RFC 8624, RFC 9276

**Modern DNS**: RFC 7858 (DoT), RFC 8484 (DoH), RFC 9250 (DoQ), RFC 7873 (Cookies)

**Privacy**: RFC 7816 (QNAME Minimization), RFC 8198 (Aggressive NSEC), RFC 8914 (EDE)

See [docs/WIRE_PROTOCOL.md](docs/WIRE_PROTOCOL.md) for complete RFC matrix.

## Building

```bash
# Build all binaries
make build

# Run tests
make test

# Run integration tests
make test-integration

# Build Docker image
make docker

# Create release
make release
```

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting pull requests.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

---

**DNS Science** - DNS Data, Management, Analytics, and Security Experts

[Website](https://dnsscience.io) | [Documentation](https://dnsscience.io/docs/server) | [API](https://dnsscience.io/docs/api)
