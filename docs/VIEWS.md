# DNS Views (Split-Horizon DNS)

Views allow dnsscienced to serve different DNS responses based on the source of the query. This enables split-horizon DNS where internal clients get private IPs and external clients get public IPs.

## Architecture

### View Matching Flow
```
Query Arrives
    ↓
Extract Client Info (Source IP, EDNS subnet, etc.)
    ↓
Match Against Views (in priority order)
    ↓
Select Matching View
    ↓
Query View-Specific Zones
    ↓
Use View-Specific Cache
    ↓
Apply View-Specific Options
    ↓
Return Response
```

### View Layers

1. **Static Auth DNS** - Each view has its own set of authoritative zones
2. **Cache DNS** - Each view has its own cache (prevents cross-view cache poisoning)
3. **Overrides** - Per-view record overrides
4. **Recursion** - Per-view recursion settings and forwarders

## Configuration

### View Definition
```yaml
views:
  - name: internal
    description: Internal corporate network
    priority: 10
    match_clients:
      - type: source_ip
        value: 10.0.0.0/8
      - type: source_ip
        value: 192.168.0.0/16
    options:
      recursion: true
      dnssec: true
      cache_size: 512  # MB
      log_queries: true
      forwarders:
        - 1.1.1.1
        - 8.8.8.8
    zones:
      - example.com
      - internal.local
      - 10.in-addr.arpa

  - name: dmz
    description: DMZ servers
    priority: 20
    match_clients:
      - type: source_network
        value: dmz-net
    options:
      recursion: false
      dnssec: true
      log_queries: true
    zones:
      - example.com

  - name: external
    description: Public Internet
    priority: 100
    match_clients:
      - type: any
        value: "*"
    options:
      recursion: false
      dnssec: true
      cache_size: 1024
    zones:
      - example.com
```

## Match Criteria Types

- **source_ip**: Match CIDR (10.0.0.0/8, 192.168.1.0/24)
- **source_network**: Match named network from IPAM
- **asn**: Match AS number
- **country**: Match GeoIP country code
- **acl**: Match named ACL
- **edns_subnet**: Match EDNS client subnet
- **any**: Catch-all (use for default/external view)

## Integration with DHCP/IPAM

### Dynamic DNS Updates Per View

When DHCP assigns a lease, it can update DNS records in specific views:

1. **Internal View**: Gets private IP (10.x.x.x)
   ```
   workstation1.example.com → 10.50.10.100 (internal view)
   ```

2. **External View**: Gets public IP or no record
   ```
   workstation1.example.com → NXDOMAIN (external view)
   ```

### IPAM Integration

IPAM tracks which subnet/IP pool belongs to which view:

```
Subnet: 10.50.10.0/24
  ├─ View: internal
  ├─ DHCP Pool: 10.50.10.100 - 10.50.10.200
  └─ DNS Zone: internal.example.com

Subnet: 203.0.113.0/24
  ├─ View: external
  ├─ Static IPs: 203.0.113.10 - 203.0.113.20
  └─ DNS Zone: example.com
```

When DHCP assigns from 10.50.10.0/24:
1. DHCP → IPAM: NotifyLease(10.50.10.100, hostname)
2. IPAM determines view = "internal" based on subnet
3. IPAM → DNS: UpdateRecords(zone="example.com", view="internal", A=10.50.10.100)

## API Usage

### Create View
```grpc
CreateView({
  name: "internal",
  priority: 10,
  match_clients: [
    {type: SOURCE_IP, value: "10.0.0.0/8"}
  ],
  options: {
    recursion: true,
    cache_size: 512
  }
})
```

### Attach Zone to View
```grpc
AttachZoneToView({
  view_name: "internal",
  zone_name: "example.com"
})
```

### Match Client
```grpc
MatchClientToView({
  client_ip: "10.50.10.5"
})
// Returns: view_name = "internal"
```

### Update Records in View
```grpc
UpdateRecords({
  zone_name: "example.com",
  view_name: "internal",  // NEW: view parameter
  updates: [
    {
      operation: ADD,
      name: "server1.example.com",
      type: "A",
      data: "10.50.10.10",
      ttl: 3600
    }
  ]
})
```

## Common Use Cases

### 1. Split-Horizon DNS

**Internal View:**
```
server1.example.com → 10.50.10.10 (private IP)
```

**External View:**
```
server1.example.com → 203.0.113.10 (public IP)
```

### 2. Development vs Production

**Dev View** (from dev network):
```
api.example.com → 10.0.1.100 (dev environment)
```

**Prod View** (from production network):
```
api.example.com → 10.0.2.100 (production environment)
```

### 3. Geo-based Views

**US View:**
```
cdn.example.com → 203.0.113.10 (US CDN)
```

**EU View:**
```
cdn.example.com → 198.51.100.20 (EU CDN)
```

## Security Benefits

1. **Information Hiding**: External clients don't see internal infrastructure
2. **Cache Isolation**: Each view has separate cache (prevents poisoning)
3. **Access Control**: Recursion only for trusted views
4. **Audit Logging**: Per-view query logging

## Performance

- Views are evaluated in priority order (lower number first)
- First matching view is selected
- Per-view caches prevent memory bloat
- View matching uses optimized CIDR lookup
