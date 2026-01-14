# DNSScienced Observability & Monitoring Strategy

## Overview

This document defines the comprehensive observability strategy for DNSScienced, covering metrics, logging, tracing, alerting, and dashboarding across all deployment scenarios.

---

## Observability Pillars

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       THREE PILLARS OF OBSERVABILITY                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐   │
│  │       METRICS       │ │        LOGS         │ │       TRACES        │   │
│  │                     │ │                     │ │                     │   │
│  │  • Query rates      │ │  • Query logs       │ │  • Request tracing  │   │
│  │  • Latency dist.    │ │  • Error logs       │ │  • Resolution path  │   │
│  │  • Cache stats      │ │  • Security events  │ │  • Upstream calls   │   │
│  │  • Resource usage   │ │  • Audit trail      │ │  • Plugin execution │   │
│  │  • DNSSEC stats     │ │  • Debug output     │ │  • Cache lookup     │   │
│  │  • Error rates      │ │  • Zone changes     │ │                     │   │
│  │                     │ │                     │ │                     │   │
│  │  Prometheus/        │ │  Structured JSON    │ │  OpenTelemetry      │   │
│  │  StatsD             │ │  to aggregator      │ │  Jaeger/Zipkin      │   │
│  │                     │ │                     │ │                     │   │
│  └──────────┬──────────┘ └──────────┬──────────┘ └──────────┬──────────┘   │
│             │                       │                       │               │
│             └───────────────────────┼───────────────────────┘               │
│                                     │                                       │
│                          ┌──────────▼──────────┐                           │
│                          │                     │                           │
│                          │    CORRELATION      │                           │
│                          │    REQUEST ID       │                           │
│                          │                     │                           │
│                          └─────────────────────┘                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Metrics

### Prometheus Metrics

```yaml
# /etc/dnsscienced/dnsscienced.conf
metrics:
  prometheus:
    enabled: true
    listen: "0.0.0.0:9153"
    path: "/metrics"

    # Histogram buckets for latency
    latency_buckets:
      - 0.0001   # 100μs
      - 0.0005   # 500μs
      - 0.001    # 1ms
      - 0.005    # 5ms
      - 0.01     # 10ms
      - 0.05     # 50ms
      - 0.1      # 100ms
      - 0.5      # 500ms
      - 1.0      # 1s
      - 5.0      # 5s

    # Custom labels
    labels:
      environment: "production"
      datacenter: "us-east-1"
      cluster: "dns-prod-1"
```

### Core Metrics

```prometheus
# ============================================================================
# QUERY METRICS
# ============================================================================

# Total queries received
# TYPE: Counter
dns_queries_total{type, class, rcode, transport, zone, source}

# Query duration histogram
# TYPE: Histogram
dns_query_duration_seconds{type, transport, cache_hit}

# Current queries in flight
# TYPE: Gauge
dns_queries_in_flight{transport}

# Response size histogram
# TYPE: Histogram
dns_response_size_bytes{type, rcode}

# ============================================================================
# CACHE METRICS
# ============================================================================

# Cache hit/miss counter
# TYPE: Counter
dns_cache_requests_total{result}  # result: hit, miss, expired, negative

# Cache size
# TYPE: Gauge
dns_cache_entries{type}
dns_cache_size_bytes

# Cache evictions
# TYPE: Counter
dns_cache_evictions_total{reason}  # reason: expired, lru, memory_pressure

# Cache entry age histogram
# TYPE: Histogram
dns_cache_entry_age_seconds{type}

# ============================================================================
# DNSSEC METRICS
# ============================================================================

# DNSSEC validation results
# TYPE: Counter
dns_dnssec_validations_total{result}  # result: secure, insecure, bogus, indeterminate

# DNSSEC signatures created (authd)
# TYPE: Counter
dns_dnssec_signatures_total{algorithm, zone}

# Key status
# TYPE: Gauge
dns_dnssec_key_age_seconds{zone, key_type, key_id}
dns_dnssec_key_expiry_seconds{zone, key_type, key_id}

# ============================================================================
# ZONE METRICS
# ============================================================================

# Zone query rate
# TYPE: Counter
dns_zone_queries_total{zone, type, rcode}

# Zone record count
# TYPE: Gauge
dns_zone_records{zone, type}

# Zone serial
# TYPE: Gauge
dns_zone_serial{zone}

# Zone transfer metrics
# TYPE: Counter
dns_zone_transfers_total{zone, type, result}  # type: axfr, ixfr; result: success, failed

# TYPE: Histogram
dns_zone_transfer_duration_seconds{zone, type}

# ============================================================================
# RESOLVER METRICS (cached)
# ============================================================================

# Upstream query counter
# TYPE: Counter
dns_upstream_queries_total{upstream, result}

# Upstream latency
# TYPE: Histogram
dns_upstream_latency_seconds{upstream}

# Resolution depth histogram
# TYPE: Histogram
dns_resolution_depth{domain_level}

# ============================================================================
# RATE LIMITING METRICS
# ============================================================================

# Rate limit actions
# TYPE: Counter
dns_rate_limit_actions_total{action}  # action: drop, slip, pass

# Current rate by client (top-K)
# TYPE: Gauge
dns_client_query_rate{client_ip}

# ============================================================================
# SECURITY METRICS
# ============================================================================

# Blocked queries
# TYPE: Counter
dns_blocked_queries_total{reason, zone}  # reason: rpz, acl, attack

# Security events
# TYPE: Counter
dns_security_events_total{event_type, severity}

# ============================================================================
# RESOURCE METRICS
# ============================================================================

# Memory usage
# TYPE: Gauge
dns_memory_bytes{type}  # type: heap, stack, cache, buffers

# Goroutines
# TYPE: Gauge
dns_goroutines

# File descriptors
# TYPE: Gauge
dns_file_descriptors{type}  # type: used, limit

# Network connections
# TYPE: Gauge
dns_connections{transport, state}  # state: active, idle

# ============================================================================
# TRANSPORT METRICS
# ============================================================================

# TLS handshake duration
# TYPE: Histogram
dns_tls_handshake_duration_seconds

# HTTP/2 streams (DoH)
# TYPE: Gauge
dns_http2_streams{state}

# QUIC connections (DoQ)
# TYPE: Gauge
dns_quic_connections{state}

# ============================================================================
# PLUGIN METRICS
# ============================================================================

# Plugin execution time
# TYPE: Histogram
dns_plugin_duration_seconds{plugin, hook}

# Plugin errors
# TYPE: Counter
dns_plugin_errors_total{plugin, error_type}

# ============================================================================
# WEB3 METRICS
# ============================================================================

# Web3 resolution requests
# TYPE: Counter
dns_web3_requests_total{provider, result}  # provider: ens, sns, unstoppable

# Web3 resolution latency
# TYPE: Histogram
dns_web3_latency_seconds{provider, cache_hit}

# Blockchain RPC calls
# TYPE: Counter
dns_blockchain_rpc_calls_total{chain, method}

# ============================================================================
# DIP METRICS
# ============================================================================

# AI inference time
# TYPE: Histogram
dns_dip_inference_duration_seconds{model}

# Threat detection
# TYPE: Counter
dns_dip_threats_detected_total{threat_type, action}

# Sample rate
# TYPE: Gauge
dns_dip_sample_rate

# ============================================================================
# LICENSING METRICS
# ============================================================================

# License status
# TYPE: Gauge
dns_license_valid{tier}  # 1 if valid, 0 if invalid/expired

# Feature usage
# TYPE: Counter
dns_feature_access_total{feature, allowed}

# Seat usage
# TYPE: Gauge
dns_license_seats_used
dns_license_seats_total
```

### StatsD Metrics (Alternative)

```yaml
metrics:
  statsd:
    enabled: true
    address: "statsd.example.com:8125"
    prefix: "dnsscience"
    sample_rate: 1.0  # 100% sampling

    # Metric mapping
    mappings:
      queries: "counter"
      latency: "timing"
      cache_size: "gauge"
```

---

## Logging

### Structured Logging Configuration

```yaml
logging:
  # Global settings
  level: "info"  # debug, info, warn, error
  format: "json"  # json, text
  output: "file"  # stdout, file, syslog
  file:
    path: /var/log/dnsscienced/server.log
    max_size_mb: 100
    max_backups: 10
    max_age_days: 30
    compress: true

  # Query logging
  query:
    enabled: true
    file: /var/log/dnsscienced/query.log
    format: "json"

    # Fields to include
    fields:
      - timestamp
      - request_id
      - client_ip
      - client_port
      - edns_client_subnet
      - query_name
      - query_type
      - query_class
      - transport
      - response_code
      - response_flags
      - response_size
      - answer_count
      - authority_count
      - additional_count
      - duration_ms
      - cache_hit
      - dnssec_status
      - upstream_server
      - plugin_chain

    # Sampling (for high volume)
    sampling:
      enabled: false
      rate: 1.0  # 100%
      always_log:
        - rcode: SERVFAIL
        - rcode: REFUSED
        - duration_ms: "> 1000"

  # Security event logging
  security:
    enabled: true
    file: /var/log/dnsscienced/security.log
    format: "json"

    events:
      - rate_limit_exceeded
      - query_blocked
      - acl_denied
      - attack_detected
      - dnssec_validation_failed
      - tsig_auth_failed
      - zone_transfer_denied

  # Audit logging
  audit:
    enabled: true
    file: /var/log/dnsscienced/audit.log
    format: "json"

    events:
      - config_reload
      - zone_update
      - dnssec_key_rollover
      - admin_action
      - api_call
```

### Log Formats

```json
// Query log entry (JSON)
{
  "timestamp": "2024-01-15T10:30:15.123456Z",
  "level": "info",
  "logger": "query",
  "request_id": "req_abc123",
  "client": {
    "ip": "10.0.1.100",
    "port": 54321,
    "edns_subnet": "10.0.0.0/24"
  },
  "query": {
    "name": "www.example.com",
    "type": "A",
    "class": "IN"
  },
  "response": {
    "rcode": "NOERROR",
    "flags": ["QR", "RD", "RA", "AD"],
    "size": 128,
    "answers": 2,
    "authority": 0,
    "additional": 1
  },
  "transport": "udp",
  "duration_ms": 0.5,
  "cache_hit": true,
  "dnssec": {
    "validated": true,
    "status": "secure"
  }
}
```

```json
// Security event (JSON)
{
  "timestamp": "2024-01-15T10:30:20.456789Z",
  "level": "warn",
  "logger": "security",
  "request_id": "req_def456",
  "event": "rate_limit_exceeded",
  "severity": "medium",
  "client": {
    "ip": "203.0.113.50"
  },
  "details": {
    "queries_in_window": 1500,
    "limit": 1000,
    "window_seconds": 1,
    "action": "drop"
  }
}
```

```json
// Audit log entry (JSON)
{
  "timestamp": "2024-01-15T10:35:00.000000Z",
  "level": "info",
  "logger": "audit",
  "event": "zone_update",
  "actor": {
    "type": "api",
    "user": "admin@example.com",
    "ip": "10.0.0.50"
  },
  "resource": {
    "type": "zone",
    "name": "example.com"
  },
  "action": "record_add",
  "details": {
    "record_name": "new-host",
    "record_type": "A",
    "record_data": "192.0.2.100"
  },
  "result": "success"
}
```

### Log Shipping

```yaml
# Fluent Bit configuration
[SERVICE]
    Flush         5
    Log_Level     info
    Parsers_File  parsers.conf

[INPUT]
    Name              tail
    Path              /var/log/dnsscienced/*.log
    Parser            json
    Tag               dns.*
    Refresh_Interval  10
    Mem_Buf_Limit     50MB

[FILTER]
    Name              modify
    Match             dns.*
    Add               hostname ${HOSTNAME}
    Add               cluster dns-prod-1

[OUTPUT]
    Name              es
    Match             dns.query
    Host              elasticsearch.example.com
    Port              9200
    Index             dns-queries
    Type              _doc

[OUTPUT]
    Name              es
    Match             dns.security
    Host              elasticsearch.example.com
    Port              9200
    Index             dns-security
    Type              _doc

[OUTPUT]
    Name              loki
    Match             dns.*
    Host              loki.example.com
    Port              3100
    Labels            job=dnsscienced,cluster=dns-prod-1
```

---

## Distributed Tracing

### OpenTelemetry Configuration

```yaml
tracing:
  enabled: true
  provider: "opentelemetry"

  opentelemetry:
    # Exporter
    exporter: "otlp"  # otlp, jaeger, zipkin
    endpoint: "otel-collector.example.com:4317"
    insecure: false
    headers:
      Authorization: "Bearer ${OTEL_TOKEN}"

    # Sampling
    sampler: "parentbased_traceidratio"
    sample_rate: 0.1  # 10% of requests

    # Resource attributes
    resource:
      service.name: "dnsscienced"
      service.version: "1.2.3"
      deployment.environment: "production"
      host.name: "${HOSTNAME}"

    # Propagators
    propagators:
      - "tracecontext"
      - "baggage"

  # Span configuration
  spans:
    # Include these spans
    enabled:
      - query_receive
      - cache_lookup
      - dnssec_validation
      - upstream_query
      - zone_lookup
      - plugin_execute
      - response_send

    # Span attributes
    attributes:
      query:
        - name
        - type
        - class
      response:
        - rcode
        - size
      client:
        - ip
        - transport
```

### Trace Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          QUERY TRACE EXAMPLE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Trace ID: abc123def456                                                     │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ dns.query                                                   15.2ms  │   │
│  │ name: www.example.com, type: A, client: 10.0.1.100                  │   │
│  │                                                                      │   │
│  │   ┌─────────────────────────────────────────────────────┐           │   │
│  │   │ dns.receive                                  0.1ms   │           │   │
│  │   │ transport: udp, size: 45                             │           │   │
│  │   └─────────────────────────────────────────────────────┘           │   │
│  │                                                                      │   │
│  │   ┌─────────────────────────────────────────────────────┐           │   │
│  │   │ dns.cache.lookup                             0.05ms  │           │   │
│  │   │ result: miss                                         │           │   │
│  │   └─────────────────────────────────────────────────────┘           │   │
│  │                                                                      │   │
│  │   ┌─────────────────────────────────────────────────────┐           │   │
│  │   │ dns.plugin.rpz                               0.2ms   │           │   │
│  │   │ action: pass                                         │           │   │
│  │   └─────────────────────────────────────────────────────┘           │   │
│  │                                                                      │   │
│  │   ┌─────────────────────────────────────────────────────────────┐   │   │
│  │   │ dns.upstream.query                                   12.5ms │   │   │
│  │   │ server: 198.51.100.1, attempt: 1                            │   │   │
│  │   │                                                              │   │   │
│  │   │   ┌─────────────────────────────────────────────┐           │   │   │
│  │   │   │ dns.net.send                         0.02ms  │           │   │   │
│  │   │   └─────────────────────────────────────────────┘           │   │   │
│  │   │                                                              │   │   │
│  │   │   ┌─────────────────────────────────────────────┐           │   │   │
│  │   │   │ dns.net.receive                     12.4ms   │           │   │   │
│  │   │   └─────────────────────────────────────────────┘           │   │   │
│  │   │                                                              │   │   │
│  │   └──────────────────────────────────────────────────────────────┘   │   │
│  │                                                                      │   │
│  │   ┌─────────────────────────────────────────────────────┐           │   │
│  │   │ dns.dnssec.validate                          1.8ms   │           │   │
│  │   │ result: secure, signatures: 2                        │           │   │
│  │   └─────────────────────────────────────────────────────┘           │   │
│  │                                                                      │   │
│  │   ┌─────────────────────────────────────────────────────┐           │   │
│  │   │ dns.cache.store                              0.03ms  │           │   │
│  │   │ ttl: 300                                             │           │   │
│  │   └─────────────────────────────────────────────────────┘           │   │
│  │                                                                      │   │
│  │   ┌─────────────────────────────────────────────────────┐           │   │
│  │   │ dns.response.send                            0.02ms  │           │   │
│  │   │ rcode: NOERROR, size: 128                            │           │   │
│  │   └─────────────────────────────────────────────────────┘           │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Alerting

### Alert Rules

```yaml
# Prometheus alerting rules
# /etc/prometheus/rules/dnsscience.yml

groups:
  - name: dnsscience.availability
    rules:
      - alert: DNSServiceDown
        expr: up{job="dnsscience"} == 0
        for: 1m
        labels:
          severity: critical
          team: dns-ops
        annotations:
          summary: "DNS service {{ $labels.instance }} is down"
          description: "DNS service has been unreachable for more than 1 minute"
          runbook: "https://runbooks.example.com/dns/service-down"

      - alert: DNSHighErrorRate
        expr: >
          rate(dns_queries_total{rcode="SERVFAIL"}[5m]) /
          rate(dns_queries_total[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
          team: dns-ops
        annotations:
          summary: "High SERVFAIL rate on {{ $labels.instance }}"
          description: "SERVFAIL rate is {{ $value | humanizePercentage }}"

  - name: dnsscience.performance
    rules:
      - alert: DNSHighLatency
        expr: >
          histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket[5m])) > 0.1
        for: 10m
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "DNS p99 latency high on {{ $labels.instance }}"
          description: "P99 latency is {{ $value | humanizeDuration }}"

      - alert: DNSCacheHitRateLow
        expr: >
          rate(dns_cache_requests_total{result="hit"}[5m]) /
          rate(dns_cache_requests_total[5m]) < 0.7
        for: 15m
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "DNS cache hit rate below 70%"
          description: "Cache hit rate is {{ $value | humanizePercentage }}"

      - alert: DNSQueryRateSpike
        expr: >
          rate(dns_queries_total[5m]) > 1.5 *
          avg_over_time(rate(dns_queries_total[5m])[1h:])
        for: 5m
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "Unusual query rate spike detected"

  - name: dnsscience.security
    rules:
      - alert: DNSRateLimitTriggered
        expr: rate(dns_rate_limit_actions_total{action="drop"}[5m]) > 100
        for: 5m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "DNS rate limiting active on {{ $labels.instance }}"
          description: "Dropping {{ $value }} queries/second"

      - alert: DNSAttackDetected
        expr: increase(dns_security_events_total{event_type="attack_detected"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "DNS attack detected on {{ $labels.instance }}"
          runbook: "https://runbooks.example.com/dns/attack-response"

      - alert: DNSSECValidationFailures
        expr: >
          rate(dns_dnssec_validations_total{result="bogus"}[5m]) /
          rate(dns_dnssec_validations_total[5m]) > 0.01
        for: 10m
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "High DNSSEC validation failure rate"

  - name: dnsscience.dnssec
    rules:
      - alert: DNSSECKeyExpiringSoon
        expr: dns_dnssec_key_expiry_seconds < 7 * 24 * 3600
        for: 1h
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "DNSSEC key expiring soon for {{ $labels.zone }}"
          description: "Key {{ $labels.key_id }} expires in {{ $value | humanizeDuration }}"

      - alert: DNSSECKeyExpired
        expr: dns_dnssec_key_expiry_seconds < 0
        for: 0m
        labels:
          severity: critical
          team: dns-ops
        annotations:
          summary: "DNSSEC key expired for {{ $labels.zone }}"
          runbook: "https://runbooks.example.com/dns/dnssec-key-expired"

  - name: dnsscience.resources
    rules:
      - alert: DNSHighMemoryUsage
        expr: dns_memory_bytes{type="heap"} / dns_memory_bytes{type="limit"} > 0.85
        for: 10m
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "DNS memory usage above 85%"

      - alert: DNSHighFileDescriptors
        expr: dns_file_descriptors{type="used"} / dns_file_descriptors{type="limit"} > 0.8
        for: 5m
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "DNS file descriptor usage above 80%"

  - name: dnsscience.zones
    rules:
      - alert: DNSZoneTransferFailed
        expr: increase(dns_zone_transfers_total{result="failed"}[1h]) > 0
        for: 0m
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "Zone transfer failed for {{ $labels.zone }}"

      - alert: DNSZoneStale
        expr: time() - dns_zone_last_update_timestamp > 24 * 3600
        for: 1h
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "Zone {{ $labels.zone }} hasn't been updated in 24h"

  - name: dnsscience.licensing
    rules:
      - alert: DNSLicenseExpiringSoon
        expr: dns_license_expiry_seconds < 30 * 24 * 3600
        for: 1h
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "DNS license expires in {{ $value | humanizeDuration }}"
          description: "Renew license to avoid service interruption"

      - alert: DNSLicenseSeatsExhausted
        expr: dns_license_seats_used >= dns_license_seats_total
        for: 0m
        labels:
          severity: warning
          team: dns-ops
        annotations:
          summary: "All license seats are in use"
```

### Alert Routing

```yaml
# Alertmanager configuration
route:
  receiver: 'default'
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h

  routes:
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      continue: true

    - match:
        severity: critical
        team: security
      receiver: 'security-oncall'

    - match:
        severity: warning
      receiver: 'slack-warnings'

receivers:
  - name: 'default'
    slack_configs:
      - api_url: '${SLACK_WEBHOOK_URL}'
        channel: '#dns-alerts'

  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: '${PAGERDUTY_KEY}'
        severity: critical

  - name: 'security-oncall'
    pagerduty_configs:
      - service_key: '${SECURITY_PAGERDUTY_KEY}'
    slack_configs:
      - api_url: '${SLACK_WEBHOOK_URL}'
        channel: '#security-alerts'

  - name: 'slack-warnings'
    slack_configs:
      - api_url: '${SLACK_WEBHOOK_URL}'
        channel: '#dns-warnings'
```

---

## Dashboards

### Grafana Dashboard Structure

```yaml
dashboards:
  # Overview dashboard
  dns_overview:
    title: "DNS Science - Overview"
    refresh: 10s
    panels:
      - title: "Queries per Second"
        type: graph
        query: "rate(dns_queries_total[1m])"
        legend: "{{ instance }}"

      - title: "Query Latency (p50, p95, p99)"
        type: graph
        queries:
          - expr: "histogram_quantile(0.50, rate(dns_query_duration_seconds_bucket[5m]))"
            legend: "p50"
          - expr: "histogram_quantile(0.95, rate(dns_query_duration_seconds_bucket[5m]))"
            legend: "p95"
          - expr: "histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket[5m]))"
            legend: "p99"

      - title: "Cache Hit Rate"
        type: gauge
        query: "rate(dns_cache_requests_total{result='hit'}[5m]) / rate(dns_cache_requests_total[5m])"
        thresholds:
          - value: 0.7
            color: red
          - value: 0.85
            color: yellow
          - value: 0.95
            color: green

      - title: "Response Codes"
        type: piechart
        query: "sum by (rcode) (rate(dns_queries_total[5m]))"

      - title: "Active Connections"
        type: stat
        query: "sum(dns_connections{state='active'})"

  # Performance dashboard
  dns_performance:
    title: "DNS Science - Performance"
    panels:
      - title: "Latency Heatmap"
        type: heatmap
        query: "rate(dns_query_duration_seconds_bucket[5m])"

      - title: "Queries by Transport"
        type: graph
        query: "sum by (transport) (rate(dns_queries_total[1m]))"

      - title: "Cache Statistics"
        type: table
        queries:
          - expr: "dns_cache_entries"
            format: "entries"
          - expr: "dns_cache_size_bytes"
            format: "bytes"
          - expr: "rate(dns_cache_evictions_total[5m])"
            format: "evictions/s"

      - title: "Upstream Latency"
        type: graph
        query: "histogram_quantile(0.99, rate(dns_upstream_latency_seconds_bucket[5m]))"

  # Security dashboard
  dns_security:
    title: "DNS Science - Security"
    panels:
      - title: "Blocked Queries"
        type: graph
        query: "rate(dns_blocked_queries_total[5m])"

      - title: "Rate Limited Clients"
        type: table
        query: "topk(10, dns_client_query_rate)"

      - title: "DNSSEC Validation"
        type: piechart
        query: "sum by (result) (rate(dns_dnssec_validations_total[5m]))"

      - title: "Security Events"
        type: logs
        query: "{job=\"dnsscienced\", logger=\"security\"}"

  # DNSSEC dashboard
  dns_dnssec:
    title: "DNS Science - DNSSEC"
    panels:
      - title: "Key Status"
        type: table
        columns:
          - zone
          - key_type
          - key_id
          - age_days
          - expires_in

      - title: "Signatures Created"
        type: graph
        query: "rate(dns_dnssec_signatures_total[5m])"

      - title: "Validation Results"
        type: stat
        queries:
          - expr: "sum(rate(dns_dnssec_validations_total{result='secure'}[24h]))"
            title: "Secure"
          - expr: "sum(rate(dns_dnssec_validations_total{result='bogus'}[24h]))"
            title: "Bogus"

  # Zones dashboard
  dns_zones:
    title: "DNS Science - Zones"
    panels:
      - title: "Zone Query Rate"
        type: graph
        query: "sum by (zone) (rate(dns_zone_queries_total[1m]))"

      - title: "Zone Serials"
        type: table
        query: "dns_zone_serial"

      - title: "Zone Transfer Status"
        type: state-timeline
        query: "dns_zone_transfer_status"

  # Web3 dashboard
  dns_web3:
    title: "DNS Science - Web3"
    panels:
      - title: "Web3 Requests by Provider"
        type: graph
        query: "sum by (provider) (rate(dns_web3_requests_total[5m]))"

      - title: "Web3 Latency"
        type: graph
        query: "histogram_quantile(0.99, rate(dns_web3_latency_seconds_bucket[5m]))"

      - title: "Blockchain RPC Calls"
        type: graph
        query: "sum by (chain) (rate(dns_blockchain_rpc_calls_total[5m]))"
```

---

## Health Checks

### Endpoints

```yaml
health:
  # Liveness probe
  liveness:
    path: /health/live
    response:
      status: "ok"  # or "fail"

  # Readiness probe
  readiness:
    path: /health/ready
    response:
      status: "ready"  # or "not_ready"
      checks:
        - name: "zones"
          status: "pass"
        - name: "cache"
          status: "pass"
        - name: "upstream"
          status: "pass"

  # Detailed health
  detailed:
    path: /health
    response:
      status: "healthy"
      uptime_seconds: 86400
      version: "1.2.3"
      checks:
        zones:
          status: "pass"
          loaded: 50
          errors: 0
        cache:
          status: "pass"
          hit_rate: 0.92
          size_bytes: 524288000
        upstream:
          status: "pass"
          servers:
            - address: "198.51.100.1"
              status: "healthy"
              latency_ms: 12
            - address: "198.51.100.2"
              status: "healthy"
              latency_ms: 15
        dnssec:
          status: "pass"
          keys_valid: true
          expiring_soon: false
        license:
          status: "pass"
          tier: "enterprise"
          expires_in_days: 180
```

### Kubernetes Probes

```yaml
# In Kubernetes deployment
spec:
  containers:
    - name: dnsscienced
      livenessProbe:
        httpGet:
          path: /health/live
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 10
        timeoutSeconds: 5
        failureThreshold: 3

      readinessProbe:
        httpGet:
          path: /health/ready
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 5
        timeoutSeconds: 3
        failureThreshold: 3

      startupProbe:
        httpGet:
          path: /health/ready
          port: 8080
        initialDelaySeconds: 0
        periodSeconds: 5
        timeoutSeconds: 3
        failureThreshold: 30  # Allow 150s for startup
```

---

## SLA Monitoring

### SLI/SLO Definitions

```yaml
slis:
  # Availability SLI
  availability:
    description: "Percentage of successful DNS queries"
    query: >
      sum(rate(dns_queries_total{rcode=~"NOERROR|NXDOMAIN"}[5m])) /
      sum(rate(dns_queries_total[5m]))

  # Latency SLI
  latency_p99:
    description: "99th percentile query latency"
    query: >
      histogram_quantile(0.99, rate(dns_query_duration_seconds_bucket[5m]))

  # DNSSEC SLI
  dnssec_validation:
    description: "DNSSEC validation success rate"
    query: >
      sum(rate(dns_dnssec_validations_total{result!="bogus"}[5m])) /
      sum(rate(dns_dnssec_validations_total[5m]))

slos:
  # 99.99% availability
  availability:
    target: 0.9999
    window: "30d"
    alert_burn_rate:
      - burn_rate: 14.4
        window: 1h
        severity: critical
      - burn_rate: 6
        window: 6h
        severity: warning

  # p99 latency < 50ms
  latency:
    target_value: 0.050
    comparison: "<"
    window: "30d"

  # DNSSEC success > 99.9%
  dnssec:
    target: 0.999
    window: "30d"
```

### Error Budget

```yaml
error_budget:
  # Monthly error budget
  monthly:
    availability:
      target: 0.9999
      budget_minutes: 4.38  # ~4 minutes/month

    calculation: >
      error_budget_remaining =
        (target - actual_availability) * total_minutes_in_period

  # Dashboard panel
  panel:
    title: "Error Budget Status"
    queries:
      - name: "Budget Used"
        expr: >
          (1 - avg_over_time(sli:availability[30d])) / (1 - 0.9999) * 100

      - name: "Budget Remaining"
        expr: >
          100 - ((1 - avg_over_time(sli:availability[30d])) / (1 - 0.9999) * 100)
```

---

## Capacity Planning

### Metrics for Capacity

```yaml
capacity_metrics:
  # Current utilization
  utilization:
    - metric: "dns_queries_total"
      label: "Query Rate"
      unit: "queries/second"
      capacity_threshold: 0.7  # Alert at 70% of max

    - metric: "dns_cache_size_bytes"
      label: "Cache Size"
      unit: "bytes"
      capacity_threshold: 0.8

    - metric: "dns_connections"
      label: "Connections"
      unit: "connections"
      capacity_threshold: 0.75

  # Growth tracking
  growth:
    - metric: "rate(dns_queries_total[1d])"
      label: "Daily Query Growth"
      forecast_days: 90

  # Forecasting query
  forecast: >
    predict_linear(
      avg_over_time(rate(dns_queries_total[1h])[30d:1h]),
      86400 * 90
    )
```

---

*Document Version: 1.0*
*Observability & Monitoring Strategy*
