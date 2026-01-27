package ports

import (
	"context"
)

// DNSResolver exposes recursive/authoritative query functions.
type DNSResolver interface {
	Resolve(ctx context.Context, name string, qtype string, class string, dnssec bool, rd bool, cd bool) (*ResolveResult, error)
}

type ResolveResult struct {
	RCode       int32
	RCodeName   string
	Answer      []ResourceRecord
	Authority   []ResourceRecord
	Additional  []ResourceRecord
	Authoritative bool
	Truncated     bool
	RecursionAvailable bool
	Meta        map[string]string
	Wire        []byte
}

type ResourceRecord struct {
	Name  string
	Type  string
	Class string
	TTL   uint32
	Data  string
	RData []byte
}

// ZoneManager manages zones and records.
type ZoneManager interface {
	ListZones(ctx context.Context, zoneType string, pattern string) ([]ZoneInfo, error)
	GetZone(ctx context.Context, name string, includeRecords bool, recordType string) (*ZoneInfo, []ResourceRecord, error)
	ReloadZone(ctx context.Context, name string, verifyOnly bool) (*ReloadOutcome, error)
	Notify(ctx context.Context, name string, servers []string) (*NotifyOutcome, error)
	Transfer(ctx context.Context, name string, typ string, server string) (*TransferOutcome, error)
	UpdateRecords(ctx context.Context, name string, updates []RecordUpdate, incrementSerial bool) (*UpdateOutcome, error)
	GetRecords(ctx context.Context, name string, host string, rtype string) ([]ResourceRecord, error)
}

type ZoneInfo struct {
	Name            string
	Type            string
	File            string
	LastReloadUnix  int64
	Status          string
	SOA             SOA
	RecordCount     int32
	DNSSECEnabled   bool
	DNSSECAlgorithm string
	Primaries       []string
	LastTransferUnix int64
	NotifySlaves    []string
	AllowTransfer   []string
}

type SOA struct {
	Primary string
	Admin   string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

type ReloadOutcome struct {
	Zone       string
	Success    bool
	Message    string
	OldSerial  uint32
	NewSerial  uint32
	RecordCount int32
	DurationMs int64
	Errors     []string
}

type NotifyOutcome struct {
	Zone    string
	Serial  uint32
	Results []NotifyResult
}

type NotifyResult struct {
	Server       string
	Acknowledged bool
	Message      string
}

type TransferOutcome struct {
	Zone       string
	Type       string
	Success    bool
	OldSerial  uint32
	NewSerial  uint32
	Changed    int32
	DurationMs int64
	Error      string
}

type RecordUpdate struct {
	Operation string // add, delete, replace
	Name      string
	Type      string
	TTL       uint32
	Data      string
	OldData   string
}

type UpdateOutcome struct {
	Zone      string
	Applied   int32
	Failed    int32
	NewSerial uint32
	Results   []UpdateResult
}

type UpdateResult struct {
	Update  RecordUpdate
	Success bool
	Error   string
}

// CacheManager exposes cache controls.
type CacheManager interface {
	Stats(ctx context.Context, backend string) (*CacheStats, error)
	Lookup(ctx context.Context, name, rtype string) ([]CacheEntry, error)
	Flush(ctx context.Context, scope string, domain string, rtype string, includeSubs bool) (*FlushResult, error)
	Prefetch(ctx context.Context, names []string, types []string, priority int32) (*PrefetchOutcome, error)
}

type CacheStats struct {
	Entries     int64
	SizeBytes   int64
	MaxBytes    int64
	Utilization float32
	Hits        int64
	Misses      int64
	HitRate     float32
	ByType      map[string]int64
	AvgTTL      uint32
	MinTTL      uint32
	MaxTTL      uint32
	Evictions   int64
	EvictByReason map[string]int64
	MeasuredAtUnix int64
	Backend     string
}

type CacheEntry struct {
	Name         string
	Type         string
	Class        string
	TTL          uint32
	OriginalTTL  uint32
	Data         []string
	CachedAtUnix int64
	ExpiresAtUnix int64
	Source       string
}

type FlushResult struct {
	Removed int32
	BytesFreed int64
	FlushedAtUnix int64
}

type PrefetchOutcome struct {
	Queued int32
	Errors []string
}

// ControlManager exposes server controls and stats.
type ControlManager interface {
	Status(ctx context.Context, includeResources bool) (*StatusSnapshot, error)
	Stats(ctx context.Context, period string, breakdowns []string) (*StatsSnapshot, error)
	Reload(ctx context.Context, sections []string) (*ReloadReport, error)
	Shutdown(ctx context.Context, timeoutSec int32, force bool) (*ShutdownReport, error)
	Config(ctx context.Context, section string, redact bool) (map[string]string, error)
	License(ctx context.Context) (*LicenseInfo, error)
}

type StatusSnapshot struct {
	Server   ServerInfo
	Health   Health
	Resources Resources
	Network  Network
}

type ServerInfo struct {
	ID      string
	Version string
	Daemon  string
	Uptime  int64
	StartedUnix int64
	Hostname string
}

type Health struct {
	Status    string // healthy, degraded, unhealthy
	Checks    []HealthCheck
}

type HealthCheck struct {
	Name   string
	Status string
	Message string
	ErrorCount int32
}

type Resources struct {
	CPUPercent float32
	MemoryBytes int64
	MemoryPercent float32
	Goroutines int32
	OpenFDs  int32
	MaxFDs   int32
}

type Network struct {
	UDP int32
	TCP int32
	TLS int32
	HTTPS int32
	QUIC int32
}

type StatsSnapshot struct {
	Period   string
	MeasuredAtUnix int64
	Queries  QueryStats
	Latency  LatencyStats
	Cache    CacheStats
	DNSSEC   DNSSECStats
}

type QueryStats struct {
	Total int64
	PerSecond float64
	ByType map[string]int64
	ByRcode map[string]int64
	ByTransport map[string]int64
}

type LatencyStats struct {
	AvgMs float64
	P50Ms float64
	P95Ms float64
	P99Ms float64
	MaxMs float64
}

type DNSSECStats struct {
	Validations int64
	Secure int64
	Insecure int64
	Bogus int64
	Indeterminate int64
}

type ReloadReport struct {
	Success bool
	Message string
	DurationMs int32
	Reloaded []string
	Errors []string
}

type ShutdownReport struct {
	Message string
	GracefulPeriodSec int32
}

type LicenseInfo struct {
	Product string
	Version string
	Licensee string
	IssuedUnix int64
	ExpiresUnix int64
	IsValid bool
	DaysUntilExpiry int32
	Features []string
	Serial string
}

// DNSSECManager exposes DNSSEC management.
type DNSSECManager interface {
	Status(ctx context.Context, zone string) (*DNSSECStatus, error)
	Sign(ctx context.Context, zone string, incSerial bool, resignAll bool) (*SignOutcome, error)
	Rollover(ctx context.Context, zone string, keyType string, newAlgo string, keySize int32) (*RolloverPlan, error)
	GetDS(ctx context.Context, zone string, keyType string) ([]DSRecord, error)
	GenerateKey(ctx context.Context, zone string, typ string, algo string, keySize int32, activate bool) (*KeyMaterial, error)
	ImportKey(ctx context.Context, zone string, typ string, algo string, pub string, priv string, activate bool) (*KeyInfo, error)
	ExportKey(ctx context.Context, zone string, keyID string, includePrivate bool) (*KeyMaterial, error)
	DeleteKey(ctx context.Context, zone string, keyID string, force bool) (*DeleteResult, error)
	ValidateChain(ctx context.Context, zone string, anchors []string) (*ValidationReport, error)
}

type DNSSECStatus struct {
	Zone string
	Enabled bool
	Signed bool
	Algorithm string
	Keys []KeyInfo
	LastValidationUnix int64
	ChainValid bool
	SigsValid bool
	ExpiringSoon bool
	ValidationErrors []string
}

type KeyInfo struct {
	ID string
	KeyTag uint32
	Type string
	Algorithm string
	Status string
	CreatedUnix int64
	ActivatedUnix int64
	InactivatedUnix int64
	DeletedUnix int64
	ExpiresUnix int64
	PublicKey string
	HasPrivate bool
	DS []DSRecord
	KeySize int32
}

type DSRecord struct {
	KeyTag uint32
	Algorithm string
	DigestType uint32
	Digest string
	Record string
}

type SignOutcome struct {
	Zone string
	Success bool
	OldSerial uint32
	NewSerial uint32
	SignaturesCreated int32
	SignaturesUpdated int32
	DurationMs int64
	Errors []string
}

type RolloverPlan struct {
	Zone string
	KeyType string
	Status string
	OldKey KeyInfo
	NewKey KeyInfo
	Timeline []RolloverPhase
}

type RolloverPhase struct {
	Phase string
	ScheduledUnix int64
	CompletedUnix int64
	Status string
}

type KeyMaterial struct {
	Key KeyInfo
	Public string
	Private string
	DS []DSRecord
}

type DeleteResult struct {
	KeyID string
	Success bool
	Message string
}

type ValidationReport struct {
	Zone string
	Valid bool
	Path []string
	Errors []string
}
