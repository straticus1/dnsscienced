package transport

import (
	"context"
	"net"
	"sync"

	dnsasm "github.com/dnsscience/dnsscienced/dnsasm/go"
	"github.com/dnsscience/dnsscienced/internal/engine"
	"github.com/miekg/dns"
)

// FastUDPServer is a high-performance UDP DNS server using DNSASM.
// It bypasses the miekg/dns unpacking for initial request parsing
// to achieve maximum throughput.
type FastUDPServer struct {
	mu sync.Mutex

	addr     string
	conn     *net.UDPConn
	resolver *engine.Resolver
	acl      *engine.ACL
	limiter  *engine.RateLimiter
	rpz      *engine.RPZAggregate

	running bool
	done    chan struct{}

	// Stats
	statsLock   sync.RWMutex
	packetsRecv uint64
	packetsSent uint64
	parseErrors uint64
	aclBlocked  uint64
	rateBlocked uint64
	rpzBlocked  uint64
	resolveErrs uint64
}

// FastUDPServerConfig holds configuration for the fast UDP server.
type FastUDPServerConfig struct {
	Addr     string
	Upstream string

	// Security
	Enable0x20      bool
	EnableScrubbing bool
	EnableQNAMEMin  bool
}

// NewFastUDPServer creates a new high-performance UDP DNS server.
func NewFastUDPServer(cfg FastUDPServerConfig) *FastUDPServer {
	resolverCfg := engine.ResolverConfig{
		Upstream:        cfg.Upstream,
		Enable0x20:      cfg.Enable0x20,
		EnableScrubbing: cfg.EnableScrubbing,
		EnableQNAMEMin:  cfg.EnableQNAMEMin,
	}

	return &FastUDPServer{
		addr:     cfg.Addr,
		resolver: engine.NewResolverWithConfig(resolverCfg),
		acl:      engine.NewACL(true), // Default allow
		limiter:  engine.NewRateLimiter(engine.DefaultRateLimiterConfig()),
		rpz:      engine.NewRPZAggregate(),
		done:     make(chan struct{}),
	}
}

// SetACL sets the access control list.
func (s *FastUDPServer) SetACL(acl *engine.ACL) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acl = acl
}

// SetRateLimiter sets the rate limiter.
func (s *FastUDPServer) SetRateLimiter(rl *engine.RateLimiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limiter = rl
}

// AddRPZ adds an RPZ zone to the server.
func (s *FastUDPServer) AddRPZ(rpz *engine.RPZ) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rpz.AddZone(rpz)
}

// Start starts the fast UDP server.
func (s *FastUDPServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	// Set receive buffer for high throughput
	conn.SetReadBuffer(4 * 1024 * 1024) // 4MB
	conn.SetWriteBuffer(4 * 1024 * 1024)

	s.conn = conn
	s.running = true

	// Start worker pool
	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		go s.worker()
	}

	return nil
}

// Stop stops the server.
func (s *FastUDPServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	close(s.done)
	if s.conn != nil {
		s.conn.Close()
	}
	s.running = false
	return nil
}

// Stats returns server statistics.
func (s *FastUDPServer) Stats() map[string]uint64 {
	s.statsLock.RLock()
	defer s.statsLock.RUnlock()
	return map[string]uint64{
		"packets_recv":   s.packetsRecv,
		"packets_sent":   s.packetsSent,
		"parse_errors":   s.parseErrors,
		"acl_blocked":    s.aclBlocked,
		"rate_blocked":   s.rateBlocked,
		"rpz_blocked":    s.rpzBlocked,
		"resolve_errors": s.resolveErrs,
	}
}

func (s *FastUDPServer) worker() {
	buf := make([]byte, 65535)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		s.statsLock.Lock()
		s.packetsRecv++
		s.statsLock.Unlock()

		// Process packet
		go s.handlePacket(buf[:n], addr)
	}
}

func (s *FastUDPServer) handlePacket(packet []byte, addr *net.UDPAddr) {
	// Fast parse header using DNSASM
	header, err := dnsasm.ParseHeader(packet)
	if err != nil {
		s.statsLock.Lock()
		s.parseErrors++
		s.statsLock.Unlock()
		return
	}

	// Skip responses
	if header.QR {
		return
	}

	// Access control
	if !s.acl.IsAllowed(addr.IP) {
		s.statsLock.Lock()
		s.aclBlocked++
		s.statsLock.Unlock()
		s.sendRefused(packet, header.ID, addr)
		return
	}

	// Rate limiting
	if !s.limiter.Allow(addr.IP) {
		s.statsLock.Lock()
		s.rateBlocked++
		s.statsLock.Unlock()
		s.sendRefused(packet, header.ID, addr)
		return
	}

	// Parse question using DNSASM
	if header.QDCount == 0 {
		s.sendFormatError(packet, header.ID, addr)
		return
	}

	question, _, err := dnsasm.ParseQuestion(packet, 12)
	if err != nil {
		s.statsLock.Lock()
		s.parseErrors++
		s.statsLock.Unlock()
		s.sendFormatError(packet, header.ID, addr)
		return
	}

	// RPZ check
	rule, action := s.rpz.Check(question.Name + ".")
	if rule != nil && action != engine.RPZActionPassthru {
		s.statsLock.Lock()
		s.rpzBlocked++
		s.statsLock.Unlock()
		s.handleRPZAction(packet, header.ID, question.Name, action, addr)
		return
	}

	// Resolve - currently fallback to miekg/dns for the actual resolution
	// as we need to forward to upstream
	dnsReq := new(dns.Msg)
	if err := dnsReq.Unpack(packet); err != nil {
		s.sendFormatError(packet, header.ID, addr)
		return
	}

	result, err := s.resolver.Resolve(
		context.Background(),
		question.Name+".",
		dns.TypeToString[question.Type],
		dns.ClassToString[question.Class],
		dnsReq.IsEdns0() != nil,
		header.RD,
		false, // CheckingDisabled
	)
	if err != nil {
		s.statsLock.Lock()
		s.resolveErrs++
		s.statsLock.Unlock()
		s.sendServFail(packet, header.ID, addr)
		return
	}

	// Send response
	s.conn.WriteToUDP(result.Wire, addr)
	s.statsLock.Lock()
	s.packetsSent++
	s.statsLock.Unlock()
}

func (s *FastUDPServer) sendRefused(origPacket []byte, id uint16, addr *net.UDPAddr) {
	resp := make([]byte, 512)
	flags := uint16(dnsasm.FlagQR | dnsasm.FlagRA | dnsasm.RCodeRefused)
	n := dnsasm.BuildHeader(resp, id, flags, 0, 0, 0, 0)
	s.conn.WriteToUDP(resp[:n], addr)
}

func (s *FastUDPServer) sendFormatError(origPacket []byte, id uint16, addr *net.UDPAddr) {
	resp := make([]byte, 512)
	flags := uint16(dnsasm.FlagQR | dnsasm.FlagRA | dnsasm.RCodeFormErr)
	n := dnsasm.BuildHeader(resp, id, flags, 0, 0, 0, 0)
	s.conn.WriteToUDP(resp[:n], addr)
}

func (s *FastUDPServer) sendServFail(origPacket []byte, id uint16, addr *net.UDPAddr) {
	resp := make([]byte, 512)
	flags := uint16(dnsasm.FlagQR | dnsasm.FlagRA | dnsasm.RCodeServFail)
	n := dnsasm.BuildHeader(resp, id, flags, 0, 0, 0, 0)
	s.conn.WriteToUDP(resp[:n], addr)
}

func (s *FastUDPServer) handleRPZAction(origPacket []byte, id uint16, name string, action engine.RPZAction, addr *net.UDPAddr) {
	resp := make([]byte, 512)
	var flags uint16

	switch action {
	case engine.RPZActionNXDomain:
		flags = uint16(dnsasm.FlagQR | dnsasm.FlagRA | dnsasm.RCodeNXDomain)
	case engine.RPZActionNoData:
		flags = uint16(dnsasm.FlagQR | dnsasm.FlagRA | dnsasm.RCodeNoError)
	case engine.RPZActionDrop:
		// Don't respond at all
		return
	default:
		flags = uint16(dnsasm.FlagQR | dnsasm.FlagRA | dnsasm.RCodeNoError)
	}

	n := dnsasm.BuildHeader(resp, id, flags, 0, 0, 0, 0)
	s.conn.WriteToUDP(resp[:n], addr)
}
