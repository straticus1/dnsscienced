package transport

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DoHListener implements a DNS-over-HTTPS listener per RFC 8484.
type DoHListener struct {
	mu       sync.Mutex
	addr     string
	server   *http.Server
	handler  Handler
	running  bool
	listener net.Listener
}

// DoHConfig holds configuration for the DoH listener.
type DoHConfig struct {
	Address   string        // Listen address (default ":443")
	Path      string        // URL path for DNS queries (default "/dns-query")
	TLSConfig *tls.Config   // TLS configuration
	CertFile  string        // Path to TLS certificate (if TLSConfig not provided)
	KeyFile   string        // Path to TLS private key (if TLSConfig not provided)
	Timeout   time.Duration // Request timeout
}

// NewDoHListener creates a new DNS-over-HTTPS listener.
func NewDoHListener(cfg DoHConfig, handler Handler) (*DoHListener, error) {
	if cfg.Address == "" {
		cfg.Address = ":443"
	}
	if cfg.Path == "" {
		cfg.Path = "/dns-query"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	var tlsConfig *tls.Config
	if cfg.TLSConfig != nil {
		tlsConfig = cfg.TLSConfig.Clone()
	} else if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	} else {
		return nil, fmt.Errorf("TLS configuration required: provide TLSConfig or CertFile/KeyFile")
	}

	l := &DoHListener{
		addr:    cfg.Address,
		handler: handler,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Path, l.handleDoH)

	l.server = &http.Server{
		Addr:         cfg.Address,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  cfg.Timeout,
		WriteTimeout: cfg.Timeout,
		IdleTimeout:  30 * time.Second,
	}

	return l, nil
}

// Start begins accepting connections.
func (l *DoHListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("listener already running")
	}

	listener, err := tls.Listen("tcp", l.addr, l.server.TLSConfig)
	if err != nil {
		return fmt.Errorf("failed to start HTTPS listener: %w", err)
	}

	l.listener = listener
	l.running = true

	go func() {
		l.server.Serve(listener)
	}()

	return nil
}

// Stop gracefully stops the listener.
func (l *DoHListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return nil
	}
	l.running = false

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return l.server.Shutdown(ctx)
}

// Addr returns the listener's address.
func (l *DoHListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Addr()
	}
	return nil
}

func (l *DoHListener) handleDoH(w http.ResponseWriter, r *http.Request) {
	var dnsRequest *dns.Msg
	var err error

	switch r.Method {
	case http.MethodGet:
		// GET method: DNS query in ?dns= parameter (base64url encoded)
		dnsRequest, err = l.parseGET(r)
	case http.MethodPost:
		// POST method: DNS query in request body
		dnsRequest, err = l.parsePOST(r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Bad request: %v", err), http.StatusBadRequest)
		return
	}

	// Handle the DNS query
	ctx := r.Context()
	dnsResponse, err := l.handler.HandleDNS(ctx, dnsRequest)
	if err != nil {
		// Return SERVFAIL
		dnsResponse = new(dns.Msg)
		dnsResponse.SetRcode(dnsRequest, dns.RcodeServerFailure)
	}

	// Serialize response
	respBytes, err := dnsResponse.Pack()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set appropriate headers
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", l.getCacheControl(dnsResponse))
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

func (l *DoHListener) parseGET(r *http.Request) (*dns.Msg, error) {
	dnsParam := r.URL.Query().Get("dns")
	if dnsParam == "" {
		return nil, fmt.Errorf("missing 'dns' query parameter")
	}

	// Decode base64url-encoded DNS message
	// Handle both padded and unpadded base64url
	dnsParam = strings.ReplaceAll(dnsParam, "-", "+")
	dnsParam = strings.ReplaceAll(dnsParam, "_", "/")

	// Add padding if needed
	switch len(dnsParam) % 4 {
	case 2:
		dnsParam += "=="
	case 3:
		dnsParam += "="
	}

	msgBytes, err := base64.StdEncoding.DecodeString(dnsParam)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBytes); err != nil {
		return nil, fmt.Errorf("invalid DNS message: %w", err)
	}

	return msg, nil
}

func (l *DoHListener) parsePOST(r *http.Request) (*dns.Msg, error) {
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/dns-message") {
		return nil, fmt.Errorf("unsupported content type: %s", contentType)
	}

	// Limit request body size
	body, err := io.ReadAll(io.LimitReader(r.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("invalid DNS message: %w", err)
	}

	return msg, nil
}

func (l *DoHListener) getCacheControl(resp *dns.Msg) string {
	// Find the minimum TTL in the response
	minTTL := uint32(300) // Default 5 minutes

	for _, rr := range resp.Answer {
		if ttl := rr.Header().Ttl; ttl < minTTL {
			minTTL = ttl
		}
	}

	if resp.Rcode != dns.RcodeSuccess {
		// Negative responses - shorter cache time
		return "max-age=60"
	}

	return fmt.Sprintf("max-age=%d", minTTL)
}
