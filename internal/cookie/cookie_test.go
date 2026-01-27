package cookie

import (
	"bytes"
	"net"
	"testing"
)

func TestGenerateClientCookie(t *testing.T) {
	clientIP := net.ParseIP("192.0.2.1").To4()
	serverIP := net.ParseIP("192.0.2.53").To4()

	cookie1 := GenerateClientCookie(clientIP, serverIP)
	cookie2 := GenerateClientCookie(clientIP, serverIP)

	// Cookies should be different (include random component)
	if bytes.Equal(cookie1[:], cookie2[:]) {
		t.Error("client cookies should be unique")
	}

	// Should be correct size
	if len(cookie1) != clientCookieSize {
		t.Errorf("client cookie size = %d, want %d", len(cookie1), clientCookieSize)
	}
}

func TestGenerateServerCookie(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Should be correct size
	if len(serverCookie) != serverCookieSize {
		t.Errorf("server cookie size = %d, want %d", len(serverCookie), serverCookieSize)
	}

	// Same input should produce same output (deterministic)
	serverCookie2, _ := m.GenerateServerCookie(clientCookie, clientIP)

	// Note: This will fail if more than 1 second passes between calls
	// because timestamp is included. In production, we'd mock time.Now()
	if !bytes.Equal(serverCookie[:], serverCookie2[:]) {
		t.Error("same input should produce same server cookie (within same second)")
	}
}

func TestValidateServerCookie(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// Generate valid cookie
	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Should validate successfully
	err = m.ValidateServerCookie(clientCookie, serverCookie, clientIP)
	if err != nil {
		t.Errorf("ValidateServerCookie() should succeed, got error: %v", err)
	}

	// Invalid cookie should fail
	var invalidCookie [8]byte
	copy(invalidCookie[:], []byte("invalid!"))

	err = m.ValidateServerCookie(clientCookie, invalidCookie, clientIP)
	if err == nil {
		t.Error("ValidateServerCookie() should fail for invalid cookie")
	}

	// Wrong client IP should fail
	wrongIP := net.ParseIP("192.0.2.99").To4()
	err = m.ValidateServerCookie(clientCookie, serverCookie, wrongIP)
	if err == nil {
		t.Error("ValidateServerCookie() should fail for wrong client IP")
	}
}

func TestValidateServerCookie_Rotation(t *testing.T) {
	cfg := Config{Enabled: true}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// Generate cookie with current secret
	serverCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() error: %v", err)
	}

	// Rotate secret
	if err := m.rotateSecret(); err != nil {
		t.Fatalf("rotateSecret() error: %v", err)
	}

	// Old cookie should still validate (using previous secret)
	err = m.ValidateServerCookie(clientCookie, serverCookie, clientIP)
	if err != nil {
		t.Errorf("ValidateServerCookie() should accept cookie from previous secret, got error: %v", err)
	}

	// New cookie with new secret should also validate
	newServerCookie, err := m.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("GenerateServerCookie() after rotation error: %v", err)
	}

	err = m.ValidateServerCookie(clientCookie, newServerCookie, clientIP)
	if err != nil {
		t.Errorf("ValidateServerCookie() should accept new cookie, got error: %v", err)
	}
}

func TestParseCookie(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		wantClientLen  int
		wantServerLen  int
		wantErr        bool
	}{
		{
			name:          "client cookie only",
			data:          []byte{1, 2, 3, 4, 5, 6, 7, 8},
			wantClientLen: 8,
			wantServerLen: 0,
			wantErr:       false,
		},
		{
			name:          "client + server cookie",
			data:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			wantClientLen: 8,
			wantServerLen: 8,
			wantErr:       false,
		},
		{
			name:    "too short",
			data:    []byte{1, 2, 3},
			wantErr: true,
		},
		{
			name:    "server cookie too long (>32 bytes)",
			data:    make([]byte, 8+33), // client + 33 byte server
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientCookie, serverCookie, err := ParseCookie(tt.data)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(clientCookie) != tt.wantClientLen {
					t.Errorf("client cookie len = %d, want %d", len(clientCookie), tt.wantClientLen)
				}
				if len(serverCookie) != tt.wantServerLen {
					t.Errorf("server cookie len = %d, want %d", len(serverCookie), tt.wantServerLen)
				}
			}
		})
	}
}

func TestFormatCookie(t *testing.T) {
	var clientCookie [8]byte
	copy(clientCookie[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	// Client cookie only
	data := FormatCookie(clientCookie, nil)
	if len(data) != 8 {
		t.Errorf("format client only: len = %d, want 8", len(data))
	}
	if !bytes.Equal(data, clientCookie[:]) {
		t.Error("format client only: data mismatch")
	}

	// Client + server cookie
	serverCookie := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	data = FormatCookie(clientCookie, serverCookie)
	if len(data) != 16 {
		t.Errorf("format client+server: len = %d, want 16", len(data))
	}

	// Parse back
	parsedClient, parsedServer, err := ParseCookie(data)
	if err != nil {
		t.Fatalf("parse formatted cookie: %v", err)
	}
	if !bytes.Equal(parsedClient[:], clientCookie[:]) {
		t.Error("parsed client cookie mismatch")
	}
	if !bytes.Equal(parsedServer, serverCookie) {
		t.Error("parsed server cookie mismatch")
	}
}

func TestValidateQueryCookie(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		RequireValid: true,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// First query - no server cookie (should be OK)
	badCookie, err := m.ValidateQueryCookie(clientCookie, nil, clientIP)
	if badCookie || err != nil {
		t.Error("first query without server cookie should be accepted")
	}

	// Generate valid server cookie
	serverCookie, _ := m.GenerateServerCookie(clientCookie, clientIP)

	// Query with valid cookie
	badCookie, err = m.ValidateQueryCookie(clientCookie, serverCookie[:], clientIP)
	if badCookie || err != nil {
		t.Error("query with valid cookie should be accepted")
	}

	// Query with invalid cookie (RequireValid=true should reject)
	var invalidServer [8]byte
	copy(invalidServer[:], []byte("badsecrt"))
	badCookie, err = m.ValidateQueryCookie(clientCookie, invalidServer[:], clientIP)
	if !badCookie {
		t.Error("query with invalid cookie should trigger BADCOOKIE when RequireValid=true")
	}
}

func TestValidateQueryCookie_NotRequired(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		RequireValid: false, // Don't require valid cookie
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	// Invalid cookie but RequireValid=false
	var invalidServer [8]byte
	copy(invalidServer[:], []byte("badsecrt"))
	badCookie, err := m.ValidateQueryCookie(clientCookie, invalidServer[:], clientIP)
	if badCookie {
		t.Error("invalid cookie should be accepted when RequireValid=false")
	}
}

func TestClusterSecret(t *testing.T) {
	// Create shared cluster secret
	clusterSecret := []byte("shared-cluster-secret-1234567890")

	cfg1 := Config{
		Enabled:       true,
		ClusterSecret: clusterSecret,
	}
	m1, err := NewManager(cfg1)
	if err != nil {
		t.Fatalf("NewManager(m1) error: %v", err)
	}

	cfg2 := Config{
		Enabled:       true,
		ClusterSecret: clusterSecret,
	}
	m2, err := NewManager(cfg2)
	if err != nil {
		t.Fatalf("NewManager(m2) error: %v", err)
	}

	// Both servers should generate same server cookie
	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	copy(clientCookie[:], []byte("testcook"))

	cookie1, err := m1.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("m1.GenerateServerCookie() error: %v", err)
	}

	cookie2, err := m2.GenerateServerCookie(clientCookie, clientIP)
	if err != nil {
		t.Fatalf("m2.GenerateServerCookie() error: %v", err)
	}

	// Cookies should match (same secret)
	if !bytes.Equal(cookie1[:], cookie2[:]) {
		t.Error("servers with same cluster secret should generate same cookie")
	}

	// Each server should validate the other's cookies
	err = m1.ValidateServerCookie(clientCookie, cookie2, clientIP)
	if err != nil {
		t.Errorf("m1 should validate m2's cookie: %v", err)
	}

	err = m2.ValidateServerCookie(clientCookie, cookie1, clientIP)
	if err != nil {
		t.Errorf("m2 should validate m1's cookie: %v", err)
	}
}

func TestCookiesDisabled(t *testing.T) {
	cfg := Config{
		Enabled: false, // Cookies disabled
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	var serverCookie [8]byte

	// Should always accept when disabled
	badCookie, err := m.ValidateQueryCookie(clientCookie, serverCookie[:], clientIP)
	if badCookie || err != nil {
		t.Error("disabled cookies should always accept")
	}
}

// Benchmark cookie generation
func BenchmarkGenerateServerCookie(b *testing.B) {
	cfg := Config{Enabled: true}
	m, _ := NewManager(cfg)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.GenerateServerCookie(clientCookie, clientIP)
	}
}

// Benchmark cookie validation
func BenchmarkValidateServerCookie(b *testing.B) {
	cfg := Config{Enabled: true}
	m, _ := NewManager(cfg)

	clientIP := net.ParseIP("192.0.2.1").To4()
	var clientCookie [8]byte
	serverCookie, _ := m.GenerateServerCookie(clientCookie, clientIP)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ValidateServerCookie(clientCookie, serverCookie, clientIP)
	}
}
