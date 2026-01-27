package server

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
)

type Config struct {
	ListenAddr   string   // e.g. ":8443"
	TLSCertFile  string
	TLSKeyFile   string
	APIKeys      []string // optional static API keys (via "authorization: Bearer <key>")
}

type Deps struct {
	Register func(s *grpc.Server) // function to register all service servers
	Unary    []grpc.UnaryServerInterceptor
	Stream   []grpc.StreamServerInterceptor
}

// New creates a TLS gRPC server with basic auth interceptors.
func New(cfg Config, deps Deps) (*grpc.Server, net.Listener, error) {
	var opts []grpc.ServerOption

	// TLS config
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("tls: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// Interceptors (chain)
	unaries := append([]grpc.UnaryServerInterceptor{apiKeyUnaryInterceptor(cfg.APIKeys)}, deps.Unary...)
	streams := append([]grpc.StreamServerInterceptor{apiKeyStreamInterceptor(cfg.APIKeys)}, deps.Stream...)
	opts = append(opts,
		grpc.ChainUnaryInterceptor(unaries...),
		grpc.ChainStreamInterceptor(streams...),
	)

	gs := grpc.NewServer(opts...)
	if deps.Register != nil {
		deps.Register(gs)
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, nil, err
	}
	return gs, ln, nil
}

func apiKeyUnaryInterceptor(validKeys []string) grpc.UnaryServerInterceptor {
	set := make(map[string]struct{}, len(validKeys))
	for _, k := range validKeys {
		set[k] = struct{}{}
	}
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if len(set) > 0 {
			md, _ := metadata.FromIncomingContext(ctx)
			if !authorize(md, set) {
				return nil, status.Error(codes.Unauthenticated, "unauthenticated")
			}
		}
		return handler(ctx, req)
	}
}

func apiKeyStreamInterceptor(validKeys []string) grpc.StreamServerInterceptor {
	set := make(map[string]struct{}, len(validKeys))
	for _, k := range validKeys {
		set[k] = struct{}{}
	}
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if len(set) > 0 {
			md, _ := metadata.FromIncomingContext(ss.Context())
			if !authorize(md, set) {
				return status.Error(codes.Unauthenticated, "unauthenticated")
			}
		}
		return handler(srv, ss)
	}
}

func authorize(md metadata.MD, set map[string]struct{}) bool {
	if md == nil {
		return false
	}
	vals := md.Get("authorization")
	for _, v := range vals {
		var token string
		fmt.Sscanf(v, "Bearer %s", &token)
		if _, ok := set[token]; ok {
			return true
		}
	}
	return false
}
