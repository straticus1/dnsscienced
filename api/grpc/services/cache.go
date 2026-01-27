package services

import (
	"context"

	"github.com/dnsscience/dnsscienced/api/grpc/ports"
	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CacheService struct {
	pb.UnimplementedCacheServiceServer
	Mgr ports.CacheManager
}

func NewCacheService(m ports.CacheManager) *CacheService { return &CacheService{Mgr: m} }

func (s *CacheService) GetStats(ctx context.Context, in *pb.GetCacheStatsRequest) (*pb.GetCacheStatsResponse, error) {
	st, err := s.Mgr.Stats(ctx, in.GetBackend())
	if err != nil { return nil, err }
	return &pb.GetCacheStatsResponse{Stats: &pb.CacheStats{Entries: st.Entries, SizeBytes: st.SizeBytes, MaxBytes: st.MaxBytes, Utilization: float32(st.Utilization), Hits: st.Hits, Misses: st.Misses, HitRate: float32(st.HitRate), ByType: st.ByType, AvgTtlSeconds: st.AvgTTL, MinTtlSeconds: st.MinTTL, MaxTtlSeconds: st.MaxTTL, EvictionsTotal: st.Evictions, EvictionsByReason: st.EvictByReason, Backend: st.Backend}}, nil
}

func (s *CacheService) Lookup(ctx context.Context, in *pb.CacheLookupRequest) (*pb.CacheLookupResponse, error) {
	entries, err := s.Mgr.Lookup(ctx, in.GetName(), in.GetType())
	if err != nil { return nil, err }
	resp := &pb.CacheLookupResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &pb.CacheEntry{Name: e.Name, Type: e.Type, Class: e.Class, Ttl: e.TTL, OriginalTtl: e.OriginalTTL, Data: e.Data, Source: e.Source})
	}
	resp.Count = int32(len(resp.Entries))
	return resp, nil
}

func (s *CacheService) Flush(ctx context.Context, in *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
	fr, err := s.Mgr.Flush(ctx, in.GetScope().String(), in.GetDomain(), in.GetType(), in.GetIncludeSubdomains())
	if err != nil { return nil, err }
	return &pb.FlushCacheResponse{EntriesRemoved: fr.Removed, BytesFreed: fr.BytesFreed}, nil
}

func (s *CacheService) Prefetch(ctx context.Context, in *pb.PrefetchRequest) (*pb.PrefetchResponse, error) {
	pr, err := s.Mgr.Prefetch(ctx, in.GetNames(), in.GetTypes(), in.GetPriority())
	if err != nil { return nil, err }
	return &pb.PrefetchResponse{Queued: pr.Queued, Errors: pr.Errors}, nil
}

func (s *CacheService) WatchCache(*pb.WatchCacheRequest, pb.CacheService_WatchCacheServer) error {
	return status.Error(codes.Unimplemented, "WatchCache not implemented yet")
}
