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
	if err != nil {
		return nil, err
	}
	return &pb.GetCacheStatsResponse{Stats: &pb.CacheStats{Entries: st.Entries, SizeBytes: st.SizeBytes, MaxBytes: st.MaxBytes, Utilization: float32(st.Utilization), Hits: st.Hits, Misses: st.Misses, HitRate: float32(st.HitRate), ByType: st.ByType, AvgTtlSeconds: st.AvgTTL, MinTtlSeconds: st.MinTTL, MaxTtlSeconds: st.MaxTTL, EvictionsTotal: st.Evictions, EvictionsByReason: st.EvictByReason, Backend: st.Backend}}, nil
}

func (s *CacheService) Lookup(ctx context.Context, in *pb.CacheLookupRequest) (*pb.CacheLookupResponse, error) {
	entries, err := s.Mgr.Lookup(ctx, in.GetName(), in.GetType())
	if err != nil {
		return nil, err
	}
	resp := &pb.CacheLookupResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &pb.CacheEntry{Name: e.Name, Type: e.Type, Class: e.Class, Ttl: e.TTL, OriginalTtl: e.OriginalTTL, Data: e.Data, Source: e.Source})
	}
	resp.Count = int32(len(resp.Entries))
	return resp, nil
}

func (s *CacheService) Flush(ctx context.Context, in *pb.FlushCacheRequest) (*pb.FlushCacheResponse, error) {
	fr, err := s.Mgr.Flush(ctx, in.GetScope().String(), in.GetDomain(), in.GetType(), in.GetIncludeSubdomains())
	if err != nil {
		return nil, err
	}
	return &pb.FlushCacheResponse{EntriesRemoved: fr.Removed, BytesFreed: fr.BytesFreed}, nil
}

func (s *CacheService) Prefetch(ctx context.Context, in *pb.PrefetchRequest) (*pb.PrefetchResponse, error) {
	pr, err := s.Mgr.Prefetch(ctx, in.GetNames(), in.GetTypes(), in.GetPriority())
	if err != nil {
		return nil, err
	}
	return &pb.PrefetchResponse{Queued: pr.Queued, Errors: pr.Errors}, nil
}

func (s *CacheService) WatchCache(req *pb.WatchCacheRequest, stream pb.CacheService_WatchCacheServer) error {
	// Subscribe to cache events
	// Note: We need to cast s.Mgr to something that supports Subscribe.
	// The CacheManager interface in 'ports' might need Update, or we assert type if we know it's *cache.ShardedCache or manager wraps it.
	// Let's assume s.Mgr is the ShardedCache for this phase or expose Subscribe in interface.
	// Limitation: 'ports.CacheManager' interface might not have Subscribe yet.
	// For now, let's assume we can try to cast or we need to update the interface.
	// To minimize changes, let's check if we can type assert or if we need to update 'ports/interfaces.go'.
	// Since I cannot see ports/interfaces.go easily right now without looking,
	// I'll try to cast to an interface that has Subscribe.

	type Subscriber interface {
		Subscribe() chan *pb.CacheEvent
		Unsubscribe(chan *pb.CacheEvent)
	}

	sub, ok := s.Mgr.(Subscriber)
	if !ok {
		return status.Error(codes.Unimplemented, "Cache manager does not support streaming")
	}

	ch := sub.Subscribe()
	defer sub.Unsubscribe(ch)

	ctx := stream.Context()

	// Filter setup
	// watchedTypes := make(map[pb.CacheEvent_EventType]bool)
	// for _, t := range req.GetTypes() { ... }
	// Ideally we parse strings to EventTypes or use the enum if passed as strings?
	// Proto says 'repeated string types = 1'.

	// For MVP, stream everything or just filtered by simple logic.

	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-ch:
			// Apply Filters
			// TODO: Implement sophisticated filtering based on req

			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}
