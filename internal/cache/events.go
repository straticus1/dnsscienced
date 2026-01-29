package cache

import (
	"sync"
	"sync/atomic"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Broadcaster manages event subscriptions using a lock-free publication model
// optimized for extremely high throughput (4M+ QPS).
type Broadcaster struct {
	mu          sync.Mutex   // Protects writes to subscribers list
	subscribers atomic.Value // Stores []chan *pb.CacheEvent
}

// NewBroadcaster creates a new event broadcaster
func NewBroadcaster() *Broadcaster {
	b := &Broadcaster{}
	b.subscribers.Store(make([]chan *pb.CacheEvent, 0))
	return b
}

// Subscribe adds a channel to the subscribers list
func (b *Broadcaster) Subscribe() chan *pb.CacheEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Load existing subscribers
	existing := b.subscribers.Load().([]chan *pb.CacheEvent)

	// Create new list properly sized
	newSubs := make([]chan *pb.CacheEvent, len(existing)+1)
	copy(newSubs, existing)

	// Create new channel with larger buffer for high throughput
	ch := make(chan *pb.CacheEvent, 1024)
	newSubs[len(existing)] = ch

	// Atomic store
	b.subscribers.Store(newSubs)
	return ch
}

// Unsubscribe removes a channel from the subscribers list
func (b *Broadcaster) Unsubscribe(ch chan *pb.CacheEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	existing := b.subscribers.Load().([]chan *pb.CacheEvent)
	newSubs := make([]chan *pb.CacheEvent, 0, len(existing))

	found := false
	for _, sub := range existing {
		if sub != ch {
			newSubs = append(newSubs, sub)
		} else {
			found = true
		}
	}

	if found {
		b.subscribers.Store(newSubs)
		close(ch)
	}
}

// Publish sends an event to all subscribers non-blocking and LOCK-FREE
func (b *Broadcaster) Publish(eventType pb.CacheEvent_EventType, entry *Entry, reason string) {
	// Fast path: check if any subscribers exist before allocating event
	existing := b.subscribers.Load().([]chan *pb.CacheEvent)
	if len(existing) == 0 {
		return
	}

	// Construct protobuf event
	// Note: Allocation here is necessary, but maybe we can pool events later?
	event := &pb.CacheEvent{
		Type:      eventType,
		Timestamp: timestamppb.Now(),
		Name:      entry.QName,
		Reason:    reason,
		Entry: &pb.CacheEntry{
			Name:         entry.QName,
			ThreatScore:  entry.ThreatScore,
			Categories:   entry.Categories,
			Reputation:   entry.Reputation,
			ThreatSource: entry.ThreatSource,
			FirstSeen:    timestamppb.New(entry.FirstSeen),
			LastSeen:     timestamppb.New(entry.LastSeen),
		},
	}

	for _, ch := range existing {
		select {
		case ch <- event:
		default:
			// Buffer full, drop event to protect core performance
		}
	}
}

// PublishStore publishes a store event
func (b *Broadcaster) PublishStore(entry *Entry) {
	b.Publish(pb.CacheEvent_EVENT_TYPE_STORE, entry, "new_entry")
}
