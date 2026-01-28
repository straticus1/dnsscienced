package cache

import (
	"sync"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Broadcaster manages event subscriptions
type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[chan *pb.CacheEvent]struct{}
}

// NewBroadcaster creates a new event broadcaster
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan *pb.CacheEvent]struct{}),
	}
}

// Subscribe adds a channel to the subscribers list
// The returned channel is the same as the input, provided for convenience
func (b *Broadcaster) Subscribe() chan *pb.CacheEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan *pb.CacheEvent, 100) // Buffer to prevent blocking the broadcaster
	b.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a channel from the subscribers list
func (b *Broadcaster) Unsubscribe(ch chan *pb.CacheEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// Publish sends an event to all subscribers non-blocking
func (b *Broadcaster) Publish(eventType pb.CacheEvent_EventType, entry *Entry, reason string) {
	// Construct protobuf event
	event := &pb.CacheEvent{
		Type:      eventType,
		Timestamp: timestamppb.Now(),
		Name:      entry.QName,
		// QueryType: entry.QType, // Need to convert uint16 to string or map
		Reason: reason,
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

	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subscribers {
		select {
		case ch <- event:
		default:
			// Buffer full, drop event for this slow subscriber
			// In production, might want to count dropped events or kick slow consumer
		}
	}
}

// PublishHit publishes a cache hit event
func (b *Broadcaster) PublishHit(entry *Entry) {
	b.Publish(pb.CacheEvent_EVENT_TYPE_HIT, entry, "")
}

// PublishMiss publishes a cache miss event (technically miss usually doesn't have an Entry yet.. but maybe we pass what we looked for?)
// For miss, we might not have a full entry. Let's adjust Publish to take optional entry.
// For now, let's assume we use it when we STORE (which is separate).
// Miss events might be harder if we don't have an Entry struct.
// Let's focus on Threat Intelligence: We care about STORE (new threat) and EVICT.
// Hit/Miss checks are high volume.
func (b *Broadcaster) PublishStore(entry *Entry) {
	b.Publish(pb.CacheEvent_EVENT_TYPE_STORE, entry, "new_entry")
}
