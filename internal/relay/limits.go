package relay

import (
	"sync"
	"time"
)

// Limits bound everything a stranger can make the relay do
// (docs/rendezvous.md §6). A relay is public infrastructure exposed to anyone
// who can reach port 443, so every quantity it tracks has a ceiling.
type Limits struct {
	// CodeTTL is how long an unclaimed invite code stays published.
	CodeTTL time.Duration
	// MaxPendingCodes bounds unclaimed codes across the whole relay.
	MaxPendingCodes int
	// MaxCircuits bounds concurrent relayed circuits.
	MaxCircuits int
	// CircuitIdle closes a circuit that has carried nothing for this long.
	CircuitIdle time.Duration
	// CircuitLifetime closes a circuit regardless of activity.
	CircuitLifetime time.Duration
	// CircuitBytes bounds bytes copied in each direction of a circuit.
	CircuitBytes int64
	// MaxConnsPerIP bounds concurrent connections from one source address.
	MaxConnsPerIP int
	// PublishesPerIPPerMin bounds how fast one source can publish codes.
	PublishesPerIPPerMin int
	// PunchDelay is the relative delay peers are told to wait before
	// punching, which gives both sides time to receive their pairing.
	PunchDelay time.Duration
}

// DefaultLimits returns the documented defaults.
func DefaultLimits() Limits {
	return Limits{
		CodeTTL:              5 * time.Minute,
		MaxPendingCodes:      4096,
		MaxCircuits:          512,
		CircuitIdle:          90 * time.Second,
		CircuitLifetime:      12 * time.Hour,
		CircuitBytes:         256 << 20,
		MaxConnsPerIP:        32,
		PublishesPerIPPerMin: 30,
		PunchDelay:           250 * time.Millisecond,
	}
}

// rateCounter is a fixed-window counter, which is all the precision a
// per-minute publish cap needs.
type rateCounter struct {
	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	count int
	start time.Time
}

func newRateCounter() *rateCounter {
	return &rateCounter{windows: make(map[string]*window)}
}

// allow records an event for key and reports whether it stays under limit.
func (r *rateCounter) allow(key string, limit int, per time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	w, ok := r.windows[key]
	if !ok || now.Sub(w.start) > per {
		r.windows[key] = &window{count: 1, start: now}
		return true
	}
	if w.count >= limit {
		return false
	}
	w.count++
	return true
}

// sweep drops windows that have fallen out of scope, so the map cannot grow
// without bound from one-off source addresses.
func (r *rateCounter) sweep(per time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, w := range r.windows {
		if now.Sub(w.start) > per {
			delete(r.windows, k)
		}
	}
}
