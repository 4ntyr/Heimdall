// Package transfer moves files over an established Heimdall session
// (docs/protocol.md §13).
//
// It owns chunking, reassembly, incremental digests, filename safety, the
// download directory and the local limits a peer cannot influence. It knows
// nothing about sockets or the terminal: frames leave through a Link the
// session layer implements, and progress goes back the same way for the
// session to turn into a user-visible event.
package transfer

import "time"

// Limits bounds what a peer can cause locally. Every field is the receiver's
// own; nothing a sender declares relaxes one.
//
// The shape follows internal/relay/limits.go so tests can inject small values
// instead of exercising the real ceilings.
type Limits struct {
	// MaxFileSize is the largest file that will be accepted, in bytes.
	MaxFileSize int64
	// MaxPerPeer bounds concurrent transfers with any one peer.
	MaxPerPeer int
	// MaxTotal bounds concurrent transfers across all peers.
	MaxTotal int
	// Stall is how long a transfer may make no progress before it is
	// cancelled.
	Stall time.Duration
	// RelayCircuitBytes mirrors the relay's per-direction circuit budget
	// (docs/rendezvous.md §6). A relayed transfer that would carry the
	// connection past RelayBudgetFraction of it is refused up front, because
	// the relay enforces the ceiling by silently closing the circuit. A
	// self-hosted relay may be configured differently; this is the
	// documented default, not something the relay tells us.
	RelayCircuitBytes int64
	// RelayBudgetFraction is how much of RelayCircuitBytes may be committed
	// before an offer is refused.
	RelayBudgetFraction float64
	// AcceptIncoming reports whether offers are accepted at all. When false
	// every offer is refused with CancelRefused.
	AcceptIncoming bool
}

// DefaultLimits returns the documented defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxFileSize:         1 << 30, // 1 GiB
		MaxPerPeer:          4,
		MaxTotal:            16,
		Stall:               60 * time.Second,
		RelayCircuitBytes:   256 << 20,
		RelayBudgetFraction: 0.9,
		AcceptIncoming:      true,
	}
}

// chunkWireCost is what one full chunk costs a relay: the transport length
// prefix, the frame header, the nonce, the payload and the tag. Used to judge
// a transfer against the circuit budget before starting it.
const chunkWireCost = 4 + 22 + 12 + 4080 + 16

// relayOverhead is chunkWireCost as a multiplier over payload bytes (~1.32%).
const relayOverhead = float64(chunkWireCost) / 4080.0
