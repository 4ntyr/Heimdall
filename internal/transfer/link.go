package transfer

import (
	"context"
	"fmt"

	"github.com/4ntyr/heimdall/internal/peers"
)

// Direction says which way a transfer moves.
type Direction int

const (
	// Outgoing is a file this node is sending.
	Outgoing Direction = iota
	// Incoming is a file this node is receiving.
	Incoming
)

func (d Direction) String() string {
	if d == Outgoing {
		return "out"
	}
	return "in"
}

// Link is the session capability this package needs.
//
// It is declared here and implemented by internal/session, which keeps the
// dependency pointing one way: this package never imports the session, so it
// stays testable with no socket and no handshake.
type Link interface {
	// PeerName is the peer's display name. A label only, never an identity.
	PeerName() string
	// PeerFingerprint identifies the peer, and names its download directory.
	PeerFingerprint() string
	// Trust is the peer's current trust level.
	Trust() peers.TrustLevel
	// Path reports how the connection was established, so a relayed
	// transfer can be judged against the circuit budget.
	Path() string
	// BytesSent is what this connection has written at the framing layer.
	BytesSent() int64
	// SendControl queues a control frame. It must not block.
	SendControl(typ byte, payload []byte) error
	// SendBulk queues a bulk frame, blocking until there is room so that
	// backpressure reaches the file reader.
	SendBulk(ctx context.Context, typ byte, payload []byte) error
	// TransferStarted and TransferFinished bracket a transfer so the session
	// can protect the connection from being replaced mid-file.
	TransferStarted()
	TransferFinished()
	// Notify reports progress. It must not block, and nothing in this
	// package may depend on a notification being delivered.
	Notify(Progress)
}

// RelayPath is the Path() value meaning the connection runs through a relay.
// It matches session.PathRelay, restated to avoid importing the session.
const RelayPath = "RELAY"

// State is where a transfer has got to.
type State int

const (
	// Offered means an offer has been sent or received, with no data yet.
	Offered State = iota
	// Running means chunks are moving.
	Running
	// Done means the file arrived and its digest matched.
	Done
	// Failed means the transfer stopped without completing.
	Failed
)

func (s State) String() string {
	switch s {
	case Offered:
		return "offered"
	case Running:
		return "running"
	case Done:
		return "done"
	case Failed:
		return "failed"
	}
	return "unknown"
}

// Progress describes a transfer at one moment. Values are absolute, never
// deltas, so a dropped notification costs nothing: the next one is still
// correct on its own.
type Progress struct {
	ID        uint64
	Direction Direction
	Peer      string
	Name      string
	Size      int64
	Done      int64
	State     State
	// Path is the published location, set once State is Done.
	Path string
	// Err explains a Failed transfer.
	Err error
}

// Percent reports completion, or 0 when the size is unknown.
func (p Progress) Percent() int {
	if p.Size <= 0 {
		return 0
	}
	if p.Done >= p.Size {
		return 100
	}
	return int(p.Done * 100 / p.Size)
}

// String renders a transfer for a terminal. The filename is quoted because a
// peer chose it.
func (p Progress) String() string {
	return fmt.Sprintf("%s %s %s %d%% (%d/%d bytes) %s",
		p.Direction, DisplayName(p.Name), p.State, p.Percent(), p.Done, p.Size, p.Peer)
}

// relayBudgetExceeded reports whether sending size more payload bytes over
// this link would carry it past the share of the relay's circuit budget we are
// willing to commit.
//
// Only the sending side can judge this: the budget is per direction, and the
// receiver cannot see what the sender has already spent. A relay enforces the
// ceiling by closing the circuit without a word, and a live session is never
// migrated off the relay (docs/rendezvous.md §8.1), so refusing up front is
// the only way the user learns why.
func relayBudgetExceeded(l Link, lim Limits, size int64) bool {
	if l.Path() != RelayPath {
		return false
	}
	if lim.RelayCircuitBytes <= 0 {
		return false
	}
	projected := float64(l.BytesSent()) + float64(size)*relayOverhead
	return projected > float64(lim.RelayCircuitBytes)*lim.RelayBudgetFraction
}
