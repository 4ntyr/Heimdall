package rendezvous

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Control message types (docs/rendezvous.md §3.1).
const (
	MsgPublish   = "publish"
	MsgPublished = "published"
	MsgClaim     = "claim"
	MsgPaired    = "paired"
	MsgCircuit   = "circuit"
	MsgCircuitOK = "circuit_ok"
	MsgError     = "error"
	MsgBye       = "bye"
)

// Rendezvous roles. The publisher is the handshake responder and the claimer
// is the handshake initiator. Roles come from the rendezvous rather than from
// which socket won the race, so both peers agree even when hole punching
// yields two connections (docs/rendezvous.md §3.2).
const (
	RolePublisher = "publisher"
	RoleClaimer   = "claimer"
)

// MaxControlFrame bounds a single control message. The control plane carries
// only small fixed-shape messages, so a tight cap costs nothing and denies an
// obvious memory-exhaustion vector.
const MaxControlFrame = 8 << 10 // 8 KiB

// ErrControlTooLarge indicates a control message beyond MaxControlFrame.
var ErrControlTooLarge = errors.New("rendezvous: control message too large")

// Message is the single control-plane envelope. JSON is used deliberately:
// the control plane carries no secrets — candidate lists arrive already
// sealed under the pairing key, and the relay never holds either — so
// inspectability is worth more than compactness here.
type Message struct {
	Type string `json:"type"`

	// RendezvousID is the value the relay pairs on (base64).
	RendezvousID string `json:"rid,omitempty"`
	// Candidates is this peer's sealed candidate list (base64).
	Candidates string `json:"cand,omitempty"`

	// Observed is the TCP source address the relay sees for this peer: the
	// server-reflexive candidate, which is why no STUN is needed.
	Observed string `json:"observed,omitempty"`

	// Role is this peer's rendezvous role (see RolePublisher/RoleClaimer).
	Role string `json:"role,omitempty"`
	// PeerCandidates is the other peer's sealed candidate list (base64).
	PeerCandidates string `json:"peer_cand,omitempty"`
	// PeerObserved is the other peer's server-reflexive address.
	PeerObserved string `json:"peer_observed,omitempty"`
	// PunchInMS is a RELATIVE delay before starting to punch. It is relative
	// rather than absolute because peer clocks are not synchronised and a
	// relative delay needs no clock agreement.
	PunchInMS int64 `json:"punch_in_ms,omitempty"`
	// Ticket authorises one circuit connection (base64). Each side gets a
	// distinct ticket for the same circuit.
	Ticket string `json:"ticket,omitempty"`

	// Reason carries human-readable detail on error/bye.
	Reason string `json:"reason,omitempty"`
}

// EncodeMessage serialises a control message for one WebSocket binary frame.
func EncodeMessage(m *Message) ([]byte, error) {
	buf, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(buf) > MaxControlFrame {
		return nil, ErrControlTooLarge
	}
	return buf, nil
}

// DecodeMessage parses a control message, rejecting anything oversized before
// it reaches the JSON parser.
func DecodeMessage(buf []byte) (*Message, error) {
	if len(buf) > MaxControlFrame {
		return nil, ErrControlTooLarge
	}
	var m Message
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, fmt.Errorf("rendezvous: bad control message: %w", err)
	}
	if m.Type == "" {
		return nil, errors.New("rendezvous: control message without a type")
	}
	return &m, nil
}

// b64 and unb64 keep the binary-field encoding in one place.
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string, max int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("rendezvous: bad base64 field: %w", err)
	}
	if len(b) > max {
		return nil, fmt.Errorf("rendezvous: field too long (%d > %d)", len(b), max)
	}
	return b, nil
}
