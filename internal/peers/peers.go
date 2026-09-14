// Package peers implements the trust store: the persistent record of peer
// identity public keys and their verification state.
//
// Trust rules (see docs/protocol.md §9):
//   - A peer is identified by its Ed25519 public key / fingerprint, never by
//     its display name.
//   - A new peer starts UNVERIFIED; the user verifies it out-of-band with
//     /verify after comparing fingerprints.
//   - If a previously known peer presents a DIFFERENT key, that is a
//     possible MITM or key replacement: the change is flagged, the old key
//     is kept, and the connection is UNTRUSTED until the user explicitly
//     re-verifies. Keys are never silently replaced.
package peers

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/4ntyr/heimdall_cli/internal/identity"
)

// TrustLevel describes how much we trust a peer's presented identity.
type TrustLevel int

const (
	// TrustUnknown is a peer we have never seen before.
	TrustUnknown TrustLevel = iota
	// TrustUnverified is a known peer whose fingerprint has not been
	// verified out-of-band. Encrypted, but not authenticated to a human.
	TrustUnverified
	// TrustVerified is a peer whose fingerprint the user has confirmed.
	TrustVerified
	// TrustChanged means the peer presented a different key than the one
	// stored — possible MITM. Never trusted until explicit re-verification.
	TrustChanged
)

func (t TrustLevel) String() string {
	switch t {
	case TrustVerified:
		return "VERIFIED"
	case TrustUnverified:
		return "UNVERIFIED"
	case TrustChanged:
		return "IDENTITY CHANGED"
	default:
		return "UNKNOWN"
	}
}

// Peer is a stored record of a remote party.
type Peer struct {
	// Name is the last-seen display name (a label, not an identity).
	Name string `json:"name"`
	// PublicKey is the trusted/recorded identity public key.
	PublicKey []byte `json:"public_key"`
	// Fingerprint is the SHA-256 fingerprint of PublicKey (display aid).
	Fingerprint string `json:"fingerprint"`
	// Verified reports whether the user confirmed the fingerprint.
	Verified bool `json:"verified"`
	// Address is the last known network address (for /connect memory).
	Address string `json:"address,omitempty"`
	// FirstSeen / LastSeen bookkeep the relationship.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// PendingKey, when non-nil, is a newly presented key that differs from
	// PublicKey and awaits an explicit user decision.
	PendingKey []byte `json:"pending_key,omitempty"`
}

// PendingFingerprint returns the fingerprint of a pending (changed) key.
func (p *Peer) PendingFingerprint() string {
	if len(p.PendingKey) == 0 {
		return ""
	}
	return identity.FingerprintOf(ed25519.PublicKey(p.PendingKey))
}

// Store is a concurrency-safe, persistent trust store.
type Store struct {
	mu    sync.RWMutex
	path  string
	peers map[string]*Peer // keyed by stable peer ID (fingerprint)
}

// peerID derives the stable map key from a public key. We deliberately key
// by fingerprint, not by name: names collide and are attacker-controlled.
func peerID(pub ed25519.PublicKey) string { return identity.FingerprintOf(pub) }

// OpenStore loads (or creates) the trust store at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, peers: make(map[string]*Peer)}
	buf, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*Peer
	if err := json.Unmarshal(buf, &list); err != nil {
		return nil, fmt.Errorf("peers: corrupt trust store: %w", err)
	}
	for _, p := range list {
		if len(p.PublicKey) != ed25519.PublicKeySize {
			continue // skip malformed entries rather than trusting them
		}
		s.peers[peerID(ed25519.PublicKey(p.PublicKey))] = p
	}
	return s, nil
}

// save persists the store atomically (temp file + rename), mode 0600: it
// contains security-relevant trust decisions.
func (s *Store) saveLocked() error {
	list := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	buf, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Observe records a peer presenting pub at address. It returns the peer
// record and the resulting trust level:
//
//   - first sighting            → new record, TrustUnknown
//   - same key as recorded      → TrustUnverified or TrustVerified
//   - different key             → TrustChanged; PendingKey set, old key kept
func (s *Store) Observe(name, address string, pub ed25519.PublicKey) (*Peer, TrustLevel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := peerID(pub)
	now := time.Now()

	if p, ok := s.peers[id]; ok {
		// Same key: update metadata, keep verification state.
		p.Name = name
		if address != "" {
			p.Address = address
		}
		p.LastSeen = now
		p.PendingKey = nil
		lvl := TrustUnverified
		if p.Verified {
			lvl = TrustVerified
		}
		return p, lvl, s.saveLocked()
	}

	// Is this a name we already know under a DIFFERENT key?
	for _, p := range s.peers {
		if p.Name == name {
			p.PendingKey = append([]byte(nil), pub...)
			p.LastSeen = now
			return p, TrustChanged, s.saveLocked()
		}
	}

	// Genuinely new peer.
	p := &Peer{
		Name:        name,
		PublicKey:   append([]byte(nil), pub...),
		Fingerprint: identity.FingerprintOf(pub),
		Address:     address,
		FirstSeen:   now,
		LastSeen:    now,
	}
	s.peers[id] = p
	return p, TrustUnknown, s.saveLocked()
}

// Verify marks the peer identified by name as verified by the user. If the
// peer has a pending (changed) key, verification adopts the new key — this
// is the only way a key is ever replaced, and it requires explicit user
// action after comparing fingerprints out-of-band.
func (s *Store) Verify(name string) (*Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.findByNameLocked(name)
	if p == nil {
		return nil, fmt.Errorf("peers: no such peer %q", name)
	}
	if len(p.PendingKey) > 0 {
		oldID := peerID(ed25519.PublicKey(p.PublicKey))
		p.PublicKey = p.PendingKey
		p.PendingKey = nil
		p.Fingerprint = identity.FingerprintOf(ed25519.PublicKey(p.PublicKey))
		delete(s.peers, oldID)
		s.peers[peerID(ed25519.PublicKey(p.PublicKey))] = p
	}
	p.Verified = true
	return p, s.saveLocked()
}

// Reject discards a pending (changed) key for the named peer, keeping the
// previously recorded key as the trusted one.
func (s *Store) Reject(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.findByNameLocked(name)
	if p == nil {
		return fmt.Errorf("peers: no such peer %q", name)
	}
	p.PendingKey = nil
	return s.saveLocked()
}

// Get returns the record for the named peer, or nil.
func (s *Store) Get(name string) *Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p := s.findByNameLocked(name); p != nil {
		cp := *p
		return &cp
	}
	return nil
}

// List returns all stored peers sorted by name.
func (s *Store) List() []*Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		cp := *p
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// TrustOf returns the trust level for a presented public key without
// modifying the store.
func (s *Store) TrustOf(name string, pub ed25519.PublicKey) TrustLevel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id := peerID(pub)
	if p, ok := s.peers[id]; ok {
		if p.Verified {
			return TrustVerified
		}
		return TrustUnverified
	}
	for _, p := range s.peers {
		if p.Name == name {
			return TrustChanged
		}
	}
	return TrustUnknown
}

func (s *Store) findByNameLocked(name string) *Peer {
	for _, p := range s.peers {
		if p.Name == name {
			return p
		}
	}
	return nil
}
