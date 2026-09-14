package peers

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/4ntyr/heimdall_cli/internal/identity"
)

func newKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	id, err := identity.Generate("tmp")
	if err != nil {
		t.Fatal(err)
	}
	return id.PublicKey()
}

func TestObserveNewPeer(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	pub := newKey(t)
	p, lvl, err := s.Observe("alice", "10.0.0.1:8471", pub)
	if err != nil {
		t.Fatal(err)
	}
	if lvl != TrustUnknown {
		t.Fatalf("new peer trust = %v, want UNKNOWN", lvl)
	}
	if p.Verified {
		t.Fatal("new peer must not be verified")
	}
	if p.Fingerprint != identity.FingerprintOf(pub) {
		t.Fatal("fingerprint mismatch")
	}
}

func TestObserveSameKeyKeepsTrust(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	pub := newKey(t)
	if _, _, err := s.Observe("alice", "", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify("alice"); err != nil {
		t.Fatal(err)
	}
	_, lvl, err := s.Observe("alice", "1.2.3.4:1", pub)
	if err != nil {
		t.Fatal(err)
	}
	if lvl != TrustVerified {
		t.Fatalf("returning verified peer trust = %v, want VERIFIED", lvl)
	}
}

func TestIdentityChangeDetectedAndNotSilentlyAccepted(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	oldKey := newKey(t)
	if _, _, err := s.Observe("alice", "", oldKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify("alice"); err != nil {
		t.Fatal(err)
	}

	// "alice" returns with a different key — possible MITM.
	newKey := newKey(t)
	p, lvl, err := s.Observe("alice", "", newKey)
	if err != nil {
		t.Fatal(err)
	}
	if lvl != TrustChanged {
		t.Fatalf("changed-key trust = %v, want IDENTITY CHANGED", lvl)
	}
	// The recorded key must still be the OLD one.
	if string(p.PublicKey) != string(oldKey) {
		t.Fatal("old key was silently replaced")
	}
	if p.PendingFingerprint() == "" {
		t.Fatal("pending fingerprint not recorded")
	}

	// TrustOf must reflect the change.
	if got := s.TrustOf("alice", newKey); got != TrustChanged {
		t.Fatalf("TrustOf = %v, want IDENTITY CHANGED", got)
	}
}

func TestVerifyAdoptsPendingKeyOnlyExplicitly(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	oldKey := newKey(t)
	s.Observe("alice", "", oldKey)
	newKey := newKey(t)
	s.Observe("alice", "", newKey) // sets pending

	p, err := s.Verify("alice") // explicit user action adopts new key
	if err != nil {
		t.Fatal(err)
	}
	if string(p.PublicKey) != string(newKey) {
		t.Fatal("verify did not adopt pending key")
	}
	if !p.Verified {
		t.Fatal("peer not verified after /verify")
	}
	// Old key must no longer resolve as alice.
	if got := s.TrustOf("alice", oldKey); got == TrustVerified {
		t.Fatal("old key still trusted after key adoption")
	}
}

func TestRejectKeepsOldKey(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	oldKey := newKey(t)
	s.Observe("alice", "", oldKey)
	s.Observe("alice", "", newKey(t)) // pending
	if err := s.Reject("alice"); err != nil {
		t.Fatal(err)
	}
	p := s.Get("alice")
	if p == nil || string(p.PublicKey) != string(oldKey) || len(p.PendingKey) != 0 {
		t.Fatal("reject did not keep old key / clear pending")
	}
}

func TestVerifyUnknownPeer(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	if _, err := s.Verify("nobody"); err == nil {
		t.Fatal("expected error verifying unknown peer")
	}
}

func TestNamesCollideKeysDoNot(t *testing.T) {
	s, _ := OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	k1, k2 := newKey(t), newKey(t)
	if _, lvl1, _ := s.Observe("alice", "", k1); lvl1 != TrustUnknown {
		t.Fatal("first alice should be UNKNOWN")
	}
	// A second, distinct key under the same name = identity change, not a
	// second trusted record.
	if _, lvl2, _ := s.Observe("alice", "", k2); lvl2 != TrustChanged {
		t.Fatalf("duplicate-name-different-key = %v, want IDENTITY CHANGED", lvl2)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	s, _ := OpenStore(path)
	pub := newKey(t)
	s.Observe("alice", "10.0.0.1:8471", pub)
	s.Verify("alice")

	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	p := s2.Get("alice")
	if p == nil || !p.Verified || p.Fingerprint != identity.FingerprintOf(pub) {
		t.Fatal("trust store did not persist")
	}
	if got := s2.TrustOf("alice", pub); got != TrustVerified {
		t.Fatalf("reloaded trust = %v, want VERIFIED", got)
	}
}

func TestCorruptStoreRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path); err == nil {
		t.Fatal("expected error for corrupt trust store")
	}
}
