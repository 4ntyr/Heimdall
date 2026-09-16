package session

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/4ntyr/heimdall/internal/identity"
	"github.com/4ntyr/heimdall/internal/peers"
)

// newTestManager builds a manager with a throwaway identity and trust store.
func newTestManager(t *testing.T, name string) *Manager {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	store, err := peers.OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatalf("opening trust store: %v", err)
	}
	return NewManager(id, store)
}

// socketPair returns two connected TCP sockets on the loopback interface.
//
// net.Pipe is unsuitable here: it is unbuffered and synchronous, so the two
// sides of the pairing confirmation — which are sent simultaneously rather
// than in alternation — deadlock against each other. A real socket buffers the
// ~80-byte frame, as does a relay circuit.
func socketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer ln.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		accepted <- result{conn, err}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	got := <-accepted
	if got.err != nil {
		t.Fatalf("accepting: %v", got.err)
	}
	t.Cleanup(func() {
		dialed.Close()
		got.conn.Close()
	})
	return dialed, got.conn
}

// adoptPair runs both sides of a handshake over a loopback socket pair.
func adoptPair(t *testing.T, a, b *Manager, keyA, keyB []byte) (errA, errB error) {
	t.Helper()
	ca, cb := socketPair(t)

	done := make(chan error, 1)
	go func() {
		done <- b.Adopt(cb, AdoptOptions{PairingKey: keyB, Path: PathRelay})
	}()
	errA = a.Adopt(ca, AdoptOptions{Initiator: true, PairingKey: keyA, Path: PathRelay})

	select {
	case errB = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("responder side never finished")
	}
	return errA, errB
}

// TestPairingConfirmationAcceptsMatchingKeys is the baseline: two peers who
// hold the same invite code connect normally.
func TestPairingConfirmationAcceptsMatchingKeys(t *testing.T) {
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	bob := newTestManager(t, "bob")
	defer bob.Shutdown()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	if errA, errB := adoptPair(t, alice, bob, key, key); errA != nil || errB != nil {
		t.Fatalf("matching pairing keys were rejected: initiator=%v responder=%v", errA, errB)
	}
	if got := len(alice.Peers()); got != 1 {
		t.Fatalf("expected one connected peer, got %d", got)
	}
}

// TestPairingConfirmationRejectsMismatchedKeys is the property that makes an
// invite code safe over an untrusted relay (docs/rendezvous.md §4).
//
// A relay that answers a rendezvous itself completes the handshake perfectly
// well — it just cannot produce the confirmation, because it never saw the
// code. The connection must be dropped AND leave no trust-store record, or a
// failed impersonation would still earn the attacker trust-on-first-use.
func TestPairingConfirmationRejectsMismatchedKeys(t *testing.T) {
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	mallory := newTestManager(t, "mallory")
	defer mallory.Shutdown()

	good := make([]byte, 32)
	bad := make([]byte, 32)
	for i := range good {
		good[i] = byte(i)
		bad[i] = byte(i) ^ 0xFF
	}

	errA, errB := adoptPair(t, alice, mallory, good, bad)
	if errA == nil {
		t.Error("the inviting side accepted a peer that could not prove it held the code")
	}
	if errB == nil {
		t.Error("the joining side accepted a peer that could not prove it held the code")
	}

	if got := len(alice.Peers()); got != 0 {
		t.Errorf("a rejected peer left %d connections registered", got)
	}
	if p := alice.store.Get("mallory"); p != nil {
		t.Error("a rejected peer was written to the trust store")
	}
}

// TestPairingConfirmationRequiredWhenExpected checks the downgrade case: a
// peer that simply never sends a confirmation is rejected, rather than the
// absence being treated as acceptable.
func TestPairingConfirmationRequiredWhenExpected(t *testing.T) {
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	bob := newTestManager(t, "bob")
	defer bob.Shutdown()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// A stalling peer must time out rather than be accepted. Shorten the
	// production timeout so the suite does not wait it out in real time.
	restore := pairConfirmTimeout
	pairConfirmTimeout = 500 * time.Millisecond
	defer func() { pairConfirmTimeout = restore }()

	// Bob adopts with no pairing key at all, so he sends no confirmation.
	errA, _ := adoptPair(t, alice, bob, key, nil)
	if errA == nil {
		t.Fatal("a missing pairing confirmation was accepted as a fallback")
	}
	if got := len(alice.Peers()); got != 0 {
		t.Errorf("a rejected peer left %d connections registered", got)
	}
}
