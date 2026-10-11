package session

import (
	"strings"
	"testing"
	"time"

	"github.com/4ntyr/heimdall/internal/proto"
)

// waitForMessage drains events until a chat message arrives or time runs out.
// Connection announcements land on the same channel, so a caller cannot simply
// take the first event.
func waitForMessage(t *testing.T, m *Manager, timeout time.Duration) Event {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-m.Events():
			if ev.Type == EventMessage {
				return ev
			}
		case <-deadline:
			t.Fatalf("no chat message within %v", timeout)
		}
	}
}

// TestSendRejectsOversizedTextWithoutKillingSession pins the contract that
// survives sealing moving from enqueue into writeLoop.
//
// Seal refuses a payload over MaxPlaintext. While Send sealed inline, that came
// back to the caller as an error. Now that writeLoop seals, an oversized
// payload reaching it could only be answered by dropping the connection — a
// message the user typed would silently kill their session. enqueue therefore
// checks the length up front, and this test is what proves the two agree: the
// error still reaches the caller, and the connection is still usable
// afterwards.
func TestSendRejectsOversizedTextWithoutKillingSession(t *testing.T) {
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	bob := newTestManager(t, "bob")
	defer bob.Shutdown()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if errA, errB := adoptPair(t, alice, bob, key, key); errA != nil || errB != nil {
		t.Fatalf("pairing failed: initiator=%v responder=%v", errA, errB)
	}

	// The limit applies to the encoded payload, which carries a 2-byte length
	// prefix, so the largest sendable text is MaxPlaintext-2.
	tooLong := strings.Repeat("x", proto.MaxPlaintext-1)
	if err := alice.Send("bob", tooLong); err == nil {
		t.Fatal("a text longer than one frame was accepted")
	}

	if got := len(alice.Peers()); got != 1 {
		t.Fatalf("the oversized send cost us the connection: %d peers, want 1", got)
	}
	if err := alice.Send("bob", "still here"); err != nil {
		t.Fatalf("the connection was unusable after an oversized send: %v", err)
	}
	if ev := waitForMessage(t, bob, 10*time.Second); ev.Text != "still here" {
		t.Fatalf("bob received %q, want %q", ev.Text, "still here")
	}
}

// TestSendAcceptsLargestFittingText guards the boundary from the other side, so
// the up-front check in enqueue cannot drift tighter than Seal's.
func TestSendAcceptsLargestFittingText(t *testing.T) {
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	bob := newTestManager(t, "bob")
	defer bob.Shutdown()

	key := make([]byte, 32)
	if errA, errB := adoptPair(t, alice, bob, key, key); errA != nil || errB != nil {
		t.Fatalf("pairing failed: initiator=%v responder=%v", errA, errB)
	}

	text := strings.Repeat("y", proto.MaxPlaintext-2)
	if err := alice.Send("bob", text); err != nil {
		t.Fatalf("the largest text that fits one frame was rejected: %v", err)
	}
	if ev := waitForMessage(t, bob, 10*time.Second); ev.Text != text {
		t.Fatalf("bob received %d bytes, want %d", len(ev.Text), len(text))
	}
}

// TestEnqueueRejectsOversizedPayload covers the guard that Send's own
// validation hides.
//
// Send cannot reach it: proto.EncodeChatPayload rejects over-long text first.
// But enqueue is the single door every other frame type goes through, and once
// file chunks use it, an encoder bug producing an oversized payload would
// otherwise reach writeLoop — where the only possible response is to drop the
// connection. So the guard is tested where it actually applies.
func TestEnqueueRejectsOversizedPayload(t *testing.T) {
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	bob := newTestManager(t, "bob")
	defer bob.Shutdown()

	key := make([]byte, 32)
	if errA, errB := adoptPair(t, alice, bob, key, key); errA != nil || errB != nil {
		t.Fatalf("pairing failed: initiator=%v responder=%v", errA, errB)
	}

	alice.mu.Lock()
	var c *conn
	for _, got := range alice.conns {
		c = got
	}
	alice.mu.Unlock()
	if c == nil {
		t.Fatal("no connection registered")
	}

	if err := alice.enqueue(c, proto.TypeChat, make([]byte, proto.MaxPlaintext+1)); err == nil {
		t.Fatal("enqueue accepted a payload larger than MaxPlaintext")
	}
	if err := alice.enqueue(c, proto.TypeChat, make([]byte, proto.MaxPlaintext)); err != nil {
		t.Fatalf("enqueue rejected a payload of exactly MaxPlaintext: %v", err)
	}
	// The oversized attempt must not have cost us the connection.
	if got := len(alice.Peers()); got != 1 {
		t.Fatalf("%d peers after an oversized enqueue, want 1", got)
	}
}
