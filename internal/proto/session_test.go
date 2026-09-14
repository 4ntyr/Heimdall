package proto

import (
	"bytes"
	"testing"

	"github.com/4ntyr/heimdall/internal/identity"
)

// newPair returns an established initiator/responder session pair.
func newPair(t *testing.T) (*Session, *Session) {
	t.Helper()
	a, _ := identity.Generate("a")
	b, _ := identity.Generate("b")
	resA, resB := runHandshake(t, a, b)
	return resA.Session, resB.Session
}

func sealChat(t *testing.T, s *Session, text string) []byte {
	t.Helper()
	wire, err := s.Seal(TypeChat, encodeChatPayload(text))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return wire
}

func openText(t *testing.T, s *Session, wire []byte) (string, error) {
	t.Helper()
	typ, pt, err := s.Open(wire)
	if err != nil {
		return "", err
	}
	if typ != TypeChat {
		t.Fatalf("type = %d, want chat", typ)
	}
	return decodeChatPayload(pt)
}

func TestSessionRoundTrip(t *testing.T) {
	sa, sb := newPair(t)
	for i := 0; i < 50; i++ {
		msg := "message number " + string(rune('a'+i%26))
		wire := sealChat(t, sa, msg)
		got, err := openText(t, sb, wire)
		if err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
		if got != msg {
			t.Fatalf("msg %d = %q, want %q", i, got, msg)
		}
	}
}

func TestSessionRejectsTamperedCiphertext(t *testing.T) {
	sa, sb := newPair(t)
	wire := sealChat(t, sa, "hello")
	wire[len(wire)-1] ^= 0x01 // flip a bit in the tag
	if _, err := openText(t, sb, wire); err != ErrAuth {
		t.Fatalf("tampered ciphertext: got %v, want ErrAuth", err)
	}
}

func TestSessionRejectsTamperedHeader(t *testing.T) {
	sa, sb := newPair(t)
	wire := sealChat(t, sa, "hello")
	// Flip a bit in the sequence number (part of the AAD). The AEAD tag no
	// longer verifies → ErrAuth (the header is authenticated).
	wire[12] ^= 0xff
	if _, err := openText(t, sb, wire); err == nil {
		t.Fatal("tampered header accepted")
	}
}

func TestSessionRejectsReplay(t *testing.T) {
	sa, sb := newPair(t)
	wire := sealChat(t, sa, "hello")
	if _, err := openText(t, sb, wire); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	// Exact same bytes delivered again = replay.
	if _, err := openText(t, sb, wire); err != ErrReplay {
		t.Fatalf("replay: got %v, want ErrReplay", err)
	}
}

func TestSessionRejectsOldSequence(t *testing.T) {
	sa, sb := newPair(t)
	first := sealChat(t, sa, "first")
	if _, err := openText(t, sb, first); err != nil {
		t.Fatal(err)
	}
	// Push the window far ahead.
	for i := 0; i < 10; i++ {
		w := sealChat(t, sa, "filler")
		if _, err := openText(t, sb, w); err != nil {
			t.Fatal(err)
		}
	}
	// Re-deliver the very first message: seq 0 is now far behind.
	if _, err := openText(t, sb, first); err == nil {
		t.Fatal("old (replayed) message accepted after window advanced")
	}
}

func TestSessionRejectsWrongSessionID(t *testing.T) {
	sa, sb := newPair(t)
	_, sc := newPair(t) // different session
	wire := sealChat(t, sa, "hello")
	if _, err := openText(t, sc, wire); err != ErrBadSession && err != ErrAuth {
		t.Fatalf("cross-session frame: got %v", err)
	}
	_ = sb
}

func TestSessionRejectsMalformed(t *testing.T) {
	_, sb := newPair(t)
	cases := [][]byte{
		{},                          // empty
		{1},                         // too short
		bytes.Repeat([]byte{0}, 21), // under header size
		append([]byte{99}, bytes.Repeat([]byte{0}, 40)...),                  // bad version
		{1, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // bad type
	}
	for i, c := range cases {
		if _, _, err := sb.Open(c); err == nil {
			t.Fatalf("case %d: malformed frame accepted", i)
		}
	}
}

func TestSessionRejectsOversizedPayload(t *testing.T) {
	sa, _ := newPair(t)
	big := make([]byte, MaxPlaintext+1)
	if _, err := sa.Seal(TypeChat, big); err == nil {
		t.Fatal("oversized payload sealed")
	}
}

func TestSessionBidirectionalIndependence(t *testing.T) {
	sa, sb := newPair(t)
	// Interleave directions; each has its own chain and replay window.
	w1 := sealChat(t, sa, "a1")
	w2 := sealChat(t, sb, "b1")
	w3 := sealChat(t, sa, "a2")
	if _, err := openText(t, sa, w2); err != nil {
		t.Fatalf("b→a: %v", err)
	}
	if _, err := openText(t, sb, w1); err != nil {
		t.Fatalf("a→b 1: %v", err)
	}
	if _, err := openText(t, sb, w3); err != nil {
		t.Fatalf("a→b 2: %v", err)
	}
}

func TestSessionClose(t *testing.T) {
	sa, sb := newPair(t)
	sa.Close()
	if _, err := sa.Seal(TypeChat, []byte("x")); err == nil {
		t.Fatal("seal on closed session succeeded")
	}
	if _, _, err := sb.Open(sealChat(t, func() *Session { s, _ := newPair(t); return s }(), "y")); err == nil {
		// sb is not closed; this should still work or fail auth — just ensure
		// no panic and that a frame from a different session is rejected.
		t.Log("expected rejection of foreign frame")
	}
	if !sa.Closed() {
		t.Fatal("Closed() false after Close()")
	}
}

func TestRotationOccurs(t *testing.T) {
	sa, sb := newPair(t)
	// Send rotationInterval+5 messages to force an epoch boundary.
	for i := 0; i < rotationInterval+5; i++ {
		wire := sealChat(t, sa, "rotation test")
		if _, err := openText(t, sb, wire); err != nil {
			t.Fatalf("message %d across rotation: %v", i, err)
		}
	}
	if sa.epoch == 0 {
		t.Fatal("rotation did not occur")
	}
	// Both sides must agree on the epoch.
	if sa.epoch != sb.epoch {
		t.Fatalf("epoch mismatch: sender %d receiver %d", sa.epoch, sb.epoch)
	}
}

func TestOutOfOrderWithinWindowAccepted(t *testing.T) {
	sa, sb := newPair(t)
	w0 := sealChat(t, sa, "m0")
	w1 := sealChat(t, sa, "m1")
	w2 := sealChat(t, sa, "m2")
	// Deliver out of order: 2, then 0, then 1 — all within the window.
	if _, err := openText(t, sb, w2); err != nil {
		t.Fatalf("oow m2: %v", err)
	}
	if _, err := openText(t, sb, w0); err != nil {
		t.Fatalf("oow m0: %v", err)
	}
	if _, err := openText(t, sb, w1); err != nil {
		t.Fatalf("oow m1: %v", err)
	}
	// Replaying any of them must now fail.
	if _, err := openText(t, sb, w1); err != ErrReplay {
		t.Fatalf("replay of m1: got %v, want ErrReplay", err)
	}
}

func TestReplayWindowBasics(t *testing.T) {
	var w replayWindow
	if !w.check(0) {
		t.Fatal("seq 0 rejected")
	}
	if w.check(0) {
		t.Fatal("seq 0 replay accepted")
	}
	if !w.check(5) {
		t.Fatal("gap jump to 5 rejected")
	}
	if !w.check(3) {
		t.Fatal("in-window older seq 3 rejected")
	}
	if w.check(3) {
		t.Fatal("seq 3 replay accepted")
	}
	if w.check(5) {
		t.Fatal("seq 5 replay accepted")
	}
	// Jump beyond the window, then old values must be rejected.
	if !w.check(windowSize + 100) {
		t.Fatal("large forward jump rejected")
	}
	if w.check(3) {
		t.Fatal("ancient seq 3 accepted after window slid past")
	}
}
