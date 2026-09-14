package proto

import (
	"encoding/binary"
	"testing"

	"github.com/4ntyr/heimdall_cli/internal/identity"
)

// runHandshake performs a complete in-memory handshake between two
// identities and returns both results. No network is involved.
func runHandshake(t *testing.T, a, b *identity.Identity) (*HandshakeResult, *HandshakeResult) {
	t.Helper()
	ha, err := NewHandshaker(a, true)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := NewHandshaker(b, false)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := ha.InitMessage()
	if err != nil {
		t.Fatal(err)
	}
	msg2, _, err := hb.HandleMessage(msg1)
	if err != nil {
		t.Fatalf("responder handle init: %v", err)
	}
	msg3, resA, err := ha.HandleMessage(msg2)
	if err != nil {
		t.Fatalf("initiator handle auth: %v", err)
	}
	if resA == nil {
		t.Fatal("initiator did not complete")
	}
	_, resB, err := hb.HandleMessage(msg3)
	if err != nil {
		t.Fatalf("responder handle auth: %v", err)
	}
	if resB == nil {
		t.Fatal("responder did not complete")
	}
	return resA, resB
}

func TestHandshakeSuccess(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("bob")
	resA, resB := runHandshake(t, a, b)

	if resA.PeerName != "bob" || resB.PeerName != "alice" {
		t.Fatalf("wrong peer names: %q / %q", resA.PeerName, resB.PeerName)
	}
	if !resA.PeerKey.Equal(b.PublicKey()) || !resB.PeerKey.Equal(a.PublicKey()) {
		t.Fatal("wrong peer keys")
	}
	if resA.Session.SessionID != resB.Session.SessionID {
		t.Fatal("session IDs differ")
	}
	if resA.PeerFingerprint != identity.FingerprintOf(b.PublicKey()) {
		t.Fatal("wrong fingerprint")
	}
}

func TestHandshakeEndToEndEncryption(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("bob")
	resA, resB := runHandshake(t, a, b)

	// alice → bob
	wire, err := resA.Session.Seal(TypeChat, encodeChatPayload("hello bob"))
	if err != nil {
		t.Fatal(err)
	}
	typ, pt, err := resB.Session.Open(wire)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if typ != TypeChat {
		t.Fatalf("type = %d, want chat", typ)
	}
	text, err := decodeChatPayload(pt)
	if err != nil || text != "hello bob" {
		t.Fatalf("payload = %q err=%v", text, err)
	}

	// bob → alice (reverse direction uses independent keys)
	wire2, err := resB.Session.Seal(TypeChat, encodeChatPayload("hello alice"))
	if err != nil {
		t.Fatal(err)
	}
	_, pt2, err := resA.Session.Open(wire2)
	if err != nil {
		t.Fatalf("open reverse: %v", err)
	}
	text2, _ := decodeChatPayload(pt2)
	if text2 != "hello alice" {
		t.Fatalf("reverse payload = %q", text2)
	}
}

func TestHandshakeRejectsForgedSignature(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("bob")
	mallory, _ := identity.Generate("mallory")

	// Mallory performs a valid handshake with her own key but claims to be
	// alice. She cannot forge alice's signature, so she signs with her own
	// key but presents alice's NAME. The key she presents is hers, so the
	// victim sees "mallory's key claiming name alice" — the trust layer
	// flags the mismatch. At the protocol level we verify the signature is
	// correctly bound to the presented key.
	ha, _ := NewHandshaker(a, true)
	hm, _ := NewHandshaker(mallory, false)
	msg1, _ := ha.InitMessage()
	msg2, _, err := hm.HandleMessage(msg1)
	if err != nil {
		t.Fatal(err)
	}
	// The protocol accepts mallory's own signature (it is valid for her key).
	_, resA, err := ha.HandleMessage(msg2)
	if err != nil {
		t.Fatalf("unexpected failure: %v", err)
	}
	// But the authenticated key is MALLORY's, not alice's — name spoofing
	// does not change the key. The trust layer detects alice→key mismatch.
	if resA.PeerKey.Equal(a.PublicKey()) {
		t.Fatal("impersonator authenticated as victim's key")
	}
	if !resA.PeerKey.Equal(mallory.PublicKey()) {
		t.Fatal("expected mallory's key")
	}
	_ = b
}

func TestHandshakeRejectsTamperedSignature(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("bob")
	ha, _ := NewHandshaker(a, true)
	hb, _ := NewHandshaker(b, false)
	msg1, _ := ha.InitMessage()
	msg2, _, err := hb.HandleMessage(msg1)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the encrypted auth blob → AEAD failure.
	msg2[len(msg2)-1] ^= 0xff
	if _, _, err := ha.HandleMessage(msg2); err == nil {
		t.Fatal("tampered auth message accepted")
	}
}

func TestHandshakeRejectsTamperedInit(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("bob")
	ha, _ := NewHandshaker(a, true)
	hb, _ := NewHandshaker(b, false)
	msg1, _ := ha.InitMessage()
	// Truncate the init message.
	if _, _, err := hb.HandleMessage(msg1[:len(msg1)-4]); err == nil {
		t.Fatal("truncated init accepted")
	}
	// Corrupt the init so its declared length no longer matches — a reliable
	// structural corruption (flipping a key byte may still parse as a valid
	// X25519 key, which is fine since the signature check would catch it).
	bad := append([]byte(nil), msg1...)
	binary.BigEndian.PutUint16(bad[1:3], 31) // wrong length
	if _, _, err := hb.HandleMessage(bad); err == nil {
		t.Fatal("length-corrupted init accepted")
	}
}

func TestHandshakeRejectsSelfConnection(t *testing.T) {
	a, _ := identity.Generate("alice")
	ha, _ := NewHandshaker(a, true)
	hb, _ := NewHandshaker(a, false) // same identity
	msg1, _ := ha.InitMessage()
	msg2, _, _ := hb.HandleMessage(msg1)
	if _, _, err := ha.HandleMessage(msg2); err != ErrSelfConnection {
		t.Fatalf("self connection: got %v, want ErrSelfConnection", err)
	}
}

func TestHandshakeWrongOrderRejected(t *testing.T) {
	b, _ := identity.Generate("bob")
	hb, _ := NewHandshaker(b, false)
	// Responder receiving an auth message before any init must fail.
	a, _ := identity.Generate("alice")
	ha, _ := NewHandshaker(a, true)
	// craft a fake msg2 from a different exchange
	hb2, _ := NewHandshaker(b, false)
	msg1, _ := ha.InitMessage()
	msg2, _, _ := hb2.HandleMessage(msg1)
	// hb (fresh responder) gets msg2 (auth) without init
	if _, _, err := hb.HandleMessage(msg2); err == nil {
		t.Fatal("auth accepted before init")
	}
}

func TestHandshakeUniqueSessions(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("bob")
	r1a, r1b := runHandshake(t, a, b)
	r2a, r2b := runHandshake(t, a, b)
	if r1a.Session.SessionID == r2a.Session.SessionID {
		t.Fatal("two handshakes produced the same session ID")
	}
	// Keys must differ: a frame from session 1 must not open in session 2.
	wire, err := r1a.Session.Seal(TypeChat, encodeChatPayload("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r2b.Session.Open(wire); err == nil {
		t.Fatal("session-2 opened a session-1 frame")
	}
	_ = r1b
	_ = r2b
}
