package transport

import (
	"bytes"
	"net"
	"testing"
)

// framePair returns two FrameIOs over a connected loopback socket pair.
func framePair(t *testing.T) (*FrameIO, *FrameIO) {
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
	return NewFrameIO(dialed), NewFrameIO(got.conn)
}

// TestFrameRoundTrip covers the framing contract at the sizes that matter: a
// small frame, an empty one (the length prefix must still be written, with no
// payload after it), and one large enough that the kernel may well split the
// write.
func TestFrameRoundTrip(t *testing.T) {
	a, b := framePair(t)

	payloads := [][]byte{
		[]byte("hello"),
		{},
		bytes.Repeat([]byte("x"), 4096),
		bytes.Repeat([]byte{0xAB}, 512<<10),
	}
	for i, want := range payloads {
		if err := a.Send(want); err != nil {
			t.Fatalf("payload %d: send: %v", i, err)
		}
		got, err := b.Recv()
		if err != nil {
			t.Fatalf("payload %d: recv: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("payload %d: round-tripped %d bytes, sent %d", i, len(got), len(want))
		}
	}
}

// TestFrameSequenceStaysAligned is the property a partial write would break:
// several frames sent back to back must come back out individually, in order,
// with no bytes of one leaking into the next.
func TestFrameSequenceStaysAligned(t *testing.T) {
	a, b := framePair(t)

	const frames = 200
	for i := 0; i < frames; i++ {
		if err := a.Send(bytes.Repeat([]byte{byte(i)}, i+1)); err != nil {
			t.Fatalf("frame %d: send: %v", i, err)
		}
	}
	for i := 0; i < frames; i++ {
		got, err := b.Recv()
		if err != nil {
			t.Fatalf("frame %d: recv: %v", i, err)
		}
		want := bytes.Repeat([]byte{byte(i)}, i+1)
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: got %d bytes %v…, want %d", i, len(got), got[:min(4, len(got))], len(want))
		}
	}
}

// TestSendRejectsOversizedFrame keeps the guard that stops a local bug from
// announcing a length the peer is required to refuse.
func TestSendRejectsOversizedFrame(t *testing.T) {
	a, _ := framePair(t)
	if err := a.Send(make([]byte, MaxFrameSize+1)); err != ErrFrameTooLarge {
		t.Fatalf("oversized frame: got %v, want %v", err, ErrFrameTooLarge)
	}
}
