package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// openFile seals through one session and opens through its peer, returning the
// frame type and plaintext. It asserts the round trip survives the real AEAD
// path rather than testing the codecs in isolation.
func openFile(t *testing.T, from, to *Session, wire []byte) (byte, []byte) {
	t.Helper()
	typ, pt, err := to.Open(wire)
	if err != nil {
		t.Fatalf("opening frame: %v", err)
	}
	return typ, pt
}

func TestFileOfferRoundTrip(t *testing.T) {
	sa, sb := newPair(t)

	want := FileOffer{ID: 0xDEADBEEFCAFEF00D, Size: 1 << 30, Name: "quarterly report.pdf"}
	wire, err := sa.SealFileOffer(want)
	if err != nil {
		t.Fatalf("sealing offer: %v", err)
	}
	typ, pt := openFile(t, sa, sb, wire)
	if typ != TypeFileOffer {
		t.Fatalf("frame type %d, want %d", typ, TypeFileOffer)
	}
	got, err := DecodeFileOffer(pt)
	if err != nil {
		t.Fatalf("decoding offer: %v", err)
	}
	if got != want {
		t.Fatalf("offer round-tripped as %+v, want %+v", got, want)
	}
}

func TestFileAcceptRoundTrip(t *testing.T) {
	sa, sb := newPair(t)

	wire, err := sa.SealFileAccept(42, 0)
	if err != nil {
		t.Fatalf("sealing accept: %v", err)
	}
	typ, pt := openFile(t, sa, sb, wire)
	if typ != TypeFileAccept {
		t.Fatalf("frame type %d, want %d", typ, TypeFileAccept)
	}
	id, off, err := DecodeFileAccept(pt)
	if err != nil {
		t.Fatalf("decoding accept: %v", err)
	}
	if id != 42 || off != 0 {
		t.Fatalf("accept round-tripped as id=%d offset=%d, want id=42 offset=0", id, off)
	}
}

func TestFileChunkRoundTrip(t *testing.T) {
	sa, sb := newPair(t)

	data := bytes.Repeat([]byte{0x5A}, MaxFileChunk)
	wire, err := sa.SealFileChunk(7, 4080, data)
	if err != nil {
		t.Fatalf("sealing chunk: %v", err)
	}
	typ, pt := openFile(t, sa, sb, wire)
	if typ != TypeFileChunk {
		t.Fatalf("frame type %d, want %d", typ, TypeFileChunk)
	}
	id, off, got, err := DecodeFileChunk(pt)
	if err != nil {
		t.Fatalf("decoding chunk: %v", err)
	}
	if id != 7 || off != 4080 || !bytes.Equal(got, data) {
		t.Fatalf("chunk round-tripped as id=%d offset=%d len=%d, want id=7 offset=4080 len=%d",
			id, off, len(got), len(data))
	}
}

func TestFileDoneRoundTrip(t *testing.T) {
	sa, sb := newPair(t)

	sum := sha256.Sum256([]byte("contents"))
	wire, err := sa.SealFileDone(9, sum[:])
	if err != nil {
		t.Fatalf("sealing done: %v", err)
	}
	typ, pt := openFile(t, sa, sb, wire)
	if typ != TypeFileDone {
		t.Fatalf("frame type %d, want %d", typ, TypeFileDone)
	}
	id, digest, err := DecodeFileDone(pt)
	if err != nil {
		t.Fatalf("decoding done: %v", err)
	}
	if id != 9 || !bytes.Equal(digest, sum[:]) {
		t.Fatalf("done round-tripped as id=%d digest=%x, want id=9 digest=%x", id, digest, sum[:])
	}
}

func TestFileCancelRoundTrip(t *testing.T) {
	sa, sb := newPair(t)

	wire, err := sa.SealFileCancel(11, CancelTooLarge)
	if err != nil {
		t.Fatalf("sealing cancel: %v", err)
	}
	typ, pt := openFile(t, sa, sb, wire)
	if typ != TypeFileCancel {
		t.Fatalf("frame type %d, want %d", typ, TypeFileCancel)
	}
	id, reason, err := DecodeFileCancel(pt)
	if err != nil {
		t.Fatalf("decoding cancel: %v", err)
	}
	if id != 11 || reason != CancelTooLarge {
		t.Fatalf("cancel round-tripped as id=%d reason=%d, want id=11 reason=%d", id, reason, CancelTooLarge)
	}
}

// TestFileChunkSizeBoundary pins the limit the sender chunks to. One byte over
// must fail at the codec, not deeper in Seal, so a caller gets a usable error.
func TestFileChunkSizeBoundary(t *testing.T) {
	sa, _ := newPair(t)

	if _, err := sa.SealFileChunk(1, 0, bytes.Repeat([]byte{1}, MaxFileChunk)); err != nil {
		t.Fatalf("a %d-byte chunk should seal: %v", MaxFileChunk, err)
	}
	if _, err := sa.SealFileChunk(1, 0, bytes.Repeat([]byte{1}, MaxFileChunk+1)); err == nil {
		t.Fatalf("a %d-byte chunk sealed, but MaxFileChunk is %d", MaxFileChunk+1, MaxFileChunk)
	}
	if _, err := sa.SealFileChunk(1, 0, nil); err == nil {
		t.Fatal("an empty chunk sealed; empty chunks must be refused (docs/protocol.md §13.3)")
	}
}

// TestMaxLengthOfferFitsPlaintext is the reason MaxFileNameLen is 255: an offer
// carrying the longest permitted name must still fit MaxPlaintext.
func TestMaxLengthOfferFitsPlaintext(t *testing.T) {
	sa, sb := newPair(t)

	name := strings.Repeat("n", MaxFileNameLen)
	wire, err := sa.SealFileOffer(FileOffer{ID: 1, Size: 1, Name: name})
	if err != nil {
		t.Fatalf("a maximum-length name must fit one frame: %v", err)
	}
	_, pt := openFile(t, sa, sb, wire)
	got, err := DecodeFileOffer(pt)
	if err != nil {
		t.Fatalf("decoding maximum-length offer: %v", err)
	}
	if got.Name != name {
		t.Fatalf("name round-tripped as %d bytes, want %d", len(got.Name), len(name))
	}
}

// TestFileDecodersRejectMalformed covers the structural failures a hostile peer
// can produce. Every one must be ErrMalformed, never a panic and never a
// silently wrong value.
func TestFileDecodersRejectMalformed(t *testing.T) {
	// A valid offer, to mutate.
	validOffer := func() []byte {
		b := make([]byte, 0, 18+3)
		b = binary.BigEndian.AppendUint64(b, 1)
		b = binary.BigEndian.AppendUint64(b, 100)
		b = binary.BigEndian.AppendUint16(b, 3)
		return append(b, "abc"...)
	}

	cases := []struct {
		name   string
		decode func() error
	}{
		{"offer: empty", func() error { _, err := DecodeFileOffer(nil); return err }},
		{"offer: truncated fixed fields", func() error { _, err := DecodeFileOffer(validOffer()[:17]); return err }},
		{"offer: name length overruns payload", func() error {
			b := validOffer()
			binary.BigEndian.PutUint16(b[16:18], 9999)
			_, err := DecodeFileOffer(b)
			return err
		}},
		{"offer: zero-length name", func() error {
			b := validOffer()
			binary.BigEndian.PutUint16(b[16:18], 0)
			_, err := DecodeFileOffer(b)
			return err
		}},
		{"offer: name is not valid UTF-8", func() error {
			b := make([]byte, 0, 21)
			b = binary.BigEndian.AppendUint64(b, 1)
			b = binary.BigEndian.AppendUint64(b, 1)
			b = binary.BigEndian.AppendUint16(b, 2)
			b = append(b, 0xFF, 0xFE)
			_, err := DecodeFileOffer(b)
			return err
		}},
		{"accept: too short", func() error { _, _, err := DecodeFileAccept(make([]byte, 15)); return err }},
		{"chunk: header only, no data", func() error {
			_, _, _, err := DecodeFileChunk(make([]byte, fileChunkHeader))
			return err
		}},
		{"chunk: shorter than its header", func() error {
			_, _, _, err := DecodeFileChunk(make([]byte, 4))
			return err
		}},
		{"chunk: data over MaxFileChunk", func() error {
			_, _, _, err := DecodeFileChunk(make([]byte, fileChunkHeader+MaxFileChunk+1))
			return err
		}},
		{"done: too short for a digest", func() error { _, _, err := DecodeFileDone(make([]byte, 39)); return err }},
		{"cancel: missing reason", func() error { _, _, err := DecodeFileCancel(make([]byte, 8)); return err }},
	}

	for _, c := range cases {
		err := c.decode()
		if err == nil {
			t.Errorf("%s: accepted, want ErrMalformed", c.name)
			continue
		}
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", c.name, err)
		}
	}
}

// TestFileDecodersTolerateTrailingBytes is the forward-compatibility rule of
// docs/protocol.md §13.4: a later version may append fields to the control
// payloads, so today's decoders must ignore what they do not know. This looks
// like laxness and is deliberate — without it, adding a field later would need
// a new frame type.
func TestFileDecodersTolerateTrailingBytes(t *testing.T) {
	pad := bytes.Repeat([]byte{0xAA}, 7)

	offer := make([]byte, 0, 32)
	offer = binary.BigEndian.AppendUint64(offer, 5)
	offer = binary.BigEndian.AppendUint64(offer, 64)
	offer = binary.BigEndian.AppendUint16(offer, 2)
	offer = append(offer, "hi"...)
	got, err := DecodeFileOffer(append(offer, pad...))
	if err != nil {
		t.Fatalf("offer with trailing bytes: %v", err)
	}
	if got.ID != 5 || got.Size != 64 || got.Name != "hi" {
		t.Fatalf("offer with trailing bytes decoded as %+v", got)
	}

	accept := make([]byte, 16)
	binary.BigEndian.PutUint64(accept[0:8], 6)
	if id, off, err := DecodeFileAccept(append(accept, pad...)); err != nil || id != 6 || off != 0 {
		t.Fatalf("accept with trailing bytes: id=%d offset=%d err=%v", id, off, err)
	}

	done := make([]byte, 8+fileDigestSize)
	binary.BigEndian.PutUint64(done[0:8], 7)
	if id, digest, err := DecodeFileDone(append(done, pad...)); err != nil || id != 7 || len(digest) != fileDigestSize {
		t.Fatalf("done with trailing bytes: id=%d digest=%d bytes err=%v", id, len(digest), err)
	}

	cancel := make([]byte, 9)
	binary.BigEndian.PutUint64(cancel[0:8], 8)
	cancel[8] = CancelUserRequest
	if id, reason, err := DecodeFileCancel(append(cancel, pad...)); err != nil || id != 8 || reason != CancelUserRequest {
		t.Fatalf("cancel with trailing bytes: id=%d reason=%d err=%v", id, reason, err)
	}
}

// TestParseFrameAcceptsFileTypes guards the whitelist in parseFrame. A type
// missing from it is rejected before decryption, which would make the feature
// fail silently rather than loudly — so this asserts the five new types are
// present and that the next unused one is still refused.
func TestParseFrameAcceptsFileTypes(t *testing.T) {
	sa, _ := newPair(t)

	for _, typ := range []byte{TypeFileOffer, TypeFileAccept, TypeFileChunk, TypeFileDone, TypeFileCancel} {
		wire, err := sa.Seal(typ, []byte("payload"))
		if err != nil {
			t.Fatalf("sealing type %d: %v", typ, err)
		}
		if _, err := parseFrame(wire); err != nil {
			t.Errorf("type %d is not in parseFrame's whitelist: %v", typ, err)
		}
	}

	// 11 is unassigned; it must still be refused structurally.
	wire, err := sa.Seal(TypeFileCancel, []byte("payload"))
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	wire[1] = 11
	if _, err := parseFrame(wire); !errors.Is(err, ErrMalformed) {
		t.Errorf("unassigned type 11: got %v, want ErrMalformed", err)
	}
}

// TestFileChunkStreamCrossesEpochBoundaries exercises a scale only file
// transfer reaches. Key rotation happens every rotationInterval sent frames and
// the receiver accepts a single forward roll, so a long run of chunks walks the
// epoch machinery repeatedly — something chat, at human pace, never does.
func TestFileChunkStreamCrossesEpochBoundaries(t *testing.T) {
	sa, sb := newPair(t)

	const frames = rotationInterval*2 + 50 // two full rotations and change
	data := bytes.Repeat([]byte{0x11}, 512)
	for i := 0; i < frames; i++ {
		wire, err := sa.SealFileChunk(1, uint64(i)*512, data)
		if err != nil {
			t.Fatalf("sealing chunk %d: %v", i, err)
		}
		typ, pt, err := sb.Open(wire)
		if err != nil {
			t.Fatalf("opening chunk %d (epoch boundary?): %v", i, err)
		}
		if typ != TypeFileChunk {
			t.Fatalf("chunk %d: frame type %d, want %d", i, typ, TypeFileChunk)
		}
		id, off, got, err := DecodeFileChunk(pt)
		if err != nil {
			t.Fatalf("decoding chunk %d: %v", i, err)
		}
		if id != 1 || off != uint64(i)*512 || !bytes.Equal(got, data) {
			t.Fatalf("chunk %d decoded as id=%d offset=%d len=%d", i, id, off, len(got))
		}
	}
	if sa.epoch < 2 {
		t.Fatalf("sender epoch is %d after %d frames; the test did not cross two rotations", sa.epoch, frames)
	}
}
