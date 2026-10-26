package transfer

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/4ntyr/heimdall/internal/peers"
	"github.com/4ntyr/heimdall/internal/proto"
)

// fakeLink stands in for a session connection. The point of declaring Link in
// this package is that a transfer can be driven with no socket at all.
type fakeLink struct {
	name  string
	fp    string
	trust peers.TrustLevel
	path  string

	mu       sync.Mutex
	control  []frameRec
	bulk     []frameRec
	progress []Progress
	sent     int64
	started  int
	finished int
	// blockBulk, when set, makes SendBulk wait on it.
	blockBulk chan struct{}
}

type frameRec struct {
	typ     byte
	payload []byte
}

func newFakeLink() *fakeLink {
	return &fakeLink{
		name:  "bob",
		fp:    "SHA256: AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
		trust: peers.TrustUnverified,
		path:  "DIRECT",
	}
}

func (f *fakeLink) PeerName() string        { return f.name }
func (f *fakeLink) PeerFingerprint() string { return f.fp }
func (f *fakeLink) Trust() peers.TrustLevel { return f.trust }
func (f *fakeLink) Path() string            { return f.path }
func (f *fakeLink) BytesSent() int64        { return f.sent }
func (f *fakeLink) TransferStarted()        { f.mu.Lock(); f.started++; f.mu.Unlock() }
func (f *fakeLink) TransferFinished()       { f.mu.Lock(); f.finished++; f.mu.Unlock() }
func (f *fakeLink) Notify(p Progress)       { f.mu.Lock(); f.progress = append(f.progress, p); f.mu.Unlock() }

func (f *fakeLink) SendControl(typ byte, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.control = append(f.control, frameRec{typ, append([]byte(nil), payload...)})
	return nil
}

func (f *fakeLink) SendBulk(ctx context.Context, typ byte, payload []byte) error {
	if f.blockBulk != nil {
		select {
		case <-f.blockBulk:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bulk = append(f.bulk, frameRec{typ, append([]byte(nil), payload...)})
	return nil
}

// lastControl returns the most recent control frame of a type.
func (f *fakeLink) lastControl(typ byte) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.control) - 1; i >= 0; i-- {
		if f.control[i].typ == typ {
			return f.control[i].payload, true
		}
	}
	return nil, false
}

// lastBulk returns the most recent bulk frame of a type. The end-of-file
// marker travels the bulk path so it cannot overtake the chunks ahead of it,
// so it is found here rather than among the control frames.
func (f *fakeLink) lastBulk(typ byte) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.bulk) - 1; i >= 0; i-- {
		if f.bulk[i].typ == typ {
			return f.bulk[i].payload, true
		}
	}
	return nil, false
}

func (f *fakeLink) lastProgress() (Progress, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.progress) == 0 {
		return Progress{}, false
	}
	return f.progress[len(f.progress)-1], true
}

func testRegistry(t *testing.T, lim Limits) (*Registry, string) {
	t.Helper()
	root := t.TempDir()
	return NewRegistry(root, lim), root
}

// offerTo runs an offer through a registry and returns the link it used.
func offerTo(t *testing.T, r *Registry, l *fakeLink, o proto.FileOffer) {
	t.Helper()
	r.Offer(l, o)
}

// TestOfferRefusedWhenIncomingDisabled covers the off switch.
func TestOfferRefusedWhenIncomingDisabled(t *testing.T) {
	lim := DefaultLimits()
	lim.AcceptIncoming = false
	r, root := testRegistry(t, lim)
	l := newFakeLink()

	offerTo(t, r, l, proto.FileOffer{ID: 1, Size: 10, Name: "a.txt"})

	if _, ok := l.lastControl(proto.TypeFileAccept); ok {
		t.Fatal("an offer was accepted while incoming transfers were disabled")
	}
	payload, ok := l.lastControl(proto.TypeFileCancel)
	if !ok {
		t.Fatal("no cancel was sent")
	}
	_, reason, err := proto.DecodeFileCancel(payload)
	if err != nil {
		t.Fatalf("decoding cancel: %v", err)
	}
	if reason != proto.CancelRefused {
		t.Fatalf("cancel reason %d, want CancelRefused", reason)
	}
	assertNoFiles(t, root)
}

// TestOfferRefusedFromIdentityChangedPeer is the trust gate. That state means
// a MITM warning is on screen unresolved; writing files from it unattended is
// not defensible, and refusing is a default rather than a prompt.
func TestOfferRefusedFromIdentityChangedPeer(t *testing.T) {
	r, root := testRegistry(t, DefaultLimits())
	l := newFakeLink()
	l.trust = peers.TrustChanged

	offerTo(t, r, l, proto.FileOffer{ID: 1, Size: 10, Name: "a.txt"})

	if _, ok := l.lastControl(proto.TypeFileAccept); ok {
		t.Fatal("a file was accepted from a peer whose identity key changed")
	}
	if _, ok := l.lastControl(proto.TypeFileCancel); !ok {
		t.Fatal("no cancel was sent")
	}
	p, ok := l.lastProgress()
	if !ok || p.State != Failed || p.Err == nil {
		t.Fatal("the user was not told why the file was refused")
	}
	assertNoFiles(t, root)
}

// TestOfferRefusedOverSizeCap checks the declared size is screened before any
// file is created.
func TestOfferRefusedOverSizeCap(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxFileSize = 1024
	r, root := testRegistry(t, lim)
	l := newFakeLink()

	offerTo(t, r, l, proto.FileOffer{ID: 1, Size: 4096, Name: "big.bin"})

	payload, ok := l.lastControl(proto.TypeFileCancel)
	if !ok {
		t.Fatal("no cancel was sent")
	}
	_, reason, _ := proto.DecodeFileCancel(payload)
	if reason != proto.CancelTooLarge {
		t.Fatalf("cancel reason %d, want CancelTooLarge", reason)
	}
	assertNoFiles(t, root)
}

// TestOfferRefusedOnBadName keeps a hostile name from reaching the filesystem
// at all, rather than relying on a later check.
func TestOfferRefusedOnBadName(t *testing.T) {
	r, root := testRegistry(t, DefaultLimits())
	l := newFakeLink()

	offerTo(t, r, l, proto.FileOffer{ID: 1, Size: 10, Name: "../../etc/passwd"})

	payload, ok := l.lastControl(proto.TypeFileCancel)
	if !ok {
		t.Fatal("no cancel was sent")
	}
	_, reason, _ := proto.DecodeFileCancel(payload)
	if reason != proto.CancelBadName {
		t.Fatalf("cancel reason %d, want CancelBadName", reason)
	}
	assertNoFiles(t, root)
}

// TestConcurrencyLimits covers both the per-peer and the global cap.
func TestConcurrencyLimits(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxPerPeer = 2
	lim.MaxTotal = 3
	r, _ := testRegistry(t, lim)

	l1 := newFakeLink()
	for i := 1; i <= 3; i++ {
		offerTo(t, r, l1, proto.FileOffer{ID: uint64(i), Size: 10, Name: "a.txt"})
	}
	if got := len(r.List()); got != 2 {
		t.Fatalf("%d transfers accepted from one peer, want 2", got)
	}

	l2 := newFakeLink()
	l2.fp = "SHA256: 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
	for i := 10; i <= 12; i++ {
		offerTo(t, r, l2, proto.FileOffer{ID: uint64(i), Size: 10, Name: "b.txt"})
	}
	if got := len(r.List()); got != 3 {
		t.Fatalf("%d transfers in total, want the global cap of 3", got)
	}
}

// TestChunkEnforcesOffset is the invariant that stops a peer seeking. An
// honoured offset would let it write anywhere in the file, and a huge one
// would make a sparse file of that size.
func TestChunkEnforcesOffset(t *testing.T) {
	r, _ := testRegistry(t, DefaultLimits())
	l := newFakeLink()
	offerTo(t, r, l, proto.FileOffer{ID: 1, Size: 10, Name: "a.txt"})

	rc, ok := r.Receiver(l.fp, 1)
	if !ok {
		t.Fatal("offer was not accepted")
	}

	if err := rc.Chunk(0, []byte("hello"), r.Limits().MaxFileSize); err != nil {
		t.Fatalf("first chunk rejected: %v", err)
	}
	// A gap.
	if err := rc.Chunk(99, []byte("x"), r.Limits().MaxFileSize); err == nil {
		t.Fatal("a chunk with a gap in the offset was accepted")
	}
	// Rewinding.
	if err := rc.Chunk(0, []byte("x"), r.Limits().MaxFileSize); err == nil {
		t.Fatal("a chunk rewriting earlier bytes was accepted")
	}
	// Empty.
	if err := rc.Chunk(5, nil, r.Limits().MaxFileSize); err == nil {
		t.Fatal("an empty chunk was accepted")
	}
}

// TestChunkEnforcesDeclaredSize is why the declared size is a ceiling to
// check rather than a fact to trust: a peer can declare one size and send
// more.
func TestChunkEnforcesDeclaredSize(t *testing.T) {
	r, _ := testRegistry(t, DefaultLimits())
	l := newFakeLink()
	offerTo(t, r, l, proto.FileOffer{ID: 1, Size: 4, Name: "a.txt"})

	rc, ok := r.Receiver(l.fp, 1)
	if !ok {
		t.Fatal("offer was not accepted")
	}
	if err := rc.Chunk(0, []byte("abcd"), r.Limits().MaxFileSize); err != nil {
		t.Fatalf("chunk filling the declared size rejected: %v", err)
	}
	if err := rc.Chunk(4, []byte("e"), r.Limits().MaxFileSize); err == nil {
		t.Fatal("a peer sent more than it declared and was not stopped")
	}
}

// TestReceiveRoundTripPublishes is the receive happy path end to end.
func TestReceiveRoundTripPublishes(t *testing.T) {
	r, root := testRegistry(t, DefaultLimits())
	l := newFakeLink()
	body := []byte("the quick brown fox")
	offerTo(t, r, l, proto.FileOffer{ID: 7, Size: uint64(len(body)), Name: "fox.txt"})

	rc, ok := r.Receiver(l.fp, 7)
	if !ok {
		t.Fatal("offer was not accepted")
	}
	if err := rc.Chunk(0, body, r.Limits().MaxFileSize); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	sum := sha256.Sum256(body)
	r.Done(l, 7, sum[:])

	got, err := os.ReadFile(filepath.Join(root, PeerDir(l.fp), "fox.txt"))
	if err != nil {
		t.Fatalf("published file missing: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("published %q, want %q", got, body)
	}
	if len(r.List()) != 0 {
		t.Fatal("the completed transfer was left in the registry")
	}
	// The done channel must be closed so a blocked reader is released.
	select {
	case <-rc.Done():
	default:
		t.Fatal("the transfer's done channel was left open")
	}
}

// TestReceiveDigestMismatchLeavesNothing covers the integrity check at the
// registry level, including that the slot is released.
func TestReceiveDigestMismatchLeavesNothing(t *testing.T) {
	r, root := testRegistry(t, DefaultLimits())
	l := newFakeLink()
	body := []byte("real contents")
	offerTo(t, r, l, proto.FileOffer{ID: 3, Size: uint64(len(body)), Name: "a.txt"})

	rc, _ := r.Receiver(l.fp, 3)
	if err := rc.Chunk(0, body, r.Limits().MaxFileSize); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	wrong := sha256.Sum256([]byte("forged"))
	r.Done(l, 3, wrong[:])

	assertNoFiles(t, filepath.Join(root, PeerDir(l.fp)))
	if len(r.List()) != 0 {
		t.Fatal("the failed transfer was left in the registry")
	}
	payload, ok := l.lastControl(proto.TypeFileCancel)
	if !ok {
		t.Fatal("no cancel was sent for a digest mismatch")
	}
	_, reason, _ := proto.DecodeFileCancel(payload)
	if reason != proto.CancelDigestMismatch {
		t.Fatalf("cancel reason %d, want CancelDigestMismatch", reason)
	}
}

// TestUnknownCancelIsIgnored keeps two peers from volleying cancels forever.
func TestUnknownCancelIsIgnored(t *testing.T) {
	r, _ := testRegistry(t, DefaultLimits())
	l := newFakeLink()

	r.Refuse(l, 12345, proto.CancelProtocol)

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.control) != 0 {
		t.Fatalf("a cancel for an unknown transfer was answered with %d frames", len(l.control))
	}
}

// TestReapStalledCancels covers the case nothing else notices: a sender that
// goes quiet mid-file while the session itself stays healthy.
func TestReapStalledCancels(t *testing.T) {
	lim := DefaultLimits()
	lim.Stall = 20 * time.Millisecond
	r, root := testRegistry(t, lim)
	l := newFakeLink()
	offerTo(t, r, l, proto.FileOffer{ID: 1, Size: 100, Name: "a.txt"})

	rc, _ := r.Receiver(l.fp, 1)
	if err := rc.Chunk(0, []byte("partial"), lim.MaxFileSize); err != nil {
		t.Fatalf("chunk: %v", err)
	}

	time.Sleep(60 * time.Millisecond)
	r.ReapStalled()

	if len(r.List()) != 0 {
		t.Fatal("a stalled transfer was left in the registry")
	}
	assertNoFiles(t, filepath.Join(root, PeerDir(l.fp)))
	select {
	case <-rc.Done():
	default:
		t.Fatal("a stalled transfer left its done channel open")
	}
}

// TestCancelPeerStopsEverything covers connection loss.
func TestCancelPeerStopsEverything(t *testing.T) {
	r, root := testRegistry(t, DefaultLimits())
	l := newFakeLink()
	for i := 1; i <= 3; i++ {
		offerTo(t, r, l, proto.FileOffer{ID: uint64(i), Size: 100, Name: "a.txt"})
	}
	if len(r.List()) != 3 {
		t.Fatalf("%d transfers registered, want 3", len(r.List()))
	}

	r.CancelPeer(l.fp)

	if len(r.List()) != 0 {
		t.Fatalf("%d transfers survived the peer going away", len(r.List()))
	}
	assertNoFiles(t, filepath.Join(root, PeerDir(l.fp)))
}

// TestRelayBudgetRefusesOversizeOffer covers the ceiling a relay enforces by
// silently closing the circuit. Refusing up front is the only way the user
// learns why, since a live session is never moved off the relay.
func TestRelayBudgetRefusesOversizeOffer(t *testing.T) {
	lim := DefaultLimits()
	lim.RelayCircuitBytes = 1 << 20 // 1 MiB
	lim.RelayBudgetFraction = 0.9
	l := newFakeLink()
	l.path = RelayPath

	// Well within budget.
	if relayBudgetExceeded(l, lim, 100<<10) {
		t.Fatal("a small file was refused on a relayed path")
	}
	// Past the fraction.
	if !relayBudgetExceeded(l, lim, 1<<20) {
		t.Fatal("a file larger than the circuit budget was allowed")
	}
	// Already-spent bytes count.
	l.sent = 900 << 10
	if !relayBudgetExceeded(l, lim, 100<<10) {
		t.Fatal("bytes already sent on the circuit were not counted")
	}
	// A direct path is never limited by this.
	l.path = "DIRECT"
	if relayBudgetExceeded(l, lim, 1<<30) {
		t.Fatal("a direct connection was judged against the relay budget")
	}
}

// TestSendRefusesOverSizeCapAndRelayBudget covers the sender-side screening,
// which happens before any frame goes out.
func TestSendRefusesOverSizeCapAndRelayBudget(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxFileSize = 16
	r, _ := testRegistry(t, lim)
	l := newFakeLink()

	big := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(big, make([]byte, 64), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if _, err := r.Send(context.Background(), l, big); err == nil {
		t.Fatal("a file over the local cap was offered")
	}

	// A directory is not a file.
	if _, err := r.Send(context.Background(), l, t.TempDir()); err == nil {
		t.Fatal("a directory was offered as a file")
	}
	// A missing file.
	if _, err := r.Send(context.Background(), l, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("a missing file was offered")
	}

	l.mu.Lock()
	n := len(l.control)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d frames were sent for offers that should have failed locally", n)
	}
}

// TestSendStreamsAndCompletes drives the whole outgoing path against a fake
// link, with no socket involved.
func TestSendStreamsAndCompletes(t *testing.T) {
	r, _ := testRegistry(t, DefaultLimits())
	l := newFakeLink()

	body := make([]byte, proto.MaxFileChunk*2+17) // spans three chunks
	for i := range body {
		body[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	id, err := r.Send(context.Background(), l, path)
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	// The offer goes first; accept it as a peer would.
	waitFor(t, func() bool { _, ok := l.lastControl(proto.TypeFileOffer); return ok })
	r.Accept(l, id, 0)

	// Then chunks, then a done frame carrying the digest.
	waitFor(t, func() bool { _, ok := l.lastBulk(proto.TypeFileDone); return ok })

	l.mu.Lock()
	var chunks []frameRec
	for _, f := range l.bulk {
		if f.typ == proto.TypeFileChunk {
			chunks = append(chunks, f)
		}
	}
	bulkLen := len(l.bulk)
	lastTyp := l.bulk[bulkLen-1].typ
	l.mu.Unlock()
	if len(chunks) != 3 {
		t.Fatalf("%d chunk frames, want 3", len(chunks))
	}
	// The marker must be last on the bulk path, or it would reach the peer
	// before chunks still queued behind it and the digest would be checked
	// against a short file.
	if lastTyp != proto.TypeFileDone {
		t.Fatalf("the last bulk frame was type %d, want the end-of-file marker", lastTyp)
	}

	// Reassemble and compare, exactly as a receiver would.
	var got []byte
	for i, c := range chunks {
		gotID, offset, data, err := proto.DecodeFileChunk(c.payload)
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		if gotID != id {
			t.Fatalf("chunk %d carried id %d, want %d", i, gotID, id)
		}
		if offset != uint64(len(got)) {
			t.Fatalf("chunk %d offset %d, want %d", i, offset, len(got))
		}
		got = append(got, data...)
	}
	if string(got) != string(body) {
		t.Fatalf("reassembled %d bytes, sent %d", len(got), len(body))
	}

	donePayload, _ := l.lastBulk(proto.TypeFileDone)
	_, digest, err := proto.DecodeFileDone(donePayload)
	if err != nil {
		t.Fatalf("decoding done: %v", err)
	}
	want := sha256.Sum256(body)
	if string(digest) != string(want[:]) {
		t.Fatal("the digest does not match the bytes that were sent")
	}
}

// TestSendReportsPeerRefusal covers the refusal path on the sending side.
func TestSendReportsPeerRefusal(t *testing.T) {
	r, _ := testRegistry(t, DefaultLimits())
	l := newFakeLink()

	path := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	id, err := r.Send(context.Background(), l, path)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor(t, func() bool { _, ok := l.lastControl(proto.TypeFileOffer); return ok })

	r.Refuse(l, id, proto.CancelTooLarge)

	waitFor(t, func() bool {
		p, ok := l.lastProgress()
		return ok && p.State == Failed
	})
	p, _ := l.lastProgress()
	if p.Err == nil {
		t.Fatal("a refused transfer reported no reason")
	}
}

// TestSendUnsupportedPeerTimesOut is why an accept frame exists at all.
//
// The frame types are not negotiated, so a peer too old to know them discards
// the offer structurally and says nothing. Silence is the only signal, and
// without a timeout the sender would wait forever with nothing on screen.
func TestSendUnsupportedPeerTimesOut(t *testing.T) {
	old := offerTimeout
	offerTimeout = 50 * time.Millisecond
	t.Cleanup(func() { offerTimeout = old })

	r, _ := testRegistry(t, DefaultLimits())
	l := newFakeLink()
	path := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if _, err := r.Send(context.Background(), l, path); err != nil {
		t.Fatalf("send: %v", err)
	}

	waitFor(t, func() bool {
		p, ok := l.lastProgress()
		return ok && p.State == Failed && p.Err != nil
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.bulk) != 0 {
		t.Fatalf("%d chunks were sent without an accept", len(l.bulk))
	}
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was not met within the deadline")
}

// assertNoFiles fails if dir contains any entries. A missing directory counts
// as empty.
func assertNoFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) != 0 {
		t.Fatalf("expected no files in %s, found %v", dir, names)
	}
}

// TestBusyCountReturnsToZero covers a leak that is invisible until much later.
//
// The session marks a connection busy while a transfer runs, so duplicate
// resolution will not swap it out mid-file. If a termination path forgets to
// report the transfer finished, the count never returns to zero and that
// connection stays "busy" forever — refusing legitimate replacement by a
// better path for the rest of the session, with nothing on screen to explain
// it. There are six ways an incoming transfer can end, so this walks each one
// and checks the books balance.
func TestBusyCountReturnsToZero(t *testing.T) {
	body := []byte("contents")
	sum := sha256.Sum256(body)

	cases := []struct {
		name string
		end  func(t *testing.T, r *Registry, l *fakeLink, rc *recv)
	}{
		{"completed", func(t *testing.T, r *Registry, l *fakeLink, rc *recv) {
			if err := rc.Chunk(0, body, r.Limits().MaxFileSize); err != nil {
				t.Fatalf("chunk: %v", err)
			}
			r.Done(l, 1, sum[:])
		}},
		{"digest mismatch", func(t *testing.T, r *Registry, l *fakeLink, rc *recv) {
			if err := rc.Chunk(0, body, r.Limits().MaxFileSize); err != nil {
				t.Fatalf("chunk: %v", err)
			}
			bad := sha256.Sum256([]byte("forged"))
			r.Done(l, 1, bad[:])
		}},
		{"rule-violating chunk", func(t *testing.T, r *Registry, l *fakeLink, rc *recv) {
			r.Chunk(l, 1, 999, []byte("x"))
		}},
		{"peer cancelled", func(t *testing.T, r *Registry, l *fakeLink, rc *recv) {
			r.Refuse(l, 1, proto.CancelUserRequest)
		}},
		{"user cancelled", func(t *testing.T, r *Registry, l *fakeLink, rc *recv) {
			if err := r.Cancel(l.fp, 1); err != nil {
				t.Fatalf("cancel: %v", err)
			}
		}},
		{"connection lost", func(t *testing.T, r *Registry, l *fakeLink, rc *recv) {
			r.CancelPeer(l.fp)
		}},
	}

	for _, c := range cases {
		lim := DefaultLimits()
		r, _ := testRegistry(t, lim)
		l := newFakeLink()
		offerTo(t, r, l, proto.FileOffer{ID: 1, Size: uint64(len(body)), Name: "a.txt"})

		rc, ok := r.Receiver(l.fp, 1)
		if !ok {
			t.Fatalf("%s: offer was not accepted", c.name)
		}
		l.mu.Lock()
		started, finished := l.started, l.finished
		l.mu.Unlock()
		if started != 1 || finished != 0 {
			t.Fatalf("%s: before ending, started=%d finished=%d, want 1 and 0",
				c.name, started, finished)
		}

		c.end(t, r, l, rc)

		l.mu.Lock()
		started, finished = l.started, l.finished
		l.mu.Unlock()
		if started != finished {
			t.Errorf("%s: started=%d finished=%d — the connection would stay busy forever",
				c.name, started, finished)
		}
	}
}

// TestStalledTransferBalancesBusyCount covers the sixth path, which needs its
// own timing.
func TestStalledTransferBalancesBusyCount(t *testing.T) {
	lim := DefaultLimits()
	lim.Stall = 20 * time.Millisecond
	r, _ := testRegistry(t, lim)
	l := newFakeLink()
	offerTo(t, r, l, proto.FileOffer{ID: 1, Size: 100, Name: "a.txt"})

	rc, _ := r.Receiver(l.fp, 1)
	if err := rc.Chunk(0, []byte("partial"), lim.MaxFileSize); err != nil {
		t.Fatalf("chunk: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	r.ReapStalled()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started != l.finished {
		t.Fatalf("started=%d finished=%d after a stall — the connection would stay busy",
			l.started, l.finished)
	}
}
