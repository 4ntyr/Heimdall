package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/4ntyr/heimdall/internal/transfer"
)

// transferPair returns two connected managers with file transfer enabled, and
// the download root of each.
func transferPair(t *testing.T, lim transfer.Limits) (*Manager, string, *Manager, string) {
	t.Helper()
	alice := newTestManager(t, "alice")
	t.Cleanup(alice.Shutdown)
	bob := newTestManager(t, "bob")
	t.Cleanup(bob.Shutdown)

	aRoot := t.TempDir()
	bRoot := t.TempDir()
	alice.EnableTransfers(aRoot, lim)
	bob.EnableTransfers(bRoot, lim)

	key := make([]byte, 32)
	if errA, errB := adoptPair(t, alice, bob, key, key); errA != nil || errB != nil {
		t.Fatalf("pairing failed: initiator=%v responder=%v", errA, errB)
	}
	return alice, aRoot, bob, bRoot
}

// writeRandom creates a file of n random bytes and returns its path and digest.
func writeRandom(t *testing.T, n int) (string, []byte) {
	t.Helper()
	body := make([]byte, n)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("generating body: %v", err)
	}
	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing payload: %v", err)
	}
	sum := sha256.Sum256(body)
	return path, sum[:]
}

// direction selects which side of a transfer an awaited event must concern.
type direction int

const (
	anyDirection direction = iota
	incoming
	outgoing
)

func (d direction) matches(info *TransferInfo) bool {
	switch d {
	case incoming:
		return !info.Outgoing
	case outgoing:
		return info.Outgoing
	}
	return true
}

// awaitTransferEvent drains a manager's events until a matching transfer event
// arrives.
//
// The direction filter matters whenever a manager is both sending and
// receiving: a sender emits a completion of its own, so waiting for "a Done
// event" would return the wrong transfer's and let the test read a file that
// is still being written.
func awaitTransferEvent(t *testing.T, m *Manager, want EventType, dir direction, timeout time.Duration) *TransferInfo {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-m.Events():
			if ev.Transfer == nil {
				continue
			}
			if ev.Type == want && dir.matches(ev.Transfer) {
				return ev.Transfer
			}
			if ev.Type == EventTransferFailed && want != EventTransferFailed && dir.matches(ev.Transfer) {
				t.Fatalf("transfer failed unexpectedly: %v", ev.Transfer.Err)
			}
		case <-deadline:
			t.Fatalf("no event of type %d within %v", want, timeout)
		}
	}
}

// receivedFile returns the single file in a peer's download directory.
func receivedFile(t *testing.T, root, peerFP string) (string, []byte) {
	t.Helper()
	dir := filepath.Join(root, transfer.PeerDir(peerFP))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e.Name())
		}
	}
	if len(files) != 1 {
		t.Fatalf("expected one file in %s, found %v", dir, files)
	}
	p := filepath.Join(dir, files[0])
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("reading %s: %v", p, err)
	}
	return files[0], body
}

// TestFileTransferEndToEnd sends a real file over a real socket pair through
// the whole stack — offer, accept, chunking, reassembly, digest — and checks
// the bytes arrive identical.
func TestFileTransferEndToEnd(t *testing.T) {
	alice, _, bob, bRoot := transferPair(t, transfer.DefaultLimits())

	const size = 300 << 10 // spans ~75 chunks, several progress updates
	path, want := writeRandom(t, size)

	if _, err := alice.SendFile(context.Background(), "bob", path); err != nil {
		t.Fatalf("SendFile: %v", err)
	}

	info := awaitTransferEvent(t, bob, EventTransferDone, incoming, 30*time.Second)
	if info.Size != size || info.Done != size {
		t.Fatalf("received %d of %d bytes", info.Done, info.Size)
	}

	name, got := receivedFile(t, bRoot, alice.id.Fingerprint())
	if name != "payload.bin" {
		t.Fatalf("file published as %q, want payload.bin", name)
	}
	if len(got) != size {
		t.Fatalf("published %d bytes, sent %d", len(got), size)
	}
	gotSum := sha256.Sum256(got)
	if !bytes.Equal(gotSum[:], want) {
		t.Fatal("the received file does not match what was sent")
	}

	// Both sides must release the transfer, so a slot is not leaked.
	waitUntil(t, 10*time.Second, func() bool {
		return len(alice.Transfers()) == 0 && len(bob.Transfers()) == 0
	}, "transfers were not released")
}

// TestFileTransferBothDirections runs two transfers at once over one session,
// which is also what proves a single connection's queues and disk writer are
// not confused by concurrent work.
func TestFileTransferBothDirections(t *testing.T) {
	alice, aRoot, bob, bRoot := transferPair(t, transfer.DefaultLimits())

	aPath, aWant := writeRandom(t, 80<<10)
	bPath, bWant := writeRandom(t, 120<<10)

	if _, err := alice.SendFile(context.Background(), "bob", aPath); err != nil {
		t.Fatalf("alice SendFile: %v", err)
	}
	if _, err := bob.SendFile(context.Background(), "alice", bPath); err != nil {
		t.Fatalf("bob SendFile: %v", err)
	}

	awaitTransferEvent(t, bob, EventTransferDone, incoming, 30*time.Second)
	awaitTransferEvent(t, alice, EventTransferDone, incoming, 30*time.Second)

	_, gotAtBob := receivedFile(t, bRoot, alice.id.Fingerprint())
	if sum := sha256.Sum256(gotAtBob); !bytes.Equal(sum[:], aWant) {
		t.Fatal("the file bob received does not match what alice sent")
	}
	_, gotAtAlice := receivedFile(t, aRoot, bob.id.Fingerprint())
	if sum := sha256.Sum256(gotAtAlice); !bytes.Equal(sum[:], bWant) {
		t.Fatal("the file alice received does not match what bob sent")
	}
}

// TestChatSurvivesFileTransfer is the regression test for the queueing work.
//
// Against a single shared send queue this fails: a file saturates the queue,
// chat sends start returning "send queue full", and the keepalive ping that
// cannot be queued makes the connection drop outright. It asserts all three
// things that were broken — chat still queues, chat still arrives, and the
// session is still up afterwards.
func TestChatSurvivesFileTransfer(t *testing.T) {
	alice, _, bob, _ := transferPair(t, transfer.DefaultLimits())

	path, _ := writeRandom(t, 400<<10)
	if _, err := alice.SendFile(context.Background(), "bob", path); err != nil {
		t.Fatalf("SendFile: %v", err)
	}

	// Interleave chat with the transfer. Every send must succeed.
	const messages = 20
	for i := 0; i < messages; i++ {
		if err := alice.Send("bob", "while the file is in flight"); err != nil {
			t.Fatalf("chat send %d failed during a transfer: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// And they must actually arrive.
	seen := 0
	deadline := time.After(30 * time.Second)
	for seen < messages {
		select {
		case ev := <-bob.Events():
			switch ev.Type {
			case EventMessage:
				seen++
			case EventPeerDisconnected:
				t.Fatal("the session was dropped during a file transfer")
			case EventTransferFailed:
				if ev.Transfer != nil {
					t.Fatalf("transfer failed: %v", ev.Transfer.Err)
				}
				t.Fatal("transfer failed")
			}
		case <-deadline:
			t.Fatalf("only %d of %d chat messages arrived during a transfer", seen, messages)
		}
	}

	if got := len(alice.Peers()); got != 1 {
		t.Fatalf("alice has %d peers after a transfer, want 1", got)
	}
	if got := len(bob.Peers()); got != 1 {
		t.Fatalf("bob has %d peers after a transfer, want 1", got)
	}
}

// TestFileTransferRefusedByReceiverPolicy checks the refusal travels back to
// the sender rather than leaving it waiting.
func TestFileTransferRefusedByReceiverPolicy(t *testing.T) {
	lim := transfer.DefaultLimits()
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	bob := newTestManager(t, "bob")
	defer bob.Shutdown()

	alice.EnableTransfers(t.TempDir(), lim)
	// Bob refuses everything.
	bobLim := lim
	bobLim.AcceptIncoming = false
	bob.EnableTransfers(t.TempDir(), bobLim)

	key := make([]byte, 32)
	if errA, errB := adoptPair(t, alice, bob, key, key); errA != nil || errB != nil {
		t.Fatalf("pairing failed: initiator=%v responder=%v", errA, errB)
	}

	path, _ := writeRandom(t, 4096)
	if _, err := alice.SendFile(context.Background(), "bob", path); err != nil {
		t.Fatalf("SendFile: %v", err)
	}

	info := awaitTransferEvent(t, alice, EventTransferFailed, outgoing, 30*time.Second)
	if info.Err == nil {
		t.Fatal("the sender was not told why the transfer failed")
	}
}

// TestFileTransferOverSizeCapIsRefused covers the receiver's cap end to end:
// the sender's own limit is higher, so only the receiver can stop this.
func TestFileTransferOverSizeCapIsRefused(t *testing.T) {
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	bob := newTestManager(t, "bob")
	defer bob.Shutdown()

	senderLim := transfer.DefaultLimits()
	alice.EnableTransfers(t.TempDir(), senderLim)
	recvLim := transfer.DefaultLimits()
	recvLim.MaxFileSize = 1024
	bobRoot := t.TempDir()
	bob.EnableTransfers(bobRoot, recvLim)

	key := make([]byte, 32)
	if errA, errB := adoptPair(t, alice, bob, key, key); errA != nil || errB != nil {
		t.Fatalf("pairing failed: initiator=%v responder=%v", errA, errB)
	}

	path, _ := writeRandom(t, 8192)
	if _, err := alice.SendFile(context.Background(), "bob", path); err != nil {
		t.Fatalf("SendFile: %v", err)
	}

	info := awaitTransferEvent(t, alice, EventTransferFailed, outgoing, 30*time.Second)
	if info.Err == nil {
		t.Fatal("the sender was not told the file was refused")
	}
	// Nothing may be left on the receiver's disk.
	dir := filepath.Join(bobRoot, transfer.PeerDir(alice.id.Fingerprint()))
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				t.Fatalf("a refused transfer left %s behind", e.Name())
			}
		}
	}
}

// TestFileTransferDisabledRefusesOffer checks a manager with transfers off
// still answers, rather than leaving the sender to time out.
func TestFileTransferDisabledRefusesOffer(t *testing.T) {
	alice := newTestManager(t, "alice")
	defer alice.Shutdown()
	bob := newTestManager(t, "bob")
	defer bob.Shutdown()

	alice.EnableTransfers(t.TempDir(), transfer.DefaultLimits())
	// bob never calls EnableTransfers.

	key := make([]byte, 32)
	if errA, errB := adoptPair(t, alice, bob, key, key); errA != nil || errB != nil {
		t.Fatalf("pairing failed: initiator=%v responder=%v", errA, errB)
	}

	path, _ := writeRandom(t, 2048)
	if _, err := alice.SendFile(context.Background(), "bob", path); err != nil {
		t.Fatalf("SendFile: %v", err)
	}
	info := awaitTransferEvent(t, alice, EventTransferFailed, outgoing, 30*time.Second)
	if info.Err == nil {
		t.Fatal("the sender was not told the peer refuses transfers")
	}
}

// TestSendFileWithoutTransfersEnabled is the guard for a Manager that never
// enabled the feature.
func TestSendFileWithoutTransfersEnabled(t *testing.T) {
	alice, _ := pairedManagers(t)
	path, _ := writeRandom(t, 16)
	if _, err := alice.SendFile(context.Background(), "bob", path); err == nil {
		t.Fatal("SendFile succeeded with transfers disabled")
	}
}

// TestTransferCancelledOnDisconnect covers teardown: there is no resume, so a
// transfer cannot outlive its connection, and its partial file and slot must
// be released.
func TestTransferCancelledOnDisconnect(t *testing.T) {
	lim := transfer.DefaultLimits()
	alice, _, bob, bRoot := transferPair(t, lim)

	path, _ := writeRandom(t, 2<<20) // big enough to still be running
	if _, err := alice.SendFile(context.Background(), "bob", path); err != nil {
		t.Fatalf("SendFile: %v", err)
	}
	// Wait until bob is actually receiving.
	waitUntil(t, 20*time.Second, func() bool { return len(bob.Transfers()) > 0 },
		"bob never started receiving")

	if err := alice.Disconnect("bob"); err != nil {
		t.Fatalf("disconnect: %v", err)
	}

	waitUntil(t, 20*time.Second, func() bool { return len(bob.Transfers()) == 0 },
		"bob kept a transfer after the connection closed")

	// No completed file, and no .part left behind.
	dir := filepath.Join(bRoot, transfer.PeerDir(alice.id.Fingerprint()))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // directory never created, which is fine
	}
	for _, e := range entries {
		if !e.IsDir() {
			t.Fatalf("an aborted transfer left %s behind", e.Name())
		}
	}
}

// TestFileTransferLargeFile exercises enough chunks to cross several key
// rotation epochs, at a size worth skipping in a short run.
func TestFileTransferLargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-megabyte transfer skipped in short mode")
	}
	alice, _, bob, bRoot := transferPair(t, transfer.DefaultLimits())

	const size = 6 << 20 // ~1540 chunks, past one rotation interval
	path, want := writeRandom(t, size)
	if _, err := alice.SendFile(context.Background(), "bob", path); err != nil {
		t.Fatalf("SendFile: %v", err)
	}

	awaitTransferEvent(t, bob, EventTransferDone, incoming, 2*time.Minute)

	_, got := receivedFile(t, bRoot, alice.id.Fingerprint())
	if len(got) != size {
		t.Fatalf("received %d bytes, sent %d", len(got), size)
	}
	if sum := sha256.Sum256(got); !bytes.Equal(sum[:], want) {
		t.Fatal("a multi-megabyte transfer did not arrive intact")
	}
}

// waitUntil polls cond until it holds or the timeout expires.
func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}
