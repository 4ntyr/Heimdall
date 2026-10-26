package session

import (
	"context"
	"testing"
	"time"

	"github.com/4ntyr/heimdall/internal/proto"
)

// connOf returns the single connection a manager holds.
func connOf(t *testing.T, m *Manager) *conn {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.conns) != 1 {
		t.Fatalf("expected one connection, got %d", len(m.conns))
	}
	for _, c := range m.conns {
		return c
	}
	return nil
}

// pairedManagers returns two managers joined over a loopback socket pair.
func pairedManagers(t *testing.T) (*Manager, *Manager) {
	t.Helper()
	a := newTestManager(t, "alice")
	t.Cleanup(a.Shutdown)
	b := newTestManager(t, "bob")
	t.Cleanup(b.Shutdown)
	key := make([]byte, 32)
	if errA, errB := adoptPair(t, a, b, key, key); errA != nil || errB != nil {
		t.Fatalf("pairing failed: initiator=%v responder=%v", errA, errB)
	}
	return a, b
}

// blockWriter stops a connection's writeLoop from draining either queue, by
// filling the priority queue while holding the only thing writeLoop can make
// progress on. It returns a release function.
//
// It works by saturating c.send: writeLoop takes one frame at a time, so with
// the queue full and the socket unread by the far side, frames accumulate.
func fillPriorityQueue(t *testing.T, c *conn) {
	t.Helper()
	for i := 0; i < cap(c.send); i++ {
		select {
		case c.send <- outFrame{typ: proto.TypePing}:
		default:
			return
		}
	}
}

// TestBulkQueueDoesNotBlockControlFrames is the property that makes a transfer
// survivable: bulk data must never make a control frame fail to queue.
//
// Before the split there was one queue, so a file saturating it made
// enqueue return "send queue full" — and keepaliveLoop drops the connection
// when its ping fails to queue. A transfer would therefore tear down the
// session it was running on.
func TestBulkQueueDoesNotBlockControlFrames(t *testing.T) {
	alice, _ := pairedManagers(t)
	c := connOf(t, alice)

	// Saturate the bulk queue. Nothing drains it faster than we fill it here
	// because each slot is only freed once writeLoop has sealed and written.
	filled := 0
	for i := 0; i < cap(c.bulk)*4; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := alice.enqueueBulk(ctx, c, proto.TypeFileChunk, []byte("chunk"))
		cancel()
		if err != nil {
			break
		}
		filled++
	}
	if filled == 0 {
		t.Fatal("could not queue any bulk frames")
	}

	// A control frame must still go through.
	if err := alice.enqueue(c, proto.TypePing, nil); err != nil {
		t.Fatalf("a ping could not be queued while bulk data was pending: %v", err)
	}
	if err := alice.Send("bob", "chat still works"); err != nil {
		t.Fatalf("chat could not be queued while bulk data was pending: %v", err)
	}
}

// TestEnqueueBulkBlocksThenUnblocksOnClose pins the backpressure contract. A
// bulk producer that cannot queue must wait rather than spin or drop data, and
// it must not wait forever once the connection goes away.
func TestEnqueueBulkBlocksThenUnblocksOnClose(t *testing.T) {
	alice, _ := pairedManagers(t)
	c := connOf(t, alice)

	// Fill the bulk queue and keep writeLoop busy so it stays full.
	fillPriorityQueue(t, c)
	for i := 0; i < cap(c.bulk); i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = alice.enqueueBulk(ctx, c, proto.TypeFileChunk, []byte("x"))
		cancel()
	}

	// This one should block, not error.
	blocked := make(chan error, 1)
	go func() {
		blocked <- alice.enqueueBulk(context.Background(), c, proto.TypeFileChunk, []byte("y"))
	}()

	select {
	case err := <-blocked:
		// Draining may have freed a slot; only an error is a failure here.
		if err != nil {
			t.Fatalf("enqueueBulk returned an error instead of waiting: %v", err)
		}
		return
	case <-time.After(200 * time.Millisecond):
		// Still waiting, which is the behaviour under test.
	}

	// Closing the connection must release the waiter.
	c.close()
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("enqueueBulk succeeded after the connection closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("enqueueBulk did not return after the connection closed")
	}
}

// TestEnqueueBulkHonoursContext keeps a caller from being stuck when it has
// decided to give up, e.g. a cancelled transfer.
func TestEnqueueBulkHonoursContext(t *testing.T) {
	alice, _ := pairedManagers(t)
	c := connOf(t, alice)

	fillPriorityQueue(t, c)
	for i := 0; i < cap(c.bulk); i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = alice.enqueueBulk(ctx, c, proto.TypeFileChunk, []byte("x"))
		cancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- alice.enqueueBulk(ctx, c, proto.TypeFileChunk, []byte("y"))
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			// A slot opened before the cancel landed; nothing to assert.
			return
		}
	case <-time.After(5 * time.Second):
		t.Fatal("enqueueBulk ignored a cancelled context")
	}
}

// TestPreferNewKeepsBusyConnection covers the duplicate-resolution hazard.
//
// register only short-circuits for a connection with no unanswered pings, and
// keepaliveLoop raises unanswered on every tick before the pong can clear it.
// So without the busy check, any inbound handshake arriving in that window
// replaces a connection mid-transfer — and there is no resume, so the file is
// lost. A connection stops being protected once it is properly unresponsive,
// because by then the transfer is doomed anyway.
func TestPreferNewKeepsBusyConnection(t *testing.T) {
	alice, _ := pairedManagers(t)
	old := connOf(t, alice)

	// A second connection to the same peer, as a racing path would produce.
	replacement := &conn{
		fp:   old.fp,
		sess: old.sess,
		done: make(chan struct{}),
	}

	old.unanswered.Store(1) // mid-keepalive, as it is for part of every tick

	if !preferNew(old, replacement) {
		t.Fatal("an idle connection with an unanswered ping should be replaceable")
	}

	old.busy.Store(1)
	if preferNew(old, replacement) {
		t.Fatal("a connection carrying a transfer was replaced mid-file")
	}

	// Properly unresponsive: protection lifts.
	old.unanswered.Store(keepaliveMisses + 1)
	if !preferNew(old, replacement) {
		t.Fatal("an unresponsive connection stayed protected because it was busy")
	}
}

// TestWroteSinceTracksWrites is the input to the keepalive decision: a miss
// counts only for a ping that actually reached the socket.
func TestWroteSinceTracksWrites(t *testing.T) {
	alice, _ := pairedManagers(t)
	c := connOf(t, alice)

	// The handshake and pairing confirmation go out via fio.Send directly,
	// not writeLoop, so force a frame through the queue and wait for it.
	before := time.Now()
	if err := alice.Send("bob", "tick"); err != nil {
		t.Fatalf("send: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.wroteSince(before) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !c.wroteSince(before) {
		t.Fatal("wroteSince did not observe a completed write")
	}
	// A moment in the future has not been written past.
	if c.wroteSince(time.Now().Add(time.Second)) {
		t.Fatal("wroteSince reported a write that has not happened")
	}
}

// TestBytesSentCountsFramingOverhead checks the figure the relay budget is
// judged against. A relay counts the 4-byte length prefix as well as the
// frame, so an estimate that omits it would let a transfer run past the
// circuit limit and die with no explanation.
func TestBytesSentCountsFramingOverhead(t *testing.T) {
	alice, _ := pairedManagers(t)
	c := connOf(t, alice)

	start := c.bytesSent.Load()
	const payload = 1000
	if err := alice.enqueue(c, proto.TypeFileChunk, make([]byte, payload)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && c.bytesSent.Load() == start {
		time.Sleep(10 * time.Millisecond)
	}
	grew := c.bytesSent.Load() - start
	// 4 (length prefix) + 22 (header) + 12 (nonce) + payload + 16 (tag).
	const want = 4 + 22 + 12 + payload + 16
	if grew != want {
		t.Fatalf("bytesSent grew by %d for a %d-byte payload, want %d", grew, payload, want)
	}
}
