package transfer

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/4ntyr/heimdall/internal/peers"
	"github.com/4ntyr/heimdall/internal/proto"
)

// progressInterval is the minimum gap between progress notifications.
//
// Notifications are for people, and the terminal has no cursor control to
// rewrite a line, so they appear as ordinary output. Emitting one per 4 KiB
// chunk would bury the conversation.
const progressInterval = 5 * time.Second

// progressStep is the completion increment that also triggers a notification,
// so a fast transfer still reports more than once.
const progressStep = 10

// notifyRefusal tells the user about an offer that was turned down.
//
// A refusal is reported because auto-accept means the user was not asked:
// without this, a file they were told about out-of-band would simply never
// appear, with nothing on screen to explain why. The name comes from the peer,
// so Progress.String quotes it.
func (r *Registry) notifyRefusal(l Link, o proto.FileOffer, err error) {
	l.Notify(Progress{
		ID:        o.ID,
		Direction: Incoming,
		Peer:      l.PeerName(),
		Name:      o.Name,
		Size:      int64(o.Size),
		State:     Failed,
		Err:       err,
	})
}

// recv is one incoming transfer.
type recv struct {
	id   uint64
	name string
	size int64

	link Link
	part *PartFile

	received  atomic.Int64
	state     atomic.Int32
	lastPct   int
	lastAt    time.Time
	lastChunk atomic.Int64

	// done is closed once this transfer stops accepting chunks, for any
	// reason. The session's reader selects on it so a transfer that has given
	// up cannot leave the reader blocked on a queue nobody will drain.
	done     chan struct{}
	closeOne sync.Once

	mu      sync.Mutex
	lastErr error
	outPath string
}

// Offer handles an inbound TypeFileOffer, deciding whether to accept.
//
// Every check here is the receiver's own. Nothing the sender declares relaxes
// one, and the declared size in particular is treated as a claim to be
// enforced rather than a fact (docs/protocol.md §13.5).
func (r *Registry) Offer(l Link, o proto.FileOffer) {
	refuse := func(reason byte) {
		_ = l.SendControl(proto.TypeFileCancel, proto.EncodeFileCancel(o.ID, reason))
	}

	if !r.lim.AcceptIncoming {
		refuse(proto.CancelRefused)
		return
	}
	// A peer whose identity key changed is in an unresolved MITM state, with
	// a security warning on screen right now. Writing its files to disk
	// unattended is not defensible, whatever the rest of the policy says.
	if l.Trust() == peers.TrustChanged {
		refuse(proto.CancelRefused)
		r.notifyRefusal(l, o, errors.New(
			"refused: this peer's identity key has changed; verify the new fingerprint before accepting files"))
		return
	}
	if o.Size > uint64(r.lim.MaxFileSize) {
		refuse(proto.CancelTooLarge)
		r.notifyRefusal(l, o, fmt.Errorf("refused: %d bytes is over the %d-byte limit",
			o.Size, r.lim.MaxFileSize))
		return
	}
	safe, err := SafeName(o.Name)
	if err != nil {
		refuse(proto.CancelBadName)
		r.notifyRefusal(l, o, fmt.Errorf("refused: %w", err))
		return
	}

	store, err := OpenStore(r.root, l.PeerFingerprint())
	if err != nil {
		refuse(proto.CancelLocalError)
		r.notifyRefusal(l, o, err)
		return
	}
	part, err := store.Create(safe)
	if err != nil {
		refuse(proto.CancelLocalError)
		r.notifyRefusal(l, o, err)
		return
	}

	rc := &recv{
		id:   o.ID,
		name: part.Name(),
		size: int64(o.Size),
		link: l,
		part: part,
		done: make(chan struct{}),
	}
	rc.lastAt = time.Now()
	rc.lastChunk.Store(time.Now().UnixNano())

	if err := r.add(l.PeerFingerprint(), o.ID, &sendOrRecv{recv: rc}); err != nil {
		part.Discard()
		refuse(proto.CancelTooMany)
		r.notifyRefusal(l, o, err)
		return
	}

	if err := l.SendControl(proto.TypeFileAccept, proto.EncodeFileAccept(o.ID, 0)); err != nil {
		part.Discard()
		r.remove(l.PeerFingerprint(), o.ID)
		return
	}
	rc.state.Store(int32(Running))
	l.TransferStarted()
	rc.notify(Running)
}

// Chunk applies one inbound chunk.
//
// The offset is enforced, not trusted: it must be exactly where this transfer
// has reached. A receiver that honoured an arbitrary offset would let a peer
// seek, and a peer that sent a huge one would have it create a sparse file of
// that size (docs/protocol.md §13.3).
func (rc *recv) Chunk(offset uint64, data []byte, maxSize int64) error {
	if len(data) == 0 {
		return errors.New("empty chunk")
	}
	written := rc.part.Written()
	if int64(offset) != written {
		return fmt.Errorf("chunk offset %d does not continue from %d", offset, written)
	}
	end := written + int64(len(data))
	if end > rc.size {
		return fmt.Errorf("chunk would exceed the declared size (%d > %d)", end, rc.size)
	}
	if end > maxSize {
		return fmt.Errorf("chunk would exceed the %d-byte limit", maxSize)
	}
	if err := rc.part.Write(data); err != nil {
		return err
	}
	rc.received.Store(end)
	rc.lastChunk.Store(time.Now().UnixNano())
	rc.maybeNotify()
	return nil
}

// Finish verifies the digest and publishes the file.
func (rc *recv) Finish(digest []byte) error {
	if got := rc.part.Written(); got != rc.size {
		return fmt.Errorf("transfer ended after %d of %d bytes", got, rc.size)
	}
	path, err := rc.part.Publish(digest)
	if err != nil {
		return err
	}
	rc.mu.Lock()
	rc.outPath = path
	rc.mu.Unlock()
	rc.state.Store(int32(Done))
	rc.notify(Done)
	return nil
}

// stalled reports whether no chunk has arrived within d.
func (rc *recv) stalled(d time.Duration) bool {
	last := rc.lastChunk.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) > d
}

func (rc *recv) fail(err error) {
	rc.mu.Lock()
	rc.lastErr = err
	rc.mu.Unlock()
	rc.part.Discard()
	rc.state.Store(int32(Failed))
	rc.notify(Failed)
}

// closeDone releases anyone waiting to hand this transfer a chunk.
func (rc *recv) closeDone() {
	rc.closeOne.Do(func() { close(rc.done) })
}

func (rc *recv) maybeNotify() {
	p := rc.progress()
	pct := p.Percent()
	rc.mu.Lock()
	due := time.Since(rc.lastAt) >= progressInterval || pct/progressStep > rc.lastPct/progressStep
	if due {
		rc.lastAt = time.Now()
		rc.lastPct = pct
	}
	rc.mu.Unlock()
	if due {
		rc.link.Notify(p)
	}
}

func (rc *recv) notify(st State) {
	p := rc.progress()
	p.State = st
	rc.link.Notify(p)
}

func (rc *recv) progress() Progress {
	rc.mu.Lock()
	err := rc.lastErr
	out := rc.outPath
	rc.mu.Unlock()
	return Progress{
		ID:        rc.id,
		Direction: Incoming,
		Peer:      rc.link.PeerName(),
		Name:      rc.name,
		Size:      rc.size,
		Done:      rc.received.Load(),
		State:     State(rc.state.Load()),
		Path:      out,
		Err:       err,
	}
}

func (rc *recv) stop(reason byte) {
	_ = rc.link.SendControl(proto.TypeFileCancel, proto.EncodeFileCancel(rc.id, reason))
	rc.fail(fmt.Errorf("cancelled: %s", CancelReason(reason)))
	rc.closeDone()
}
