package transfer

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/4ntyr/heimdall/internal/proto"
)

// sendOrRecv holds one side of a transfer. Exactly one field is set.
type sendOrRecv struct {
	send *send
	recv *recv
}

func (x *sendOrRecv) progress() Progress {
	if x.send != nil {
		return x.send.progress()
	}
	return x.recv.progress()
}

func (x *sendOrRecv) stop(reason byte) {
	if x.send != nil {
		x.send.stop(reason)
		return
	}
	x.recv.stop(reason)
}

// key identifies a transfer. The peer fingerprint is part of it because
// transfer ids are chosen independently by each sender, so two peers can
// legitimately pick the same one.
type key struct {
	peer string
	id   uint64
}

// Registry tracks every transfer in progress and enforces the limits that
// bound them collectively.
type Registry struct {
	root string
	lim  Limits

	mu    sync.Mutex
	items map[key]*sendOrRecv
}

// NewRegistry creates a registry writing downloads beneath root.
func NewRegistry(root string, lim Limits) *Registry {
	return &Registry{
		root:  root,
		lim:   lim,
		items: make(map[key]*sendOrRecv),
	}
}

// Limits reports the limits in force.
func (r *Registry) Limits() Limits { return r.lim }

// Root reports the download directory.
func (r *Registry) Root() string { return r.root }

// add registers a transfer, enforcing the concurrency limits.
func (r *Registry) add(peer string, id uint64, x *sendOrRecv) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.items) >= r.lim.MaxTotal {
		return fmt.Errorf("transfer: %d transfers already in progress", len(r.items))
	}
	n := 0
	for k := range r.items {
		if k.peer == peer {
			n++
		}
	}
	if n >= r.lim.MaxPerPeer {
		return fmt.Errorf("transfer: %d transfers already in progress with this peer", n)
	}
	k := key{peer: peer, id: id}
	if _, exists := r.items[k]; exists {
		return errors.New("transfer: duplicate transfer id")
	}
	r.items[k] = x
	return nil
}

func (r *Registry) remove(peer string, id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.items, key{peer: peer, id: id})
}

func (r *Registry) lookup(peer string, id uint64) (*sendOrRecv, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	x, ok := r.items[key{peer: peer, id: id}]
	return x, ok
}

// Accept handles an inbound TypeFileAccept.
func (r *Registry) Accept(l Link, id, startOffset uint64) {
	x, ok := r.lookup(l.PeerFingerprint(), id)
	if !ok || x.send == nil {
		return
	}
	if err := x.send.accept(startOffset); err != nil {
		x.send.stop(proto.CancelProtocol)
	}
}

// Refuse handles an inbound TypeFileCancel.
//
// A cancel naming a transfer we do not know is ignored, never answered with a
// cancel of our own: two peers each replying to the other's unknown-transfer
// cancel would volley forever (docs/protocol.md §13.6).
func (r *Registry) Refuse(l Link, id uint64, reason byte) {
	x, ok := r.lookup(l.PeerFingerprint(), id)
	if !ok {
		return
	}
	if x.send != nil {
		x.send.refuse(reason)
		return
	}
	x.recv.fail(fmt.Errorf("peer cancelled: %s", CancelReason(reason)))
	x.recv.closeDone()
	r.remove(l.PeerFingerprint(), id)
}

// Chunk handles an inbound TypeFileChunk.
func (r *Registry) Chunk(l Link, id, offset uint64, data []byte) {
	x, ok := r.lookup(l.PeerFingerprint(), id)
	if !ok || x.recv == nil {
		return
	}
	if err := x.recv.Chunk(offset, data, r.lim.MaxFileSize); err != nil {
		x.recv.fail(err)
		x.recv.closeDone()
		_ = l.SendControl(proto.TypeFileCancel, proto.EncodeFileCancel(id, proto.CancelProtocol))
		r.remove(l.PeerFingerprint(), id)
	}
}

// Done handles an inbound TypeFileDone.
func (r *Registry) Done(l Link, id uint64, digest []byte) {
	x, ok := r.lookup(l.PeerFingerprint(), id)
	if !ok || x.recv == nil {
		return
	}
	defer r.remove(l.PeerFingerprint(), id)
	// closeDone reports the transfer finished; see recv.closeDone.
	defer x.recv.closeDone()
	if err := x.recv.Finish(digest); err != nil {
		x.recv.fail(err)
		_ = l.SendControl(proto.TypeFileCancel, proto.EncodeFileCancel(id, proto.CancelDigestMismatch))
	}
}

// Cancel stops one transfer at the user's request.
func (r *Registry) Cancel(peer string, id uint64) error {
	x, ok := r.lookup(peer, id)
	if !ok {
		return fmt.Errorf("transfer: no transfer %d in progress", id)
	}
	x.stop(proto.CancelUserRequest)
	r.remove(peer, id)
	return nil
}

// CancelPeer stops every transfer with a peer, used when its connection goes
// away. No frame is sent: the connection is already gone.
func (r *Registry) CancelPeer(peer string) {
	r.mu.Lock()
	var doomed []*sendOrRecv
	for k, x := range r.items {
		if k.peer == peer {
			doomed = append(doomed, x)
			delete(r.items, k)
		}
	}
	r.mu.Unlock()
	for _, x := range doomed {
		if x.send != nil {
			if x.send.cancel != nil {
				x.send.cancel()
			}
			continue
		}
		x.recv.fail(errors.New("connection closed"))
		x.recv.closeDone()
	}
}

// List reports every transfer in progress, for a user-facing listing.
func (r *Registry) List() []Progress {
	r.mu.Lock()
	items := make([]*sendOrRecv, 0, len(r.items))
	for _, x := range r.items {
		items = append(items, x)
	}
	r.mu.Unlock()
	out := make([]Progress, 0, len(items))
	for _, x := range items {
		out = append(out, x.progress())
	}
	return out
}

// Receiver returns the receive side of a transfer, if there is one. The
// session's reader uses it to find the channel to hand a chunk to and the done
// channel to give up on.
func (r *Registry) Receiver(peer string, id uint64) (*recv, bool) {
	x, ok := r.lookup(peer, id)
	if !ok || x.recv == nil {
		return nil, false
	}
	return x.recv, true
}

// Done reports the channel closed when a receive stops accepting chunks.
func (rc *recv) Done() <-chan struct{} { return rc.done }

// ReapStalled cancels transfers that have made no progress within the stall
// limit.
//
// A sender that stops mid-file without saying so would otherwise hold a
// concurrency slot and a .part file indefinitely; nothing else notices,
// because the session itself is healthy.
func (r *Registry) ReapStalled() {
	if r.lim.Stall <= 0 {
		return
	}
	r.mu.Lock()
	type doomed struct {
		k key
		x *sendOrRecv
	}
	var list []doomed
	for k, x := range r.items {
		if x.recv != nil && x.recv.stalled(r.lim.Stall) {
			list = append(list, doomed{k, x})
		}
	}
	for _, d := range list {
		delete(r.items, d.k)
	}
	r.mu.Unlock()
	for _, d := range list {
		d.x.recv.stop(proto.CancelStalled)
	}
}

// StallCheckInterval is how often a caller should run ReapStalled.
func StallCheckInterval(lim Limits) time.Duration {
	if lim.Stall <= 0 {
		return time.Minute
	}
	d := lim.Stall / 2
	if d < time.Second {
		d = time.Second
	}
	return d
}
