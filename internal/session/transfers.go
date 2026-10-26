package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/4ntyr/heimdall/internal/peers"
	"github.com/4ntyr/heimdall/internal/proto"
	"github.com/4ntyr/heimdall/internal/transfer"
)

// chunkQueueDepth is how many inbound chunks may wait for the disk.
//
// Sized so a brief disk hiccup costs nothing while the total stays bounded by
// the number of connections: 32 chunks is ~128 KiB per peer. Beyond that,
// readLoop waits, which is how backpressure reaches the sender.
const chunkQueueDepth = 32

var errTransfersDisabled = errors.New("session: file transfer is disabled")

func errNotConnected(name string) error {
	return fmt.Errorf("session: not connected to %q", name)
}

func errNoSuchTransfer(id uint64) error {
	return fmt.Errorf("session: no transfer %d in progress", id)
}

// connLink adapts one connection to the capability internal/transfer needs.
//
// The interface is declared there and implemented here, which is what keeps
// the dependency pointing one way: transfer knows nothing about sockets, and
// the session remains the only thing that reaches the user.
type connLink struct {
	m *Manager
	c *conn
}

func (l connLink) PeerName() string        { return l.c.name }
func (l connLink) PeerFingerprint() string { return l.c.fp }
func (l connLink) Trust() peers.TrustLevel { return l.c.trust }
func (l connLink) Path() string            { return l.c.path }
func (l connLink) BytesSent() int64        { return l.c.bytesSent.Load() }

func (l connLink) SendControl(typ byte, payload []byte) error {
	return l.m.enqueue(l.c, typ, payload)
}

func (l connLink) SendBulk(ctx context.Context, typ byte, payload []byte) error {
	return l.m.enqueueBulk(ctx, l.c, typ, payload)
}

// TransferStarted and TransferFinished mark the connection busy, so duplicate
// resolution will not swap it out mid-file (see preferNew).
func (l connLink) TransferStarted()  { l.c.busy.Add(1) }
func (l connLink) TransferFinished() { l.c.busy.Add(-1) }

// Notify turns transfer progress into a user-visible event.
//
// Events are for people only: emit drops them when the UI is behind, so
// nothing in the transfer state machine may depend on one arriving. That is
// why Progress carries absolute counts rather than deltas — a dropped update
// costs nothing, because the next one is complete on its own.
func (l connLink) Notify(p transfer.Progress) {
	info := &TransferInfo{
		ID:        p.ID,
		Outgoing:  p.Direction == transfer.Outgoing,
		Name:      p.Name,
		Size:      p.Size,
		Done:      p.Done,
		Path:      p.Path,
		Err:       p.Err,
		Peer:      p.Peer,
		Percent:   p.Percent(),
		StateName: p.State.String(),
	}
	var typ EventType
	switch p.State {
	case transfer.Offered, transfer.Running:
		typ = EventTransferProgress
		if p.Done == 0 {
			typ = EventTransferStarted
		}
	case transfer.Done:
		typ = EventTransferDone
	default:
		typ = EventTransferFailed
	}
	l.m.emit(Event{
		Type:        typ,
		Peer:        l.c.name,
		Fingerprint: l.c.fp,
		Trust:       l.c.trust,
		Path:        l.c.path,
		Transfer:    info,
	})
}

// link returns the transfer Link for a connection.
func (m *Manager) link(c *conn) transfer.Link { return connLink{m: m, c: c} }

// EnableTransfers turns file transfer on, writing downloads beneath root.
//
// It is separate from NewManager so a Manager without it simply has no
// transfer support, which is what the tests that predate this feature rely on
// and what -no-file-transfer produces for the receiving direction.
func (m *Manager) EnableTransfers(root string, lim transfer.Limits) {
	reg := transfer.NewRegistry(root, lim)
	m.mu.Lock()
	m.transfers = reg
	m.mu.Unlock()

	m.wg.Add(1)
	go m.reapStalledLoop(reg)
}

// registry returns the transfer registry, or nil when transfers are off.
func (m *Manager) registry() *transfer.Registry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.transfers
}

// reapStalledLoop cancels transfers that stop making progress.
//
// A sender that goes quiet mid-file leaves nothing else to notice: the session
// is healthy, keepalives are answered, and the partial file and its
// concurrency slot would be held indefinitely.
func (m *Manager) reapStalledLoop(reg *transfer.Registry) {
	defer m.wg.Done()
	t := time.NewTicker(transfer.StallCheckInterval(reg.Limits()))
	defer t.Stop()
	for {
		select {
		case <-m.closed:
			return
		case <-t.C:
			reg.ReapStalled()
		}
	}
}

// SendFile offers a file to a peer. It returns once the offer is on its way;
// progress and completion arrive as events.
func (m *Manager) SendFile(ctx context.Context, name, path string) (uint64, error) {
	reg := m.registry()
	if reg == nil {
		return 0, errTransfersDisabled
	}
	m.mu.Lock()
	c, ok := m.byName[name]
	m.mu.Unlock()
	if !ok {
		return 0, errNotConnected(name)
	}
	return reg.Send(ctx, m.link(c), path)
}

// Transfers lists every transfer in progress.
func (m *Manager) Transfers() []transfer.Progress {
	reg := m.registry()
	if reg == nil {
		return nil
	}
	return reg.List()
}

// CancelTransfer stops one transfer by id, whichever peer it belongs to.
func (m *Manager) CancelTransfer(id uint64) error {
	reg := m.registry()
	if reg == nil {
		return errTransfersDisabled
	}
	m.mu.Lock()
	fps := make([]string, 0, len(m.conns))
	for fp := range m.conns {
		fps = append(fps, fp)
	}
	m.mu.Unlock()
	for _, fp := range fps {
		if err := reg.Cancel(fp, id); err == nil {
			return nil
		}
	}
	return errNoSuchTransfer(id)
}

// dispatchFile handles the file-transfer frame types.
//
// Everything here is either cheap or handed to another goroutine: this runs on
// readLoop, so time spent inside it is time the peer's next frame — including
// its keepalive answers — waits.
func (m *Manager) dispatchFile(c *conn, typ byte, pt []byte) {
	reg := m.registry()
	if reg == nil {
		// Transfers are off. Refuse an offer so the peer is not left waiting;
		// everything else is noise we can drop, and a cancel is never
		// answered with a cancel (docs/protocol.md §13.6).
		if typ == proto.TypeFileOffer {
			if o, err := proto.DecodeFileOffer(pt); err == nil {
				_ = m.enqueue(c, proto.TypeFileCancel,
					proto.EncodeFileCancel(o.ID, proto.CancelRefused))
			}
		}
		return
	}
	l := m.link(c)

	switch typ {
	case proto.TypeFileOffer:
		o, err := proto.DecodeFileOffer(pt)
		if err != nil {
			return
		}
		reg.Offer(l, o)
	case proto.TypeFileAccept:
		id, start, err := proto.DecodeFileAccept(pt)
		if err != nil {
			return
		}
		reg.Accept(l, id, start)
	case proto.TypeFileChunk:
		id, offset, data, err := proto.DecodeFileChunk(pt)
		if err != nil {
			return
		}
		m.deliverToDisk(c, reg, inboundChunk{id: id, offset: offset, data: data})
	case proto.TypeFileDone:
		id, digest, err := proto.DecodeFileDone(pt)
		if err != nil {
			return
		}
		// Copy the digest: it aliases the frame plaintext, and the handoff
		// outlives this call.
		m.deliverToDisk(c, reg, inboundChunk{
			id:     id,
			digest: append([]byte(nil), digest...),
		})
	case proto.TypeFileCancel:
		id, reason, err := proto.DecodeFileCancel(pt)
		if err != nil {
			return
		}
		reg.Refuse(l, id, reason)
	}
}

// chunkHandoffTimeout bounds how long readLoop will wait to hand a chunk to
// the writer goroutine.
//
// Blocking here is deliberate: it is what pushes backpressure into the peer's
// TCP window when the disk cannot keep up, instead of buffering without
// limit. But it cannot be unbounded, because while readLoop waits it is not
// answering the peer's pings — and if both ends are transferring to each other
// with slow disks, two unbounded waits would deadlock both sessions until the
// write deadlines fired. On timeout the transfer is cancelled and the session
// carries on.
const chunkHandoffTimeout = 5 * time.Second

// inboundChunk is one piece of a transfer on its way to the disk writer.
//
// The end-of-file marker travels this queue too, rather than being handled
// where it is decoded. It has to: chunks are handed off asynchronously, so a
// marker acted on immediately would be compared against a file that still had
// queued chunks outstanding, and every transfer would fail its digest check
// a few chunks short.
type inboundChunk struct {
	id     uint64
	offset uint64
	data   []byte
	// digest is set, and data nil, for an end-of-file marker.
	digest []byte
}

// deliverToDisk hands one piece of a transfer to the connection's disk writer,
// preserving the order it arrived in.
func (m *Manager) deliverToDisk(c *conn, reg *transfer.Registry, ch inboundChunk) {
	rc, ok := reg.Receiver(c.fp, ch.id)
	if !ok {
		// Unknown transfer: ignore. Answering with a cancel invites a volley
		// (docs/protocol.md §13.6).
		return
	}
	// The plaintext is freshly allocated per frame by the crypto layer, so it
	// can be passed on without copying.
	select {
	case c.chunks <- ch:
	case <-c.done:
	case <-rc.Done():
		// The transfer gave up while we were waiting. Without this case the
		// reader would block forever on a queue nobody is draining.
	case <-time.After(chunkHandoffTimeout):
		_ = reg.Cancel(c.fp, ch.id)
	}
}

// diskLoop writes inbound transfer data for one connection.
//
// One goroutine per connection rather than per transfer: it bounds memory by
// the number of peers instead of the number of files, and it keeps the writes
// for one peer serialised without any further locking. Order matters here —
// an end-of-file marker is processed only once the chunks ahead of it have
// been written.
func (m *Manager) diskLoop(c *conn) {
	defer m.wg.Done()
	for {
		select {
		case <-c.done:
			return
		case ch := <-c.chunks:
			reg := m.registry()
			if reg == nil {
				continue
			}
			if ch.digest != nil {
				reg.Done(m.link(c), ch.id, ch.digest)
				continue
			}
			reg.Chunk(m.link(c), ch.id, ch.offset, ch.data)
		}
	}
}
