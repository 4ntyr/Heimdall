package transfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/4ntyr/heimdall/internal/proto"
)

// offerTimeout bounds the wait for a peer's answer to an offer.
//
// It is what turns an unsupported peer into a message instead of a hang. The
// frame types are not negotiated, so a peer too old to know them rejects the
// offer structurally and says nothing at all (docs/protocol.md §13.2); silence
// is the only signal available.
var offerTimeout = 30 * time.Second

// send is one outgoing transfer.
type send struct {
	id   uint64
	name string
	size int64
	path string

	link Link
	lim  Limits

	// accepted is closed when the peer agrees to receive.
	accepted chan struct{}
	// refusal carries the peer's cancel reason, if it refuses.
	refusal chan byte

	sent     atomic.Int64
	state    atomic.Int32
	cancel   context.CancelFunc
	finished sync.Once
	lastErr  error
	mu       sync.Mutex
}

// newTransferID returns a random 64-bit transfer identifier.
func newTransferID() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// Send offers a file to a peer and, if accepted, streams it.
//
// It blocks until the transfer finishes, so callers run it on its own
// goroutine. Progress arrives through the Link.
func (r *Registry) Send(ctx context.Context, l Link, path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("transfer: %w", err)
	}
	if fi.IsDir() {
		return 0, fmt.Errorf("transfer: %s is a directory", path)
	}
	if !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("transfer: %s is not a regular file", path)
	}
	size := fi.Size()
	if size > r.lim.MaxFileSize {
		return 0, fmt.Errorf("transfer: %s is %d bytes, over the %d-byte limit",
			path, size, r.lim.MaxFileSize)
	}

	// The name the peer sees is the base name, and it has to survive the same
	// rules the receiving side will apply — better to fail here, where the
	// user can rename the file, than to be refused after the offer.
	name := filepath.Base(path)
	if _, err := SafeName(name); err != nil {
		return 0, fmt.Errorf("transfer: %w", err)
	}

	if relayBudgetExceeded(l, r.lim, size) {
		return 0, fmt.Errorf(
			"transfer: this connection runs through a relay, which closes a circuit after %d MiB; "+
				"sending %d more bytes would exceed that. Ask your peer for a direct connection, or split the file",
			r.lim.RelayCircuitBytes>>20, size)
	}

	id, err := newTransferID()
	if err != nil {
		return 0, err
	}

	s := &send{
		id:       id,
		name:     name,
		size:     size,
		path:     path,
		link:     l,
		lim:      r.lim,
		accepted: make(chan struct{}),
		refusal:  make(chan byte, 1),
	}
	if err := r.add(l.PeerFingerprint(), id, &sendOrRecv{send: s}); err != nil {
		return 0, err
	}

	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	l.TransferStarted()
	go func() {
		defer l.TransferFinished()
		defer cancel()
		defer r.remove(l.PeerFingerprint(), id)
		s.run(ctx)
	}()
	return id, nil
}

// run drives one outgoing transfer: offer, wait, stream, finish.
func (s *send) run(ctx context.Context) {
	payload, err := proto.EncodeFileOffer(proto.FileOffer{
		ID:   s.id,
		Size: uint64(s.size),
		Name: s.name,
	})
	if err != nil {
		s.fail(err)
		return
	}
	if err := s.link.SendControl(proto.TypeFileOffer, payload); err != nil {
		s.fail(err)
		return
	}
	s.notify(Offered)

	select {
	case <-s.accepted:
	case reason := <-s.refusal:
		s.fail(fmt.Errorf("peer declined: %s", CancelReason(reason)))
		return
	case <-ctx.Done():
		s.fail(ctx.Err())
		return
	case <-time.After(offerTimeout):
		// No answer at all. Either the peer is wedged or it does not
		// understand these frames; both look identical from here.
		s.fail(errors.New("peer did not answer the offer; it may be running a build without file transfer"))
		return
	}

	s.state.Store(int32(Running))
	s.notify(Running)
	if err := s.stream(ctx); err != nil {
		s.fail(err)
		return
	}
}

// stream reads the file and sends it as chunks, hashing as it goes.
//
// The digest is computed here rather than before the offer so the file is read
// once, and so the digest describes the bytes actually sent rather than the
// bytes present at some earlier moment.
func (s *send) stream(ctx context.Context) error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	digest := sha256.New()
	buf := make([]byte, proto.MaxFileChunk)
	var offset int64
	lastNotify := time.Now()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			// The payload is handed to another goroutine to seal, so it must
			// not be the buffer we are about to overwrite.
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			digest.Write(chunk)

			payload, err := proto.EncodeFileChunk(s.id, uint64(offset), chunk)
			if err != nil {
				return err
			}
			if err := s.link.SendBulk(ctx, proto.TypeFileChunk, payload); err != nil {
				return err
			}
			offset += int64(n)
			s.sent.Store(offset)

			if relayBudgetExceeded(s.link, s.lim, 0) {
				return errors.New("the relay's circuit budget is exhausted; transfer stopped before the circuit was closed")
			}
			if time.Since(lastNotify) >= progressInterval {
				lastNotify = time.Now()
				s.notify(Running)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	if offset != s.size {
		// The file changed under us. Say so rather than sending a digest the
		// receiver will reject with no explanation.
		return fmt.Errorf("file changed while sending: expected %d bytes, read %d", s.size, offset)
	}

	payload, err := proto.EncodeFileDone(s.id, digest.Sum(nil))
	if err != nil {
		return err
	}
	// The end marker goes on the bulk path, not the control path.
	//
	// Control frames are written ahead of bulk ones, by design — that is what
	// keeps a transfer from delaying a keepalive. But it means a marker sent
	// as a control frame overtakes the chunks still queued behind it, and the
	// receiver then checks the digest against a file that is short by however
	// much was in flight. Queueing it with the chunks keeps it last.
	if err := s.link.SendBulk(ctx, proto.TypeFileDone, payload); err != nil {
		return err
	}
	s.state.Store(int32(Done))
	s.notify(Done)
	return nil
}

// accept records the peer's agreement to receive.
func (s *send) accept(startOffset uint64) error {
	// Resume is specified but not implemented; a non-zero offset means the
	// peer is running something this build does not know how to satisfy.
	if startOffset != 0 {
		return fmt.Errorf("transfer: peer asked to resume at %d, which is unsupported", startOffset)
	}
	// A peer that sends two accepts must not close the channel twice.
	s.finished.Do(func() { close(s.accepted) })
	return nil
}

// refuse records the peer's refusal.
func (s *send) refuse(reason byte) {
	select {
	case s.refusal <- reason:
	default:
	}
}

func (s *send) fail(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
	s.state.Store(int32(Failed))
	s.notify(Failed)
}

func (s *send) notify(st State) {
	s.mu.Lock()
	err := s.lastErr
	s.mu.Unlock()
	s.link.Notify(Progress{
		ID:        s.id,
		Direction: Outgoing,
		Peer:      s.link.PeerName(),
		Name:      s.name,
		Size:      s.size,
		Done:      s.sent.Load(),
		State:     st,
		Err:       err,
	})
}

func (s *send) progress() Progress {
	s.mu.Lock()
	err := s.lastErr
	s.mu.Unlock()
	return Progress{
		ID:        s.id,
		Direction: Outgoing,
		Peer:      s.link.PeerName(),
		Name:      s.name,
		Size:      s.size,
		Done:      s.sent.Load(),
		State:     State(s.state.Load()),
		Err:       err,
	}
}

func (s *send) stop(reason byte) {
	if s.cancel != nil {
		s.cancel()
	}
	_ = s.link.SendControl(proto.TypeFileCancel, proto.EncodeFileCancel(s.id, reason))
}

// CancelReason renders a cancel code for a user. A peer's stated reason is
// display material only; nothing is decided from it (docs/protocol.md §13.6).
func CancelReason(r byte) string {
	switch r {
	case proto.CancelRefused:
		return "refused"
	case proto.CancelBadName:
		return "unusable file name"
	case proto.CancelTooLarge:
		return "file too large"
	case proto.CancelTooMany:
		return "too many transfers in progress"
	case proto.CancelProtocol:
		return "protocol error"
	case proto.CancelDigestMismatch:
		return "contents did not match the digest"
	case proto.CancelLocalError:
		return "local error"
	case proto.CancelStalled:
		return "stalled"
	case proto.CancelUserRequest:
		return "cancelled"
	case proto.CancelRelayBudget:
		return "would exceed the relay's circuit budget"
	}
	return "unspecified"
}
