// Package session manages peer connections: inbound/outbound handshakes,
// the per-peer read/write loops, keepalive, disconnect detection, clean
// shutdown, and automatic reconnection. It renders nothing and knows nothing
// about the terminal; it emits Events that the chat layer consumes.
package session

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/4ntyr/heimdall/internal/identity"
	"github.com/4ntyr/heimdall/internal/peers"
	"github.com/4ntyr/heimdall/internal/proto"
	"github.com/4ntyr/heimdall/internal/transport"
)

// EventType classifies Events emitted by the Manager.
type EventType int

const (
	EventPeerConnected EventType = iota
	EventPeerDisconnected
	EventMessage
	EventSecurityWarning
	EventError
)

// Event is delivered from the Manager to the chat layer.
type Event struct {
	Type EventType
	// Peer is the display name (a label, not an identity).
	Peer string
	// Fingerprint is the peer's identity fingerprint.
	Fingerprint string
	// Text carries message text or an error/warning description.
	Text string
	// Trust is the peer's trust level at the time of the event.
	Trust peers.TrustLevel
	// Path records how the connection was established (see PathDirect and
	// friends). Empty for events that do not concern one connection.
	Path string
}

// How a connection was established, for display. Connectivity is identical on
// all three; the label exists so a user can see whether their traffic is
// flowing through a relay (docs/rendezvous.md §7.1).
const (
	PathDirect  = "DIRECT"
	PathPunched = "PUNCHED"
	PathRelay   = "RELAY"
)

// Keepalive parameters. Middleboxes reap idle connections aggressively and a
// black-holed TCP connection produces no error for a long time, so liveness is
// established by unanswered pings rather than by I/O failure
// (docs/rendezvous.md §1.4).
const (
	keepaliveInterval = 20 * time.Second
	keepaliveMisses   = 3
)

// settleDelay is how long a freshly authenticated connection waits before it
// is announced to the user.
//
// Racing several paths means more than one of them can succeed, a moment
// apart. Announcing the first to finish and then swapping it for a later
// arrival tears down a socket that may already be carrying a message — a user
// who connects and types immediately would lose what they typed, silently,
// because chat frames are not acknowledged. Letting the duplicates resolve
// first costs a fraction of a second and makes the connection the user is told
// about the one that lasts.
const settleDelay = 750 * time.Millisecond

// Manager owns all peer connections for the local node.
type Manager struct {
	id    *identity.Identity
	store *peers.Store
	ln    *transport.Listener

	mu      sync.Mutex
	conns   map[string]*conn // keyed by peer fingerprint
	byName  map[string]*conn // display-name index (best effort)
	events  chan Event
	closing bool
	wg      sync.WaitGroup

	// reconnect bookkeeping
	reconnectDelay time.Duration

	// inboundHook, when set, is consulted for every inbound connection. It
	// lets the layer that owns rendezvous state say that a connection belongs
	// to one, so the accepting side applies the same pairing requirement as
	// the dialling side. Without it, whichever peer happened to accept would
	// silently skip the invite-code check.
	inboundHook func(net.Conn) (AdoptOptions, bool)
}

// conn is one established peer session.
type conn struct {
	fp    string
	name  string
	io    *transport.FrameIO
	sess  *proto.Session
	trust peers.TrustLevel
	addr  string
	send  chan []byte
	done  chan struct{}
	once  sync.Once

	// path is how this connection was established.
	path string
	// unanswered counts pings sent since the last pong.
	unanswered atomic.Int32
	// announced reports whether the user has been told about this
	// connection. An announced connection is never swapped out from under
	// them; see settleDelay.
	announced atomic.Bool
}

// NewManager creates a Manager bound to an identity and trust store.
func NewManager(id *identity.Identity, store *peers.Store) *Manager {
	return &Manager{
		id:             id,
		store:          store,
		conns:          make(map[string]*conn),
		byName:         make(map[string]*conn),
		events:         make(chan Event, 256),
		reconnectDelay: 2 * time.Second,
	}
}

// SetInboundHook installs the inbound-connection hook. Pass nil to remove it.
// The hook must not block.
func (m *Manager) SetInboundHook(fn func(net.Conn) (AdoptOptions, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inboundHook = fn
}

// inboundOptions asks the hook how to treat an inbound connection, falling
// back to an ordinary unsolicited inbound connection.
func (m *Manager) inboundOptions(nc net.Conn) AdoptOptions {
	m.mu.Lock()
	hook := m.inboundHook
	m.mu.Unlock()
	if hook != nil {
		if opts, ok := hook(nc); ok {
			return opts
		}
	}
	return AdoptOptions{Path: PathDirect}
}

// Events returns the channel of events for the chat layer.
func (m *Manager) Events() <-chan Event { return m.events }

// Listen starts accepting inbound connections on addr. An empty addr disables
// the listener entirely, which is a fully supported way to run Heimdall: every
// path this node uses is outbound, so a peer with no listener, no forwarded
// port and a default-deny firewall still works (docs/rendezvous.md §1.1).
func (m *Manager) Listen(addr string) (string, error) {
	if addr == "" {
		return "", nil
	}
	ln, err := transport.Listen(addr)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.ln = ln
	m.mu.Unlock()
	m.wg.Add(1)
	go m.acceptLoop(ln)
	return ln.Addr(), nil
}

// ListenAddr returns the bound address, or "".
func (m *Manager) ListenAddr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ln == nil {
		return ""
	}
	return m.ln.Addr()
}

// acceptLoop accepts inbound connections and runs the responder handshake.
func (m *Manager) acceptLoop(ln *transport.Listener) {
	defer m.wg.Done()
	for {
		nc, err := ln.AcceptConn()
		if err != nil {
			return // listener closed
		}
		m.HandleInbound(nc)
	}
}

// HandleInbound runs the responder handshake on a connection established
// elsewhere — an inbound hole-punch arrival, for instance. It does not block.
func (m *Manager) HandleInbound(nc net.Conn) {
	opts := m.inboundOptions(nc)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		_ = m.runHandshake(transport.NewFrameIO(nc), opts)
	}()
}

// Connect dials a peer at addr and runs the initiator handshake.
func (m *Manager) Connect(addr string) error {
	fio, err := transport.Dial(addr)
	if err != nil {
		return err
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		_ = m.runHandshake(fio, AdoptOptions{Initiator: true, Path: PathDirect})
	}()
	return nil
}

// AdoptOptions describe a connection that some other layer has already
// established — a direct dial, a hole-punched socket, or a relay circuit.
type AdoptOptions struct {
	// Initiator selects the handshake role. For a rendezvous-established
	// connection this comes from the rendezvous role, not from which side
	// dialled, so both peers agree even when punching yields two connections.
	Initiator bool
	// PairingKey, when set, makes the pairing confirmation of
	// docs/rendezvous.md §4 mandatory: the peer must prove it holds the
	// invite code before it is trusted, recorded, or shown to the user.
	PairingKey []byte
	// Path labels how the connection was established.
	Path string
	// OnEstablished, when set, is called once the peer is authenticated and
	// registered. It lets a caller racing several paths learn that a session
	// exists even when the winning connection was accepted rather than
	// dialled — otherwise the race sees only the paths it dialled itself and
	// reports failure over a session that is already up.
	OnEstablished func()
}

// Adopt runs the handshake over an already-connected transport and, on
// success, registers the peer. It blocks until the handshake either completes
// or fails, so a caller racing several paths can act on the outcome.
func (m *Manager) Adopt(nc net.Conn, opts AdoptOptions) error {
	return m.runHandshake(transport.NewFrameIO(nc), opts)
}

// runHandshake performs the cryptographic handshake over fio, confirms the
// pairing when the connection came from a rendezvous, then registers the
// connection and starts its loops.
//
// Nothing is written to the trust store and nothing reaches the user until
// every check has passed: a connection that fails the pairing confirmation
// must leave no trace, or a hostile relay would get a trust-on-first-use
// record out of a failed impersonation attempt.
func (m *Manager) runHandshake(fio *transport.FrameIO, opts AdoptOptions) error {
	_ = fio.SetDeadline(time.Now().Add(transport.HandshakeTimeout))

	hs, err := proto.NewHandshaker(m.id, opts.Initiator)
	if err != nil {
		fio.Close()
		return err
	}

	var res *proto.HandshakeResult
	if opts.Initiator {
		msg1, err := hs.InitMessage()
		if err != nil {
			fio.Close()
			return err
		}
		if err := fio.Send(msg1); err != nil {
			fio.Close()
			return err
		}
		msg2, err := fio.Recv()
		if err != nil {
			fio.Close()
			return err
		}
		msg3, r, err := hs.HandleMessage(msg2)
		if err != nil {
			m.emit(Event{Type: EventError, Text: "handshake failed (possible MITM): " + err.Error()})
			fio.Close()
			return err
		}
		if err := fio.Send(msg3); err != nil {
			fio.Close()
			return err
		}
		res = r
	} else {
		msg1, err := fio.Recv()
		if err != nil {
			fio.Close()
			return err
		}
		msg2, _, err := hs.HandleMessage(msg1)
		if err != nil {
			fio.Close()
			return err
		}
		if err := fio.Send(msg2); err != nil {
			fio.Close()
			return err
		}
		msg3, err := fio.Recv()
		if err != nil {
			fio.Close()
			return err
		}
		_, r, err := hs.HandleMessage(msg3)
		if err != nil {
			m.emit(Event{Type: EventError, Text: "handshake failed (possible MITM): " + err.Error()})
			fio.Close()
			return err
		}
		res = r
	}
	if res == nil {
		fio.Close()
		return errors.New("session: handshake produced no session")
	}

	// Pairing confirmation, when this connection came from an invite code.
	// This is what stops a relay answering a rendezvous itself and becoming a
	// man-in-the-middle on first contact (docs/rendezvous.md §4).
	if len(opts.PairingKey) > 0 {
		if err := m.confirmPairing(fio, res, opts.PairingKey); err != nil {
			m.emit(Event{
				Type: EventSecurityWarning,
				Peer: res.PeerName,
				Text: "The peer that answered this invite code could not prove it holds the code.\n\n" +
					"This is what a relay attempting a man-in-the-middle attack looks like.\n" +
					"The connection was dropped and the peer was NOT recorded as known.",
				Fingerprint: res.PeerFingerprint,
			})
			res.Session.Close()
			fio.Close()
			return err
		}
	}

	// Trust decision: record/observe the authenticated identity key.
	peer, trust, err := m.store.Observe(res.PeerName, fio.RemoteAddr(), res.PeerKey)
	if err != nil {
		res.Session.Close()
		fio.Close()
		return err
	}
	if trust == peers.TrustChanged {
		m.emit(Event{
			Type: EventSecurityWarning,
			Peer: res.PeerName,
			Text: fmt.Sprintf("The identity key for '%s' has changed.\n\nPrevious fingerprint:\n%s\n\nNew fingerprint:\n%s\n\nPossible MITM attack or legitimate key replacement.\nConnection marked UNTRUSTED.",
				res.PeerName, peer.Fingerprint, peer.PendingFingerprint()),
			Fingerprint: peer.PendingFingerprint(),
			Trust:       trust,
		})
	}

	_ = fio.ClearDeadline()
	path := opts.Path
	if path == "" {
		path = PathDirect
	}
	c := &conn{
		fp:    res.PeerFingerprint,
		name:  res.PeerName,
		io:    fio,
		sess:  res.Session,
		trust: trust,
		addr:  fio.RemoteAddr(),
		send:  make(chan []byte, 64),
		done:  make(chan struct{}),
		path:  path,
	}
	if !m.register(c) {
		// A better connection to this peer is already established. Close this
		// one quietly: from the user's point of view nothing happened, and the
		// peer is connected either way, so the caller still counts it a win.
		c.sess.Close()
		fio.Close()
		if opts.OnEstablished != nil {
			opts.OnEstablished()
		}
		return nil
	}
	m.wg.Add(3)
	go m.readLoop(c)
	go m.writeLoop(c)
	go m.keepaliveLoop(c)
	time.AfterFunc(settleDelay, func() { m.announce(c) })
	if opts.OnEstablished != nil {
		opts.OnEstablished()
	}
	return nil
}

// announce tells the user about a connection, once, and only if it is still
// the one in use for that peer. A connection that lost duplicate resolution
// during the settle window is never mentioned: from the user's point of view
// it never existed.
func (m *Manager) announce(c *conn) {
	select {
	case <-c.done:
		return
	default:
	}
	m.mu.Lock()
	current := m.conns[c.fp] == c
	m.mu.Unlock()
	if !current || !c.announced.CompareAndSwap(false, true) {
		return
	}
	m.emit(Event{Type: EventPeerConnected, Peer: c.name, Fingerprint: c.fp, Trust: c.trust, Path: c.path})
}

// pairConfirmTimeout bounds the wait for a peer's pairing confirmation. A
// legitimate peer sends it as the very next frame after the handshake, so this
// only ever elapses for a peer that is stalling. It is a variable so tests can
// shorten it.
var pairConfirmTimeout = transport.HandshakeTimeout

// confirmPairing exchanges the invite-code channel binding of
// docs/rendezvous.md §4 and fails closed: an absent confirmation is a failure,
// not a fallback, or an attacker could downgrade by simply omitting it.
func (m *Manager) confirmPairing(fio *transport.FrameIO, res *proto.HandshakeResult, pairingKey []byte) error {
	out, err := res.Session.SealPairConfirm(pairingKey, res.Transcript)
	if err != nil {
		return err
	}
	if err := fio.Send(out); err != nil {
		return err
	}

	deadline := time.Now().Add(pairConfirmTimeout)
	for time.Now().Before(deadline) {
		buf, err := fio.RecvBefore(deadline)
		if err != nil {
			return err
		}
		typ, pt, err := res.Session.Open(buf)
		if err != nil {
			// Undecryptable frames at this point mean the session is wrong or
			// something is injecting; neither is recoverable here.
			return proto.ErrPairConfirm
		}
		if typ != proto.TypePairConfirm {
			// Keepalives may legitimately arrive first; anything else is out
			// of order but harmless to skip while we wait for the proof.
			continue
		}
		if !proto.VerifyPairConfirm(pairingKey, res.Transcript, pt) {
			return proto.ErrPairConfirm
		}
		return nil
	}
	return proto.ErrPairConfirm
}

// register stores the connection, resolving a duplicate against any existing
// connection to the same identity. It reports whether c was kept.
func (m *Manager) register(c *conn) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.conns[c.fp]; ok {
		if old.announced.Load() && old.unanswered.Load() == 0 {
			// The user is already talking over this connection. A second path
			// finishing later is redundant, and swapping would risk the
			// in-flight message described at settleDelay.
			return false
		}
		if !preferNew(old, c) {
			return false
		}
		old.close()
	}
	m.conns[c.fp] = c
	m.byName[c.name] = c
	return true
}

// preferNew decides which of two connections to the same peer survives.
//
// Racing several paths — and hole punching in particular, where each peer
// dials the other and both succeed — legitimately produces more than one
// connection to the same identity. Both peers must independently discard the
// same one, or each spends the session replacing the other's choice.
//
// The session ID is the only identifier both ends of a connection genuinely
// agree on: it is derived from the handshake transcript, so the two ends of
// one connection compute the same value and two different connections compute
// different values. Keeping the smaller therefore converges on both sides with
// no negotiation, for any number of competing paths. Handshake roles cannot
// serve here (a rendezvous fixes them identically on every path) and neither
// can dial direction (it is opposite on the two sides).
//
// A connection that has stopped answering keepalives is replaceable outright,
// so a peer reconnecting over a black-holed path is never refused.
func preferNew(old, new *conn) bool {
	if old.unanswered.Load() > 0 {
		return true
	}
	return new.sess.SessionID < old.sess.SessionID
}

// unregister removes the connection if it is still the current one.
func (m *Manager) unregister(c *conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.conns[c.fp]; ok && cur == c {
		delete(m.conns, c.fp)
		if m.byName[c.name] == c {
			delete(m.byName, c.name)
		}
	}
}

// readLoop receives frames and dispatches them until failure/close.
func (m *Manager) readLoop(c *conn) {
	defer m.wg.Done()
	defer m.dropConn(c)
	for {
		buf, err := c.io.Recv()
		if err != nil {
			return
		}
		typ, pt, err := c.sess.Open(buf)
		if err != nil {
			// Authentication/replay/malformed failures: drop silently, but a
			// stream of them indicates attack or desync — terminate.
			if errors.Is(err, proto.ErrBadSession) {
				return
			}
			continue
		}
		switch typ {
		case proto.TypeChat:
			text, err := proto.DecodeChat(pt)
			if err != nil {
				continue
			}
			m.emit(Event{Type: EventMessage, Peer: c.name, Fingerprint: c.fp, Text: text, Trust: c.trust})
		case proto.TypePing:
			m.enqueue(c, proto.TypePong, nil)
		case proto.TypePong:
			c.unanswered.Store(0)
		case proto.TypeClose:
			return
		}
	}
}

// keepaliveLoop probes liveness.
//
// A connection through a relay or a NAT mapping can stop carrying traffic
// without either side's socket reporting an error, so liveness is measured by
// unanswered pings rather than by I/O failure: a black-holed connection is
// dropped after keepaliveMisses probes instead of hanging indefinitely. It
// also keeps the connection from being reaped as idle by a middlebox in the
// first place (docs/rendezvous.md §1.4).
func (m *Manager) keepaliveLoop(c *conn) {
	defer m.wg.Done()
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if c.unanswered.Add(1) > keepaliveMisses {
				m.dropConn(c)
				return
			}
			if err := m.enqueue(c, proto.TypePing, nil); err != nil {
				m.dropConn(c)
				return
			}
		}
	}
}

// writeLoop serializes outbound frames for one peer.
func (m *Manager) writeLoop(c *conn) {
	defer m.wg.Done()
	for {
		select {
		case <-c.done:
			return
		case buf := <-c.send:
			if err := c.io.Send(buf); err != nil {
				m.dropConn(c)
				return
			}
		}
	}
}

// enqueue seals and queues a frame for a peer.
func (m *Manager) enqueue(c *conn, typ byte, payload []byte) error {
	buf, err := c.sess.Seal(typ, payload)
	if err != nil {
		return err
	}
	select {
	case c.send <- buf:
		return nil
	case <-c.done:
		return errors.New("session: connection closed")
	default:
		return errors.New("session: send queue full")
	}
}

// dropConn tears down a connection and notifies the chat layer.
func (m *Manager) dropConn(c *conn) {
	c.once.Do(func() {
		close(c.done)
		c.sess.Close()
		c.io.Close()
		m.unregister(c)
		if c.announced.Load() {
			m.emit(Event{Type: EventPeerDisconnected, Peer: c.name, Fingerprint: c.fp, Trust: c.trust, Path: c.path})
		}
	})
}

// close is the conn-local teardown used by register's replacement path.
func (c *conn) close() {
	c.once.Do(func() {
		close(c.done)
		c.sess.Close()
		c.io.Close()
	})
}

// Send delivers a chat message to the named peer.
func (m *Manager) Send(name, text string) error {
	m.mu.Lock()
	c, ok := m.byName[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("session: not connected to %q", name)
	}
	buf, err := c.sess.SealChat(text)
	if err != nil {
		return err
	}
	select {
	case c.send <- buf:
		return nil
	case <-c.done:
		return errors.New("session: connection closed")
	default:
		return errors.New("session: send queue full")
	}
}

// Broadcast delivers a chat message to every connected peer. Returns the
// number of peers it was queued to.
func (m *Manager) Broadcast(text string) int {
	m.mu.Lock()
	list := make([]*conn, 0, len(m.conns))
	for _, c := range m.conns {
		list = append(list, c)
	}
	m.mu.Unlock()
	n := 0
	for _, c := range list {
		buf, err := c.sess.SealChat(text)
		if err != nil {
			continue
		}
		select {
		case c.send <- buf:
			n++
		default:
		}
	}
	return n
}

// Disconnect closes the connection to the named peer, sending TypeClose.
func (m *Manager) Disconnect(name string) error {
	m.mu.Lock()
	c, ok := m.byName[name]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("session: not connected to %q", name)
	}
	// Best-effort clean shutdown frame, then tear down.
	_ = m.enqueue(c, proto.TypeClose, nil)
	time.Sleep(20 * time.Millisecond)
	m.dropConn(c)
	return nil
}

// PeerInfo describes a connected peer for the UI.
type PeerInfo struct {
	Name        string
	Fingerprint string
	Address     string
	Trust       peers.TrustLevel
	// Path is how the connection was established: DIRECT, PUNCHED or RELAY.
	Path string
}

// Peers returns the currently connected peers.
func (m *Manager) Peers() []PeerInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PeerInfo, 0, len(m.conns))
	for _, c := range m.conns {
		out = append(out, PeerInfo{Name: c.name, Fingerprint: c.fp, Address: c.addr, Trust: c.trust, Path: c.path})
	}
	return out
}

// TrustOf returns the current trust level for a connected peer name.
func (m *Manager) TrustOf(name string) (peers.TrustLevel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.byName[name]; ok {
		return c.trust, true
	}
	return peers.TrustUnknown, false
}

// Shutdown closes the listener and all connections, and waits for loops.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	m.closing = true
	ln := m.ln
	list := make([]*conn, 0, len(m.conns))
	for _, c := range m.conns {
		list = append(list, c)
	}
	m.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range list {
		_ = m.enqueue(c, proto.TypeClose, nil)
	}
	time.Sleep(20 * time.Millisecond)
	for _, c := range list {
		m.dropConn(c)
	}
	m.wg.Wait()
}

// emit delivers an event without blocking indefinitely.
func (m *Manager) emit(e Event) {
	select {
	case m.events <- e:
	default:
		// UI is wedged; drop rather than block the networking path.
	}
}
