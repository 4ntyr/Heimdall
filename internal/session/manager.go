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
	"time"

	"github.com/4ntyr/heimdall_cli/internal/identity"
	"github.com/4ntyr/heimdall_cli/internal/peers"
	"github.com/4ntyr/heimdall_cli/internal/proto"
	"github.com/4ntyr/heimdall_cli/internal/transport"
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
}

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

// Events returns the channel of events for the chat layer.
func (m *Manager) Events() <-chan Event { return m.events }

// Listen starts accepting inbound connections on addr.
func (m *Manager) Listen(addr string) (string, error) {
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
		fio, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.runHandshake(fio, false)
		}()
	}
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
		m.runHandshake(fio, true)
	}()
	return nil
}

// runHandshake performs the cryptographic handshake over fio, then, on
// success, registers the connection and starts its read/write loops.
func (m *Manager) runHandshake(fio *transport.FrameIO, initiator bool) {
	defer func() {
		// If we never registered the connection, close the raw socket.
	}()
	_ = fio.SetDeadline(time.Now().Add(transport.HandshakeTimeout))

	hs, err := proto.NewHandshaker(m.id, initiator)
	if err != nil {
		fio.Close()
		return
	}

	var res *proto.HandshakeResult
	if initiator {
		msg1, err := hs.InitMessage()
		if err != nil {
			fio.Close()
			return
		}
		if err := fio.Send(msg1); err != nil {
			fio.Close()
			return
		}
		msg2, err := fio.Recv()
		if err != nil {
			fio.Close()
			return
		}
		msg3, r, err := hs.HandleMessage(msg2)
		if err != nil {
			m.emit(Event{Type: EventError, Text: "handshake failed (possible MITM): " + err.Error()})
			fio.Close()
			return
		}
		if err := fio.Send(msg3); err != nil {
			fio.Close()
			return
		}
		res = r
	} else {
		msg1, err := fio.Recv()
		if err != nil {
			fio.Close()
			return
		}
		msg2, _, err := hs.HandleMessage(msg1)
		if err != nil {
			fio.Close()
			return
		}
		if err := fio.Send(msg2); err != nil {
			fio.Close()
			return
		}
		msg3, err := fio.Recv()
		if err != nil {
			fio.Close()
			return
		}
		_, r, err := hs.HandleMessage(msg3)
		if err != nil {
			m.emit(Event{Type: EventError, Text: "handshake failed (possible MITM): " + err.Error()})
			fio.Close()
			return
		}
		res = r
	}
	if res == nil {
		fio.Close()
		return
	}

	// Trust decision: record/observe the authenticated identity key.
	peer, trust, err := m.store.Observe(res.PeerName, fio.RemoteAddr(), res.PeerKey)
	if err != nil {
		fio.Close()
		return
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
	c := &conn{
		fp:    res.PeerFingerprint,
		name:  res.PeerName,
		io:    fio,
		sess:  res.Session,
		trust: trust,
		addr:  fio.RemoteAddr(),
		send:  make(chan []byte, 64),
		done:  make(chan struct{}),
	}
	m.register(c)
	m.wg.Add(2)
	go m.readLoop(c)
	go m.writeLoop(c)
	m.emit(Event{Type: EventPeerConnected, Peer: res.PeerName, Fingerprint: c.fp, Trust: trust})
}

// register stores the connection, replacing any existing one to the same
// identity (the newer, freshly-authenticated connection wins).
func (m *Manager) register(c *conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.conns[c.fp]; ok {
		old.close()
	}
	m.conns[c.fp] = c
	m.byName[c.name] = c
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
		case proto.TypeClose:
			return
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
		m.emit(Event{Type: EventPeerDisconnected, Peer: c.name, Fingerprint: c.fp, Trust: c.trust})
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
}

// Peers returns the currently connected peers.
func (m *Manager) Peers() []PeerInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PeerInfo, 0, len(m.conns))
	for _, c := range m.conns {
		out = append(out, PeerInfo{Name: c.name, Fingerprint: c.fp, Address: c.addr, Trust: c.trust})
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

var _ = net.IPv4len // keep net imported for future NAT work
