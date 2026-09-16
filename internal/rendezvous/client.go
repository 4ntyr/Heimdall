package rendezvous

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	xcrypto "github.com/4ntyr/heimdall/internal/crypto"
)

// Client maintains the control connection to a relay.
//
// The connection is supervised: middleboxes reap idle sockets aggressively, so
// the client pings on a timer and re-dials with backoff when the connection
// dies, re-publishing any invite codes that are still outstanding
// (docs/rendezvous.md §1.4). A user who printed a code a minute ago does not
// lose it because a proxy decided the socket was idle.
type Client struct {
	ep *Endpoint

	mu        sync.Mutex
	conn      *WSConn
	rung      Rung
	observed  string
	waiters   map[string]*waiter
	connected chan struct{} // closed while a connection is live

	closeOnce sync.Once
	closed    chan struct{}
}

// Timings for the supervised control connection.
const (
	// PingInterval is well under the 60 s idle timeout common to proxies.
	PingInterval = 20 * time.Second
	// minBackoff/maxBackoff bound reconnection attempts.
	minBackoff = 1 * time.Second
	maxBackoff = 30 * time.Second
	// TicketSize is the length of a circuit ticket.
	TicketSize = 32
)

var (
	// ErrClosed indicates the client has been shut down.
	ErrClosed = errors.New("rendezvous: client closed")
	// ErrDisconnected indicates the control connection dropped mid-operation.
	ErrDisconnected = errors.New("rendezvous: control connection lost")
	// ErrRelay indicates the relay refused a request.
	ErrRelay = errors.New("rendezvous: relay refused request")
)

// waiter tracks one outstanding rendezvous.
type waiter struct {
	published chan *Message
	paired    chan *Message
	sealed    []byte
	claim     bool // true for a claim, false for a publish
	sent      bool
}

// Pairing is the result of a completed rendezvous: everything needed to reach
// the other peer by every available path.
type Pairing struct {
	// Role decides handshake roles: the publisher responds, the claimer
	// initiates (docs/rendezvous.md §3.2).
	Role string
	// PeerCandidates are the peer's validated, decrypted addresses.
	PeerCandidates []Candidate
	// PeerObserved is the peer's server-reflexive address, the target for
	// hole punching.
	PeerObserved string
	// Observed is our own server-reflexive address.
	Observed string
	// PunchIn is how long to wait before punching. It is relative because
	// peer clocks are not synchronised.
	PunchIn time.Duration
	// Ticket authorises this side's circuit connection.
	Ticket []byte
	// Rung records which ladder step reached the relay.
	Rung Rung
}

// Initiator reports whether this peer drives the handshake.
func (p *Pairing) Initiator() bool { return p.Role == RoleClaimer }

// NewClient starts a supervised control connection to the relay. It returns
// immediately; use Wait to block until the first connection is established.
func NewClient(ep *Endpoint) *Client {
	c := &Client{
		ep:        ep,
		waiters:   make(map[string]*waiter),
		connected: make(chan struct{}),
		closed:    make(chan struct{}),
	}
	go c.supervise()
	return c
}

// Wait blocks until the control connection is live, or the context expires.
func (c *Client) Wait(ctx context.Context) error {
	c.mu.Lock()
	ready := c.connected
	c.mu.Unlock()
	select {
	case <-ready:
		return nil
	case <-c.closed:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Rung reports which ladder step reached the relay, for display.
func (c *Client) Rung() Rung {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rung
}

// Observed reports our server-reflexive address as last seen by the relay.
func (c *Client) Observed() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observed
}

// Close shuts down the client and its connection.
func (c *Client) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// supervise keeps the control connection alive for the client's lifetime.
func (c *Client) supervise() {
	backoff := minBackoff
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(Ladder)+1)*RungTimeout)
		conn, rung, err := c.ep.Dial(ctx)
		cancel()
		if err != nil {
			select {
			case <-c.closed:
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = minBackoff

		c.mu.Lock()
		c.conn, c.rung = conn, rung
		close(c.connected)
		c.mu.Unlock()

		c.resendWaiters()
		stop := make(chan struct{})
		go c.pingLoop(conn, stop)
		c.readPump(conn)
		close(stop)
		conn.Close()

		c.mu.Lock()
		c.conn = nil
		c.connected = make(chan struct{})
		// Outstanding rendezvous survive the drop: resendWaiters republishes
		// them once the next connection is up.
		for _, w := range c.waiters {
			w.sent = false
		}
		c.mu.Unlock()
	}
}

// pingLoop keeps the connection from being reaped as idle.
func (c *Client) pingLoop(conn *WSConn, stop <-chan struct{}) {
	t := time.NewTicker(PingInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-c.closed:
			return
		case <-t.C:
			if err := conn.Ping(); err != nil {
				return
			}
		}
	}
}

// readPump dispatches inbound control messages until the connection fails.
func (c *Client) readPump(conn *WSConn) {
	for {
		msg, err := conn.RecvMessage()
		if err != nil {
			return
		}
		c.dispatch(msg)
	}
}

// dispatch routes one message to the waiter it belongs to.
func (c *Client) dispatch(msg *Message) {
	switch msg.Type {
	case MsgPublished:
		c.mu.Lock()
		if msg.Observed != "" {
			c.observed = msg.Observed
		}
		w := c.waiters[msg.RendezvousID]
		c.mu.Unlock()
		if w != nil {
			select {
			case w.published <- msg:
			default:
			}
		}

	case MsgPaired:
		c.mu.Lock()
		w := c.waiters[msg.RendezvousID]
		c.mu.Unlock()
		if w != nil {
			select {
			case w.paired <- msg:
			default:
			}
		}

	case MsgError:
		c.mu.Lock()
		w := c.waiters[msg.RendezvousID]
		c.mu.Unlock()
		if w != nil {
			// Deliver to whichever phase is waiting; both are buffered.
			select {
			case w.published <- msg:
			default:
			}
			select {
			case w.paired <- msg:
			default:
			}
		}
	}
}

// resendWaiters republishes outstanding rendezvous after a reconnect.
func (c *Client) resendWaiters() {
	c.mu.Lock()
	conn := c.conn
	type pending struct {
		rid string
		w   *waiter
	}
	var list []pending
	for rid, w := range c.waiters {
		if !w.sent {
			list = append(list, pending{rid, w})
		}
	}
	c.mu.Unlock()
	if conn == nil {
		return
	}
	for _, p := range list {
		typ := MsgPublish
		if p.w.claim {
			typ = MsgClaim
		}
		if err := conn.SendMessage(&Message{
			Type:         typ,
			RendezvousID: p.rid,
			Candidates:   b64(p.w.sealed),
		}); err != nil {
			return
		}
		c.mu.Lock()
		p.w.sent = true
		c.mu.Unlock()
	}
}

// register adds a waiter and sends its request if a connection is live.
func (c *Client) register(rid string, w *waiter) error {
	c.mu.Lock()
	if _, exists := c.waiters[rid]; exists {
		c.mu.Unlock()
		return errors.New("rendezvous: that code is already outstanding")
	}
	c.waiters[rid] = w
	c.mu.Unlock()
	c.resendWaiters()
	return nil
}

func (c *Client) unregister(rid string) {
	c.mu.Lock()
	delete(c.waiters, rid)
	c.mu.Unlock()
}

// Publish announces an invite code and waits for the relay to acknowledge it.
// The returned Invite blocks until a peer claims the code.
func (c *Client) Publish(ctx context.Context, rid, sealed []byte) (*Invite, error) {
	key := b64(rid)
	w := &waiter{
		published: make(chan *Message, 1),
		paired:    make(chan *Message, 1),
		sealed:    sealed,
	}
	if err := c.register(key, w); err != nil {
		return nil, err
	}
	msg, err := c.await(ctx, w.published)
	if err != nil {
		c.unregister(key)
		return nil, err
	}
	if msg.Type == MsgError {
		c.unregister(key)
		return nil, fmt.Errorf("%w: %s", ErrRelay, msg.Reason)
	}
	return &Invite{client: c, rid: key, waiter: w, observed: msg.Observed}, nil
}

// Claim redeems an invite code published by another peer.
func (c *Client) Claim(ctx context.Context, rid, sealed []byte, pairingKey []byte) (*Pairing, error) {
	key := b64(rid)
	w := &waiter{
		published: make(chan *Message, 1),
		paired:    make(chan *Message, 1),
		sealed:    sealed,
		claim:     true,
	}
	if err := c.register(key, w); err != nil {
		return nil, err
	}
	defer c.unregister(key)

	msg, err := c.await(ctx, w.paired)
	if err != nil {
		return nil, err
	}
	if msg.Type == MsgError {
		return nil, fmt.Errorf("%w: %s", ErrRelay, msg.Reason)
	}
	return c.toPairing(msg, pairingKey)
}

// await waits for a message, a shutdown, or the caller's deadline.
func (c *Client) await(ctx context.Context, ch <-chan *Message) (*Message, error) {
	select {
	case msg := <-ch:
		return msg, nil
	case <-c.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// toPairing converts a paired message into a usable Pairing, decrypting and
// validating the peer's candidate list on the way.
func (c *Client) toPairing(msg *Message, pairingKey []byte) (*Pairing, error) {
	sealed, err := unb64(msg.PeerCandidates, MaxSealedCandidates)
	if err != nil {
		return nil, err
	}
	set, err := OpenCandidates(pairingKey, sealed)
	if err != nil {
		return nil, err
	}
	ticket, err := unb64(msg.Ticket, TicketSize)
	if err != nil {
		return nil, err
	}
	if len(ticket) != TicketSize {
		return nil, errors.New("rendezvous: relay issued a malformed circuit ticket")
	}
	punchIn := time.Duration(msg.PunchInMS) * time.Millisecond
	if punchIn < 0 || punchIn > 30*time.Second {
		punchIn = 0
	}
	return &Pairing{
		Role:           msg.Role,
		PeerCandidates: set.Candidates,
		PeerObserved:   msg.PeerObserved,
		Observed:       c.Observed(),
		PunchIn:        punchIn,
		Ticket:         ticket,
		Rung:           c.Rung(),
	}, nil
}

// Invite is a published code awaiting a peer.
type Invite struct {
	client   *Client
	rid      string
	waiter   *waiter
	observed string
}

// Observed is our server-reflexive address as the relay saw it.
func (i *Invite) Observed() string { return i.observed }

// Wait blocks until a peer claims the code.
func (i *Invite) Wait(ctx context.Context, pairingKey []byte) (*Pairing, error) {
	defer i.client.unregister(i.rid)
	msg, err := i.client.await(ctx, i.waiter.paired)
	if err != nil {
		return nil, err
	}
	if msg.Type == MsgError {
		return nil, fmt.Errorf("%w: %s", ErrRelay, msg.Reason)
	}
	return i.client.toPairing(msg, pairingKey)
}

// Cancel withdraws an outstanding invite.
func (i *Invite) Cancel() { i.client.unregister(i.rid) }

// OpenCircuit dials a fresh connection up the proven ladder rung and redeems a
// circuit ticket on it, yielding a byte stream to the peer.
//
// The returned connection carries the ordinary length-prefixed transport
// framing, so the caller wraps it exactly as it would a direct TCP connection.
func (c *Client) OpenCircuit(ctx context.Context, ticket []byte) (*WSConn, error) {
	rung := c.Rung()
	conn, err := c.ep.DialRung(ctx, rung)
	if err != nil {
		return nil, err
	}
	if err := conn.SendMessage(&Message{Type: MsgCircuit, Ticket: b64(ticket)}); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(RungTimeout))
	msg, err := conn.RecvMessage()
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetReadDeadline(zeroTime)
	switch msg.Type {
	case MsgCircuitOK:
		return conn, nil
	case MsgError:
		conn.Close()
		return nil, fmt.Errorf("%w: %s", ErrRelay, msg.Reason)
	default:
		conn.Close()
		return nil, fmt.Errorf("rendezvous: unexpected %q answering circuit request", msg.Type)
	}
}

// NewTicket generates a circuit ticket. It lives here so client and server
// agree on the size.
func NewTicket() ([]byte, error) { return xcrypto.RandomBytes(TicketSize) }
