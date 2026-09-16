// Package relay implements the Heimdall rendezvous and relay server
// (docs/rendezvous.md).
//
// The relay introduces two peers who each make an outbound connection to it,
// tells each of them where the other appears to be, coordinates a hole-punch
// attempt, and — when that fails or while it is still being attempted —
// forwards opaque bytes between them.
//
// It is an untrusted component by construction. It never sees plaintext,
// never learns an identity key, a fingerprint or a display name, and cannot
// man-in-the-middle a session: it can only forward the end-to-end handshake
// unmodified, and the pairing confirmation of docs/rendezvous.md §4 stops it
// impersonating a peer on first contact. A compromised relay costs metadata,
// not confidentiality.
package relay

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/4ntyr/heimdall/internal/rendezvous"
)

// rendezvousIDSize is the exact length the relay accepts for a rendezvous ID.
// It pairs on this value and nothing else.
const rendezvousIDSize = 16

// maxReapInterval caps how long the reaper sleeps between sweeps.
const maxReapInterval = 30 * time.Second

// reapInterval sweeps at half the code TTL, bounded at both ends.
func reapInterval(ttl time.Duration) time.Duration {
	d := ttl / 2
	if d > maxReapInterval {
		return maxReapInterval
	}
	if d < time.Millisecond {
		return time.Millisecond
	}
	return d
}

// Server is a rendezvous and relay server. The zero value is not usable; call
// New.
type Server struct {
	limits Limits
	logf   func(format string, args ...any)

	mu       sync.Mutex
	pending  map[string]*pendingCode // keyed by base64 rendezvous ID
	tickets  map[string]*ticketRef   // keyed by base64 ticket
	circuits int
	ipConns  map[string]int

	publishes *rateCounter

	closeOnce sync.Once
	closed    chan struct{}
}

// pendingCode is a published, unclaimed invite code.
type pendingCode struct {
	conn     *rendezvous.WSConn
	sealed   string
	observed string
	created  time.Time
}

// circuit is one relayed byte pipe between two peers.
//
// The two halves arrive as separate connections, each on its own handler
// goroutine. Whichever arrives second runs the splice; the first waits on
// done, because its handler returning would close the socket the splice is
// still using.
type circuit struct {
	mu      sync.Mutex
	conns   [2]net.Conn
	started bool
	created time.Time

	done     chan struct{}
	released sync.Once
}

// ticketRef binds a ticket to one side of a circuit.
type ticketRef struct {
	circuit *circuit
	side    int
}

// New creates a relay server. Pass nil for logf to disable logging entirely.
//
// Note that nothing sensitive is ever passed to logf: rendezvous IDs, tickets
// and payload bytes are never logged, by design (docs/threat-model.md).
func New(limits Limits, logf func(format string, args ...any)) *Server {
	s := &Server{
		limits:    limits,
		logf:      logf,
		pending:   make(map[string]*pendingCode),
		tickets:   make(map[string]*ticketRef),
		ipConns:   make(map[string]int),
		publishes: newRateCounter(),
		closed:    make(chan struct{}),
	}
	go s.reap()
	return s
}

// Close stops the server's background work. In-flight connections are left to
// finish; the process exiting closes them.
func (s *Server) Close() {
	s.closeOnce.Do(func() { close(s.closed) })
}

// Handler returns the HTTP handler for the relay endpoint.
//
// It is an ordinary net/http handler so a relay can be mounted at a path on a
// domain that already serves a real website. On networks that permit only a
// whitelist of destinations, that is the difference between reachable and not
// (docs/rendezvous.md §1.2).
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ip := sourceIP(r.RemoteAddr)
	if !s.acquireIP(ip) {
		// Look like an ordinary overloaded web server rather than announcing
		// what this endpoint is.
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	defer s.releaseIP(ip)

	conn, err := rendezvous.ServerHandshake(w, r)
	if err != nil {
		// Not a WebSocket request: answer as any web server would for an
		// unremarkable path.
		http.NotFound(w, r)
		return
	}
	defer conn.Close()
	s.serveConn(conn, r.RemoteAddr)
}

// serveConn runs the control loop for one connection. A connection that
// redeems a circuit ticket stops being a control connection and becomes one
// half of a byte pipe.
func (s *Server) serveConn(conn *rendezvous.WSConn, remoteAddr string) {
	var published []string
	defer func() {
		for _, rid := range published {
			s.dropPending(rid, conn)
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.limits.CircuitIdle))
		msg, err := conn.RecvMessage()
		if err != nil {
			return
		}

		switch msg.Type {
		case rendezvous.MsgPublish:
			rid, ok := s.checkRID(conn, msg)
			if !ok {
				return
			}
			if !s.publishes.allow(sourceIP(remoteAddr), s.limits.PublishesPerIPPerMin, time.Minute) {
				s.refuse(conn, msg.RendezvousID, "rate limit exceeded")
				return
			}
			if !s.addPending(rid, conn, msg.Candidates, remoteAddr) {
				s.refuse(conn, msg.RendezvousID, "relay is at capacity")
				return
			}
			published = append(published, rid)
			if err := conn.SendMessage(&rendezvous.Message{
				Type:         rendezvous.MsgPublished,
				RendezvousID: rid,
				Observed:     remoteAddr,
			}); err != nil {
				return
			}

		case rendezvous.MsgClaim:
			rid, ok := s.checkRID(conn, msg)
			if !ok {
				return
			}
			if err := conn.SendMessage(&rendezvous.Message{
				Type:         rendezvous.MsgPublished,
				RendezvousID: rid,
				Observed:     remoteAddr,
			}); err != nil {
				return
			}
			if err := s.pair(rid, conn, msg.Candidates, remoteAddr); err != nil {
				s.refuse(conn, rid, err.Error())
				continue
			}

		case rendezvous.MsgCircuit:
			s.attachCircuit(conn, msg)
			return // this connection is no longer a control connection

		case rendezvous.MsgBye:
			return

		default:
			s.refuse(conn, msg.RendezvousID, "unexpected message")
			return
		}
	}
}

// checkRID validates a rendezvous ID's encoding and length.
func (s *Server) checkRID(conn *rendezvous.WSConn, msg *rendezvous.Message) (string, bool) {
	if _, err := decodeExact(msg.RendezvousID, rendezvousIDSize); err != nil {
		s.refuse(conn, msg.RendezvousID, "malformed rendezvous id")
		return "", false
	}
	if len(msg.Candidates) > rendezvous.MaxControlFrame {
		s.refuse(conn, msg.RendezvousID, "candidate list too large")
		return "", false
	}
	return msg.RendezvousID, true
}

// addPending records a published code, respecting the global ceiling.
func (s *Server) addPending(rid string, conn *rendezvous.WSConn, sealed, observed string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= s.limits.MaxPendingCodes {
		return false
	}
	// Re-publishing after a reconnect replaces the old entry rather than
	// being refused as a duplicate.
	s.pending[rid] = &pendingCode{
		conn:     conn,
		sealed:   sealed,
		observed: observed,
		created:  time.Now(),
	}
	return true
}

// dropPending removes a code, but only if it still belongs to this connection.
func (s *Server) dropPending(rid string, conn *rendezvous.WSConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.pending[rid]; ok && p.conn == conn {
		delete(s.pending, rid)
	}
}

// pair joins a claimer to a published code and issues both circuit tickets.
func (s *Server) pair(rid string, claimer *rendezvous.WSConn, claimerSealed, claimerAddr string) error {
	s.mu.Lock()
	p, ok := s.pending[rid]
	if !ok {
		s.mu.Unlock()
		return errors.New("no such invite code")
	}
	if p.conn == claimer {
		s.mu.Unlock()
		return errors.New("cannot claim your own invite code")
	}
	if s.circuits >= s.limits.MaxCircuits {
		s.mu.Unlock()
		return errors.New("relay is at capacity")
	}
	// A code is single-use: remove it before anyone else can claim it.
	delete(s.pending, rid)
	s.circuits++
	s.mu.Unlock()

	ticketA, err := rendezvous.NewTicket()
	if err != nil {
		s.releaseCircuit()
		return errors.New("internal error")
	}
	ticketB, err := rendezvous.NewTicket()
	if err != nil {
		s.releaseCircuit()
		return errors.New("internal error")
	}

	c := &circuit{created: time.Now(), done: make(chan struct{})}
	s.mu.Lock()
	s.tickets[encode(ticketA)] = &ticketRef{circuit: c, side: 0}
	s.tickets[encode(ticketB)] = &ticketRef{circuit: c, side: 1}
	s.mu.Unlock()

	punchMS := s.limits.PunchDelay.Milliseconds()

	// The publisher is the handshake responder, the claimer the initiator.
	pubErr := p.conn.SendMessage(&rendezvous.Message{
		Type:           rendezvous.MsgPaired,
		RendezvousID:   rid,
		Role:           rendezvous.RolePublisher,
		PeerCandidates: claimerSealed,
		PeerObserved:   claimerAddr,
		PunchInMS:      punchMS,
		Ticket:         encode(ticketA),
	})
	claimErr := claimer.SendMessage(&rendezvous.Message{
		Type:           rendezvous.MsgPaired,
		RendezvousID:   rid,
		Role:           rendezvous.RoleClaimer,
		PeerCandidates: p.sealed,
		PeerObserved:   p.observed,
		PunchInMS:      punchMS,
		Ticket:         encode(ticketB),
	})
	if pubErr != nil || claimErr != nil {
		s.dropCircuit(c, encode(ticketA), encode(ticketB))
		return errors.New("peer went away")
	}
	s.log("paired a rendezvous")
	return nil
}

// attachCircuit redeems a ticket, and splices once both sides have arrived.
func (s *Server) attachCircuit(conn *rendezvous.WSConn, msg *rendezvous.Message) {
	if _, err := decodeExact(msg.Ticket, rendezvous.TicketSize); err != nil {
		s.refuse(conn, "", "malformed ticket")
		return
	}
	s.mu.Lock()
	ref, ok := s.tickets[msg.Ticket]
	if ok {
		// A ticket is single-use.
		delete(s.tickets, msg.Ticket)
	}
	s.mu.Unlock()
	if !ok {
		s.refuse(conn, "", "unknown or spent ticket")
		return
	}
	if err := conn.SendMessage(&rendezvous.Message{Type: rendezvous.MsgCircuitOK}); err != nil {
		return
	}

	c := ref.circuit
	c.mu.Lock()
	c.conns[ref.side] = conn
	second := c.conns[1-ref.side] != nil && !c.started
	if second {
		c.started = true
	}
	c.mu.Unlock()

	if second {
		s.splice(c)
		close(c.done)
		return
	}

	// First half: hold the connection open until the splice finishes, the
	// peer fails to show up, or the relay shuts down. Returning here would
	// close the socket the other half is about to be spliced onto.
	select {
	case <-c.done:
	case <-time.After(s.limits.CircuitIdle):
		// The peer never arrived — most often because a direct or punched
		// path won the race and the circuit was never needed.
		conn.Close()
		s.releaseOnce(c)
	case <-s.closed:
		conn.Close()
	}
}

// splice copies bytes both ways until either side stops or a limit is hit.
// The relay does not parse, buffer or inspect anything it forwards.
func (s *Server) splice(c *circuit) {
	defer s.releaseOnce(c)
	a, b := c.conns[0], c.conns[1]
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)
	go func() { s.pump(a, b); done <- struct{}{} }()
	go func() { s.pump(b, a); done <- struct{}{} }()

	lifetime := time.NewTimer(s.limits.CircuitLifetime)
	defer lifetime.Stop()
	select {
	case <-done:
	case <-lifetime.C:
	case <-s.closed:
	}
}

// pump copies src→dst, enforcing the idle timeout and the byte ceiling.
func (s *Server) pump(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		_ = src.SetReadDeadline(time.Now().Add(s.limits.CircuitIdle))
		n, err := src.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > s.limits.CircuitBytes {
				return
			}
			_ = dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) dropCircuit(c *circuit, tickets ...string) {
	s.mu.Lock()
	for _, t := range tickets {
		delete(s.tickets, t)
	}
	s.mu.Unlock()
	s.releaseOnce(c)
}

// releaseOnce returns a circuit's slot exactly once, however it ended.
func (s *Server) releaseOnce(c *circuit) {
	c.released.Do(s.releaseCircuit)
}

func (s *Server) releaseCircuit() {
	s.mu.Lock()
	if s.circuits > 0 {
		s.circuits--
	}
	s.mu.Unlock()
}

// refuse sends an error message; the caller decides whether to close.
func (s *Server) refuse(conn *rendezvous.WSConn, rid, reason string) {
	_ = conn.SendMessage(&rendezvous.Message{
		Type:         rendezvous.MsgError,
		RendezvousID: rid,
		Reason:       reason,
	})
}

// acquireIP enforces the per-source connection ceiling.
func (s *Server) acquireIP(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipConns[ip] >= s.limits.MaxConnsPerIP {
		return false
	}
	s.ipConns[ip]++
	return true
}

func (s *Server) releaseIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.ipConns[ip]; n <= 1 {
		delete(s.ipConns, ip)
	} else {
		s.ipConns[ip] = n - 1
	}
}

// reap expires unclaimed codes, unredeemed tickets and stale rate windows.
//
// The interval follows the configured TTL rather than being fixed, so a relay
// tuned to expire codes quickly actually does: a fixed sweep would let a
// one-minute code linger for another half-minute after it should be gone.
func (s *Server) reap() {
	t := time.NewTicker(reapInterval(s.limits.CodeTTL))
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			now := time.Now()
			s.mu.Lock()
			for rid, p := range s.pending {
				if now.Sub(p.created) > s.limits.CodeTTL {
					delete(s.pending, rid)
				}
			}
			for tk, ref := range s.tickets {
				if now.Sub(ref.circuit.created) > s.limits.CodeTTL {
					delete(s.tickets, tk)
				}
			}
			s.mu.Unlock()
			s.publishes.sweep(time.Minute)
		}
	}
}

func (s *Server) log(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
	}
}

// Stats reports current occupancy, for an operator's status endpoint.
func (s *Server) Stats() (pending, circuits int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending), s.circuits
}

// sourceIP extracts the address part of a "host:port" remote address.
func sourceIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
