package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// TCP simultaneous-open hole punching (docs/rendezvous.md §7).
//
// Two peers behind NATs each dial the other's observed public endpoint from
// the same local port they already used to reach the relay. Either the
// outbound dial completes — a true TCP simultaneous open — or the local SYN
// creates a mapping that admits the peer's SYN, which the listener then
// accepts.
//
// Success depends on the NAT performing endpoint-independent mapping for TCP,
// which a meaningful share of consumer routers do not. Nothing depends on
// this succeeding: it runs alongside a relay circuit that already works, and
// only ever makes a session faster and cheaper (docs/rendezvous.md §0).

// Punch timings.
const (
	// PunchInterval is how often a punch attempt re-dials.
	PunchInterval = 250 * time.Millisecond
	// PunchDuration is how long punching is attempted before giving up.
	PunchDuration = 5 * time.Second
	// punchDialTimeout bounds one individual dial attempt.
	punchDialTimeout = 1500 * time.Millisecond
)

// ErrPunchFailed indicates no direct path was established in time.
var ErrPunchFailed = errors.New("transport: hole punch did not succeed")

// PunchListener is a reuse-bound listener that routes inbound connections
// either to a punch in progress or to the ordinary inbound handler.
//
// Routing is by source IP: a punched connection arrives from the same address
// the relay observed for that peer, so the punch that is waiting for that peer
// can claim it while unrelated inbound connections still reach the normal
// path.
type PunchListener struct {
	ln   *net.TCPListener
	port int

	mu      sync.Mutex
	waiters map[string]chan net.Conn

	// fallback receives connections no punch is waiting for. It is what makes
	// the punch port usable as an ordinary listener at the same time.
	fallback func(net.Conn)

	closeOnce sync.Once
	closed    chan struct{}
}

// NewPunchListener binds a reuse-enabled listener. Pass port 0 to let the
// kernel choose; read the chosen port back with Port.
//
// fallback is called for every inbound connection that no punch is waiting
// for, and may be nil to drop them.
func NewPunchListener(port int, fallback func(net.Conn)) (*PunchListener, error) {
	ln, err := ListenReuse(port)
	if err != nil {
		return nil, err
	}
	pl := &PunchListener{
		ln:       ln,
		port:     ln.Addr().(*net.TCPAddr).Port,
		waiters:  make(map[string]chan net.Conn),
		fallback: fallback,
		closed:   make(chan struct{}),
	}
	go pl.acceptLoop()
	return pl, nil
}

// Port is the local port shared by the listener and every punch dial.
func (p *PunchListener) Port() int { return p.port }

// Close stops accepting.
func (p *PunchListener) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return p.ln.Close()
}

func (p *PunchListener) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		p.route(conn)
	}
}

// route hands a connection to a waiting punch, or to the fallback.
func (p *PunchListener) route(conn net.Conn) {
	ip := addrIP(conn.RemoteAddr().String())
	p.mu.Lock()
	ch, ok := p.waiters[ip]
	p.mu.Unlock()
	if ok {
		select {
		case ch <- conn:
			return
		default:
			// The punch already won by another route; treat this as ordinary
			// inbound traffic rather than dropping a real peer.
		}
	}
	if p.fallback != nil {
		p.fallback(conn)
		return
	}
	conn.Close()
}

func (p *PunchListener) register(ip string) chan net.Conn {
	ch := make(chan net.Conn, 1)
	p.mu.Lock()
	p.waiters[ip] = ch
	p.mu.Unlock()
	return ch
}

func (p *PunchListener) unregister(ip string) {
	p.mu.Lock()
	delete(p.waiters, ip)
	p.mu.Unlock()
}

// Punch attempts to establish a direct connection to remote ("host:port"),
// starting after delay. It returns the first connection established in either
// direction, or ErrPunchFailed.
func (p *PunchListener) Punch(ctx context.Context, remote string, delay time.Duration) (net.Conn, error) {
	ip := addrIP(remote)
	if ip == "" {
		return nil, errors.New("transport: punch target has no address")
	}
	inbound := p.register(ip)
	defer p.unregister(ip)

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		case conn := <-inbound:
			return conn, nil
		}
	}

	ctx, cancel := context.WithTimeout(ctx, PunchDuration)
	defer cancel()

	// Dial attempts run in the background so an inbound arrival is never
	// blocked behind an outbound dial that is still timing out.
	dialed := make(chan net.Conn, 1)
	go p.dialLoop(ctx, remote, dialed)

	select {
	case conn := <-inbound:
		return conn, nil
	case conn := <-dialed:
		return conn, nil
	case <-ctx.Done():
		// Drain a connection that landed as we gave up, rather than leaking it.
		select {
		case conn := <-inbound:
			return conn, nil
		case conn := <-dialed:
			return conn, nil
		default:
		}
		return nil, ErrPunchFailed
	}
}

// dialLoop re-dials the peer until the context ends or a dial succeeds.
func (p *PunchListener) dialLoop(ctx context.Context, remote string, out chan<- net.Conn) {
	t := time.NewTicker(PunchInterval)
	defer t.Stop()
	for {
		conn, err := DialFrom(ctx, p.port, remote, punchDialTimeout)
		if err == nil {
			select {
			case out <- conn:
			default:
				conn.Close()
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// addrIP extracts the host part of a "host:port" address.
func addrIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
