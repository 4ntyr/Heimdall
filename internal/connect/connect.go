// Package connect turns a rendezvous into a connected peer.
//
// It owns the path race of docs/rendezvous.md §7.1: a direct dial to the
// peer's own addresses, a hole punch at the coordinated moment, and a relay
// circuit that is opened after a short grace period and always if nothing
// else has worked. Every path ends the same way — a net.Conn handed to
// session.Manager.Adopt — so the cryptographic layer neither knows nor cares
// which one won.
//
// The relay circuit is what makes connectivity unconditional. The other two
// only ever make a session faster and cheaper.
package connect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	xcrypto "github.com/4ntyr/heimdall/internal/crypto"
	"github.com/4ntyr/heimdall/internal/rendezvous"
	"github.com/4ntyr/heimdall/internal/session"
	"github.com/4ntyr/heimdall/internal/transport"
)

// Race timings (docs/rendezvous.md §7.1).
const (
	// RelayGrace is how long a direct or punched path is given before the
	// relay circuit is opened. It is short: a session that works now beats a
	// slightly cheaper session later.
	RelayGrace = 1500 * time.Millisecond
	// RaceTimeout bounds the whole attempt.
	RaceTimeout = 45 * time.Second
	// expectLinger keeps a rendezvous's inbound expectation alive after the
	// race has been won, so a peer's dial that is still in flight is adopted
	// with the pairing key rather than as an unsolicited connection.
	expectLinger = 10 * time.Second
	// directDialTimeout bounds one direct candidate dial.
	directDialTimeout = 3 * time.Second
)

// Config wires the pieces a connection attempt needs.
type Config struct {
	// Manager adopts whichever path wins.
	Manager *session.Manager
	// Client is the live rendezvous control connection.
	Client *rendezvous.Client
	// Punch is the reuse-bound listener shared with the relay connection's
	// local port. Nil disables hole punching; the relay still works.
	Punch *transport.PunchListener
	// ListenPort is the node's inbound port, advertised as a host candidate
	// when it has one. Zero means the node does not listen at all.
	ListenPort int
	// Expect records rendezvous in flight so that connections this node
	// accepts carry the same pairing requirement as ones it dials. Wire it to
	// the manager with SetInboundHook.
	Expect *Expectations
}

// localCandidates advertises the addresses a peer might reach us on directly.
func (c *Config) localCandidates() []rendezvous.Candidate {
	port := c.ListenPort
	if port == 0 && c.Punch != nil {
		// With no listener of its own, the punch port is still directly
		// reachable from a peer on the same LAN.
		port = c.Punch.Port()
	}
	return rendezvous.LocalCandidates(port)
}

// Invite publishes a fresh invite code and returns it for the user to pass to
// their peer out-of-band. The returned function blocks until a peer claims the
// code and the resulting connection has been attempted.
func Invite(ctx context.Context, cfg Config) (code string, wait func(context.Context) error, err error) {
	c, err := rendezvous.NewCode()
	if err != nil {
		return "", nil, err
	}
	rid, err := c.ID()
	if err != nil {
		return "", nil, err
	}
	pairingKey, err := c.PairingKey()
	if err != nil {
		return "", nil, err
	}
	sealed, err := rendezvous.SealCandidates(pairingKey, rendezvous.CandidateSet{
		Candidates: cfg.localCandidates(),
	})
	if err != nil {
		return "", nil, err
	}

	invite, err := cfg.Client.Publish(ctx, rid, sealed)
	if err != nil {
		return "", nil, err
	}

	rendered := c.String()
	// The code's own secret is no longer needed: the derived pairing key
	// carries the rest of the exchange.
	c.Zeroise()

	wait = func(ctx context.Context) error {
		pairing, err := invite.Wait(ctx, pairingKey)
		if err != nil {
			xcrypto.Zeroise(pairingKey)
			return err
		}
		// Race takes ownership of the key from here.
		return Race(ctx, cfg, pairing, pairingKey)
	}
	return rendered, wait, nil
}

// Join redeems an invite code published by another peer.
func Join(ctx context.Context, cfg Config, codeText string) error {
	c, err := rendezvous.ParseCode(codeText)
	if err != nil {
		return err
	}
	rid, err := c.ID()
	if err != nil {
		return err
	}
	pairingKey, err := c.PairingKey()
	if err != nil {
		return err
	}
	c.Zeroise()

	sealed, err := rendezvous.SealCandidates(pairingKey, rendezvous.CandidateSet{
		Candidates: cfg.localCandidates(),
	})
	if err != nil {
		xcrypto.Zeroise(pairingKey)
		return err
	}

	pairing, err := cfg.Client.Claim(ctx, rid, sealed, pairingKey)
	if err != nil {
		xcrypto.Zeroise(pairingKey)
		return err
	}
	// Race takes ownership of the key from here.
	return Race(ctx, cfg, pairing, pairingKey)
}

// Race attempts every available path concurrently and returns once one has
// produced an authenticated session.
//
// Race takes ownership of pairingKey and wipes it once nothing can still need
// it. That is later than it looks: Race returns as soon as one path wins, while
// losing attempts are still running and an inbound expectation deliberately
// lingers for a peer whose dial is still in flight. Wiping the key at return
// would pull it out from under a confirmation in progress and reject a
// legitimate peer.
//
// Paths are not cancelled the moment one wins: a later-arriving direct or
// punched path is an upgrade over a relayed one, and the manager's duplicate
// resolution settles which connection both peers keep. What a win does stop is
// the relay circuit being opened when it is not needed.
func Race(ctx context.Context, cfg Config, p *rendezvous.Pairing, pairingKey []byte) error {
	if cfg.Manager == nil {
		return errors.New("connect: no session manager")
	}
	ctx, cancel := context.WithTimeout(ctx, RaceTimeout)
	defer cancel()

	var (
		wg   sync.WaitGroup
		once sync.Once
		won  = make(chan struct{})
		mu   sync.Mutex
		errs []string
	)
	succeed := func() { once.Do(func() { close(won) }) }
	fail := func(path string, err error) {
		mu.Lock()
		errs = append(errs, path+": "+err.Error())
		mu.Unlock()
	}

	opts := session.AdoptOptions{
		Initiator:     p.Initiator(),
		PairingKey:    pairingKey,
		OnEstablished: func() { succeed() },
	}

	// A peer may reach us before we reach it. Register the addresses it might
	// arrive from, so an accepted connection is adopted with this rendezvous's
	// role and pairing key instead of being treated as an unsolicited inbound
	// connection.
	inboundOpts := opts
	inboundOpts.Path = session.PathDirect
	addrs := make([]string, 0, len(p.PeerCandidates))
	for _, cand := range p.PeerCandidates {
		addrs = append(addrs, cand.Addr)
	}
	withdraw := cfg.Expect.expect(peerIPs(p.PeerObserved, addrs), inboundOpts)

	attempt := func(path string, dial func(context.Context) (net.Conn, error)) {
		defer wg.Done()
		conn, err := dial(ctx)
		if err != nil {
			fail(path, err)
			return
		}
		o := opts
		o.Path = path
		if err := cfg.Manager.Adopt(conn, o); err != nil {
			fail(path, err)
			return
		}
		succeed()
	}

	// Direct paths: the peer's own addresses. These win instantly on a shared
	// LAN or where both peers have working global IPv6, and never touch the
	// relay.
	for _, cand := range p.PeerCandidates {
		addr := cand.Addr
		wg.Add(1)
		go attempt(session.PathDirect, func(ctx context.Context) (net.Conn, error) {
			return dialDirect(ctx, cfg, addr)
		})
	}

	// Hole punch against the peer's server-reflexive address.
	if cfg.Punch != nil && p.PeerObserved != "" {
		wg.Add(1)
		go attempt(session.PathPunched, func(ctx context.Context) (net.Conn, error) {
			return cfg.Punch.Punch(ctx, p.PeerObserved, p.PunchIn)
		})
	}

	// Relay circuit: opened after a grace period so it is skipped when a
	// cheaper path is already working, and unconditionally otherwise. This is
	// the path that makes the connection guaranteed.
	wg.Add(1)
	go attempt(session.PathRelay, func(ctx context.Context) (net.Conn, error) {
		select {
		case <-won:
			return nil, errors.New("a direct path won first")
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(RelayGrace):
		}
		return cfg.Client.OpenCircuit(ctx, p.Ticket)
	})

	// Wait for the first success, or for every dialled path to have failed.
	// A peer that dialled us signals through OnEstablished rather than through
	// one of these attempts, so the won channel is checked on every exit.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
		// Every dialled path has finished; hold the key only as long as the
		// lingering inbound expectation could still need it, then wipe both.
		time.AfterFunc(expectLinger, func() {
			withdraw()
			xcrypto.Zeroise(pairingKey)
		})
	}()

	select {
	case <-won:
		return nil
	case <-done:
		select {
		case <-won:
			return nil
		default:
		}
		mu.Lock()
		defer mu.Unlock()
		return fmt.Errorf("connect: every path failed (%v)", errs)
	case <-ctx.Done():
		return fmt.Errorf("connect: timed out establishing a session")
	}
}

// dialDirect dials one of the peer's advertised addresses.
//
// Unlike the punch, this does not bind the shared local port. Reusing that port
// only matters when dialling a peer's server-reflexive address, where the point
// is to ride the NAT mapping the relay connection created. A host candidate is
// a LAN or globally routable address with no NAT in the path, so binding buys
// nothing — and binding a port that is already carrying an established
// connection is refused outright on some hosts, which would lose a direct path
// that plain dialling reaches perfectly well.
func dialDirect(ctx context.Context, _ Config, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: directDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return conn, nil
}
