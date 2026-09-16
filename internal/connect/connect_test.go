package connect_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/4ntyr/heimdall/internal/connect"
	"github.com/4ntyr/heimdall/internal/identity"
	"github.com/4ntyr/heimdall/internal/peers"
	"github.com/4ntyr/heimdall/internal/relay"
	"github.com/4ntyr/heimdall/internal/rendezvous"
	"github.com/4ntyr/heimdall/internal/session"
	"github.com/4ntyr/heimdall/internal/transport"
)

// testRelay starts an in-process relay and returns an endpoint template.
//
// tlsMode selects the ladder rung under test: a TLS server exercises rung A
// (including the unverified fallback, since httptest signs with its own CA),
// a plain HTTP server exercises rung C.
func testRelay(t *testing.T, tlsMode bool) (*httptest.Server, func() *rendezvous.Endpoint) {
	t.Helper()
	// Keep the ladder hermetic: without this, a proxy configured in the
	// environment makes rung B attempt a real CONNECT and the test measures
	// the ambient network instead of the code.
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(key, "")
	}
	srv := relay.New(relay.DefaultLimits(), nil)
	t.Cleanup(srv.Close)

	mux := http.NewServeMux()
	mux.Handle(rendezvous.DefaultPath, srv.Handler())

	var hs *httptest.Server
	if tlsMode {
		hs = httptest.NewTLSServer(mux)
	} else {
		hs = httptest.NewServer(mux)
	}
	t.Cleanup(hs.Close)

	u, err := url.Parse(hs.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parsing test server port: %v", err)
	}

	return hs, func() *rendezvous.Endpoint {
		ep := &rendezvous.Endpoint{
			Host: u.Hostname(),
			Path: rendezvous.DefaultPath,
		}
		if tlsMode {
			ep.TLSPort = port
			// Rung C must not be reachable, so a rung-A failure is a test
			// failure rather than being papered over by the fallback.
			ep.HTTPPort = 1
		} else {
			// Force rung A to fail fast so the ladder falls through to C.
			ep.TLSPort = 1
			ep.HTTPPort = port
		}
		return ep
	}
}

// node is one Heimdall peer, deliberately with no listener at all: every path
// it uses is outbound (docs/rendezvous.md §1.1).
type node struct {
	mgr    *session.Manager
	client *rendezvous.Client
	cfg    connect.Config
	events <-chan session.Event
}

func newNode(t *testing.T, name string, ep *rendezvous.Endpoint) *node {
	return newNodeWithPunch(t, name, ep, false)
}

func newNodeWithPunch(t *testing.T, name string, ep *rendezvous.Endpoint, withPunch bool) *node {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	store, err := peers.OpenStore(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatalf("opening trust store: %v", err)
	}
	mgr := session.NewManager(id, store)
	t.Cleanup(mgr.Shutdown)

	client := rendezvous.NewClient(ep)
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Wait(ctx); err != nil {
		t.Fatalf("%s could not reach the relay: %v", name, err)
	}

	expectations := connect.NewExpectations()
	mgr.SetInboundHook(expectations.Hook)
	cfg := connect.Config{Manager: mgr, Client: client, Expect: expectations}
	if withPunch {
		punch, err := transport.NewPunchListener(0, mgr.HandleInbound)
		if err != nil {
			t.Fatalf("creating punch listener: %v", err)
		}
		t.Cleanup(func() { punch.Close() })
		cfg.Punch = punch
	}

	return &node{
		mgr:    mgr,
		client: client,
		cfg:    cfg,
		events: mgr.Events(),
	}
}

// waitFor consumes events until one of the wanted type arrives.
func (n *node) waitFor(t *testing.T, want session.EventType, timeout time.Duration) session.Event {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-n.events:
			if ev.Type == want {
				return ev
			}
			if ev.Type == session.EventError || ev.Type == session.EventSecurityWarning {
				t.Fatalf("unexpected event while waiting: %v", ev.Text)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for event type %v", want)
		}
	}
}

// pair runs an invite/join between two nodes and returns once both are up.
func pair(t *testing.T, a, b *node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	code, wait, err := connect.Invite(ctx, a.cfg)
	if err != nil {
		t.Fatalf("publishing invite: %v", err)
	}
	inviteDone := make(chan error, 1)
	go func() { inviteDone <- wait(context.Background()) }()

	if err := connect.Join(ctx, b.cfg, code); err != nil {
		t.Fatalf("joining with invite code: %v", err)
	}
	if err := <-inviteDone; err != nil {
		t.Fatalf("invite side failed: %v", err)
	}
}

// TestSessionOverRelay is the end-to-end case that matters most: two peers
// with no listener, no forwarded port and no direct reachability, connecting
// purely through the relay and exchanging a message.
func TestSessionOverRelay(t *testing.T) {
	_, endpoint := testRelay(t, true)
	alice := newNode(t, "alice", endpoint())
	bob := newNode(t, "bob", endpoint())

	pair(t, alice, bob)

	aliceSide := alice.waitFor(t, session.EventPeerConnected, 20*time.Second)
	bobSide := bob.waitFor(t, session.EventPeerConnected, 20*time.Second)

	if aliceSide.Peer != "bob" || bobSide.Peer != "alice" {
		t.Fatalf("peers identified each other wrongly: %q / %q", aliceSide.Peer, bobSide.Peer)
	}
	if aliceSide.Path != session.PathRelay {
		t.Errorf("expected the relay path, got %q", aliceSide.Path)
	}

	const text = "the relay never sees this"
	if err := alice.mgr.Send("bob", text); err != nil {
		t.Fatalf("sending: %v", err)
	}
	got := bob.waitFor(t, session.EventMessage, 10*time.Second)
	if got.Text != text {
		t.Errorf("message came through as %q, want %q", got.Text, text)
	}
	if got.Peer != "alice" {
		t.Errorf("message attributed to %q, want alice", got.Peer)
	}
}

// TestSessionOverCleartextRung proves rung C works: a network that blocks 443
// but passes 80 still connects (docs/rendezvous.md §1.5).
func TestSessionOverCleartextRung(t *testing.T) {
	_, endpoint := testRelay(t, false)
	alice := newNode(t, "alice", endpoint())
	bob := newNode(t, "bob", endpoint())

	if got := alice.client.Rung(); got != rendezvous.RungHTTPDirect {
		t.Fatalf("expected the cleartext rung, got %v", got)
	}

	pair(t, alice, bob)
	alice.waitFor(t, session.EventPeerConnected, 20*time.Second)
	bob.waitFor(t, session.EventPeerConnected, 20*time.Second)

	if err := alice.mgr.Send("bob", "hello over rung C"); err != nil {
		t.Fatalf("sending: %v", err)
	}
	if got := bob.waitFor(t, session.EventMessage, 10*time.Second); got.Text != "hello over rung C" {
		t.Errorf("unexpected message %q", got.Text)
	}
}

// TestWrongInviteCodeIsRejected checks that mistyping a code connects nobody:
// the rendezvous ID derived from it does not match, so no pairing happens and
// no peer is recorded.
//
// The stronger property — that a peer who reaches the right rendezvous but
// cannot prove it holds the code is rejected — is the pairing confirmation of
// docs/rendezvous.md §4, tested directly in internal/session.
func TestWrongInviteCodeIsRejected(t *testing.T) {
	_, endpoint := testRelay(t, true)
	alice := newNode(t, "alice", endpoint())
	mallory := newNode(t, "mallory", endpoint())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	code, wait, err := connect.Invite(ctx, alice.cfg)
	if err != nil {
		t.Fatalf("publishing invite: %v", err)
	}
	inviteDone := make(chan error, 1)
	go func() { inviteDone <- wait(context.Background()) }()

	wrong := tamper(code)
	if err := connect.Join(ctx, mallory.cfg, wrong); err == nil {
		t.Fatal("a peer with the wrong invite code was allowed to connect")
	}

	select {
	case err := <-inviteDone:
		if err == nil {
			t.Fatal("the inviting side accepted a peer that did not hold the code")
		}
	case <-time.After(2 * time.Second):
		// The rendezvous never paired at all, which is also a rejection.
	}

	// Nothing may have been recorded as a known peer.
	if list := alice.mgr.Peers(); len(list) != 0 {
		t.Errorf("failed pairing left %d connected peers", len(list))
	}
}

// tamper changes one character of a code so it decodes to a different secret.
func tamper(code string) string {
	runes := []rune(code)
	for i := len(runes) - 1; i >= 0; i-- {
		if runes[i] == '-' {
			continue
		}
		if runes[i] == 'A' {
			runes[i] = 'B'
		} else {
			runes[i] = 'A'
		}
		break
	}
	return string(runes)
}

// TestDirectPathBeatsRelay checks the race actually prefers a cheaper path:
// when the peers can reach each other directly, the relay grace period should
// expire unused and the session should not be relayed.
func TestDirectPathBeatsRelay(t *testing.T) {
	if !directPathWorks(t) {
		t.Skip("this host's own addresses are not dialable; a direct path cannot be exercised here")
	}

	_, endpoint := testRelay(t, true)
	alice := newNodeWithPunch(t, "alice", endpoint(), true)
	bob := newNodeWithPunch(t, "bob", endpoint(), true)

	pair(t, alice, bob)

	ev := alice.waitFor(t, session.EventPeerConnected, 20*time.Second)
	if ev.Path == session.PathRelay {
		t.Errorf("the relay carried a session that had a direct path available")
	}

	if err := alice.mgr.Send("bob", "direct"); err != nil {
		t.Fatalf("sending: %v", err)
	}
	if got := bob.waitFor(t, session.EventMessage, 10*time.Second); got.Text != "direct" {
		t.Errorf("unexpected message %q", got.Text)
	}
}

// directPathWorks reports whether this host can actually reach itself on one of
// the addresses it would advertise as a candidate.
//
// Merely having a non-loopback address is not enough: a sandbox may expose an
// address on an interface that cannot be dialled, in which case the direct path
// is untestable here and the test has nothing to say.
func directPathWorks(t *testing.T) bool {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return false
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	for _, cand := range rendezvous.LocalCandidates(port) {
		conn, err := net.DialTimeout("tcp", cand.Addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}
