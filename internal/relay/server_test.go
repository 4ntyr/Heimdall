package relay_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/4ntyr/heimdall/internal/relay"
	"github.com/4ntyr/heimdall/internal/rendezvous"
)

func testServer(t *testing.T, limits relay.Limits) (*relay.Server, *rendezvous.Endpoint) {
	t.Helper()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(key, "")
	}
	srv := relay.New(limits, nil)
	t.Cleanup(srv.Close)

	mux := http.NewServeMux()
	mux.Handle(rendezvous.DefaultPath, srv.Handler())
	hs := httptest.NewServer(mux)
	t.Cleanup(hs.Close)

	u, _ := url.Parse(hs.URL)
	port, _ := strconv.Atoi(u.Port())
	return srv, &rendezvous.Endpoint{
		Host:     u.Hostname(),
		TLSPort:  1, // force the ladder down to the cleartext rung
		HTTPPort: port,
		Path:     rendezvous.DefaultPath,
	}
}

func newCodeParts(t *testing.T) (rid, key []byte) {
	t.Helper()
	c, err := rendezvous.NewCode()
	if err != nil {
		t.Fatalf("generating code: %v", err)
	}
	rid, err = c.ID()
	if err != nil {
		t.Fatalf("deriving id: %v", err)
	}
	key, err = c.PairingKey()
	if err != nil {
		t.Fatalf("deriving pairing key: %v", err)
	}
	return rid, key
}

func sealedFor(t *testing.T, key []byte, addr string) []byte {
	t.Helper()
	blob, err := rendezvous.SealCandidates(key, rendezvous.CandidateSet{
		Candidates: []rendezvous.Candidate{{Addr: addr, Kind: rendezvous.KindHost}},
	})
	if err != nil {
		t.Fatalf("sealing candidates: %v", err)
	}
	return blob
}

func dialClient(t *testing.T, ep *rendezvous.Endpoint) *rendezvous.Client {
	t.Helper()
	c := rendezvous.NewClient(ep)
	t.Cleanup(func() { c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Wait(ctx); err != nil {
		t.Fatalf("connecting to relay: %v", err)
	}
	return c
}

// TestPairExchangesCandidates is the core rendezvous: two peers meet on a
// rendezvous ID and each receives the other's sealed candidates, its own
// observed address, and a circuit ticket.
func TestPairExchangesCandidates(t *testing.T) {
	_, ep := testServer(t, relay.DefaultLimits())
	publisher := dialClient(t, ep)
	claimer := dialClient(t, ep)

	rid, key := newCodeParts(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	invite, err := publisher.Publish(ctx, rid, sealedFor(t, key, "203.0.113.1:7331"))
	if err != nil {
		t.Fatalf("publishing: %v", err)
	}
	if invite.Observed() == "" {
		t.Error("the relay did not report an observed address")
	}

	paired := make(chan *rendezvous.Pairing, 1)
	go func() {
		p, err := invite.Wait(context.Background(), key)
		if err != nil {
			paired <- nil
			return
		}
		paired <- p
	}()

	claimerSide, err := claimer.Claim(ctx, rid, sealedFor(t, key, "198.51.100.2:7331"), key)
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	publisherSide := <-paired
	if publisherSide == nil {
		t.Fatal("the publishing side never paired")
	}

	if publisherSide.Role != rendezvous.RolePublisher || claimerSide.Role != rendezvous.RoleClaimer {
		t.Errorf("roles wrong: %q / %q", publisherSide.Role, claimerSide.Role)
	}
	if publisherSide.Initiator() {
		t.Error("the publisher should be the handshake responder")
	}
	if !claimerSide.Initiator() {
		t.Error("the claimer should be the handshake initiator")
	}
	if len(publisherSide.PeerCandidates) != 1 || publisherSide.PeerCandidates[0].Addr != "198.51.100.2:7331" {
		t.Errorf("publisher got peer candidates %v", publisherSide.PeerCandidates)
	}
	if len(claimerSide.PeerCandidates) != 1 || claimerSide.PeerCandidates[0].Addr != "203.0.113.1:7331" {
		t.Errorf("claimer got peer candidates %v", claimerSide.PeerCandidates)
	}
	if len(publisherSide.Ticket) != rendezvous.TicketSize || len(claimerSide.Ticket) != rendezvous.TicketSize {
		t.Error("circuit tickets are the wrong size")
	}
	if string(publisherSide.Ticket) == string(claimerSide.Ticket) {
		t.Error("both sides were issued the same ticket; they must be distinct")
	}
}

// TestCodeIsSingleUse: a second claimer must not be able to take over a
// rendezvous that has already been paired.
func TestCodeIsSingleUse(t *testing.T) {
	_, ep := testServer(t, relay.DefaultLimits())
	publisher := dialClient(t, ep)
	first := dialClient(t, ep)
	second := dialClient(t, ep)

	rid, key := newCodeParts(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	invite, err := publisher.Publish(ctx, rid, sealedFor(t, key, "203.0.113.1:7331"))
	if err != nil {
		t.Fatalf("publishing: %v", err)
	}
	go invite.Wait(context.Background(), key)

	if _, err := first.Claim(ctx, rid, sealedFor(t, key, "198.51.100.2:7331"), key); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	short, cancelShort := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShort()
	if _, err := second.Claim(short, rid, sealedFor(t, key, "198.51.100.3:7331"), key); err == nil {
		t.Error("an invite code was claimed twice")
	}
}

func TestClaimingAnUnknownCodeFails(t *testing.T) {
	_, ep := testServer(t, relay.DefaultLimits())
	client := dialClient(t, ep)

	rid, key := newCodeParts(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.Claim(ctx, rid, sealedFor(t, key, "198.51.100.2:7331"), key); err == nil {
		t.Error("claiming a code nobody published succeeded")
	}
}

// TestExpiredCodeCannotBeClaimed checks the TTL actually removes a code, so a
// code left lying around in a chat log does not stay answerable forever.
func TestExpiredCodeCannotBeClaimed(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.CodeTTL = 40 * time.Millisecond
	srv, ep := testServer(t, limits)

	publisher := dialClient(t, ep)
	claimer := dialClient(t, ep)

	rid, key := newCodeParts(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	invite, err := publisher.Publish(ctx, rid, sealedFor(t, key, "203.0.113.1:7331"))
	if err != nil {
		t.Fatalf("publishing: %v", err)
	}
	go invite.Wait(context.Background(), key)

	// Wait for the reaper to sweep the code away.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pending, _ := srv.Stats(); pending == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pending, _ := srv.Stats(); pending != 0 {
		t.Fatalf("the code was still pending %v after its TTL", limits.CodeTTL)
	}

	short, cancelShort := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShort()
	if _, err := claimer.Claim(short, rid, sealedFor(t, key, "198.51.100.2:7331"), key); err == nil {
		t.Error("an expired invite code was still claimable")
	}
}

// TestCapacityIsBounded checks a relay refuses rather than growing without
// limit when someone floods it with codes.
func TestCapacityIsBounded(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.MaxPendingCodes = 2
	limits.PublishesPerIPPerMin = 100
	_, ep := testServer(t, limits)

	client := dialClient(t, ep)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var refused int
	for i := 0; i < 5; i++ {
		rid, key := newCodeParts(t)
		if _, err := client.Publish(ctx, rid, sealedFor(t, key, "203.0.113.1:7331")); err != nil {
			refused++
			// The relay closes the connection when it refuses, so reconnect.
			client = dialClient(t, ep)
		}
	}
	if refused == 0 {
		t.Error("the relay accepted more pending codes than its limit allows")
	}
}

// TestPublishRateLimited checks the per-source publish cap.
func TestPublishRateLimited(t *testing.T) {
	limits := relay.DefaultLimits()
	limits.PublishesPerIPPerMin = 2
	_, ep := testServer(t, limits)

	client := dialClient(t, ep)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var refused int
	for i := 0; i < 5; i++ {
		rid, key := newCodeParts(t)
		if _, err := client.Publish(ctx, rid, sealedFor(t, key, "203.0.113.1:7331")); err != nil {
			refused++
			client = dialClient(t, ep)
		}
	}
	if refused == 0 {
		t.Error("the relay did not rate-limit repeated publishes from one source")
	}
}

// TestUnknownTicketRefused checks that a circuit cannot be opened by guessing.
func TestUnknownTicketRefused(t *testing.T) {
	_, ep := testServer(t, relay.DefaultLimits())
	client := dialClient(t, ep)

	ticket, err := rendezvous.NewTicket()
	if err != nil {
		t.Fatalf("generating ticket: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if conn, err := client.OpenCircuit(ctx, ticket); err == nil {
		conn.Close()
		t.Error("the relay opened a circuit for a ticket it never issued")
	}
}
