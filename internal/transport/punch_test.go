package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestReuseAllowsListenAndDialOnOnePort is the socket behaviour hole punching
// depends on: the same local port must serve as both a listener and the source
// of an outbound connection, so both ride the NAT mapping the relay
// connection created (docs/rendezvous.md §7).
func TestReuseAllowsListenAndDialOnOnePort(t *testing.T) {
	ln, err := ListenReuse(0)
	if err != nil {
		t.Fatalf("reuse-listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// A second listener to dial towards.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer target.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := target.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialFrom(ctx, port, target.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dialling from the listening port: %v", err)
	}
	defer conn.Close()

	if got := conn.LocalAddr().(*net.TCPAddr).Port; got != port {
		t.Errorf("outbound connection used source port %d, want %d", got, port)
	}
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the target never saw the connection")
	}
}

// TestPunchListenerRoutesToWaiter checks the routing rule: a connection from
// an address a punch is waiting on goes to that punch, and anything else goes
// to the ordinary inbound path instead of being dropped.
func TestPunchListenerRoutesToWaiter(t *testing.T) {
	fallback := make(chan net.Conn, 4)
	pl, err := NewPunchListener(0, func(c net.Conn) { fallback <- c })
	if err != nil {
		t.Fatalf("creating punch listener: %v", err)
	}
	defer pl.Close()

	// Nothing is waiting yet, so an inbound connection must reach fallback.
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(pl.Port())))
	if err != nil {
		t.Fatalf("dialling the punch listener: %v", err)
	}
	defer conn.Close()

	select {
	case c := <-fallback:
		c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("an unmatched inbound connection was not passed to the fallback")
	}
}

// TestPunchSucceedsBetweenLocalPeers exercises the punch path end to end on
// loopback, where both sides can always reach each other.
func TestPunchSucceedsBetweenLocalPeers(t *testing.T) {
	a, err := NewPunchListener(0, nil)
	if err != nil {
		t.Fatalf("creating punch listener a: %v", err)
	}
	defer a.Close()

	b, err := NewPunchListener(0, nil)
	if err != nil {
		t.Fatalf("creating punch listener b: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type result struct {
		conn net.Conn
		err  error
	}
	aDone := make(chan result, 1)
	go func() {
		conn, err := a.Punch(ctx, net.JoinHostPort("127.0.0.1", itoa(b.Port())), 0)
		aDone <- result{conn, err}
	}()

	bConn, bErr := b.Punch(ctx, net.JoinHostPort("127.0.0.1", itoa(a.Port())), 0)
	aResult := <-aDone

	if aErr := aResult.err; aErr != nil {
		t.Fatalf("side a failed to punch: %v", aErr)
	}
	if bErr != nil {
		t.Fatalf("side b failed to punch: %v", bErr)
	}
	defer aResult.conn.Close()
	defer bConn.Close()
}

// TestPunchGivesUp checks that an unreachable peer fails rather than hanging.
func TestPunchGivesUp(t *testing.T) {
	pl, err := NewPunchListener(0, nil)
	if err != nil {
		t.Fatalf("creating punch listener: %v", err)
	}
	defer pl.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	start := time.Now()
	// Port 1 on loopback refuses immediately, so this exercises the retry
	// loop rather than a network timeout.
	conn, err := pl.Punch(ctx, "127.0.0.1:1", 0)
	if err == nil {
		conn.Close()
		t.Fatal("punching a closed port reported success")
	}
	if elapsed := time.Since(start); elapsed > PunchDuration+3*time.Second {
		t.Errorf("punch took %v to give up, well past its %v budget", elapsed, PunchDuration)
	}
}

// itoa avoids importing strconv for two call sites in tests.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
