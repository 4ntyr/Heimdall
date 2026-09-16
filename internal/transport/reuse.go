package transport

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

// Socket reuse and port-preserving dialling.
//
// These exist for one reason: TCP hole punching needs a listener and an
// outbound connection to share a local port, so that both ride the NAT
// mapping the relay connection already established (docs/rendezvous.md §7).

// ReuseControl is the net.Dialer / net.ListenConfig Control hook that enables
// address and port reuse. Its platform-specific half lives in reuse_*.go.
func ReuseControl(_, _ string, c syscall.RawConn) error {
	var inner error
	if err := c.Control(func(fd uintptr) { inner = setReuse(fd) }); err != nil {
		return err
	}
	return inner
}

// ReuseDialer returns a dialer that binds outbound connections to localPort
// with address reuse enabled. A localPort of 0 lets the kernel choose, which
// is what a caller that does not intend to punch should pass.
func ReuseDialer(localPort int, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, Control: ReuseControl}
	if localPort > 0 {
		d.LocalAddr = &net.TCPAddr{Port: localPort}
	}
	return d
}

// ListenReuse binds a TCP listener to port with address reuse enabled, so the
// same port can also be used as the source of outbound connections. Pass 0 to
// let the kernel pick, then read the port back with Addr.
func ListenReuse(port int) (*net.TCPListener, error) {
	lc := net.ListenConfig{Control: ReuseControl}
	ln, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("transport: reuse-listen on port %d: %w", port, err)
	}
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		ln.Close()
		return nil, fmt.Errorf("transport: unexpected listener type %T", ln)
	}
	return tcpLn, nil
}

// DialFrom opens an outbound TCP connection from a specific local port.
func DialFrom(ctx context.Context, localPort int, addr string, timeout time.Duration) (net.Conn, error) {
	d := ReuseDialer(localPort, timeout)
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return conn, nil
}
