// Package transport moves opaque bytes between peers over TCP using
// length-prefixed frames. It knows nothing about cryptography or the
// terminal UI (docs/protocol.md §10).
//
// Frame layout on the wire:
//
//	4 bytes  big-endian uint32 payload length (max MaxFrameSize)
//	N bytes  opaque payload
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	// MaxFrameSize bounds a single frame; larger frames are dropped and the
	// connection is considered hostile/broken.
	MaxFrameSize = 1 << 20 // 1 MiB
	// DialTimeout bounds connection establishment.
	DialTimeout = 10 * time.Second
	// IOTimeout bounds individual read/write operations.
	IOTimeout = 30 * time.Second
	// HandshakeTimeout bounds the full handshake exchange.
	HandshakeTimeout = 15 * time.Second
)

// ErrFrameTooLarge indicates a peer sent a frame beyond the limit.
var ErrFrameTooLarge = errors.New("transport: frame too large")

// FrameIO is a framed bidirectional byte channel to one peer.
type FrameIO struct {
	conn net.Conn
}

// NewFrameIO wraps an established connection.
func NewFrameIO(conn net.Conn) *FrameIO { return &FrameIO{conn: conn} }

// Send writes one length-prefixed frame.
func (f *FrameIO) Send(payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	_ = f.conn.SetWriteDeadline(time.Now().Add(IOTimeout))
	if _, err := f.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := f.conn.Write(payload)
	return err
}

// Recv reads one length-prefixed frame. It returns ErrFrameTooLarge when the
// peer announces an oversized frame (the connection should then be dropped).
func (f *FrameIO) Recv() ([]byte, error) {
	return f.RecvBefore(time.Now().Add(IOTimeout))
}

// RecvBefore reads one frame, requiring it to arrive by deadline.
//
// Recv applies its own IOTimeout to each read, which would otherwise override
// any deadline the caller had set on the connection. A caller that needs a
// specific bound — waiting for a pairing confirmation, say — must pass it
// here rather than calling SetDeadline and hoping it survives.
func (f *FrameIO) RecvBefore(deadline time.Time) ([]byte, error) {
	var hdr [4]byte
	_ = f.conn.SetReadDeadline(deadline)
	if _, err := io.ReadFull(f.conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if n == 0 {
		return payload, nil
	}
	_ = f.conn.SetReadDeadline(deadline)
	if _, err := io.ReadFull(f.conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// SetDeadline overrides the I/O deadline (used during the handshake).
func (f *FrameIO) SetDeadline(t time.Time) error { return f.conn.SetDeadline(t) }

// ClearDeadline removes I/O deadlines for the steady-state read loop, where
// liveness is enforced by the keepalive protocol instead of deadlines.
func (f *FrameIO) ClearDeadline() error { return f.conn.SetDeadline(time.Time{}) }

// Close terminates the underlying connection.
func (f *FrameIO) Close() error { return f.conn.Close() }

// RemoteAddr returns the peer's network address.
func (f *FrameIO) RemoteAddr() string {
	if a := f.conn.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

// Listener accepts inbound peer connections.
type Listener struct {
	ln net.Listener
}

// Listen starts a TCP listener on addr (e.g. ":8471" or "0.0.0.0:8471").
func Listen(addr string) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: listen %s: %w", addr, err)
	}
	return &Listener{ln: ln}, nil
}

// Accept returns the next inbound connection as a FrameIO.
func (l *Listener) Accept() (*FrameIO, error) {
	conn, err := l.AcceptConn()
	if err != nil {
		return nil, err
	}
	return NewFrameIO(conn), nil
}

// AcceptConn returns the next inbound connection unwrapped, for callers that
// need to inspect the peer address before deciding how to handle it.
func (l *Listener) AcceptConn() (net.Conn, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return conn, nil
}

// Addr returns the listener's bound address (useful when port 0 was given).
func (l *Listener) Addr() string { return l.ln.Addr().String() }

// Close stops the listener.
func (l *Listener) Close() error { return l.ln.Close() }

// Dial opens an outbound connection to addr and returns it as a FrameIO.
func Dial(addr string) (*FrameIO, error) {
	d := net.Dialer{Timeout: DialTimeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return NewFrameIO(conn), nil
}
