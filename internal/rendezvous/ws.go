package rendezvous

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	xcrypto "github.com/4ntyr/heimdall/internal/crypto"
)

// RFC 6455 WebSocket framing, client and server side.
//
// Heimdall speaks a genuine WebSocket upgrade rather than a bespoke protocol
// because layer-7 inspecting proxies routinely permit an HTTPS WebSocket and
// drop everything else (docs/rendezvous.md §1.2). Only the subset the relay
// needs is implemented: binary data frames, ping/pong and close. That subset
// is what a middlebox checks for.

// WebSocket opcodes.
const (
	opContinuation byte = 0x0
	opText         byte = 0x1
	opBinary       byte = 0x2
	opClose        byte = 0x8
	opPing         byte = 0x9
	opPong         byte = 0xA
)

const (
	// wsGUID is the RFC 6455 handshake constant.
	wsGUID = "258EAFA5-E914-47DA-95CA-5AB0DC85B39A"
	// maxWSPayload bounds a single inbound frame. The transport above this
	// layer caps its own frames at 1 MiB; the slack covers framing overhead.
	maxWSPayload = (1 << 20) + 1024
	// maxControlPayload is the RFC 6455 limit for control frames.
	maxControlPayload = 125
	// wsWriteTimeout bounds a single frame write once a deadline is not
	// otherwise set by the caller.
	wsWriteTimeout = 30 * time.Second
)

var (
	// ErrWSHandshake indicates a failed WebSocket upgrade.
	ErrWSHandshake = errors.New("rendezvous: websocket upgrade failed")
	// ErrWSProtocol indicates a peer that violated the framing rules.
	ErrWSProtocol = errors.New("rendezvous: websocket protocol error")
)

// WSConn is a net.Conn carried inside RFC 6455 binary frames.
//
// Frame boundaries are deliberately NOT preserved across Read: the payload is
// the length-prefixed byte stream of internal/transport, which does its own
// framing. That is what lets a relay circuit be spliced with a plain copy loop
// and lets transport.NewFrameIO wrap this with no changes at all.
type WSConn struct {
	conn net.Conn
	br   *bufio.Reader
	// mask reports whether this side must mask outbound frames (clients must,
	// servers must not) and correspondingly whether inbound frames must be
	// masked (a server requires it of clients).
	mask bool

	wmu sync.Mutex

	rmu      sync.Mutex
	rem      int64   // payload bytes left in the current data frame
	rmask    [4]byte // mask of the current inbound frame
	rmasked  bool
	rmaskPos int

	closeOnce sync.Once
}

// NewWSConn wraps an already-upgraded connection. client selects the masking
// role: true on the dialling side, false on the accepting side.
func NewWSConn(conn net.Conn, br *bufio.Reader, client bool) *WSConn {
	if br == nil {
		br = bufio.NewReader(conn)
	}
	return &WSConn{conn: conn, br: br, mask: client}
}

// Read returns payload bytes from binary frames, answering ping frames and
// discarding pongs along the way.
func (c *WSConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if c.rem > 0 {
			n := len(p)
			if int64(n) > c.rem {
				n = int(c.rem)
			}
			read, err := io.ReadFull(c.br, p[:n])
			if read > 0 {
				if c.rmasked {
					for i := 0; i < read; i++ {
						p[i] ^= c.rmask[c.rmaskPos&3]
						c.rmaskPos++
					}
				}
				c.rem -= int64(read)
			}
			if err != nil {
				return read, err
			}
			return read, nil
		}
		if err := c.nextFrame(); err != nil {
			return 0, err
		}
	}
}

// nextFrame advances to the next data frame, handling control frames inline.
func (c *WSConn) nextFrame() error {
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return err
		}
		fin := hdr[0]&0x80 != 0
		if hdr[0]&0x70 != 0 {
			return fmt.Errorf("%w: reserved bits set", ErrWSProtocol)
		}
		opcode := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		length := int64(hdr[1] & 0x7F)

		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return err
			}
			length = int64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.br, ext[:]); err != nil {
				return err
			}
			v := binary.BigEndian.Uint64(ext[:])
			if v > maxWSPayload {
				return fmt.Errorf("%w: frame of %d bytes exceeds limit", ErrWSProtocol, v)
			}
			length = int64(v)
		}
		if length > maxWSPayload {
			return fmt.Errorf("%w: frame of %d bytes exceeds limit", ErrWSProtocol, length)
		}
		// A server must reject unmasked client frames; a client must reject
		// masked server frames. Both are RFC 6455 requirements, and enforcing
		// them keeps a confused middlebox from being mistaken for a peer.
		if !c.mask && !masked {
			return fmt.Errorf("%w: unmasked frame from client", ErrWSProtocol)
		}
		if c.mask && masked {
			return fmt.Errorf("%w: masked frame from server", ErrWSProtocol)
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
				return err
			}
		}

		switch opcode {
		case opBinary, opContinuation:
			c.rem = length
			c.rmask = maskKey
			c.rmasked = masked
			c.rmaskPos = 0
			if length == 0 {
				continue // empty frame: nothing to hand back, keep reading
			}
			return nil

		case opText:
			return fmt.Errorf("%w: unexpected text frame", ErrWSProtocol)

		case opClose:
			if err := c.drain(length, maskKey, masked); err != nil {
				return err
			}
			c.writeControl(opClose, nil)
			return io.EOF

		case opPing:
			if length > maxControlPayload || !fin {
				return fmt.Errorf("%w: malformed ping", ErrWSProtocol)
			}
			payload, err := c.readPayload(length, maskKey, masked)
			if err != nil {
				return err
			}
			if err := c.writeControl(opPong, payload); err != nil {
				return err
			}

		case opPong:
			if length > maxControlPayload || !fin {
				return fmt.Errorf("%w: malformed pong", ErrWSProtocol)
			}
			if err := c.drain(length, maskKey, masked); err != nil {
				return err
			}

		default:
			return fmt.Errorf("%w: unknown opcode %d", ErrWSProtocol, opcode)
		}
	}
}

func (c *WSConn) readPayload(length int64, key [4]byte, masked bool) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return nil, err
	}
	if masked {
		for i := range buf {
			buf[i] ^= key[i&3]
		}
	}
	return buf, nil
}

func (c *WSConn) drain(length int64, key [4]byte, masked bool) error {
	_, err := c.readPayload(length, key, masked)
	return err
}

// Write sends p as a single binary frame.
func (c *WSConn) Write(p []byte) (int, error) {
	if len(p) > maxWSPayload {
		return 0, fmt.Errorf("%w: outbound frame too large", ErrWSProtocol)
	}
	if err := c.writeFrame(opBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteControl sends a ping/pong/close frame.
func (c *WSConn) writeControl(opcode byte, payload []byte) error {
	if len(payload) > maxControlPayload {
		payload = payload[:maxControlPayload]
	}
	return c.writeFrame(opcode, payload)
}

// Ping sends a WebSocket ping. Middleboxes reap idle connections aggressively,
// so the control connection pings on a timer (docs/rendezvous.md §1.4).
func (c *WSConn) Ping() error { return c.writeControl(opPing, nil) }

func (c *WSConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	var hdr []byte
	b0 := byte(0x80) | opcode // FIN set: frames are never fragmented on send
	switch n := len(payload); {
	case n < 126:
		hdr = []byte{b0, byte(n)}
	case n <= 0xFFFF:
		hdr = []byte{b0, 126, 0, 0}
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
	default:
		hdr = make([]byte, 10)
		hdr[0], hdr[1] = b0, 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}

	var body []byte
	if c.mask {
		key, err := xcrypto.RandomBytes(4)
		if err != nil {
			return err
		}
		hdr[1] |= 0x80
		hdr = append(hdr, key...)
		// Mask into a copy: the caller's buffer must not be mutated.
		body = make([]byte, len(payload))
		for i := range payload {
			body[i] = payload[i] ^ key[i&3]
		}
	} else {
		body = payload
	}

	// One write for the whole frame keeps it off the wire as a single segment
	// where possible, which matters for looking like ordinary WebSocket
	// traffic rather than a header/payload drip.
	out := make([]byte, 0, len(hdr)+len(body))
	out = append(out, hdr...)
	out = append(out, body...)
	if _, err := c.conn.Write(out); err != nil {
		return err
	}
	return nil
}

// Close sends a close frame (best effort) and closes the connection.
func (c *WSConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = c.writeControl(opClose, []byte{0x03, 0xE8}) // 1000 normal closure
	})
	return c.conn.Close()
}

func (c *WSConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *WSConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *WSConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *WSConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *WSConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// SendMessage writes one control message as a binary frame.
func (c *WSConn) SendMessage(m *Message) error {
	buf, err := EncodeMessage(m)
	if err != nil {
		return err
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	return c.writeFrame(opBinary, buf)
}

// RecvMessage reads one control message. Control messages are small and always
// sent as a single frame, so a bounded read is sufficient and denies an
// attacker an unbounded accumulation buffer.
func (c *WSConn) RecvMessage() (*Message, error) {
	buf := make([]byte, MaxControlFrame)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	// A control message must arrive whole. Any residue means the peer sent
	// something larger than the control plane permits.
	c.rmu.Lock()
	residue := c.rem
	c.rmu.Unlock()
	if residue > 0 {
		return nil, ErrControlTooLarge
	}
	return DecodeMessage(buf[:n])
}

// --- handshake ---

// acceptKey computes the RFC 6455 Sec-WebSocket-Accept value.
func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ClientHandshake performs the HTTP/1.1 WebSocket upgrade over an established
// (possibly TLS-wrapped) connection. The request is written by hand rather
// than through net/http because the connection must survive the upgrade.
func ClientHandshake(conn net.Conn, host, path string, timeout time.Duration) (*bufio.Reader, error) {
	nonce, err := xcrypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce)

	if path == "" {
		path = "/"
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWSHandshake, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWSHandshake, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("%w: server answered %s", ErrWSHandshake, resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("%w: missing websocket upgrade header", ErrWSHandshake)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		return nil, fmt.Errorf("%w: bad Sec-WebSocket-Accept", ErrWSHandshake)
	}
	return br, nil
}

// ServerHandshake validates an inbound upgrade request and hijacks the
// connection, returning it wrapped for server-side framing. It is exported so
// internal/relay can mount itself as an ordinary net/http handler beside a
// real website.
func ServerHandshake(w http.ResponseWriter, r *http.Request) (*WSConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		return nil, fmt.Errorf("%w: not an upgrade request", ErrWSHandshake)
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, fmt.Errorf("%w: unsupported websocket version", ErrWSHandshake)
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("%w: missing Sec-WebSocket-Key", ErrWSHandshake)
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("%w: connection cannot be hijacked", ErrWSHandshake)
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWSHandshake, err)
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrWSHandshake, err)
	}
	return NewWSConn(conn, brw.Reader, false), nil
}

// headerContainsToken reports whether a comma-separated header lists a token.
func headerContainsToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}
