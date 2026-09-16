package rendezvous

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The connection ladder (docs/rendezvous.md §1.5).
//
// Walked once, when the control connection is established; the rung that
// worked is remembered and reused for circuit connections, so the cost of
// discovery is paid a single time.

// Rung identifies one step of the ladder.
type Rung int

const (
	// RungTLSDirect is TLS + WebSocket straight to the relay on its TLS port.
	RungTLSDirect Rung = iota
	// RungTLSProxy is the same tunnelled through an HTTP CONNECT proxy.
	RungTLSProxy
	// RungHTTPDirect is a plain HTTP WebSocket upgrade on the cleartext port,
	// for networks that block 443 but pass 80.
	RungHTTPDirect
)

func (r Rung) String() string {
	switch r {
	case RungTLSDirect:
		return "tls"
	case RungTLSProxy:
		return "tls-via-proxy"
	case RungHTTPDirect:
		return "http"
	default:
		return "unknown"
	}
}

// Ladder is the order rungs are attempted in.
var Ladder = []Rung{RungTLSDirect, RungTLSProxy, RungHTTPDirect}

// Defaults for endpoint parsing and rung timeouts.
const (
	DefaultTLSPort  = 443
	DefaultHTTPPort = 80
	DefaultPath     = "/hmdl"
	// RungTimeout bounds one rung before the next is tried.
	RungTimeout = 5 * time.Second
)

var zeroTime time.Time

// Endpoint describes a relay and how to reach it.
type Endpoint struct {
	// Host is the relay hostname or IP, without a port.
	Host string
	// TLSPort and HTTPPort are the ports for rungs A/B and C respectively.
	TLSPort  int
	HTTPPort int
	// Path is the HTTP path the relay is mounted at.
	Path string

	// Pin, when set, is the base64 SHA-256 of the relay certificate's
	// SubjectPublicKeyInfo. It is the way to use a self-signed relay safely.
	Pin string
	// Verify forces strict verification against the system roots, disabling
	// the unverified fallback described below.
	Verify bool
	// Proxy overrides the proxy environment variables for rung B.
	Proxy string

	// Dialer is used for every TCP connection. The caller supplies one bound
	// to a fixed local port so that hole punching can reuse the NAT mapping
	// this connection creates (docs/rendezvous.md §7).
	Dialer *net.Dialer
}

// ParseEndpoint accepts "example.com", "example.com:8443",
// "https://example.com/hmdl" or "http://example.com:8080/hmdl".
func ParseEndpoint(s string) (*Endpoint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("rendezvous: empty relay address")
	}
	ep := &Endpoint{TLSPort: DefaultTLSPort, HTTPPort: DefaultHTTPPort, Path: DefaultPath}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("rendezvous: bad relay address %q: %w", s, err)
		}
		ep.Host = u.Hostname()
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 65535 {
				return nil, fmt.Errorf("rendezvous: bad relay port %q", p)
			}
			// An explicit port applies to whichever scheme was named, and the
			// other rung keeps its default.
			if u.Scheme == "http" {
				ep.HTTPPort = n
			} else {
				ep.TLSPort = n
			}
		}
		if u.Path != "" && u.Path != "/" {
			ep.Path = u.Path
		}
	} else if host, port, err := net.SplitHostPort(s); err == nil {
		n, convErr := strconv.Atoi(port)
		if convErr != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("rendezvous: bad relay port %q", port)
		}
		ep.Host, ep.TLSPort = host, n
	} else {
		ep.Host = s
	}

	if ep.Host == "" {
		return nil, fmt.Errorf("rendezvous: bad relay address %q: no host", s)
	}
	if !strings.HasPrefix(ep.Path, "/") {
		ep.Path = "/" + ep.Path
	}
	return ep, nil
}

// dialer returns the dialer to use, defaulting to a plain one.
func (e *Endpoint) dialer() *net.Dialer {
	if e.Dialer != nil {
		return e.Dialer
	}
	return &net.Dialer{Timeout: RungTimeout}
}

// Dial walks the ladder and returns the first rung that yields a working
// WebSocket connection, along with which rung that was.
func (e *Endpoint) Dial(ctx context.Context) (*WSConn, Rung, error) {
	var errs []string
	for _, rung := range Ladder {
		conn, err := e.DialRung(ctx, rung)
		if err == nil {
			return conn, rung, nil
		}
		errs = append(errs, rung.String()+": "+err.Error())
		if ctx.Err() != nil {
			break
		}
	}
	return nil, 0, fmt.Errorf("rendezvous: no route to relay %s (%s)", e.Host, strings.Join(errs, "; "))
}

// DialRung attempts exactly one rung.
func (e *Endpoint) DialRung(ctx context.Context, rung Rung) (*WSConn, error) {
	ctx, cancel := context.WithTimeout(ctx, RungTimeout)
	defer cancel()

	var (
		conn net.Conn
		err  error
		host string
	)
	switch rung {
	case RungTLSDirect:
		host = net.JoinHostPort(e.Host, strconv.Itoa(e.TLSPort))
		conn, err = e.dialTLS(ctx, host, nil)

	case RungTLSProxy:
		proxy, perr := ProxyURL(e.Proxy)
		if perr != nil {
			return nil, perr
		}
		host = net.JoinHostPort(e.Host, strconv.Itoa(e.TLSPort))
		conn, err = e.dialTLS(ctx, host, proxy)

	case RungHTTPDirect:
		host = net.JoinHostPort(e.Host, strconv.Itoa(e.HTTPPort))
		conn, err = e.dialer().DialContext(ctx, "tcp", host)

	default:
		return nil, fmt.Errorf("rendezvous: unknown rung %d", rung)
	}
	if err != nil {
		return nil, err
	}

	br, err := ClientHandshake(conn, e.Host, e.Path, RungTimeout)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return NewWSConn(conn, br, true), nil
}

// dialTLS establishes a TLS connection, optionally through a proxy.
//
// On a certificate verification failure — and only when no pin and no strict
// mode is configured — it retries once without verification. This is
// deliberate, not a workaround: the relay is an untrusted byte pipe, all
// security is end-to-end, and a TLS-intercepting corporate proxy must not be
// able to keep two people from talking (docs/rendezvous.md §1.3). It is safe
// only because the pairing confirmation of §4 is mandatory.
func (e *Endpoint) dialTLS(ctx context.Context, hostPort string, proxy *url.URL) (net.Conn, error) {
	raw, err := e.dialRaw(ctx, hostPort, proxy)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, e.tlsConfig(false))
	if err := conn.HandshakeContext(ctx); err == nil {
		return conn, nil
	} else if e.Pin != "" || e.Verify || !isCertError(err) {
		raw.Close()
		return nil, err
	}

	// Verification failed and we are permitted to proceed anyway.
	raw.Close()
	raw, err = e.dialRaw(ctx, hostPort, proxy)
	if err != nil {
		return nil, err
	}
	conn = tls.Client(raw, e.tlsConfig(true))
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func (e *Endpoint) dialRaw(ctx context.Context, hostPort string, proxy *url.URL) (net.Conn, error) {
	if proxy != nil {
		return DialViaProxy(ctx, e.dialer(), proxy, hostPort)
	}
	return e.dialer().DialContext(ctx, "tcp", hostPort)
}

// tlsConfig builds the client TLS configuration for this endpoint.
func (e *Endpoint) tlsConfig(skipVerify bool) *tls.Config {
	cfg := &tls.Config{
		ServerName: e.Host,
		MinVersion: tls.VersionTLS12,
		// Present the same ALPN a browser would for an HTTP/1.1 upgrade, so
		// the handshake does not stand out from ordinary web traffic.
		NextProtos: []string{"http/1.1"},
	}
	if e.Pin != "" {
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = e.verifyPin
		return cfg
	}
	cfg.InsecureSkipVerify = skipVerify
	return cfg
}

// verifyPin accepts only a certificate whose SubjectPublicKeyInfo matches the
// configured pin, which is how a self-signed relay is used without weakening
// anything.
func (e *Endpoint) verifyPin(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	want, err := base64.StdEncoding.DecodeString(e.Pin)
	if err != nil {
		return fmt.Errorf("rendezvous: bad relay pin: %w", err)
	}
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if len(want) == len(sum) && subtleEqual(want, sum[:]) {
			return nil
		}
	}
	return errors.New("rendezvous: relay certificate does not match -relay-pin")
}

// PinFor renders the pin value for a certificate, so an operator can print the
// pin for their own relay.
func PinFor(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// isCertError reports whether a TLS failure was a certificate-verification
// failure specifically, as opposed to a network or protocol failure.
func isCertError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidErr) ||
		errors.As(err, &certErr)
}

// subtleEqual compares two equal-length byte slices in constant time.
func subtleEqual(a, b []byte) bool {
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
