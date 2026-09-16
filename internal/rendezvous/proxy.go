package rendezvous

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// HTTP CONNECT proxy support (rung B of the connection ladder,
// docs/rendezvous.md §1.5).
//
// On networks where direct outbound TCP is blocked and an HTTP proxy is
// mandatory — the common corporate arrangement — the only way out is to ask
// the proxy to tunnel. The TLS handshake and the WebSocket upgrade then run
// inside the tunnel exactly as they would directly, so the rest of the stack
// is unchanged.

// ErrNoProxy indicates no proxy is configured for this environment.
var ErrNoProxy = errors.New("rendezvous: no HTTP proxy configured")

// ProxyURL resolves the proxy to use: an explicit setting wins, otherwise the
// conventional environment variables. Returns ErrNoProxy when there is none.
func ProxyURL(explicit string) (*url.URL, error) {
	raw := explicit
	if raw == "" {
		for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			if v := os.Getenv(key); v != "" {
				raw = v
				break
			}
		}
	}
	if raw == "" {
		return nil, ErrNoProxy
	}
	// A bare host:port is a common way to write a proxy; give it a scheme so
	// url.Parse treats it as an authority rather than a path.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("rendezvous: bad proxy %q: %w", explicit, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("rendezvous: bad proxy %q: no host", explicit)
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Host, "8080")
	}
	return u, nil
}

// DialViaProxy opens a tunnel to target ("host:port") through an HTTP proxy
// using CONNECT, and returns the tunnelled connection.
func DialViaProxy(ctx context.Context, d *net.Dialer, proxy *url.URL, target string) (net.Conn, error) {
	conn, err := d.DialContext(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("rendezvous: dial proxy %s: %w", proxy.Host, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := "CONNECT " + target + " HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"Proxy-Connection: Keep-Alive\r\n"
	if proxy.User != nil {
		pass, _ := proxy.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(proxy.User.Username() + ":" + pass))
		req += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("rendezvous: proxy CONNECT write: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("rendezvous: proxy CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("rendezvous: proxy refused CONNECT: %s", resp.Status)
	}
	// Anything buffered past the response would be data we cannot hand to the
	// TLS layer, which reads from the raw connection. A well-behaved proxy
	// sends nothing until we do.
	if br.Buffered() > 0 {
		conn.Close()
		return nil, errors.New("rendezvous: proxy sent unexpected data after CONNECT")
	}
	_ = conn.SetDeadline(zeroTime)
	return conn, nil
}
