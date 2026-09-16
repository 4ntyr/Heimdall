package rendezvous

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeProxy is a minimal HTTP CONNECT proxy: it accepts CONNECT, dials the
// requested target and splices. requireAuth makes it demand credentials first.
type fakeProxy struct {
	ln       net.Listener
	tunnels  atomic.Int32
	required string // expected Proxy-Authorization value, empty for none
}

func newFakeProxy(t *testing.T, required string) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	p := &fakeProxy{ln: ln, required: required}
	t.Cleanup(func() { ln.Close() })
	go p.serve()
	return p
}

func (p *fakeProxy) addr() string { return p.ln.Addr().String() }

func (p *fakeProxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *fakeProxy) handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		conn.Close()
		return
	}
	if req.Method != http.MethodConnect {
		io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		conn.Close()
		return
	}
	if p.required != "" && req.Header.Get("Proxy-Authorization") != p.required {
		io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		conn.Close()
		return
	}
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		conn.Close()
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		conn.Close()
		upstream.Close()
		return
	}
	p.tunnels.Add(1)
	go func() { io.Copy(upstream, br); upstream.Close() }()
	go func() { io.Copy(conn, upstream); conn.Close() }()
}

func TestProxyURLPrefersExplicitThenEnvironment(t *testing.T) {
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(key, "")
	}
	if _, err := ProxyURL(""); err == nil {
		t.Error("expected ErrNoProxy with nothing configured")
	}

	t.Setenv("HTTPS_PROXY", "proxy.internal:3128")
	u, err := ProxyURL("")
	if err != nil {
		t.Fatalf("reading proxy from environment: %v", err)
	}
	if u.Host != "proxy.internal:3128" {
		t.Errorf("environment proxy parsed as %q", u.Host)
	}

	u, err = ProxyURL("http://explicit.example:8080")
	if err != nil {
		t.Fatalf("explicit proxy: %v", err)
	}
	if u.Host != "explicit.example:8080" {
		t.Errorf("explicit proxy parsed as %q, and should win over the environment", u.Host)
	}

	// A bare host gets the conventional default port rather than being read
	// as a path.
	u, err = ProxyURL("proxy.internal")
	if err != nil {
		t.Fatalf("bare host proxy: %v", err)
	}
	if u.Port() == "" {
		t.Error("a bare proxy host was left without a port")
	}
}

// TestDialViaProxyReachesTarget is rung B: the only route out is a CONNECT
// proxy, and the WebSocket must come up through the tunnel.
func TestDialViaProxyReachesTarget(t *testing.T) {
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(key, "")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := ServerHandshake(w, r)
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	})
	hs := httptest.NewTLSServer(mux)
	defer hs.Close()

	proxy := newFakeProxy(t, "")
	u, _ := url.Parse(hs.URL)
	port, _ := strconv.Atoi(u.Port())

	ep := &Endpoint{
		Host:    u.Hostname(),
		TLSPort: port,
		Path:    "/ws",
		Proxy:   proxy.addr(),
	}

	conn, err := ep.DialRung(context.Background(), RungTLSProxy)
	if err != nil {
		t.Fatalf("dialling through the proxy: %v", err)
	}
	defer conn.Close()

	if proxy.tunnels.Load() == 0 {
		t.Error("the connection did not actually go through the proxy")
	}

	payload := []byte("through a corporate proxy")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("writing: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload came back as %q", got)
	}
}

// TestDialViaProxySendsCredentials checks Proxy-Authorization, without which
// an authenticating proxy — the usual corporate arrangement — refuses.
func TestDialViaProxySendsCredentials(t *testing.T) {
	// base64("user:secret")
	const expected = "Basic dXNlcjpzZWNyZXQ="
	proxy := newFakeProxy(t, expected)

	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer target.Close()
	go func() {
		conn, err := target.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	proxyURL, err := ProxyURL("http://user:secret@" + proxy.addr())
	if err != nil {
		t.Fatalf("parsing proxy: %v", err)
	}
	conn, err := DialViaProxy(context.Background(), &net.Dialer{}, proxyURL, target.Addr().String())
	if err != nil {
		t.Fatalf("authenticated CONNECT failed: %v", err)
	}
	conn.Close()

	// Without credentials the same proxy must refuse.
	bare, _ := ProxyURL("http://" + proxy.addr())
	if _, err := DialViaProxy(context.Background(), &net.Dialer{}, bare, target.Addr().String()); err == nil {
		t.Error("the proxy accepted a CONNECT with no credentials")
	} else if !strings.Contains(err.Error(), "407") {
		t.Errorf("expected a 407 refusal, got %v", err)
	}
}
