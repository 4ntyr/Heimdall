package rendezvous

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		tlsPort  int
		httpPort int
		path     string
	}{
		{"relay.example.com", "relay.example.com", 443, 80, DefaultPath},
		{"relay.example.com:8443", "relay.example.com", 8443, 80, DefaultPath},
		{"https://relay.example.com/hmdl", "relay.example.com", 443, 80, "/hmdl"},
		{"https://relay.example.com:9443/meet", "relay.example.com", 9443, 80, "/meet"},
		{"http://relay.example.com:8080/meet", "relay.example.com", 443, 8080, "/meet"},
		{"203.0.113.9:443", "203.0.113.9", 443, 80, DefaultPath},
	}
	for _, c := range cases {
		ep, err := ParseEndpoint(c.in)
		if err != nil {
			t.Errorf("ParseEndpoint(%q): %v", c.in, err)
			continue
		}
		if ep.Host != c.host || ep.TLSPort != c.tlsPort || ep.HTTPPort != c.httpPort || ep.Path != c.path {
			t.Errorf("ParseEndpoint(%q) = {%s %d %d %s}, want {%s %d %d %s}",
				c.in, ep.Host, ep.TLSPort, ep.HTTPPort, ep.Path,
				c.host, c.tlsPort, c.httpPort, c.path)
		}
	}
	for _, bad := range []string{"", "   ", "relay.example.com:0", "relay.example.com:99999"} {
		if _, err := ParseEndpoint(bad); err == nil {
			t.Errorf("ParseEndpoint(%q) was accepted", bad)
		}
	}
}

// tlsEcho starts a TLS WebSocket echo server signed by an unknown CA, which is
// what both a self-signed relay and an intercepting proxy look like.
func tlsEcho(t *testing.T) (*httptest.Server, *Endpoint) {
	t.Helper()
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
	t.Cleanup(hs.Close)

	u, _ := url.Parse(hs.URL)
	port, _ := strconv.Atoi(u.Port())
	return hs, &Endpoint{Host: u.Hostname(), TLSPort: port, HTTPPort: 1, Path: "/ws"}
}

// TestUnverifiableCertificateIsToleratedByDefault is the behaviour that lets
// Heimdall through a TLS-intercepting corporate proxy, where an application
// that pins certificates simply fails (docs/rendezvous.md §1.3). It is safe
// because the relay is an untrusted byte pipe and first contact is
// authenticated end-to-end by the pairing confirmation.
func TestUnverifiableCertificateIsToleratedByDefault(t *testing.T) {
	_, ep := tlsEcho(t)
	conn, err := ep.DialRung(context.Background(), RungTLSDirect)
	if err != nil {
		t.Fatalf("an unverifiable relay certificate blocked the connection: %v", err)
	}
	conn.Close()
}

// TestRelayVerifyRefusesUnverifiableCertificate covers the opt-out for users
// who would rather fail than tolerate interception.
func TestRelayVerifyRefusesUnverifiableCertificate(t *testing.T) {
	_, ep := tlsEcho(t)
	ep.Verify = true
	if conn, err := ep.DialRung(context.Background(), RungTLSDirect); err == nil {
		conn.Close()
		t.Error("-relay-verify accepted a certificate it could not verify")
	}
}

// TestPinnedCertificate covers running a self-signed relay safely: the right
// pin connects, a wrong pin does not, and a pin is never silently downgraded.
func TestPinnedCertificate(t *testing.T) {
	hs, ep := tlsEcho(t)

	ep.Pin = PinFor(hs.Certificate())
	conn, err := ep.DialRung(context.Background(), RungTLSDirect)
	if err != nil {
		t.Fatalf("the correct pin was rejected: %v", err)
	}
	conn.Close()

	ep.Pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if conn, err := ep.DialRung(context.Background(), RungTLSDirect); err == nil {
		conn.Close()
		t.Error("a wrong pin was accepted")
	}
}
