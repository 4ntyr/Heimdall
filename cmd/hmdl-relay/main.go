// Command hmdl-relay is the Heimdall rendezvous and relay server
// (docs/rendezvous.md).
//
// It introduces two peers who each connect outbound, tells each where the
// other appears to be, and forwards opaque encrypted bytes between them when a
// direct path cannot be established. It never sees plaintext and never learns
// who is talking to whom: see docs/rendezvous.md §9.
//
// Run it on a host with a public address, on port 443, ideally behind a
// hostname you already serve — that is what makes it reachable from
// restrictive networks.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/4ntyr/heimdall/internal/relay"
	"github.com/4ntyr/heimdall/internal/rendezvous"
)

const usageText = `hmdl-relay — Heimdall rendezvous and relay server

Usage:
  hmdl-relay [flags]

The relay lets two peers behind NATs or firewalls reach each other without
port forwarding. It forwards opaque encrypted frames only: it cannot read
messages, learn either peer's identity, or impersonate either peer.

Flags:
  -addr    TLS listen address (default ":443")
  -http    cleartext HTTP listen address for restricted networks
           (default ":80"; set to "" to disable)
  -path    URL path the relay is mounted at (default "/hmdl")
  -cert    TLS certificate file (PEM); omit to generate a self-signed one
  -key     TLS private key file (PEM)
  -quiet   suppress connection logging

Clients connect with:
  hmdl -relay <host>            (valid certificate)
  hmdl -relay <host> -relay-pin <pin>   (self-signed; pin is printed at startup)
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hmdl-relay:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("hmdl-relay", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	addr := fs.String("addr", ":443", "TLS listen address")
	httpAddr := fs.String("http", ":80", "cleartext HTTP listen address")
	path := fs.String("path", rendezvous.DefaultPath, "URL path to mount at")
	certFile := fs.String("cert", "", "TLS certificate file (PEM)")
	keyFile := fs.String("key", "", "TLS key file (PEM)")
	quiet := fs.Bool("quiet", false, "suppress connection logging")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	logf := log.Printf
	if *quiet {
		logf = func(string, ...any) {}
	}

	srv := relay.New(relay.DefaultLimits(), logf)
	defer srv.Close()

	mux := http.NewServeMux()
	mux.Handle(*path, srv.Handler())
	// Everything else answers like an unremarkable web server, so the
	// endpoint does not advertise what it is to a casual scan.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	tlsConfig, pin, err := loadTLS(*certFile, *keyFile)
	if err != nil {
		return err
	}

	errs := make(chan error, 2)

	if *addr != "" {
		ln, err := net.Listen("tcp", *addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", *addr, err)
		}
		server := &http.Server{
			Handler: mux,
			// No read/write timeouts: relayed circuits are long-lived by
			// design. Idle and lifetime limits are enforced per circuit
			// inside internal/relay instead.
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 15 * time.Second,
		}
		fmt.Printf("Relay listening on %s%s (TLS)\n", *addr, *path)
		if pin != "" {
			fmt.Println("Self-signed certificate. Clients must pass:")
			fmt.Printf("  -relay-pin %s\n", pin)
		}
		go func() { errs <- server.ServeTLS(ln, "", "") }()
	}

	if *httpAddr != "" {
		ln, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", *httpAddr, err)
		}
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 15 * time.Second}
		fmt.Printf("Relay listening on %s%s (cleartext fallback)\n", *httpAddr, *path)
		go func() { errs <- server.Serve(ln) }()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errs:
		return err
	case <-sig:
		pending, circuits := srv.Stats()
		fmt.Printf("\nShutting down (%d pending codes, %d open circuits)\n", pending, circuits)
		return nil
	}
}

// loadTLS builds the server TLS configuration, generating a self-signed
// certificate when none is supplied.
//
// A self-signed certificate is a legitimate way to run a relay: the relay is
// an untrusted byte pipe and its TLS is not a security boundary
// (docs/rendezvous.md §1.3). Clients either pin it or accept it unverified;
// either way the end-to-end guarantees are unchanged.
func loadTLS(certFile, keyFile string) (*tls.Config, string, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, "", fmt.Errorf("-cert and -key must be given together")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("loading certificate: %w", err)
		}
		return baseTLSConfig(cert), "", nil
	}

	cert, pin, err := selfSignedCert()
	if err != nil {
		return nil, "", err
	}
	return baseTLSConfig(cert), pin, nil
}

func baseTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}

// selfSignedCert generates an in-memory certificate and returns its pin.
func selfSignedCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "hmdl-relay"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        parsed,
	}, rendezvous.PinFor(parsed), nil
}
