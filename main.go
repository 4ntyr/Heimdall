// Command hmdl is the entry point of Heimdall (production name HMDL), a
// terminal-only, peer-to-peer, end-to-end encrypted messenger. This file
// only wires the internal packages together; all logic lives in internal/.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/4ntyr/heimdall/internal/connect"
	"github.com/4ntyr/heimdall/internal/identity"
	"github.com/4ntyr/heimdall/internal/peers"
	"github.com/4ntyr/heimdall/internal/rendezvous"
	"github.com/4ntyr/heimdall/internal/session"
	"github.com/4ntyr/heimdall/internal/transport"
)

const usageText = `hmdl — terminal-only, peer-to-peer, end-to-end encrypted messenger

Usage:
  hmdl [flags]

Flags:
  -name         your display name (required on first run; afterwards read from
                the identity file)
  -listen       address to listen on for incoming peers (default ":7331";
                pass "" to disable — a relay needs no inbound port at all)
  -connect      address of a peer to connect to on startup
  -data         directory for the identity and trust store
                (default "~/.heimdall")
  -relay        rendezvous relay to use, e.g. relay.example.com or
                https://example.com/hmdl. Enables /invite and /join, which
                work from behind any NAT or firewall without port forwarding.
  -relay-pin    certificate pin for a self-signed relay (printed by hmdl-relay)
  -relay-verify require a valid relay certificate (see below)
  -proxy        HTTP proxy for reaching the relay; defaults to HTTPS_PROXY

Interactive commands:
  /invite             publish an invite code for a peer to join with
  /join <code>        connect to the peer who published an invite code
  /connect <addr>     connect directly to a peer at a known address
  /msg <name> <text>  send a message to one peer
  /all <text>         broadcast a message to all connected peers
  /peers              list connected peers, their trust level and path
  /verify <name>      mark a peer's fingerprint as verified
  /help               show this help
  /quit               exit

Relay privacy: the relay forwards encrypted frames only. It never sees your
messages, your name or your identity key, and it cannot impersonate a peer —
an invite code is verified end-to-end. Relay certificates are not a security
boundary, so an intercepting corporate proxy cannot block you; use
-relay-verify if you would rather fail than tolerate interception.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hmdl:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("hmdl", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	name := fs.String("name", "", "display name (required on first run)")
	listen := fs.String("listen", ":7331", "address to listen on (\"\" to disable)")
	connectAddr := fs.String("connect", "", "peer address to connect to on startup")
	data := fs.String("data", defaultDataDir(), "data directory")
	relayAddr := fs.String("relay", "", "rendezvous relay address")
	relayPin := fs.String("relay-pin", "", "relay certificate pin")
	relayVerify := fs.Bool("relay-verify", false, "require a valid relay certificate")
	proxy := fs.String("proxy", "", "HTTP proxy for reaching the relay")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	id, err := loadOrCreateIdentity(*data, *name)
	if err != nil {
		return err
	}
	fmt.Println("Your identity fingerprint (share this out-of-band so peers can verify you):")
	fmt.Println(" ", id.Fingerprint())

	store, err := peers.OpenStore(filepath.Join(*data, "peers.json"))
	if err != nil {
		return err
	}

	mgr := session.NewManager(id, store)
	addr, err := mgr.Listen(*listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}
	if addr != "" {
		fmt.Println("Listening for peers on", addr)
	} else {
		fmt.Println("No listener (outbound connections only)")
	}

	// The punch listener shares its local port with the relay connection, so
	// that hole punching can reuse the NAT mapping the relay connection
	// creates (docs/rendezvous.md §7). It also accepts ordinary inbound
	// connections, which is what makes a punched connection work in the
	// direction where our peer's SYN arrives first.
	punch, err := transport.NewPunchListener(0, mgr.HandleInbound)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hmdl: hole punching unavailable:", err)
	}
	if punch != nil {
		defer punch.Close()
	}

	var rz *rendezvous.Client
	if *relayAddr != "" {
		ep, err := rendezvous.ParseEndpoint(*relayAddr)
		if err != nil {
			return err
		}
		ep.Pin, ep.Verify, ep.Proxy = *relayPin, *relayVerify, *proxy
		if punch != nil {
			ep.Dialer = transport.ReuseDialer(punch.Port(), rendezvous.RungTimeout)
		}
		rz = rendezvous.NewClient(ep)
		defer rz.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = rz.Wait(ctx)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "hmdl: relay %s unreachable: %v\n", ep.Host, err)
			fmt.Fprintln(os.Stderr, "      /invite and /join will retry in the background.")
		} else {
			fmt.Printf("Relay %s reachable over %s; /invite and /join are available\n", ep.Host, rz.Rung())
		}
	}

	expectations := connect.NewExpectations()
	mgr.SetInboundHook(expectations.Hook)

	cfg := connect.Config{
		Manager:    mgr,
		Client:     rz,
		Punch:      punch,
		ListenPort: portOf(addr),
		Expect:     expectations,
	}

	if *connectAddr != "" {
		if err := mgr.Connect(*connectAddr); err != nil {
			fmt.Fprintf(os.Stderr, "hmdl: connect to %s: %v\n", *connectAddr, err)
		}
	}

	// Print session events (incoming messages, connect/disconnect,
	// security warnings) in the background.
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case ev := <-mgr.Events():
				printEvent(ev)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nShutting down…")
		close(done)
		mgr.Shutdown()
		os.Exit(0)
	}()

	repl(mgr, store, cfg)
	close(done)
	mgr.Shutdown()
	return nil
}

// portOf extracts the numeric port from a listener address, or 0 when there
// is no listener.
func portOf(addr string) int {
	if addr == "" {
		return 0
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}

// defaultDataDir returns ~/.heimdall, falling back to the current
// directory if the home directory cannot be determined.
func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".heimdall"
	}
	return filepath.Join(home, ".heimdall")
}

// loadOrCreateIdentity loads the identity file if it exists, otherwise
// generates a new identity and saves it encrypted with a passphrase the
// user is prompted for. The passphrase is read from the HMDL_PASSPHRASE
// environment variable if set, otherwise interactively from the terminal.
func loadOrCreateIdentity(dataDir, name string) (*identity.Identity, error) {
	path := filepath.Join(dataDir, "identity.hmdl")

	if _, err := os.Stat(path); err == nil {
		pass, err := readPassphrase("Identity passphrase: ")
		if err != nil {
			return nil, err
		}
		id, err := identity.Load(path, pass)
		if err != nil {
			return nil, err
		}
		fmt.Println("Welcome back,", id.Name)
		return id, nil
	}

	if strings.TrimSpace(name) == "" {
		return nil, errors.New("no identity found; run again with -name <your-name> to create one")
	}
	id, err := identity.Generate(name)
	if err != nil {
		return nil, err
	}
	pass, err := readPassphrase("Choose a passphrase to protect your identity file: ")
	if err != nil {
		return nil, err
	}
	if err := id.Save(path, pass); err != nil {
		return nil, err
	}
	fmt.Println("Created new identity for", name, "stored in", path)
	return id, nil
}

// readPassphrase reads a passphrase from the HMDL_PASSPHRASE environment
// variable, or prompts on the terminal. Interactive entry is only used so
// the CLI stays standard-library only.
func readPassphrase(prompt string) (string, error) {
	if p := os.Getenv("HMDL_PASSPHRASE"); p != "" {
		return p, nil
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func printEvent(ev session.Event) {
	switch ev.Type {
	case session.EventPeerConnected:
		fmt.Printf("\n*** %s connected [%s, %s]\n> ", ev.Peer, ev.Trust, ev.Path)
	case session.EventPeerDisconnected:
		fmt.Printf("\n*** %s disconnected\n> ", ev.Peer)
	case session.EventMessage:
		fmt.Printf("\n%s: %s\n> ", ev.Peer, ev.Text)
	case session.EventSecurityWarning:
		fmt.Printf("\n!!! SECURITY WARNING !!!\n%s\n> ", ev.Text)
	case session.EventError:
		fmt.Printf("\n*** error: %s\n> ", ev.Text)
	}
}

// repl is the interactive read-eval-print loop over stdin.
func repl(mgr *session.Manager, store *peers.Store, cfg connect.Config) {
	sc := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			fmt.Print("> ")
			continue
		}
		if !strings.HasPrefix(line, "/") {
			// Bare text broadcasts to every connected peer.
			if n := mgr.Broadcast(line); n == 0 {
				fmt.Println("(no connected peers — use /connect <addr>)")
			}
			fmt.Print("> ")
			continue
		}
		if handleCommand(mgr, store, cfg, line) {
			return // /quit
		}
		fmt.Print("> ")
	}
}

// handleCommand executes one slash command. It returns true when the user
// asked to quit.
func handleCommand(mgr *session.Manager, store *peers.Store, cfg connect.Config, line string) bool {
	fields := strings.Fields(line)
	cmd := strings.TrimPrefix(fields[0], "/")

	switch cmd {
	case "quit", "exit":
		return true

	case "help":
		fmt.Print(usageText)

	case "invite":
		if cfg.Client == nil {
			fmt.Println("no relay configured — start hmdl with -relay <host> to use invite codes")
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		code, wait, err := connect.Invite(ctx, cfg)
		cancel()
		if err != nil {
			fmt.Println("could not publish an invite:", err)
			break
		}
		fmt.Println("Give this code to your peer; it is valid for five minutes:")
		fmt.Println()
		fmt.Println("   ", code)
		fmt.Println()
		fmt.Println("Send it over a channel you trust — anyone who has it can answer it.")
		go func() {
			if err := wait(context.Background()); err != nil {
				fmt.Printf("\n*** invite failed: %v\n> ", err)
			}
		}()

	case "join":
		if cfg.Client == nil {
			fmt.Println("no relay configured — start hmdl with -relay <host> to use invite codes")
			break
		}
		if len(fields) < 2 {
			fmt.Println("usage: /join <code>")
			break
		}
		fmt.Println("Connecting…")
		go func(code string) {
			if err := connect.Join(context.Background(), cfg, code); err != nil {
				fmt.Printf("\n*** join failed: %v\n> ", err)
			}
		}(strings.Join(fields[1:], ""))

	case "connect":
		if len(fields) < 2 {
			fmt.Println("usage: /connect <addr>")
			break
		}
		if err := mgr.Connect(fields[1]); err != nil {
			fmt.Println("connect failed:", err)
		}

	case "msg":
		if len(fields) < 3 {
			fmt.Println("usage: /msg <name> <text>")
			break
		}
		if err := mgr.Send(fields[1], strings.Join(fields[2:], " ")); err != nil {
			fmt.Println("send failed:", err)
		}

	case "all":
		if len(fields) < 2 {
			fmt.Println("usage: /all <text>")
			break
		}
		if n := mgr.Broadcast(strings.Join(fields[1:], " ")); n == 0 {
			fmt.Println("(no connected peers)")
		}

	case "peers":
		list := mgr.Peers()
		if len(list) == 0 {
			fmt.Println("(no connected peers)")
			break
		}
		for _, p := range list {
			fmt.Printf("%-20s %-22s %-8s %s\n  %s\n", p.Name, p.Address, p.Path, p.Trust, p.Fingerprint)
		}

	case "verify":
		if len(fields) < 2 {
			fmt.Println("usage: /verify <name>")
			break
		}
		p, err := store.Verify(fields[1])
		if err != nil {
			fmt.Println("verify failed:", err)
			break
		}
		fmt.Println("verified", p.Name)

	default:
		fmt.Println("unknown command; try /help")
	}
	return false
}
