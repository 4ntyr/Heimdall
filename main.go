// Command hmdl is the entry point of Heimdall (production name HMDL), a
// terminal-only, peer-to-peer, end-to-end encrypted messenger. This file
// only wires the internal packages together; all logic lives in internal/.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/4ntyr/heimdall_cli/internal/identity"
	"github.com/4ntyr/heimdall_cli/internal/peers"
	"github.com/4ntyr/heimdall_cli/internal/session"
)

const usageText = `hmdl — terminal-only, peer-to-peer, end-to-end encrypted messenger

Usage:
  hmdl [flags]

Flags:
  -name     your display name (required on first run; afterwards read from
            the identity file)
  -listen   address to listen on for incoming peers (default ":7331")
  -connect  address of a peer to connect to on startup, e.g. 192.168.1.5:7331
  -data     directory for the identity and trust store
            (default "~/.heimdall")

Interactive commands:
  /connect <addr>     connect to a peer
  /msg <name> <text>  send a message to one peer
  /all <text>         broadcast a message to all connected peers
  /peers              list connected peers and their trust level
  /verify <name>      mark a peer's fingerprint as verified
  /help               show this help
  /quit               exit
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
	listen := fs.String("listen", ":7331", "address to listen on")
	connect := fs.String("connect", "", "peer address to connect to on startup")
	data := fs.String("data", defaultDataDir(), "data directory")
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
	fmt.Println("Listening for peers on", addr)

	if *connect != "" {
		if err := mgr.Connect(*connect); err != nil {
			fmt.Fprintf(os.Stderr, "hmdl: connect to %s: %v\n", *connect, err)
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

	repl(mgr, store)
	close(done)
	mgr.Shutdown()
	return nil
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
		fmt.Printf("\n*** %s connected [%s]\n> ", ev.Peer, ev.Trust)
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
func repl(mgr *session.Manager, store *peers.Store) {
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
		if handleCommand(mgr, store, line) {
			return // /quit
		}
		fmt.Print("> ")
	}
}

// handleCommand executes one slash command. It returns true when the user
// asked to quit.
func handleCommand(mgr *session.Manager, store *peers.Store, line string) bool {
	fields := strings.Fields(line)
	cmd := strings.TrimPrefix(fields[0], "/")

	switch cmd {
	case "quit", "exit":
		return true

	case "help":
		fmt.Print(usageText)

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
			fmt.Printf("%-20s %-18s %s\n  %s\n", p.Name, p.Address, p.Trust, p.Fingerprint)
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
