package connect

import (
	"net"
	"sync"

	"github.com/4ntyr/heimdall/internal/session"
)

// Expectations records rendezvous that are currently in flight, so that a
// connection we accept is treated exactly like one we dialled.
//
// This closes a gap that is easy to miss. Only the side that dials a peer
// holds the pairing key for a rendezvous; the side that accepts would
// otherwise fall through to the ordinary inbound path, send no pairing
// confirmation, and — because the dialling side requires one — leave the
// direct path to time out while the relay quietly won instead. Worse, the
// accepting side would have recorded that peer as known without the
// invite-code check ever running (docs/rendezvous.md §4).
//
// Expectations are keyed by source IP rather than by full address: a peer
// dialling us uses an ephemeral source port that neither side can predict.
type Expectations struct {
	mu   sync.Mutex
	byIP map[string]session.AdoptOptions
}

// NewExpectations creates an empty registry.
func NewExpectations() *Expectations {
	return &Expectations{byIP: make(map[string]session.AdoptOptions)}
}

// Hook satisfies session.Manager's inbound hook.
func (e *Expectations) Hook(conn net.Conn) (session.AdoptOptions, bool) {
	if e == nil || conn.RemoteAddr() == nil {
		return session.AdoptOptions{}, false
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return session.AdoptOptions{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	opts, ok := e.byIP[host]
	return opts, ok
}

// expect registers an expectation for every given IP and returns a function
// that withdraws it. opts should carry an OnEstablished callback so that a
// connection accepted under this expectation signals whoever is racing.
func (e *Expectations) expect(ips []string, opts session.AdoptOptions) func() {
	if e == nil || len(ips) == 0 {
		return func() {}
	}
	e.mu.Lock()
	added := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if _, exists := e.byIP[ip]; exists {
			continue
		}
		e.byIP[ip] = opts
		added = append(added, ip)
	}
	e.mu.Unlock()

	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, ip := range added {
			delete(e.byIP, ip)
		}
	}
}

// peerIPs collects every address a rendezvous peer might reach us from.
func peerIPs(observed string, candidates []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(candidates)+1)
	add := func(addr string) {
		if addr == "" {
			return
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if host == "" {
			return
		}
		if _, dup := seen[host]; dup {
			return
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	add(observed)
	for _, c := range candidates {
		add(c)
	}
	return out
}
