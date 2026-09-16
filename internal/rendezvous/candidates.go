package rendezvous

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	xcrypto "github.com/4ntyr/heimdall/internal/crypto"
)

// Candidate kinds.
const (
	KindHost      = "host"      // an address observed locally on this machine
	KindReflexive = "reflexive" // the address the relay observed for us
)

// Candidate limits (docs/rendezvous.md §3.3). A peer's candidate list is
// attacker-controlled input even after it decrypts, because the peer offering
// it may be hostile. These caps stop Heimdall being used as a packet source
// against a third party.
const (
	// MaxCandidates bounds a peer's whole candidate list.
	MaxCandidates = 8
	// MaxPrivateCandidates bounds private-range candidates specifically: a
	// legitimate peer needs at most an IPv4 LAN address and a ULA.
	MaxPrivateCandidates = 2
	// MaxSealedCandidates bounds the sealed blob on the wire.
	MaxSealedCandidates = 4 << 10
)

// ErrNoCandidates indicates a candidate list that was empty after validation.
var ErrNoCandidates = errors.New("rendezvous: no usable candidates")

// Candidate is one address a peer believes it may be reachable at.
type Candidate struct {
	Addr string `json:"addr"`
	Kind string `json:"kind"`
}

// CandidateSet is the sealed payload exchanged through the relay.
type CandidateSet struct {
	Candidates []Candidate `json:"candidates"`
}

// SealCandidates encrypts a candidate list under the pairing key. The relay
// forwards the result as an opaque blob and learns no endpoints beyond the TCP
// source addresses it observes anyway.
func SealCandidates(pairingKey []byte, set CandidateSet) ([]byte, error) {
	plain, err := json.Marshal(set)
	if err != nil {
		return nil, err
	}
	blob, err := xcrypto.Seal(pairingKey, candidateAAD(), plain)
	xcrypto.Zeroise(plain)
	if err != nil {
		return nil, err
	}
	if len(blob) > MaxSealedCandidates {
		return nil, fmt.Errorf("rendezvous: candidate list too large (%d bytes)", len(blob))
	}
	return blob, nil
}

// OpenCandidates decrypts and validates a peer's candidate list. Validation is
// not optional: the caller receives only addresses that are safe to send a TCP
// SYN to.
func OpenCandidates(pairingKey, blob []byte) (CandidateSet, error) {
	if len(blob) > MaxSealedCandidates {
		return CandidateSet{}, fmt.Errorf("rendezvous: sealed candidates too large (%d bytes)", len(blob))
	}
	plain, err := xcrypto.Open(pairingKey, candidateAAD(), blob)
	if err != nil {
		// A failure here means the peer did not hold the invite code: either
		// a wrong code, or something impersonating the peer at the relay.
		return CandidateSet{}, fmt.Errorf("rendezvous: candidate list did not authenticate: %w", err)
	}
	var set CandidateSet
	err = json.Unmarshal(plain, &set)
	xcrypto.Zeroise(plain)
	if err != nil {
		return CandidateSet{}, fmt.Errorf("rendezvous: bad candidate list: %w", err)
	}
	set.Candidates = ValidateCandidates(set.Candidates)
	return set, nil
}

// ValidateCandidates filters a peer-supplied list down to addresses it is safe
// to dial, and caps its size. It never returns an error: a hostile list simply
// yields fewer (or no) candidates, and the relay path is unaffected.
func ValidateCandidates(in []Candidate) []Candidate {
	out := make([]Candidate, 0, MaxCandidates)
	private := 0
	seen := make(map[string]struct{}, len(in))
	for _, c := range in {
		if len(out) >= MaxCandidates {
			break
		}
		host, port, err := net.SplitHostPort(c.Addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || !usableIP(ip) {
			continue
		}
		if port == "" || port == "0" {
			continue
		}
		if _, dup := seen[c.Addr]; dup {
			continue
		}
		if ip.IsPrivate() {
			if private >= MaxPrivateCandidates {
				continue
			}
			private++
		}
		seen[c.Addr] = struct{}{}
		out = append(out, Candidate{Addr: c.Addr, Kind: c.Kind})
	}
	return out
}

// usableIP rejects every address class that is either meaningless to dial or
// useful only for pointing Heimdall at something that is not the peer.
func usableIP(ip net.IP) bool {
	switch {
	case ip.IsUnspecified(),
		ip.IsLoopback(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast():
		return false
	}
	// The IPv4 broadcast address is not covered by the predicates above.
	if ip4 := ip.To4(); ip4 != nil && ip4.Equal(net.IPv4bcast) {
		return false
	}
	return true
}

// LocalCandidates enumerates this machine's own usable addresses at the given
// port. These let two peers on the same LAN — or with working global IPv6 —
// connect directly and never touch the relay at all.
func LocalCandidates(port int) []Candidate {
	if port <= 0 {
		return nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]Candidate, 0, MaxCandidates)
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || !usableIP(ipnet.IP) {
			continue
		}
		out = append(out, Candidate{
			Addr: net.JoinHostPort(ipnet.IP.String(), itoa(port)),
			Kind: KindHost,
		})
	}
	return ValidateCandidates(out)
}

// candidateAAD binds sealed candidate lists to their purpose, so a blob from
// one context can never be replayed as another.
func candidateAAD() []byte { return []byte("heimdall v1 candidates") }

// itoa renders a small non-negative int without importing strconv for one use.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
