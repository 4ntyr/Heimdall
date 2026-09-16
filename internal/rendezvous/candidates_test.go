package rendezvous

import (
	"testing"
)

func testKey() []byte {
	k := make([]byte, PairingKeySize)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

func TestCandidateSealRoundTrip(t *testing.T) {
	key := testKey()
	in := CandidateSet{Candidates: []Candidate{
		{Addr: "203.0.113.5:7331", Kind: KindHost},
		{Addr: "198.51.100.9:44321", Kind: KindReflexive},
	}}

	blob, err := SealCandidates(key, in)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	out, err := OpenCandidates(key, blob)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if len(out.Candidates) != 2 {
		t.Fatalf("got %d candidates back, want 2", len(out.Candidates))
	}
	if out.Candidates[0].Addr != in.Candidates[0].Addr {
		t.Errorf("first candidate came back as %q", out.Candidates[0].Addr)
	}
}

// TestCandidateSealRejectsTampering is what stops the relay — which handles
// the blob — from rewriting where a peer says it can be reached.
func TestCandidateSealRejectsTampering(t *testing.T) {
	key := testKey()
	blob, err := SealCandidates(key, CandidateSet{
		Candidates: []Candidate{{Addr: "203.0.113.5:7331", Kind: KindHost}},
	})
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := OpenCandidates(key, tampered); err == nil {
		t.Error("a tampered candidate blob was accepted")
	}

	wrongKey := testKey()
	wrongKey[0] ^= 0xFF
	if _, err := OpenCandidates(wrongKey, blob); err == nil {
		t.Error("a candidate blob opened under the wrong pairing key")
	}
}

// TestValidateCandidatesFiltersHostile covers the addresses a malicious peer
// would offer to make us send traffic somewhere that is not the peer.
func TestValidateCandidatesFiltersHostile(t *testing.T) {
	got := ValidateCandidates([]Candidate{
		{Addr: "127.0.0.1:7331"},       // loopback
		{Addr: "[::1]:7331"},           // loopback v6
		{Addr: "169.254.1.1:7331"},     // link-local
		{Addr: "[fe80::1]:7331"},       // link-local v6
		{Addr: "224.0.0.1:7331"},       // multicast
		{Addr: "255.255.255.255:7331"}, // broadcast
		{Addr: "0.0.0.0:7331"},         // unspecified
		{Addr: "203.0.113.5:0"},        // port 0
		{Addr: "not-an-address"},       // unparseable
		{Addr: "203.0.113.5:7331"},     // the one legitimate entry
	})
	if len(got) != 1 {
		t.Fatalf("expected exactly one surviving candidate, got %d: %v", len(got), got)
	}
	if got[0].Addr != "203.0.113.5:7331" {
		t.Errorf("wrong candidate survived: %q", got[0].Addr)
	}
}

func TestValidateCandidatesCapsCounts(t *testing.T) {
	var many []Candidate
	for i := 0; i < 50; i++ {
		many = append(many, Candidate{Addr: "203.0.113." + itoa(i%250+1) + ":7331"})
	}
	if got := ValidateCandidates(many); len(got) > MaxCandidates {
		t.Errorf("returned %d candidates, above the cap of %d", len(got), MaxCandidates)
	}

	var private []Candidate
	for i := 1; i < 10; i++ {
		private = append(private, Candidate{Addr: "192.168.1." + itoa(i) + ":7331"})
	}
	if got := ValidateCandidates(private); len(got) > MaxPrivateCandidates {
		t.Errorf("returned %d private candidates, above the cap of %d", len(got), MaxPrivateCandidates)
	}
}

func TestValidateCandidatesDropsDuplicates(t *testing.T) {
	got := ValidateCandidates([]Candidate{
		{Addr: "203.0.113.5:7331"},
		{Addr: "203.0.113.5:7331"},
	})
	if len(got) != 1 {
		t.Errorf("expected duplicates to be collapsed, got %d", len(got))
	}
}
