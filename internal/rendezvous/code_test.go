package rendezvous

import (
	"bytes"
	"strings"
	"testing"
)

func TestCodeRoundTrip(t *testing.T) {
	c, err := NewCode()
	if err != nil {
		t.Fatalf("generating code: %v", err)
	}
	rendered := c.String()

	parsed, err := ParseCode(rendered)
	if err != nil {
		t.Fatalf("parsing our own rendered code %q: %v", rendered, err)
	}
	if !bytes.Equal(parsed.secret, c.secret) {
		t.Error("a code did not survive rendering and parsing")
	}
}

// TestParseCodeTolerance covers the ways a user retyping a code from another
// channel gets it wrong.
func TestParseCodeTolerance(t *testing.T) {
	c, err := NewCode()
	if err != nil {
		t.Fatalf("generating code: %v", err)
	}
	canonical := c.String()
	bare := strings.ReplaceAll(canonical, "-", "")

	for _, variant := range []string{
		canonical,
		bare,
		strings.ToLower(canonical),
		"  " + canonical + "\n",
		strings.ReplaceAll(canonical, "-", " "),
	} {
		parsed, err := ParseCode(variant)
		if err != nil {
			t.Errorf("ParseCode(%q) failed: %v", variant, err)
			continue
		}
		if !bytes.Equal(parsed.secret, c.secret) {
			t.Errorf("ParseCode(%q) produced a different secret", variant)
		}
	}
}

func TestParseCodeRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "-", "not base32 at all!", "AAAA", strings.Repeat("A", 64)} {
		if _, err := ParseCode(bad); err == nil {
			t.Errorf("ParseCode(%q) was accepted", bad)
		}
	}
}

// TestDerivationIsSeparated is the property the relay's ignorance rests on:
// the value the relay is told must not reveal the value it is not told.
func TestDerivationIsSeparated(t *testing.T) {
	c, err := NewCode()
	if err != nil {
		t.Fatalf("generating code: %v", err)
	}
	id, err := c.ID()
	if err != nil {
		t.Fatalf("deriving id: %v", err)
	}
	key, err := c.PairingKey()
	if err != nil {
		t.Fatalf("deriving pairing key: %v", err)
	}

	if len(id) != rendezvousIDSize {
		t.Errorf("rendezvous id is %d bytes, want %d", len(id), rendezvousIDSize)
	}
	if len(key) != PairingKeySize {
		t.Errorf("pairing key is %d bytes, want %d", len(key), PairingKeySize)
	}
	if bytes.HasPrefix(key, id) || bytes.Contains(key, id) {
		t.Error("the pairing key contains the rendezvous id the relay is given")
	}

	// Derivation must be deterministic, or two peers with the same code would
	// never meet.
	again, _ := c.ID()
	if !bytes.Equal(id, again) {
		t.Error("deriving the rendezvous id twice gave different answers")
	}
}

// TestDistinctCodesDiverge guards against a code generator that repeats.
func TestDistinctCodesDiverge(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		c, err := NewCode()
		if err != nil {
			t.Fatalf("generating code: %v", err)
		}
		id, err := c.ID()
		if err != nil {
			t.Fatalf("deriving id: %v", err)
		}
		key := string(id)
		if seen[key] {
			t.Fatal("two generated codes produced the same rendezvous id")
		}
		seen[key] = true
	}
}
