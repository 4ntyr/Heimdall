// Package rendezvous implements the client side of the Heimdall rendezvous
// and relay protocol (docs/rendezvous.md): invite codes, the control
// connection to a relay, sealed candidate exchange, and the connection ladder
// that gets that control connection through restrictive networks.
//
// The package moves opaque bytes and coordination metadata only. It never
// sees message plaintext, and it holds no long-term identity material: the
// end-to-end cryptography of internal/proto runs unchanged on top of whatever
// path this package establishes.
package rendezvous

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	xcrypto "github.com/4ntyr/heimdall/internal/crypto"
)

// Invite code parameters (docs/rendezvous.md §2).
const (
	// codeEntropyBytes is the size of the random secret behind an invite
	// code. 160 bits is far beyond what a 5-minute, single-claim code needs,
	// and keeps the rendered code a convenient 32 characters.
	codeEntropyBytes = 20
	// rendezvousIDSize is the length of the identifier the relay pairs on.
	rendezvousIDSize = 16
	// PairingKeySize is the length of the key that never reaches the relay.
	PairingKeySize = 32

	// groupSize is the transcription grouping of a rendered code.
	groupSize = 4

	infoRendezvousID = "heimdall v1 rendezvous id"
	infoPairingKey   = "heimdall v1 pairing key"
)

// ErrBadCode indicates an invite code that is malformed or the wrong length.
var ErrBadCode = errors.New("rendezvous: malformed invite code")

// codeEncoding is unpadded RFC 4648 base32: case-insensitive on input and
// free of the visually ambiguous characters that plague base64 when a code is
// read aloud or copied by hand.
var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Code is the secret behind an invite. It is the only thing the two peers
// share before they have ever authenticated each other, and it is never sent
// to the relay in any form (only the derived rendezvous ID is).
type Code struct {
	secret []byte
}

// NewCode generates a fresh invite code from the OS CSPRNG.
func NewCode() (*Code, error) {
	secret, err := xcrypto.RandomBytes(codeEntropyBytes)
	if err != nil {
		return nil, err
	}
	return &Code{secret: secret}, nil
}

// ParseCode decodes a code as rendered by String, tolerating lower case,
// surrounding whitespace, and any grouping of dashes or spaces — all of which
// a user retyping a code from another channel is likely to get wrong.
func ParseCode(s string) (*Code, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
	cleaned = strings.ToUpper(cleaned)
	if cleaned == "" {
		return nil, ErrBadCode
	}
	secret, err := codeEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCode, err)
	}
	if len(secret) != codeEntropyBytes {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrBadCode, codeEntropyBytes, len(secret))
	}
	return &Code{secret: secret}, nil
}

// String renders the code for the user to send out-of-band, grouped in fours
// so it can be read aloud or retyped without losing the place.
func (c *Code) String() string {
	raw := codeEncoding.EncodeToString(c.secret)
	var b strings.Builder
	for i, r := range raw {
		if i > 0 && i%groupSize == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ID derives the rendezvous identifier. This value IS sent to the relay; it is
// a random-looking label that reveals nothing about either peer and cannot be
// linked to an identity.
func (c *Code) ID() ([]byte, error) {
	return xcrypto.DeriveKey(c.secret, nil, infoRendezvousID, rendezvousIDSize)
}

// PairingKey derives the key that authenticates first contact. It is NEVER
// sent to the relay: it seals the candidate exchange and keys the pairing
// confirmation of docs/rendezvous.md §4, which is what stops a hostile relay
// impersonating a peer the user has not met before.
func (c *Code) PairingKey() ([]byte, error) {
	return xcrypto.DeriveKey(c.secret, nil, infoPairingKey, PairingKeySize)
}

// Zeroise destroys the code's secret. Call it once the rendezvous has
// completed; the derived pairing key outlives it only as long as the session
// setup needs.
func (c *Code) Zeroise() {
	xcrypto.Zeroise(c.secret)
}
