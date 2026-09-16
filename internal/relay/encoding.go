package relay

import (
	"encoding/base64"
	"fmt"
)

// decodeExact decodes a base64 field and requires an exact decoded length.
// Every binary field the relay accepts has a fixed size, so anything else is
// malformed and is rejected before it reaches a map.
func decodeExact(s string, want int) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("relay: bad base64 field: %w", err)
	}
	if len(b) != want {
		return nil, fmt.Errorf("relay: field is %d bytes, want %d", len(b), want)
	}
	return b, nil
}

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
