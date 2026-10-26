package proto

import "fmt"

// EncodeChatPayload builds the inner payload of a chat frame.
//
// It validates the *encoded* length rather than len(text), because the payload
// carries a 2-byte length prefix and it is the payload that Session.Seal
// bounds. That keeps the limit a user actually meets (text up to
// MaxPlaintext-2) identical whether a caller seals immediately or hands the
// payload to a writer that seals later. The check also guards the uint16
// length prefix, which would otherwise wrap silently above 65535.
func EncodeChatPayload(text string) ([]byte, error) {
	b := encodeChatPayload(text)
	if len(b) > MaxPlaintext {
		return nil, fmt.Errorf("proto: payload too large (%d > %d)", len(b), MaxPlaintext)
	}
	return b, nil
}

// SealChat seals a text chat message into a frame.
func (s *Session) SealChat(text string) ([]byte, error) {
	b, err := EncodeChatPayload(text)
	if err != nil {
		return nil, err
	}
	return s.Seal(TypeChat, b)
}

// DecodeChat decodes an already-opened chat plaintext into its text.
func DecodeChat(plaintext []byte) (string, error) { return decodeChatPayload(plaintext) }
