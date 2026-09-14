// Package proto implements the Heimdall cryptographic wire protocol
// specified in docs/protocol.md:
//
//   - authenticated handshake (ephemeral X25519 + Ed25519-signed transcript)
//   - session establishment with HKDF key separation
//   - per-message symmetric ratchet and epoch key rotation
//   - sliding-window replay protection
//   - AEAD framing where the header is authenticated additional data
//
// The package knows nothing about sockets or the terminal; it consumes and
// produces opaque byte slices that a transport moves between peers.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ProtocolVersion is the only supported wire version.
const ProtocolVersion = 1

// Frame types (docs/protocol.md §7). All types participate in the same
// ratchet and replay window so control traffic cannot be injected/replayed.
const (
	TypeChat  byte = 1
	TypePing  byte = 2
	TypePong  byte = 3
	TypeClose byte = 4
)

const (
	// headerSize = version(1) + type(1) + sessionID(8) + sequence(8) + rotation(4)
	headerSize = 22
	// MaxPlaintext bounds the inner payload of a chat frame.
	MaxPlaintext = 4096
	// maxFrame bounds a whole serialized frame (header + AEAD blob).
	maxFrame = headerSize + MaxPlaintext + 64
)

var (
	// ErrMalformed indicates a frame that fails structural parsing.
	ErrMalformed = errors.New("proto: malformed frame")
	// ErrAuth indicates AEAD authentication failure (tampering/wrong key).
	ErrAuth = errors.New("proto: frame authentication failed")
	// ErrReplay indicates a duplicate or too-old sequence number.
	ErrReplay = errors.New("proto: replayed or out-of-window frame")
	// ErrBadSession indicates a frame for a different session.
	ErrBadSession = errors.New("proto: frame for wrong session")
	// ErrBadEpoch indicates a frame from an unsupported rotation epoch.
	ErrBadEpoch = errors.New("proto: unsupported rotation epoch")
)

// frame is the parsed view of a session frame. Header fields are NOT trusted
// until Open has verified the AEAD tag over them.
type frame struct {
	typ      byte
	session  uint64
	sequence uint64
	rotation uint32
	blob     []byte // nonce || ciphertext || tag
}

// marshalFrame serializes header || blob. The header is the AAD.
func marshalFrame(f *frame) []byte {
	out := make([]byte, headerSize, headerSize+len(f.blob))
	out[0] = ProtocolVersion
	out[1] = f.typ
	binary.BigEndian.PutUint64(out[2:10], f.session)
	binary.BigEndian.PutUint64(out[10:18], f.sequence)
	binary.BigEndian.PutUint32(out[18:22], f.rotation)
	return append(out, f.blob...)
}

// parseFrame performs structural validation only. It does not authenticate
// anything; callers must Open before trusting any field.
func parseFrame(buf []byte) (*frame, error) {
	if len(buf) < headerSize {
		return nil, fmt.Errorf("%w: too short", ErrMalformed)
	}
	if len(buf) > maxFrame {
		return nil, fmt.Errorf("%w: too large", ErrMalformed)
	}
	if buf[0] != ProtocolVersion {
		return nil, fmt.Errorf("%w: bad version %d", ErrMalformed, buf[0])
	}
	switch buf[1] {
	case TypeChat, TypePing, TypePong, TypeClose:
	default:
		return nil, fmt.Errorf("%w: bad type %d", ErrMalformed, buf[1])
	}
	return &frame{
		typ:      buf[1],
		session:  binary.BigEndian.Uint64(buf[2:10]),
		sequence: binary.BigEndian.Uint64(buf[10:18]),
		rotation: binary.BigEndian.Uint32(buf[18:22]),
		blob:     buf[headerSize:],
	}, nil
}

// encodeChatPayload serializes a chat payload. Kept minimal and explicit.
func encodeChatPayload(text string) []byte {
	b := make([]byte, 2, 2+len(text))
	binary.BigEndian.PutUint16(b, uint16(len(text)))
	return append(b, text...)
}

func decodeChatPayload(b []byte) (string, error) {
	if len(b) < 2 {
		return "", fmt.Errorf("%w: chat payload too short", ErrMalformed)
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b)-2 < n {
		return "", fmt.Errorf("%w: chat payload truncated", ErrMalformed)
	}
	return string(b[2 : 2+n]), nil
}
