package proto

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// File transfer payload codecs (docs/protocol.md §13.1).
//
// Each Seal helper mirrors SealChat: it encodes a payload and hands it to
// Session.Seal, so a transfer is sequenced, replay-protected and rotated
// exactly as chat is. The decoders are the inverse, operating on plaintext a
// caller has already opened.

const (
	// Fixed field sizes, big-endian throughout.
	transferIDSize = 8
	// fileChunkHeader = transfer id(8) + offset(8). MaxFileChunk is derived
	// from it in frame.go.
	fileChunkHeader = transferIDSize + 8
	// MaxFileNameLen bounds a peer-supplied name. It is a label, never a
	// path; sanitising it is the receiver's job (docs/protocol.md §13.5).
	MaxFileNameLen = 255
	// fileDigestSize is the SHA-256 carried by TypeFileDone.
	fileDigestSize = 32
)

// Cancel reasons. Advisory and for display only: a peer's stated reason is
// never a basis for a decision (docs/protocol.md §13.6).
const (
	CancelUnspecified    byte = 0
	CancelRefused        byte = 1  // policy: transfers disabled, or peer untrusted
	CancelBadName        byte = 2  // the name did not survive sanitisation
	CancelTooLarge       byte = 3  // over the receiver's size cap
	CancelTooMany        byte = 4  // concurrency limit reached
	CancelProtocol       byte = 5  // malformed payload or an offset violation
	CancelDigestMismatch byte = 6  // contents did not match TypeFileDone
	CancelLocalError     byte = 7  // local I/O failure
	CancelStalled        byte = 8  // no progress within the inactivity window
	CancelUserRequest    byte = 9  // a user cancelled it
	CancelRelayBudget    byte = 10 // would exceed the relay's circuit budget
)

// FileOffer announces a file a peer may receive.
type FileOffer struct {
	ID   uint64
	Size uint64
	Name string
}

// SealFileOffer seals an offer to send a file.
func (s *Session) SealFileOffer(o FileOffer) ([]byte, error) {
	if len(o.Name) == 0 || len(o.Name) > MaxFileNameLen {
		return nil, fmt.Errorf("proto: file name length %d out of range", len(o.Name))
	}
	if !utf8.ValidString(o.Name) {
		return nil, fmt.Errorf("proto: file name is not valid UTF-8")
	}
	b := make([]byte, 0, transferIDSize+8+2+len(o.Name))
	b = binary.BigEndian.AppendUint64(b, o.ID)
	b = binary.BigEndian.AppendUint64(b, o.Size)
	b = binary.BigEndian.AppendUint16(b, uint16(len(o.Name)))
	b = append(b, o.Name...)
	return s.Seal(TypeFileOffer, b)
}

// DecodeFileOffer decodes an opened TypeFileOffer plaintext.
func DecodeFileOffer(pt []byte) (FileOffer, error) {
	const fixed = transferIDSize + 8 + 2
	if len(pt) < fixed {
		return FileOffer{}, fmt.Errorf("%w: file offer too short", ErrMalformed)
	}
	n := int(binary.BigEndian.Uint16(pt[16:18]))
	if n == 0 || n > MaxFileNameLen {
		return FileOffer{}, fmt.Errorf("%w: file name length %d out of range", ErrMalformed, n)
	}
	if len(pt)-fixed < n {
		return FileOffer{}, fmt.Errorf("%w: file offer name truncated", ErrMalformed)
	}
	name := string(pt[fixed : fixed+n])
	if !utf8.ValidString(name) {
		return FileOffer{}, fmt.Errorf("%w: file name is not valid UTF-8", ErrMalformed)
	}
	return FileOffer{
		ID:   binary.BigEndian.Uint64(pt[0:8]),
		Size: binary.BigEndian.Uint64(pt[8:16]),
		Name: name,
	}, nil
}

// SealFileAccept seals agreement to receive an offered file. startOffset is
// where the receiver wants the data to begin; this version always sends 0
// (docs/protocol.md §13.2).
func (s *Session) SealFileAccept(id, startOffset uint64) ([]byte, error) {
	b := make([]byte, 0, transferIDSize+8)
	b = binary.BigEndian.AppendUint64(b, id)
	b = binary.BigEndian.AppendUint64(b, startOffset)
	return s.Seal(TypeFileAccept, b)
}

// DecodeFileAccept decodes an opened TypeFileAccept plaintext, returning the
// transfer id and the offset the receiver asked to start at.
func DecodeFileAccept(pt []byte) (id, startOffset uint64, err error) {
	if len(pt) < transferIDSize+8 {
		return 0, 0, fmt.Errorf("%w: file accept too short", ErrMalformed)
	}
	return binary.BigEndian.Uint64(pt[0:8]), binary.BigEndian.Uint64(pt[8:16]), nil
}

// SealFileChunk seals one slice of a file. offset is where data belongs in the
// file; the receiver requires it to be exactly where it has reached, so it is
// an assertion the receiver checks rather than a position it honours
// (docs/protocol.md §13.3).
func (s *Session) SealFileChunk(id, offset uint64, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("proto: empty file chunk")
	}
	if len(data) > MaxFileChunk {
		return nil, fmt.Errorf("proto: file chunk too large (%d > %d)", len(data), MaxFileChunk)
	}
	b := make([]byte, 0, fileChunkHeader+len(data))
	b = binary.BigEndian.AppendUint64(b, id)
	b = binary.BigEndian.AppendUint64(b, offset)
	b = append(b, data...)
	return s.Seal(TypeFileChunk, b)
}

// DecodeFileChunk decodes an opened TypeFileChunk plaintext. The returned data
// aliases pt, which Session.Open allocated per frame and does not reuse.
//
// Unlike the other decoders this one cannot ignore trailing bytes, because for
// a chunk every byte after the header *is* the data.
func DecodeFileChunk(pt []byte) (id, offset uint64, data []byte, err error) {
	if len(pt) <= fileChunkHeader {
		return 0, 0, nil, fmt.Errorf("%w: file chunk carries no data", ErrMalformed)
	}
	data = pt[fileChunkHeader:]
	if len(data) > MaxFileChunk {
		return 0, 0, nil, fmt.Errorf("%w: file chunk too large", ErrMalformed)
	}
	return binary.BigEndian.Uint64(pt[0:8]), binary.BigEndian.Uint64(pt[8:16]), data, nil
}

// SealFileDone seals the end of a file together with the SHA-256 of what was
// actually sent (docs/protocol.md §13.2).
func (s *Session) SealFileDone(id uint64, digest []byte) ([]byte, error) {
	if len(digest) != fileDigestSize {
		return nil, fmt.Errorf("proto: file digest must be %d bytes, got %d", fileDigestSize, len(digest))
	}
	b := make([]byte, 0, transferIDSize+fileDigestSize)
	b = binary.BigEndian.AppendUint64(b, id)
	b = append(b, digest...)
	return s.Seal(TypeFileDone, b)
}

// DecodeFileDone decodes an opened TypeFileDone plaintext. The returned digest
// aliases pt.
func DecodeFileDone(pt []byte) (id uint64, digest []byte, err error) {
	if len(pt) < transferIDSize+fileDigestSize {
		return 0, nil, fmt.Errorf("%w: file done too short", ErrMalformed)
	}
	return binary.BigEndian.Uint64(pt[0:8]), pt[8 : 8+fileDigestSize], nil
}

// SealFileCancel seals abandonment of a transfer. Either side may send it at
// any time, and it never ends the session.
func (s *Session) SealFileCancel(id uint64, reason byte) ([]byte, error) {
	b := make([]byte, 0, transferIDSize+1)
	b = binary.BigEndian.AppendUint64(b, id)
	b = append(b, reason)
	return s.Seal(TypeFileCancel, b)
}

// DecodeFileCancel decodes an opened TypeFileCancel plaintext.
func DecodeFileCancel(pt []byte) (id uint64, reason byte, err error) {
	if len(pt) < transferIDSize+1 {
		return 0, 0, fmt.Errorf("%w: file cancel too short", ErrMalformed)
	}
	return binary.BigEndian.Uint64(pt[0:8]), pt[8], nil
}
