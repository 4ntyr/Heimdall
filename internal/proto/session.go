package proto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	xcrypto "github.com/4ntyr/heimdall_cli/internal/crypto"
)

// HKDF info labels. Every derived key uses a distinct label so keys for
// different purposes are independent (explicit key separation, §5).
const (
	infoRoot    = "heimdall v1 root"
	infoHS2     = "heimdall v1 hs2"
	infoHS3     = "heimdall v1 hs3"
	infoSendAB  = "heimdall v1 send A-to-B"
	infoSendBA  = "heimdall v1 send B-to-A"
	infoRatchet = "heimdall v1 ratchet"
	infoMsg     = "heimdall v1 msg"
	infoRotate  = "heimdall v1 rotate"
	infoSession = "heimdall v1 session id"
)

// rotationInterval is the number of sent messages after which the session
// performs a full key rotation (new epoch). See docs/protocol.md §8.
const rotationInterval = 1000

// maxEpochDrift is how many rotation epochs behind the current one we still
// accept (to tolerate in-flight messages from the previous epoch).
const maxEpochDrift = 1

// Session is an established, authenticated, encrypted channel to one peer.
// It is created only by a successful handshake. Not safe for concurrent use
// by itself; the session manager serialises access per peer.
type Session struct {
	mu sync.Mutex

	// SessionID is a random per-session identifier derived from the
	// handshake transcript. It is public metadata, not a secret.
	SessionID uint64

	// send/recv are the current ratchet chains for this epoch.
	send    *chain
	recv    *chain
	recvOld *chain // previous epoch, for in-flight messages after rotation

	epoch     uint32 // current rotation epoch
	sendSeq   uint64 // next sequence number we will send
	recvWin   replayWindow
	closed    bool
	initiator bool
	root      []byte // shared per-session root used to derive epoch seeds
}

// chain is one direction's symmetric ratchet state.
type chain struct {
	key []byte // epoch chain key (secret), constant for the epoch
}

// messageKey derives the unique key for a given sequence number on this
// chain: HKDF(chainKey, info=msg || seq). Because the derivation is a pure
// function of (chainKey, epoch, seq), both sides compute identical keys for
// in-order, out-of-order, and post-rotation messages alike.
func (c *chain) messageKey(seq uint64) ([]byte, error) {
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], seq)
	return xcrypto.DeriveKey(c.key, sb[:], infoMsg, xcrypto.KeySize)
}

// newSession builds a session from the handshake products. initiator decides
// which directional chain belongs to us (key separation by role). It derives
// the epoch-0 root and installs epoch-0 chains.
func newSession(shared, transcript []byte, initiator bool) (*Session, error) {
	root, err := xcrypto.DeriveKey(shared, transcript, infoRoot, xcrypto.KeySize)
	if err != nil {
		return nil, err
	}
	sidBytes, err := xcrypto.DeriveKey(root, nil, infoSession, 8)
	if err != nil {
		return nil, err
	}
	s := &Session{
		SessionID: binary.BigEndian.Uint64(sidBytes),
		epoch:     0,
		initiator: initiator,
		root:      root,
	}
	if err := s.installEpochLocked(0); err != nil {
		return nil, err
	}
	return s, nil
}

// epochSeed derives the shared, role-independent seed for an epoch from the
// session root. Both sides derive the identical seed, so rotation stays in
// sync without any extra messages.
func (s *Session) epochSeed(epoch uint32) ([]byte, error) {
	return xcrypto.DeriveKey(s.root, nil, infoRotate+" "+itoa(epoch), xcrypto.KeySize)
}

// installEpochLocked derives and installs the send/recv chains for `epoch`.
// The previous receive chain is retired into recvOld (one epoch of drift).
func (s *Session) installEpochLocked(epoch uint32) error {
	seed, err := s.epochSeed(epoch)
	if err != nil {
		return err
	}
	defer xcrypto.Zeroise(seed)
	ab, err := xcrypto.DeriveKey(seed, nil, infoSendAB, xcrypto.KeySize)
	if err != nil {
		return err
	}
	ba, err := xcrypto.DeriveKey(seed, nil, infoSendBA, xcrypto.KeySize)
	if err != nil {
		return err
	}
	if s.recvOld != nil {
		xcrypto.Zeroise(s.recvOld.key)
	}
	if s.recv != nil {
		s.recvOld = s.recv // keep previous epoch for in-flight messages
	}
	if s.send != nil {
		xcrypto.Zeroise(s.send.key)
	}
	if s.initiator {
		s.send = &chain{key: ab}
		s.recv = &chain{key: ba}
	} else {
		s.send = &chain{key: ba}
		s.recv = &chain{key: ab}
	}
	s.epoch = epoch
	return nil
}

// Seal encrypts and authenticates an outbound frame of the given type with
// the given plaintext payload. It enforces the per-direction sequence
// counter, the per-message ratchet, and epoch rotation.
func (s *Session) Seal(typ byte, plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("proto: session closed")
	}
	if len(plaintext) > MaxPlaintext {
		return nil, fmt.Errorf("proto: payload too large (%d > %d)", len(plaintext), MaxPlaintext)
	}

	// Full key rotation at the interval boundary.
	if s.sendSeq > 0 && s.sendSeq%rotationInterval == 0 {
		if err := s.installEpochLocked(s.epoch + 1); err != nil {
			return nil, err
		}
	}

	msgKey, err := s.send.messageKey(s.sendSeq)
	if err != nil {
		return nil, err
	}
	defer xcrypto.Zeroise(msgKey)

	f := &frame{
		typ:      typ,
		session:  s.SessionID,
		sequence: s.sendSeq,
		rotation: s.epoch,
	}
	// AAD is the header; Seal binds it to the ciphertext.
	hdr := marshalHeaderOnly(f)
	blob, err := xcrypto.Seal(msgKey, hdr, plaintext)
	if err != nil {
		return nil, err
	}
	f.blob = blob
	s.sendSeq++
	return marshalFrame(f), nil
}

// Open authenticates and decrypts an inbound frame. Nothing in the frame is
// trusted until the AEAD tag verifies. It enforces session binding, replay
// protection and epoch validity. Returns the frame type and plaintext.
func (s *Session) Open(buf []byte) (byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, nil, errors.New("proto: session closed")
	}
	f, err := parseFrame(buf)
	if err != nil {
		return 0, nil, err
	}
	if f.session != s.SessionID {
		return 0, nil, ErrBadSession
	}

	// Select the chain for the frame's epoch (current or previous only).
	recv, err := s.chainForEpochLocked(f.rotation)
	if err != nil {
		return 0, nil, err
	}

	// Replay protection BEFORE decryption would leak oracle info, so we
	// decrypt-then-check: the AEAD tag authenticates the sequence number,
	// after which the window decides freshness. Decrypting a replay costs
	// one AEAD op but reveals nothing (the tag either verifies or not).
	msgKey, err := recv.messageKey(f.sequence)
	if err != nil {
		return 0, nil, err
	}
	hdr := marshalHeaderOnly(f)
	pt, err := xcrypto.Open(msgKey, hdr, f.blob)
	xcrypto.Zeroise(msgKey)
	if err != nil {
		return 0, nil, ErrAuth
	}
	// Authenticated now: safe to apply the replay window.
	if !s.recvWin.check(f.sequence) {
		return 0, nil, ErrReplay
	}
	return f.typ, pt, nil
}

// Close marks the session closed and destroys key material.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.send != nil {
		xcrypto.Zeroise(s.send.key)
	}
	if s.recv != nil {
		xcrypto.Zeroise(s.recv.key)
	}
	if s.recvOld != nil {
		xcrypto.Zeroise(s.recvOld.key)
	}
	if s.root != nil {
		xcrypto.Zeroise(s.root)
		s.root = nil
	}
}

// Closed reports whether Close has been called.
func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// chainForEpochLocked returns the receive chain matching f.rotation. If the
// frame announces a newer epoch than ours (the sender rotated first), we
// install that epoch — the derivation is deterministic and shared, so both
// sides stay in sync without any extra messages. We accept the current
// epoch, a single forward roll, or the immediately previous epoch (for
// in-flight messages during a rotation).
func (s *Session) chainForEpochLocked(epoch uint32) (*chain, error) {
	switch {
	case epoch == s.epoch:
		return s.recv, nil
	case epoch == s.epoch+1:
		if err := s.installEpochLocked(epoch); err != nil {
			return nil, err
		}
		return s.recv, nil
	case epoch+1 == s.epoch && s.recvOld != nil:
		return s.recvOld, nil
	default:
		return nil, ErrBadEpoch
	}
}

func cloneKey(k []byte) ([]byte, error) {
	if len(k) != xcrypto.KeySize {
		return nil, errors.New("proto: bad chain key size")
	}
	out := make([]byte, len(k))
	copy(out, k)
	return out, nil
}

// marshalHeaderOnly returns the 22-byte authenticated header (the AAD).
func marshalHeaderOnly(f *frame) []byte {
	hdr := make([]byte, headerSize)
	hdr[0] = ProtocolVersion
	hdr[1] = f.typ
	binary.BigEndian.PutUint64(hdr[2:10], f.session)
	binary.BigEndian.PutUint64(hdr[10:18], f.sequence)
	binary.BigEndian.PutUint32(hdr[18:22], f.rotation)
	return hdr
}

// itoa renders a uint32 without strconv (keeps the hot path allocation-free
// enough and avoids importing strconv for one call).
func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// transcriptHash is defined here for the handshake (sha256 of the ordered
// transcript). Declared as a variable for testability.
var transcriptHash = func(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
