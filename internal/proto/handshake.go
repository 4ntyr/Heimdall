package proto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	xcrypto "github.com/4ntyr/heimdall/internal/crypto"
	"github.com/4ntyr/heimdall/internal/identity"
)

// Handshake (docs/protocol.md §3). Noise-style XX pattern: ephemeral X25519,
// then both sides sign the transcript hash with their long-term Ed25519
// identity keys.
//
//	msg1  A → B  Init { ephA_pub }                                   (clear)
//	msg2  B → A  Auth { ephB_pub || Enc_k2(idB, nameB, Sig_B(h)) }   (eph clear, auth encrypted)
//	msg3  A → B  Auth { ephA_pub || Enc_k3(idA, nameA, Sig_A(h)) }   (eph clear, auth encrypted)
//
//	h = SHA256("heimdall v1 handshake" || ephA_pub || ephB_pub)
//
// The ephemeral public keys travel in the clear: they are not secret, and
// each side's signature over the transcript hash binds BOTH ephemeral keys,
// so any substitution invalidates a signature. The identity/name/signature
// are encrypted so a passive observer learns neither party's identity.
var (
	ErrHandshake      = errors.New("proto: handshake failed")
	ErrBadSignature   = errors.New("proto: peer signature verification failed (possible MITM)")
	ErrSelfConnection = errors.New("proto: refusing to connect to self")
)

// handshakeDomain separates the transcript hash from every other SHA-256
// use in the protocol.
var handshakeDomain = []byte("heimdall v1 handshake")

const (
	hsTypeInit  byte = 1
	hsTypeAuth  byte = 2
	maxHsSize        = 4096
	maxPeerName      = 64
)

// HandshakeResult carries the outcome of a successful handshake.
type HandshakeResult struct {
	// Session is the established encrypted session.
	Session *Session
	// PeerName is the display name the peer presented (NOT an identity).
	PeerName string
	// PeerKey is the peer's authenticated long-term public key.
	PeerKey ed25519.PublicKey
	// PeerFingerprint is the SHA-256 fingerprint of PeerKey.
	PeerFingerprint string
}

// Handshaker drives one side of the handshake. It is transport-agnostic:
// the caller moves the byte slices produced/consumed here.
type Handshaker struct {
	id        *identity.Identity
	initiator bool

	eph        *ecdh.PrivateKey
	ephPub     []byte
	peerEph    []byte
	transcript []byte
	shared     []byte
	done       bool
}

// NewHandshaker prepares a handshake. The local identity must hold its
// private key (it signs the transcript).
func NewHandshaker(id *identity.Identity, initiator bool) (*Handshaker, error) {
	if !id.HasPrivateKey() {
		return nil, errors.New("proto: handshake requires the local private key")
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proto: ephemeral key generation: %w", err)
	}
	return &Handshaker{
		id:        id,
		initiator: initiator,
		eph:       eph,
		ephPub:    eph.PublicKey().Bytes(),
	}, nil
}

// InitMessage returns the initiator's first message (msg1).
func (h *Handshaker) InitMessage() ([]byte, error) {
	if !h.initiator {
		return nil, errors.New("proto: only the initiator sends msg1")
	}
	out := make([]byte, 1+2+len(h.ephPub))
	out[0] = hsTypeInit
	binary.BigEndian.PutUint16(out[1:3], uint16(len(h.ephPub)))
	copy(out[3:], h.ephPub)
	return out, nil
}

// HandleMessage processes the next incoming handshake message and returns
// the response to send (if any) and, on completion, the result.
//
//	responder:  HandleMessage(msg1) → (msg2, nil, nil)
//	initiator:  HandleMessage(msg2) → (msg3, result, nil)
//	responder:  HandleMessage(msg3) → (nil,  result, nil)
func (h *Handshaker) HandleMessage(msg []byte) ([]byte, *HandshakeResult, error) {
	if h.done {
		return nil, nil, fmt.Errorf("%w: handshake already complete", ErrHandshake)
	}
	if len(msg) == 0 || len(msg) > maxHsSize {
		return nil, nil, fmt.Errorf("%w: bad message size", ErrHandshake)
	}
	switch {
	case !h.initiator && msg[0] == hsTypeInit && h.transcript == nil:
		return h.handleInit(msg)
	case msg[0] == hsTypeAuth:
		if h.initiator {
			return h.handleAuthInitiator(msg)
		}
		return h.handleAuthResponder(msg)
	default:
		return nil, nil, fmt.Errorf("%w: unexpected message type %d", ErrHandshake, msg[0])
	}
}

// handleInit processes msg1 (responder) and produces msg2.
func (h *Handshaker) handleInit(msg []byte) ([]byte, *HandshakeResult, error) {
	peerEph, err := parseInit(msg)
	if err != nil {
		return nil, nil, err
	}
	h.peerEph = peerEph
	// Responder transcript order: ephA (peer) then ephB (ours).
	h.transcript = transcriptHash(handshakeDomain, h.peerEph, h.ephPub)
	if err := h.deriveShared(); err != nil {
		return nil, nil, err
	}
	blob, err := h.sealAuth(infoHS2)
	if err != nil {
		return nil, nil, err
	}
	return marshalAuth(h.ephPub, blob), nil, nil
}

// handleAuthInitiator processes msg2 (initiator) and produces msg3 + result.
func (h *Handshaker) handleAuthInitiator(msg []byte) ([]byte, *HandshakeResult, error) {
	ephB, blob, err := parseAuth(msg)
	if err != nil {
		return nil, nil, err
	}
	h.peerEph = ephB
	// Initiator transcript order: ephA (ours) then ephB (peer) — identical
	// value to what the responder computed.
	h.transcript = transcriptHash(handshakeDomain, h.ephPub, h.peerEph)
	if err := h.deriveShared(); err != nil {
		return nil, nil, err
	}
	pub, name, sig, err := h.openAuth(blob, infoHS2)
	if err != nil {
		return nil, nil, err
	}
	if !identity.VerifyWith(pub, h.transcript, sig) {
		return nil, nil, ErrBadSignature
	}
	if pub.Equal(h.id.PublicKey()) {
		return nil, nil, ErrSelfConnection
	}
	msg3blob, err := h.sealAuth(infoHS3)
	if err != nil {
		return nil, nil, err
	}
	msg3 := marshalAuth(h.ephPub, msg3blob)

	sess, err := newSession(h.shared, h.transcript, true)
	if err != nil {
		return nil, nil, err
	}
	h.finish()
	return msg3, &HandshakeResult{
		Session:         sess,
		PeerName:        name,
		PeerKey:         pub,
		PeerFingerprint: identity.FingerprintOf(pub),
	}, nil
}

// handleAuthResponder processes msg3 (responder) and yields the result.
func (h *Handshaker) handleAuthResponder(msg []byte) ([]byte, *HandshakeResult, error) {
	if h.transcript == nil {
		return nil, nil, fmt.Errorf("%w: auth before init", ErrHandshake)
	}
	_, blob, err := parseAuth(msg)
	if err != nil {
		return nil, nil, err
	}
	pub, name, sig, err := h.openAuth(blob, infoHS3)
	if err != nil {
		return nil, nil, err
	}
	if !identity.VerifyWith(pub, h.transcript, sig) {
		return nil, nil, ErrBadSignature
	}
	if pub.Equal(h.id.PublicKey()) {
		return nil, nil, ErrSelfConnection
	}
	sess, err := newSession(h.shared, h.transcript, false)
	if err != nil {
		return nil, nil, err
	}
	h.finish()
	return nil, &HandshakeResult{
		Session:         sess,
		PeerName:        name,
		PeerKey:         pub,
		PeerFingerprint: identity.FingerprintOf(pub),
	}, nil
}

// deriveShared runs X25519 with the peer's ephemeral key and stores the
// shared secret (kept only until the session is built).
func (h *Handshaker) deriveShared() error {
	pub, err := ecdh.X25519().NewPublicKey(h.peerEph)
	if err != nil {
		return fmt.Errorf("%w: bad peer ephemeral key", ErrHandshake)
	}
	shared, err := h.eph.ECDH(pub)
	if err != nil {
		return fmt.Errorf("%w: key agreement failed", ErrHandshake)
	}
	h.shared = shared
	return nil
}

// sealAuth encrypts our identity/name/signature under the handshake key.
func (h *Handshaker) sealAuth(info string) ([]byte, error) {
	k, err := xcrypto.DeriveKey(h.shared, h.transcript, info, xcrypto.KeySize)
	if err != nil {
		return nil, err
	}
	defer xcrypto.Zeroise(k)
	sig, err := h.id.Sign(h.transcript)
	if err != nil {
		return nil, err
	}
	plain := marshalAuthPlain(h.id.PublicKey(), h.id.Name, sig)
	blob, err := xcrypto.Seal(k, hsAAD(), plain)
	xcrypto.Zeroise(plain)
	return blob, err
}

// openAuth decrypts and parses the peer's auth blob under the handshake key.
func (h *Handshaker) openAuth(blob []byte, info string) (ed25519.PublicKey, string, []byte, error) {
	k, err := xcrypto.DeriveKey(h.shared, h.transcript, info, xcrypto.KeySize)
	if err != nil {
		return nil, "", nil, err
	}
	defer xcrypto.Zeroise(k)
	plain, err := xcrypto.Open(k, hsAAD(), blob)
	if err != nil {
		return nil, "", nil, fmt.Errorf("%w: auth message authentication failed", ErrHandshake)
	}
	pub, name, sig, perr := parseAuthPlain(plain)
	// Copy the values we return OUT of the plaintext buffer BEFORE zeroising
	// it, so the caller never holds slices into freed/zeroed memory.
	if perr == nil {
		pub = append(ed25519.PublicKey(nil), pub...)
		name = string(append([]byte(nil), name...))
		sig = append([]byte(nil), sig...)
	}
	xcrypto.Zeroise(plain)
	if perr != nil {
		return nil, "", nil, perr
	}
	return pub, name, sig, nil
}

// finish zeroises ephemeral material; the handshake is complete.
func (h *Handshaker) finish() {
	h.done = true
	if h.shared != nil {
		xcrypto.Zeroise(h.shared)
		h.shared = nil
	}
	if h.eph != nil {
		xcrypto.Zeroise(h.eph.Bytes())
		h.eph = nil
	}
}

// --- wire encoding helpers ---

// parseInit parses msg1: type(1) || len(2) || eph_pub(32).
func parseInit(msg []byte) ([]byte, error) {
	if len(msg) < 3 || msg[0] != hsTypeInit {
		return nil, fmt.Errorf("%w: bad init message", ErrHandshake)
	}
	n := int(binary.BigEndian.Uint16(msg[1:3]))
	if n != 32 || len(msg) != 3+n {
		return nil, fmt.Errorf("%w: bad init length", ErrHandshake)
	}
	return msg[3:], nil
}

// marshalAuth produces: type(1) || eph_pub(32) || len(4) || blob.
func marshalAuth(ephPub, blob []byte) []byte {
	out := make([]byte, 0, 1+32+4+len(blob))
	out = append(out, hsTypeAuth)
	out = append(out, ephPub...)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(blob)))
	out = append(out, lb[:]...)
	return append(out, blob...)
}

// parseAuth splits an auth message into the clear ephemeral key and blob.
func parseAuth(msg []byte) (ephPub, blob []byte, err error) {
	if len(msg) < 1+32+4 || msg[0] != hsTypeAuth {
		return nil, nil, fmt.Errorf("%w: bad auth message", ErrHandshake)
	}
	ephPub = msg[1 : 1+32]
	n := int(binary.BigEndian.Uint32(msg[1+32 : 1+32+4]))
	if n <= 0 || len(msg) != 1+32+4+n {
		return nil, nil, fmt.Errorf("%w: bad auth length", ErrHandshake)
	}
	return ephPub, msg[1+32+4:], nil
}

// marshalAuthPlain: id_pub(32) || name_len(2) || name || sig(64).
func marshalAuthPlain(pub ed25519.PublicKey, name string, sig []byte) []byte {
	out := make([]byte, 0, 32+2+len(name)+len(sig))
	out = append(out, pub...)
	var nl [2]byte
	binary.BigEndian.PutUint16(nl[:], uint16(len(name)))
	out = append(out, nl[:]...)
	out = append(out, name...)
	return append(out, sig...)
}

func parseAuthPlain(b []byte) (ed25519.PublicKey, string, []byte, error) {
	if len(b) < 32+2+64 {
		return nil, "", nil, fmt.Errorf("%w: auth payload too short", ErrHandshake)
	}
	pub := ed25519.PublicKey(b[:32])
	nl := int(binary.BigEndian.Uint16(b[32:34]))
	if nl <= 0 || nl > maxPeerName || len(b) != 34+nl+64 {
		return nil, "", nil, fmt.Errorf("%w: bad name length", ErrHandshake)
	}
	name := string(b[34 : 34+nl])
	sig := b[34+nl:]
	return pub, name, sig, nil
}

// hsAAD is the additional authenticated data for handshake ciphertexts.
func hsAAD() []byte { return []byte("heimdall v1 hs aad") }
