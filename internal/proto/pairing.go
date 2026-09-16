package proto

import (
	"crypto/subtle"
	"errors"

	xcrypto "github.com/4ntyr/heimdall/internal/crypto"
)

// Pairing confirmation (docs/rendezvous.md §4).
//
// When a connection is established through a rendezvous, the peers meet for
// the first time and the trust store holds no key to compare against. Without
// a binding to the invite code, a hostile relay could answer the claim itself
// and become a trust-on-first-use man-in-the-middle.
//
// The invite code yields a pairing key that never reaches the relay. After the
// §3 handshake, each side proves possession of that key over the established
// session by sending
//
//	confirm = HKDF(pairingKey, salt=transcript, info="heimdall v1 pairing confirm")
//
// The transcript hash binds the proof to this exact handshake, so a relay that
// completed its own handshake with each peer cannot forward either proof.
//
// This is HKDF plus a constant-time comparison over material the handshake
// already produces: no new cryptographic construction, and the handshake
// itself is unchanged.

// ErrPairConfirm indicates a missing or incorrect pairing confirmation, which
// means the peer could not prove knowledge of the invite code.
var ErrPairConfirm = errors.New("proto: pairing confirmation failed (possible relay MITM)")

// PairConfirmSize is the length of a confirmation value.
const PairConfirmSize = 32

// PairConfirm derives the confirmation value for a pairing key and the
// handshake transcript it is being bound to.
func PairConfirm(pairingKey, transcript []byte) ([]byte, error) {
	if len(pairingKey) == 0 {
		return nil, errors.New("proto: empty pairing key")
	}
	if len(transcript) == 0 {
		return nil, errors.New("proto: empty transcript")
	}
	return xcrypto.DeriveKey(pairingKey, transcript, infoPairConfirm, PairConfirmSize)
}

// VerifyPairConfirm reports whether got is the expected confirmation value for
// this pairing key and transcript. The comparison is constant-time.
func VerifyPairConfirm(pairingKey, transcript, got []byte) bool {
	want, err := PairConfirm(pairingKey, transcript)
	if err != nil {
		return false
	}
	defer xcrypto.Zeroise(want)
	return subtle.ConstantTimeCompare(want, got) == 1
}

// SealPairConfirm seals this side's confirmation value into a session frame.
func (s *Session) SealPairConfirm(pairingKey, transcript []byte) ([]byte, error) {
	confirm, err := PairConfirm(pairingKey, transcript)
	if err != nil {
		return nil, err
	}
	defer xcrypto.Zeroise(confirm)
	return s.Seal(TypePairConfirm, confirm)
}
