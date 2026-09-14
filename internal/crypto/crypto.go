// Package crypto provides thin wrappers over the Go standard library
// cryptographic primitives used by Heimdall: OS CSPRNG randomness,
// AES-256-GCM authenticated encryption, and HKDF-SHA-256 key derivation.
//
// No custom cryptography lives here: every construction is a direct,
// well-established stdlib primitive. This package contains no protocol
// logic; it only exposes safe, hard-to-misuse building blocks.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
)

const (
	// KeySize is the size in bytes of all symmetric keys used by the
	// protocol (AES-256).
	KeySize = 32
	// NonceSize is the size in bytes of AES-GCM nonces (96 bits, random).
	NonceSize = 12
	// TagSize is the size in bytes of the AES-GCM authentication tag.
	TagSize = 16
)

// ErrDecrypt is returned when AEAD authentication fails. The error is
// deliberately opaque so that no information about the failure reason
// leaks to an attacker (padding-oracle style side channels do not apply
// to GCM, but uniform errors are good hygiene anyway).
var ErrDecrypt = errors.New("crypto: message authentication failed")

// RandomBytes returns n cryptographically secure random bytes from the
// OS CSPRNG. It is the only source of randomness in the application.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto: CSPRNG failure: %w", err)
	}
	return b, nil
}

// RandomKey returns a fresh random 32-byte key.
func RandomKey() ([]byte, error) { return RandomBytes(KeySize) }

// DeriveKey derives a key of the given length using HKDF-SHA-256 with an
// explicit info label. Every distinct purpose in the protocol uses a
// distinct info label (explicit key separation); keys are therefore
// independent even when derived from the same secret.
func DeriveKey(secret, salt []byte, info string, length int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("crypto: empty HKDF secret")
	}
	key, err := hkdf.Key(sha256.New, secret, salt, info, length)
	if err != nil {
		return nil, fmt.Errorf("crypto: hkdf: %w", err)
	}
	return key, nil
}

// aead builds an AES-256-GCM AEAD from a 32-byte key.
func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: invalid key size %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

// Seal encrypts and authenticates plaintext with AES-256-GCM under key.
// aad is authenticated but not encrypted (it carries the protocol header).
// The returned blob is nonce || ciphertext || tag; the nonce is generated
// freshly from the CSPRNG for every call, so key/nonce reuse never occurs.
func Seal(key, aad, plaintext []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce, err := RandomBytes(NonceSize)
	if err != nil {
		return nil, err
	}
	out := gcm.Seal(nonce, nonce, plaintext, aad)
	return out, nil
}

// Open verifies and decrypts a blob produced by Seal. aad must match the
// value supplied to Seal. Any modification of the blob or aad results in
// ErrDecrypt and no plaintext is returned.
func Open(key, aad, blob []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < NonceSize+TagSize {
		return nil, ErrDecrypt
	}
	nonce := blob[:NonceSize]
	ct := blob[NonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Zeroise overwrites a byte slice in place so that key material does not
// linger in memory longer than necessary. Best-effort: the Go runtime may
// have copied the data elsewhere, but zeroising is still worthwhile.
//
// runtime.KeepAlive keeps the slice alive until after the zeroing loop so an
// aggressive compiler cannot prove the slice dead earlier and reorder the
// zeroing before a preceding read of a derived sub-slice.
func Zeroise(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
