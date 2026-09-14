// Package identity manages the client's long-term cryptographic identity:
// an Ed25519 key pair, a human-readable name, and a stable SHA-256
// fingerprint.
//
// The private key never leaves the device and is never stored in plaintext:
// the on-disk identity file is encrypted with PBKDF2-SHA-256 (600k
// iterations, random per-file salt) + AES-256-GCM. A name is a display label
// only — it is never used as proof of identity anywhere in the protocol.
package identity

import (
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	xcrypto "github.com/4ntyr/heimdall_cli/internal/crypto"
)

// identityFileVersion is the version byte of the on-disk identity format.
const identityFileVersion = 1

// pbkdf2Iterations follows the OWASP recommendation for PBKDF2-SHA-256.
const pbkdf2Iterations = 600_000

const saltSize = 16

// Identity is a client's persistent cryptographic identity.
type Identity struct {
	Name string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// Generate creates a new identity with a fresh Ed25519 key pair.
func Generate(name string) (*Identity, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("identity: name must not be empty")
	}
	pub, priv, err := ed25519.GenerateKey(nil) // uses crypto/rand
	if err != nil {
		return nil, fmt.Errorf("identity: key generation failed: %w", err)
	}
	return &Identity{Name: name, priv: priv, pub: pub}, nil
}

// FromPublicKey builds a public-only view of an identity (e.g. a peer).
func FromPublicKey(name string, pub ed25519.PublicKey) *Identity {
	return &Identity{Name: name, pub: pub}
}

// PublicKey returns the identity's public key.
func (id *Identity) PublicKey() ed25519.PublicKey { return id.pub }

// HasPrivateKey reports whether this identity holds its private key
// (false for peer identities).
func (id *Identity) HasPrivateKey() bool { return id.priv != nil }

// Fingerprint returns the stable cryptographic fingerprint of the
// identity: SHA256(public key) rendered as "SHA256: AB:CD:…".
// This — not the name — is what users compare to authenticate a peer.
func (id *Identity) Fingerprint() string { return FingerprintOf(id.pub) }

// FingerprintOf renders the fingerprint of an arbitrary Ed25519 public key.
func FingerprintOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return "SHA256: " + strings.Join(parts, ":")
}

// ShortFingerprint returns a truncated fingerprint for compact display.
func ShortFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	parts := make([]string, 4)
	for i := 0; i < 4; i++ {
		parts[i] = fmt.Sprintf("%02X", sum[i])
	}
	return "SHA256: " + strings.Join(parts, ":") + "…"
}

// Sign signs a message with the identity's private key. It fails for
// public-only identities.
func (id *Identity) Sign(msg []byte) ([]byte, error) {
	if id.priv == nil {
		return nil, errors.New("identity: cannot sign without private key")
	}
	return ed25519.Sign(id.priv, msg), nil
}

// Verify checks a signature made by this identity's key over msg.
func (id *Identity) Verify(msg, sig []byte) bool {
	return VerifyWith(id.pub, msg, sig)
}

// VerifyWith checks an Ed25519 signature against an explicit public key.
func VerifyWith(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

// diskFormat is the plaintext JSON structure sealed inside the identity
// file. The private key bytes exist only inside the encrypted blob.
type diskFormat struct {
	Name    string `json:"name"`
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

// Save encrypts the identity with the passphrase and writes it to path
// with mode 0600. The passphrase is run through PBKDF2-SHA-256 with a
// fresh random salt; an empty passphrase is rejected — an explicit
// insecure mode is the caller's decision (see SaveInsecure).
func (id *Identity) Save(path, passphrase string) error {
	if id.priv == nil {
		return errors.New("identity: cannot save without private key")
	}
	if passphrase == "" {
		return errors.New("identity: empty passphrase refused (use SaveInsecure for development)")
	}
	salt, err := xcrypto.RandomBytes(saltSize)
	if err != nil {
		return err
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iterations, xcrypto.KeySize)
	if err != nil {
		return fmt.Errorf("identity: kdf: %w", err)
	}
	defer xcrypto.Zeroise(key)

	payload, err := json.Marshal(diskFormat{Name: id.Name, Private: id.priv, Public: id.pub})
	if err != nil {
		return err
	}
	defer xcrypto.Zeroise(payload)

	blob, err := xcrypto.Seal(key, identityAAD(path), payload)
	if err != nil {
		return err
	}
	return writeIdentityFile(path, salt, blob)
}

// SaveInsecure stores the identity without encryption. This exists solely
// as an explicit, opt-in development mode; production use should call Save.
func (id *Identity) SaveInsecure(path string) error {
	if id.priv == nil {
		return errors.New("identity: cannot save without private key")
	}
	payload, err := json.Marshal(diskFormat{Name: id.Name, Private: id.priv, Public: id.pub})
	if err != nil {
		return err
	}
	return writeIdentityFile(path, nil, payload)
}

// Load reads and decrypts an identity file. If the file was stored with
// SaveInsecure, an empty passphrase must be supplied.
func Load(path, passphrase string) (*Identity, error) {
	salt, blob, err := readIdentityFile(path)
	if err != nil {
		return nil, err
	}
	var payload []byte
	if salt == nil {
		if passphrase != "" {
			return nil, errors.New("identity: file is unencrypted; use empty passphrase")
		}
		payload = blob
	} else {
		if passphrase == "" {
			return nil, errors.New("identity: passphrase required")
		}
		key, err := pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iterations, xcrypto.KeySize)
		if err != nil {
			return nil, fmt.Errorf("identity: kdf: %w", err)
		}
		defer xcrypto.Zeroise(key)
		payload, err = xcrypto.Open(key, identityAAD(path), blob)
		if err != nil {
			return nil, errors.New("identity: wrong passphrase or corrupted identity file")
		}
		defer xcrypto.Zeroise(payload)
	}
	var df diskFormat
	if err := json.Unmarshal(payload, &df); err != nil {
		return nil, fmt.Errorf("identity: invalid identity file: %w", err)
	}
	priv := ed25519.PrivateKey(df.Private)
	pub := ed25519.PublicKey(df.Public)
	if len(df.Private) > 0 {
		if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("identity: invalid key material in file")
		}
		if !pub.Equal(priv.Public().(ed25519.PublicKey)) {
			return nil, errors.New("identity: public key does not match private key")
		}
		return &Identity{Name: df.Name, priv: priv, pub: pub}, nil
	}
	return &Identity{Name: df.Name, pub: pub}, nil
}

// identityAAD binds the encrypted identity blob to its file name so a blob
// cannot be silently swapped between differently-named identities.
func identityAAD(path string) []byte {
	return []byte("heimdall identity v1 " + filepath.Base(path))
}

// writeIdentityFile serialises version || saltLen || salt || blob atomically
// (write temp + rename) with restrictive permissions.
func writeIdentityFile(path string, salt, blob []byte) error {
	buf := make([]byte, 0, 2+len(salt)+len(blob))
	buf = append(buf, identityFileVersion, byte(len(salt)))
	buf = append(buf, salt...)
	buf = append(buf, blob...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readIdentityFile(path string) (salt, blob []byte, err error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if len(buf) < 2 || buf[0] != identityFileVersion {
		return nil, nil, errors.New("identity: unsupported identity file version")
	}
	sl := int(buf[1])
	if len(buf) < 2+sl {
		return nil, nil, errors.New("identity: truncated identity file")
	}
	if sl == 0 {
		return nil, buf[2:], nil
	}
	return buf[2 : 2+sl], buf[2+sl:], nil
}

// MarshalBinary encodes an identity's public parts for the wire.
func (id *Identity) MarshalBinary() []byte {
	buf := make([]byte, 2, 2+len(id.Name)+len(id.pub))
	binary.BigEndian.PutUint16(buf, uint16(len(id.Name)))
	buf = append(buf, id.Name...)
	buf = append(buf, id.pub...)
	return buf
}
