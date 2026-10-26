package transfer

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// maxCollisionTries bounds the search for an unused filename.
const maxCollisionTries = 100

// partWriterBuf is the buffer in front of a .part file. Chunks arrive at ~4
// KiB; writing each one straight through would be one syscall per frame and
// would make "the disk is slower than the network" a routine condition rather
// than a rare one.
const partWriterBuf = 64 << 10

// PeerDir returns the directory name for a peer, derived from its fingerprint.
//
// identity.FingerprintOf renders "SHA256: AB:CD:…", whose space and colons are
// not legal in a Windows path component, so the hex is extracted and
// lowercased. The directory is keyed by fingerprint rather than display name
// because a name is an attacker-chosen label while the fingerprint is the
// identity — two peers may call themselves the same thing, and one of them may
// be doing it on purpose.
func PeerDir(fingerprint string) string {
	h := strings.TrimPrefix(fingerprint, "SHA256: ")
	h = strings.ReplaceAll(h, ":", "")
	h = strings.ToLower(strings.TrimSuffix(h, "…"))
	if len(h) > 16 {
		h = h[:16]
	}
	if h == "" {
		return "unknown"
	}
	return h
}

// Store owns the download directory for one peer.
type Store struct {
	dir string
}

// OpenStore prepares the download directory for a peer beneath root.
//
// MkdirAll neither re-permissions an existing directory nor refuses a symlink,
// so the result is checked: a symlinked download directory would let anyone
// who could plant it redirect every file this peer sends.
func OpenStore(root, fingerprint string) (*Store, error) {
	dir := filepath.Join(root, PeerDir(fingerprint))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("transfer: creating download directory: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("transfer: checking download directory: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("transfer: download path %s is not a directory", dir)
	}
	return &Store{dir: dir}, nil
}

// Dir reports the directory files land in.
func (s *Store) Dir() string { return s.dir }

// PartFile is an in-progress download.
type PartFile struct {
	store *Store
	// name is the sanitised filename this transfer will be published under.
	name string
	// partPath is where bytes accumulate until the digest is verified.
	partPath string

	f      *os.File
	w      *bufio.Writer
	digest hash.Hash

	mu      sync.Mutex
	written int64
	closed  bool
	// finalPath is set once the file has been published.
	finalPath string
}

// Create opens a .part file for a transfer.
//
// O_EXCL does two jobs: it refuses to follow a symlink someone planted at the
// path, and it makes "is this name free?" and "claim it" one atomic step. The
// alternative — Stat then Create — is a race a local attacker can win.
func (s *Store) Create(name string) (*PartFile, error) {
	safe, err := SafeName(name)
	if err != nil {
		return nil, err
	}
	// Keep the whole path within sane bounds; a deep root plus a 255-byte
	// name can otherwise fail halfway through a transfer.
	if len(filepath.Join(s.dir, safe))+len(".part") > 4000 {
		return nil, fmt.Errorf("%w: resulting path is too long", ErrBadName)
	}

	partPath, f, err := createUnique(s.dir, safe+".part")
	if err != nil {
		return nil, err
	}
	return &PartFile{
		store:    s,
		name:     safe,
		partPath: partPath,
		f:        f,
		w:        bufio.NewWriterSize(f, partWriterBuf),
		digest:   sha256.New(),
	}, nil
}

// createUnique creates a file under dir, suffixing the name until one is free.
// It returns the path it claimed.
func createUnique(dir, name string) (string, *os.File, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; i < maxCollisionTries; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d%s", stem, i, ext)
		}
		p := filepath.Join(dir, candidate)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return p, f, nil
		}
		// Only a collision is worth retrying. Anything else — a permission
		// problem, a missing directory — will not improve with a suffix.
		if !errors.Is(err, os.ErrExist) {
			return "", nil, fmt.Errorf("transfer: creating %s: %w", p, err)
		}
	}
	return "", nil, fmt.Errorf("transfer: no free name for %q after %d attempts", name, maxCollisionTries)
}

// Write appends a chunk, updating the running digest.
func (p *PartFile) Write(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("transfer: write to a closed file")
	}
	n, err := p.w.Write(b)
	if err != nil {
		return err
	}
	p.digest.Write(b[:n])
	p.written += int64(n)
	return nil
}

// Written reports how many bytes have been accepted so far. This is the value
// a chunk's offset must match.
func (p *PartFile) Written() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written
}

// Digest returns the SHA-256 of everything written so far.
func (p *PartFile) Digest() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.digest.Sum(nil)
}

// Name reports the sanitised name the file will be published under.
func (p *PartFile) Name() string { return p.name }

// Publish flushes, verifies the digest and moves the file into place.
//
// A mismatch is terminal: the partial file is removed and nothing is
// published, because a transfer that did not arrive intact must not be left
// where something might open it.
func (p *PartFile) Publish(want []byte) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return "", errors.New("transfer: publish of a closed file")
	}
	if err := p.w.Flush(); err != nil {
		p.discardLocked()
		return "", fmt.Errorf("transfer: flushing: %w", err)
	}
	if err := p.f.Close(); err != nil {
		p.discardLocked()
		return "", fmt.Errorf("transfer: closing: %w", err)
	}
	p.closed = true

	got := p.digest.Sum(nil)
	if len(want) != len(got) || !equalConstantish(got, want) {
		_ = os.Remove(p.partPath)
		return "", fmt.Errorf("transfer: digest mismatch for %s", DisplayName(p.name))
	}

	// Reserve the final name the same way the .part was claimed, then rename
	// onto it. os.Rename replaces an existing file on POSIX, so checking
	// first and renaming second would be a race; creating the target with
	// O_EXCL closes it, and also means the rename cannot land on a symlink.
	finalPath, f, err := createUnique(p.store.dir, p.name)
	if err != nil {
		_ = os.Remove(p.partPath)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(p.partPath)
		return "", err
	}
	if err := os.Rename(p.partPath, finalPath); err != nil {
		_ = os.Remove(p.partPath)
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("transfer: publishing: %w", err)
	}
	p.finalPath = finalPath
	return finalPath, nil
}

// Discard closes and removes the partial file. Safe to call more than once.
func (p *PartFile) Discard() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.discardLocked()
}

func (p *PartFile) discardLocked() {
	if !p.closed {
		_ = p.f.Close()
		p.closed = true
	}
	if p.finalPath == "" {
		_ = os.Remove(p.partPath)
	}
}

// equalConstantish compares digests without an early exit on the first
// differing byte. Digest comparison is not a secret-dependent operation here —
// both values are public — but a uniform comparison costs nothing and keeps
// the habit.
func equalConstantish(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
