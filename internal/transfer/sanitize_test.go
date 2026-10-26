package transfer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSafeNameRejectsHostileNames is the corpus that matters most in this
// package: with files accepted automatically, the filename is the only thing a
// peer chooses that reaches the filesystem.
//
// The repo avoids table-driven tests, but thirty near-identical assertions
// written out longhand would obscure rather than clarify what is covered, so
// this one loops over a literal list.
func TestSafeNameRejectsHostileNames(t *testing.T) {
	rejected := []struct {
		in, why string
	}{
		{"", "empty"},
		{".", "current directory"},
		{"..", "parent directory"},
		{"...", "trims to empty"},
		{"../../etc/passwd", "traversal"},
		{"..\\..\\windows\\system32", "windows traversal"},
		{"/etc/passwd", "absolute posix path"},
		{"/", "root"},
		{"sub/dir.txt", "forward separator"},
		{"sub\\dir.txt", "backslash separator"},
		{"C:\\evil.exe", "drive letter"},
		{"file.txt:stream", "ntfs stream"},
		{"a\x00b", "embedded NUL"},
		{"a\nb.txt", "newline"},
		{"a\rb.txt", "carriage return"},
		{"a\tb.txt", "tab"},
		{"\x1b]0;pwned\x07.txt", "terminal escape"},
		{"evil\u202Etxt.exe", "right-to-left override"},
		{"evil\u202Dtxt.exe", "left-to-right override"},
		{"a\u200Eb.txt", "left-to-right mark"},
		{"a\u2066b.txt", "isolate"},
		{"a\uFEFFb.txt", "zero-width no-break space"},
		{"CON", "reserved device"},
		{"con", "reserved device, lowercase"},
		{"CON.txt", "reserved device with extension"},
		{"aux.tar.gz", "reserved device with two extensions"},
		{"COM1", "reserved serial port"},
		{"lpt9.log", "reserved printer port"},
		{"NUL", "reserved null device"},
		{"CLOCK$", "reserved clock device"},
		{"conin$.txt", "reserved console input"},
		{". ", "dot and space trims to empty"},
		{"....", "only dots"},
		{strings.Repeat("n", 256), "over the length cap"},
		{"\xff\xfe.txt", "invalid UTF-8"},
	}

	for _, c := range rejected {
		got, err := SafeName(c.in)
		if err == nil {
			t.Errorf("SafeName(%q) returned %q, want rejection (%s)", c.in, got, c.why)
			continue
		}
		if !errors.Is(err, ErrBadName) {
			t.Errorf("SafeName(%q): got %v, want ErrBadName", c.in, err)
		}
	}
}

// TestSafeNameAcceptsOrdinaryNames guards against the rules being so strict
// they reject real files.
func TestSafeNameAcceptsOrdinaryNames(t *testing.T) {
	accepted := map[string]string{
		"report.pdf":             "report.pdf",
		"quarterly report.xlsx":  "quarterly report.xlsx",
		"a.tar.gz":               "a.tar.gz",
		".hidden":                ".hidden",
		"no-extension":           "no-extension",
		"ünïcödé.txt":            "ünïcödé.txt",
		"日本語.txt":                "日本語.txt",
		"emoji-🎉.png":            "emoji-🎉.png",
		"CONTACT.txt":            "CONTACT.txt", // not CON
		"COM.txt":                "COM.txt",     // not COM1
		"file.txt. ":             "file.txt",    // trailing dot and space stripped
		strings.Repeat("n", 255): strings.Repeat("n", 255),
	}
	for in, want := range accepted {
		got, err := SafeName(in)
		if err != nil {
			t.Errorf("SafeName(%q) was rejected: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSafeNameStripsTrailingDotsBeforeDeciding covers the Windows-specific
// trap: the platform drops trailing dots and spaces itself, so "a.txt. "
// would be created as "a.txt" — overwriting a file the collision check had
// just confirmed was a different name.
func TestSafeNameStripsTrailingDotsBeforeDeciding(t *testing.T) {
	got, err := SafeName("a.txt. ")
	if err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
	if got != "a.txt" {
		t.Fatalf("SafeName(%q) = %q, want %q", "a.txt. ", got, "a.txt")
	}
}

// TestDisplayNameQuotes is the other half of filename safety: a refusal has to
// be reported, and reporting it means printing a name the peer chose.
func TestDisplayNameQuotes(t *testing.T) {
	got := DisplayName("\x1b]0;pwned\x07")
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("DisplayName left a raw escape in %q", got)
	}
	if got := DisplayName("evil\u202Etxt.exe"); !strings.Contains(got, `\u202e`) {
		t.Fatalf("DisplayName did not escape the bidi override: %s", got)
	}
}

// TestPeerDirIsPathSafe pins the download directory name. The fingerprint
// string itself is not usable: it carries a space and 31 colons, neither of
// which is legal in a Windows path component.
func TestPeerDirIsPathSafe(t *testing.T) {
	got := PeerDir("SHA256: AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89")
	if strings.ContainsAny(got, ": /\\") {
		t.Fatalf("PeerDir returned %q, which is not a safe path component", got)
	}
	if got != "abcdef0123456789" {
		t.Fatalf("PeerDir = %q, want %q", got, "abcdef0123456789")
	}
	if PeerDir("") == "" {
		t.Fatal("PeerDir returned an empty path component")
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir(), "SHA256: AB:CD")
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	return s
}

// TestStoreRejectsSymlinkedDownloadDir covers what MkdirAll does not: it
// neither re-permissions an existing directory nor refuses a symlink, so a
// planted link would redirect everything a peer sends.
func TestStoreRejectsSymlinkedDownloadDir(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()
	peer := PeerDir("SHA256: AB:CD")
	if err := os.Symlink(elsewhere, filepath.Join(root, peer)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := OpenStore(root, "SHA256: AB:CD"); err == nil {
		t.Fatal("a symlinked download directory was accepted")
	}
}

// TestPartFileRoundTrip is the happy path: bytes in, digest verified, file
// published with restrictive permissions.
func TestPartFileRoundTrip(t *testing.T) {
	s := newStore(t)
	p, err := s.Create("report.pdf")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	body := bytes.Repeat([]byte("abc"), 1000)
	if err := p.Write(body); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := p.Written(); got != int64(len(body)) {
		t.Fatalf("Written = %d, want %d", got, len(body))
	}
	sum := sha256.Sum256(body)
	path, err := p.Publish(sum[:])
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading published file: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("published %d bytes, wrote %d", len(got), len(body))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("published file mode %v, want 0600", fi.Mode().Perm())
	}
	// No .part left behind.
	if entries, _ := os.ReadDir(s.Dir()); len(entries) != 1 {
		t.Fatalf("%d files in the download directory, want 1", len(entries))
	}
}

// TestPartFileDigestMismatchPublishesNothing is the last line against a
// truncated or tampered transfer. A file that did not arrive intact must not
// be left anywhere something might open it.
func TestPartFileDigestMismatchPublishesNothing(t *testing.T) {
	s := newStore(t)
	p, err := s.Create("report.pdf")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := p.Write([]byte("actual contents")); err != nil {
		t.Fatalf("write: %v", err)
	}
	wrong := sha256.Sum256([]byte("different contents"))
	if _, err := p.Publish(wrong[:]); err == nil {
		t.Fatal("a mismatched digest was published")
	}
	entries, err := os.ReadDir(s.Dir())
	if err != nil {
		t.Fatalf("reading download directory: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("mismatch left files behind: %v", names)
	}
}

// TestPartFileDiscardRemovesPartial covers the cancel and error paths.
func TestPartFileDiscardRemovesPartial(t *testing.T) {
	s := newStore(t)
	p, err := s.Create("x.bin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := p.Write([]byte("partial")); err != nil {
		t.Fatalf("write: %v", err)
	}
	p.Discard()
	p.Discard() // must be safe twice
	if entries, _ := os.ReadDir(s.Dir()); len(entries) != 0 {
		t.Fatalf("Discard left %d files behind", len(entries))
	}
}

// TestCreateNeverOverwrites is why O_EXCL is used rather than Stat-then-create:
// an existing file must survive, and the new one must get its own name.
func TestCreateNeverOverwrites(t *testing.T) {
	s := newStore(t)
	existing := filepath.Join(s.Dir(), "report.pdf")
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	p, err := s.Create("report.pdf")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	body := []byte("replacement")
	if err := p.Write(body); err != nil {
		t.Fatalf("write: %v", err)
	}
	sum := sha256.Sum256(body)
	path, err := p.Publish(sum[:])
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if path == existing {
		t.Fatal("the existing file was overwritten")
	}
	kept, err := os.ReadFile(existing)
	if err != nil || string(kept) != "original" {
		t.Fatalf("original file was disturbed: %q, %v", kept, err)
	}
	if filepath.Base(path) != "report-1.pdf" {
		t.Fatalf("collision produced %q, want report-1.pdf", filepath.Base(path))
	}
}

// TestCreateRefusesPlantedSymlink is the other thing O_EXCL buys: a link left
// at the .part path must not be followed.
func TestCreateRefusesPlantedSymlink(t *testing.T) {
	s := newStore(t)
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.Symlink(target, filepath.Join(s.Dir(), "x.bin.part")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p, err := s.Create("x.bin")
	if err != nil {
		// Refusing outright is fine.
		return
	}
	// Otherwise it must have chosen a different name, not followed the link.
	if err := p.Write([]byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	p.Discard()
	if _, err := os.Stat(target); err == nil {
		t.Fatal("writing followed a planted symlink")
	}
}
