package transfer

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrBadName rejects a peer-supplied filename.
var ErrBadName = errors.New("transfer: unusable file name")

// maxNameLen bounds a stored filename in bytes. Matches proto.MaxFileNameLen,
// restated here so this file reads on its own.
const maxNameLen = 255

// reservedWindowsNames are device names Windows resolves anywhere in the
// filesystem, with or without an extension. Opening one does not create a
// file, so a transfer named for one would silently write to a device.
var reservedWindowsNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM0": true, "COM1": true, "COM2": true, "COM3": true, "COM4": true,
	"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT0": true, "LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
	"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
	"CLOCK$": true, "CONIN$": true, "CONOUT$": true,
}

// SafeName reduces a peer-supplied name to a single filename safe to create
// inside the download directory, or rejects it.
//
// The name arrives from the network and is never trusted: it is a label, not a
// path (docs/protocol.md §13.5). The rules are deliberately strict — a
// rejected transfer is a far better outcome than a file written somewhere
// unexpected — and they are all about *where* the bytes land, not what they
// contain.
func SafeName(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: not valid UTF-8", ErrBadName)
	}
	if len(name) == 0 || len(name) > maxNameLen {
		return "", fmt.Errorf("%w: length %d out of range", ErrBadName, len(name))
	}

	// Reject control and format characters before anything else looks at the
	// string. Two distinct problems live here: C0/C1 controls (a newline or
	// an ESC in a filename lets a peer forge log lines or drive the
	// terminal), and the bidi overrides, where U+202E turns a displayed
	// "invoice<RLO>cod.exe" into "invoiceexe.doc" and invites a click that
	// runs a program. Homoglyphs are not addressed here and cannot be;
	// quoting at display time is what covers those.
	for _, r := range name {
		if r == utf8.RuneError {
			return "", fmt.Errorf("%w: not valid UTF-8", ErrBadName)
		}
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return "", fmt.Errorf("%w: contains a control or formatting character", ErrBadName)
		}
	}

	// Any separator at all, in either convention, means the peer is naming a
	// path. Checked on the raw string rather than relying on filepath.Base,
	// whose behaviour differs between platforms for the other separator.
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("%w: contains a path separator", ErrBadName)
	}
	// A Windows drive or stream qualifier.
	if strings.Contains(name, ":") {
		return "", fmt.Errorf("%w: contains a colon", ErrBadName)
	}

	// filepath.Base now only normalises; it cannot strip a directory,
	// because there is no separator left to strip.
	base := filepath.Base(name)

	// Windows silently drops trailing dots and spaces, so "a.txt. " would be
	// created as "a.txt" — bypassing the collision handling that just proved
	// "a.txt" was free. Normalise before, not after, deciding.
	base = strings.TrimRight(base, ". ")
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("%w: resolves to no name", ErrBadName)
	}

	// Reserved device names match case-insensitively and regardless of
	// extension: CON, con.txt and AUX.tar.gz are all the device.
	stem := base
	if i := strings.Index(stem, "."); i >= 0 {
		stem = stem[:i]
	}
	if reservedWindowsNames[strings.ToUpper(stem)] {
		return "", fmt.Errorf("%w: %q is a reserved device name", ErrBadName, base)
	}

	if len(base) > maxNameLen {
		return "", fmt.Errorf("%w: length %d out of range", ErrBadName, len(base))
	}
	return base, nil
}

// DisplayName renders a peer-supplied string for a terminal.
//
// Everything a peer chose — a filename, a display name — goes through this
// before being printed. %q escapes control characters, so a name carrying an
// ESC sequence cannot retitle the window, clear the screen or hide its own
// extension. SafeName already refuses such names for files, but a refusal has
// to be reported, and reporting it is itself a print.
func DisplayName(s string) string { return fmt.Sprintf("%q", s) }
