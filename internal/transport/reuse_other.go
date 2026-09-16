//go:build !linux && !windows && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package transport

// setReuse is a no-op on platforms without socket-option support. Hole
// punching will simply not succeed there; the relay path is unaffected, so
// connectivity is preserved either way (docs/rendezvous.md §0).
func setReuse(uintptr) error { return nil }
