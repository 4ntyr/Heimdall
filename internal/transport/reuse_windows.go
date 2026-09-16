//go:build windows

package transport

import "syscall"

// setReuse enables address reuse on a socket before it is bound.
//
// Windows has no SO_REUSEPORT; SO_REUSEADDR alone provides the binding
// behaviour hole punching needs there.
func setReuse(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
