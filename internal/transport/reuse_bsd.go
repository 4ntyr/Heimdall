//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package transport

import "syscall"

// setReuse enables address and port reuse on a socket before it is bound.
// The BSDs define SO_REUSEPORT in the standard library's syscall package.
func setReuse(fd uintptr) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
}
