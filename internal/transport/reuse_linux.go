//go:build linux

package transport

import "syscall"

// soReusePort is SO_REUSEPORT. The standard library's syscall package does not
// define it on Linux (it lives in golang.org/x/sys/unix, which Heimdall does
// not depend on), so the value is given directly. It is stable kernel ABI.
const soReusePort = 0x0F

// setReuse enables address and port reuse on a socket before it is bound.
//
// Hole punching requires binding a listener to the same local port that an
// established outbound connection is already using, so that the NAT mapping
// that connection created can be reused (docs/rendezvous.md §7). That is only
// permitted with both options set.
func setReuse(fd uintptr) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
}
