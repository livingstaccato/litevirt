//go:build unix

package fleet

import (
	"fmt"
	"net"
	"syscall"
)

// portHoldSupported: holdPort works here.
const portHoldSupported = true

// holdPort binds a TCP socket to addr:port with SO_REUSEADDR and does not
// listen on it, and returns the function that closes it.
func holdPort(addr string, port int) (func(), error) {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		return nil, fmt.Errorf("hold port: %q is not an IPv4 address", addr)
	}
	// Under ForkLock, as the net package does, so no fork between the two
	// calls can inherit the fd.
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	sa := &syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip)
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return func() { _ = syscall.Close(fd) }, nil
}
