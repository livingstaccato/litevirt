//go:build linux

package network

import (
	"time"

	"golang.org/x/sys/unix"
)

// sendRawFrames writes frame, a whole Ethernet frame, out of interface
// ifindex count times, gap apart, through an AF_PACKET socket that receives
// nothing (protocol 0).
func sendRawFrames(ifindex int, frame []byte, count int, gap time.Duration) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrLinklayer{Ifindex: ifindex, Halen: 6}
	copy(sa.Addr[:6], frame[0:6])
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(gap)
		}
		if err := unix.Sendto(fd, frame, 0, sa); err != nil {
			return err
		}
	}
	return nil
}
