//go:build linux

package network

import (
	"encoding/binary"
	"time"

	"golang.org/x/sys/unix"
)

// sendRawFrames writes frame, a whole Ethernet ARP frame, out of interface
// ifindex count times, gap apart, through an AF_PACKET socket that receives
// nothing (protocol 0); each frame is sent as ETH_P_ARP.
func sendRawFrames(ifindex int, frame []byte, count int, gap time.Duration) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrLinklayer{Protocol: htons(uint16(unix.ETH_P_ARP)), Ifindex: ifindex, Halen: 6}
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

// htons is v in network byte order, as the sockaddr wants it.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
