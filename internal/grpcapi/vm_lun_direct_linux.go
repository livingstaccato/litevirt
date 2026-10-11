//go:build linux

package grpcapi

import (
	"os"
	"syscall"
	"unsafe"
)

// openLUNDirect opens a LUN's block device read-only with O_DIRECT, so the
// blank probe reads the device and not stale pages this host's cache holds
// for it. A device or filesystem that refuses O_DIRECT is opened normally.
func openLUNDirect(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECT, 0)
	if err == nil {
		return f, nil
	}
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// alignedBuffer is an n-byte buffer aligned to 4 KiB, as a direct read needs.
func alignedBuffer(n int) []byte {
	const align = 4096
	b := make([]byte, n+align)
	off := int(uintptr(unsafe.Pointer(&b[0])) & (align - 1))
	if off != 0 {
		off = align - off
	}
	return b[off : off+n]
}
