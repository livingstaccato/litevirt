//go:build !linux

package grpcapi

import "os"

// openLUNDirect opens a LUN's block device read-only. Only Linux has the
// direct read the probe prefers.
func openLUNDirect(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

// alignedBuffer is an n-byte buffer.
func alignedBuffer(n int) []byte { return make([]byte, n) }
