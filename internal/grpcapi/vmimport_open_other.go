//go:build !linux

package grpcapi

import (
	"os"
	"syscall"
)

// openImportSourceNoLinks has no openat2 off Linux; it refuses a link in the
// final component only.
func openImportSourceNoLinks(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
