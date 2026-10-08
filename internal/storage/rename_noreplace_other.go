//go:build !linux

package storage

import (
	"os"
	"syscall"
)

// renameNoReplace has no renameat2 off Linux: it refuses (EINVAL) rather than
// fall back to a rename that could replace newpath.
func renameNoReplace(oldpath, newpath string) error {
	return &os.LinkError{Op: "renameat2", Old: oldpath, New: newpath, Err: syscall.EINVAL}
}
