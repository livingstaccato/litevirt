//go:build !linux

package grpcapi

import (
	"os"
	"syscall"
)

// renameNoReplace has no renameat2 off Linux. It fails with EINVAL, the answer
// of a filesystem that cannot do RENAME_NOREPLACE, so placeColdDisk refuses
// rather than fall back to a rename that could replace a file.
func renameNoReplace(oldpath, newpath string) error {
	return &os.LinkError{Op: "renameat2", Old: oldpath, New: newpath, Err: syscall.EINVAL}
}
