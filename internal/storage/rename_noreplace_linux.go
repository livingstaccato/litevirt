//go:build linux

package storage

import (
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldpath to newpath, failing with an error
// satisfying errors.Is(err, fs.ErrExist) if newpath exists (renameat2
// RENAME_NOREPLACE): nothing at newpath is ever replaced.
func renameNoReplace(oldpath, newpath string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE); err != nil {
		return &os.LinkError{Op: "renameat2", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}
