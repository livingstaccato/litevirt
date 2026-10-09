//go:build linux

package storage

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// cloneFile makes out a clone of in: a reflink (FICLONE) where the filesystem
// shares extents (btrfs, within one filesystem), otherwise a plain copy.
func cloneFile(out, in *os.File) error {
	err := unix.IoctlFileClone(int(out.Fd()), int(in.Fd()))
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EXDEV) &&
		!errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTTY) && !errors.Is(err, unix.ENOSYS) {
		return err
	}
	_, err = io.Copy(out, in)
	return err
}
