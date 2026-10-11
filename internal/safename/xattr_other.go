//go:build !linux

package safename

import (
	"errors"
	"os"
	"time"
)

// lutimes sets a path's times; off Linux a symlink's own times are left alone.
var lutimes = func(p string, atime, mtime time.Time) error {
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	return os.Chtimes(p, atime, mtime)
}

var errNoXattr = errors.New("extended attributes are not supported on this platform")

var lsetxattr = func(string, string, []byte) error { return errNoXattr }

func errorsIsNotSupported(err error) bool { return errors.Is(err, errNoXattr) }

func cannotStoreHere(_ string, err error) bool { return errorsIsNotSupported(err) }
