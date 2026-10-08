//go:build linux

package safename

import (
	"errors"

	"golang.org/x/sys/unix"
)

var lsetxattr = func(p, name string, v []byte) error { return unix.Lsetxattr(p, name, v, 0) }

func errorsIsNotSupported(err error) bool { return errors.Is(err, unix.ENOTSUP) }
