//go:build !linux

package pitoverlay

import (
	"errors"
	"syscall"
)

// Only Linux hosts run VMs; elsewhere the package builds, with no xattrs.

func osSetXattr(string, []byte) error { return syscall.ENOTSUP }

func osGetXattr(string) ([]byte, error) { return nil, syscall.ENOTSUP }

func osDirFSType(string) (int64, error) { return 0, nil }

var errNoAttr = errors.New("no such attribute")
