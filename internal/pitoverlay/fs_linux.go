//go:build linux

package pitoverlay

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func osSetXattr(path string, val []byte) error {
	return unix.Setxattr(path, xattrName, val, 0)
}

func osGetXattr(path string) ([]byte, error) {
	buf := make([]byte, 128)
	n, err := unix.Getxattr(path, xattrName, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// osDirFSType is the filesystem magic (statfs f_type) of dir.
func osDirFSType(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Type), nil
}

// errNoAttr is getxattr's "the file has no such attribute".
var errNoAttr error = unix.ENODATA
