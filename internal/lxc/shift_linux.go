//go:build linux

package lxc

import (
	"golang.org/x/sys/unix"
)

// getXattr reads an extended attribute of p without following a symlink; nil
// when it is absent or cannot be read.
func getXattr(p, name string) []byte {
	sz, err := unix.Lgetxattr(p, name, nil)
	if err != nil || sz <= 0 {
		return nil
	}
	buf := make([]byte, sz)
	n, err := unix.Lgetxattr(p, name, buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func setXattr(p, name string, v []byte) error { return unix.Lsetxattr(p, name, v, 0) }

// idmappableFS reports whether dir is on a filesystem with idmapped-mount
// support on every kernel this build asks for (5.19+): ext4, xfs or btrfs.
func idmappableFS(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	switch st.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC:
		return true
	}
	return false
}
