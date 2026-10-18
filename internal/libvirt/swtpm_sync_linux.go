//go:build linux

package libvirt

import (
	"golang.org/x/sys/unix"
)

// osSwtpmFlagOps reads and writes inode flags with FS_IOC_GETFLAGS and
// FS_IOC_SETFLAGS (what chattr does), never through a symlink.
var osSwtpmFlagOps = swtpmFlagOps{
	get: func(path string) (uint32, error) {
		fd, err := openForFlags(path)
		if err != nil {
			return 0, err
		}
		defer unix.Close(fd)
		return unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	},
	set: func(path string, flags uint32) error {
		fd, err := openForFlags(path)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags))
	},
}

func openForFlags(path string) (int, error) {
	return unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}
