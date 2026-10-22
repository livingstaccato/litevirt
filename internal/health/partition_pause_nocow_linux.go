package health

import (
	"os"

	"golang.org/x/sys/unix"
)

// fsNoCOWFlag is FS_NOCOW_FL (chattr +C), from linux/fs.h.
const fsNoCOWFlag = 0x00800000

// setNoCOW asks the filesystem to overwrite f's blocks in place (FS_NOCOW_FL)
// rather than copy them on write. btrfs honours it on a file that is still
// empty; ext4 and xfs overwrite in place already and refuse the flag. Best
// effort: an error leaves the file as it was.
func setNoCOW(f *os.File) error {
	fd := int(f.Fd())
	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags|fsNoCOWFlag))
}
