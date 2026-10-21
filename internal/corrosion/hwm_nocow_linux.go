//go:build linux

package corrosion

import "golang.org/x/sys/unix"

// fsNoCOWFL is FS_NOCOW_FL from linux/fs.h ('C' in chattr), which x/sys/unix
// does not define.
const fsNoCOWFL = 0x00800000

// setNoCOW marks f no-copy-on-write, best effort, through FS_IOC_GETFLAGS and
// FS_IOC_SETFLAGS as chattr +C does (the swtpm sync attribute in
// internal/libvirt/swtpm_sync_linux.go uses the same calls). On btrfs it makes
// an in-place overwrite reuse the file's blocks, so an hwm save needs no new
// space there either. A filesystem without the flag (ext4, xfs: ENOTTY or
// EOPNOTSUPP) needs none of it, and ZFS has no equivalent; every error is
// ignored.
func setNoCOW(f hwmFile) {
	fd := int(f.Fd())
	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if err != nil || flags&fsNoCOWFL != 0 {
		return
	}
	_ = unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags|fsNoCOWFL))
}
