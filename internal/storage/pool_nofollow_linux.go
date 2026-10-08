//go:build linux

package storage

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openat2Beneath opens rel below root with openat2(RESOLVE_NO_SYMLINKS |
// RESOLVE_BENEATH): no symlink anywhere in rel is followed, and nothing
// escapes root. errNoOpenat2 on a kernel without it (before 5.6).
func openat2Beneath(root, rel string, flag int, perm os.FileMode, name string) (*os.File, error) {
	if openat2Disabled {
		return nil, errNoOpenat2
	}
	dfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	fd, err := unix.Openat2(dfd, rel, &unix.OpenHow{
		Flags:   uint64(flag | unix.O_CLOEXEC),
		Mode:    uint64(perm.Perm()),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if errors.Is(err, unix.ENOSYS) {
		return nil, errNoOpenat2
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// openat2Disabled makes openat2Beneath report a kernel without openat2, so a
// test exercises the O_NOFOLLOW walk.
var openat2Disabled = false

// kernelHasNosymfollow reports whether this kernel takes the nosymfollow
// mount flag (Linux 5.10+). A var for tests.
var kernelHasNosymfollow = func() bool {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return true // unknown: require it, as before
	}
	return kernelAtLeast(unix.ByteSliceToString(u.Release[:]), 5, 10)
}
