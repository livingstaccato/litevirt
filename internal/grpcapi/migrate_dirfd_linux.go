//go:build linux

package grpcapi

import (
	"errors"

	"golang.org/x/sys/unix"
)

// openat2Beneath opens the single component name of dirfd as a directory with
// openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS. used is
// false when openat2 is not available here (kernel before 5.6, or a sandbox
// that refuses it): the caller takes the O_NOFOLLOW walk, which is the same rule.
func openat2Beneath(dirfd int, name string) (fd int, used bool, err error) {
	fd, err = unix.Openat2(dirfd, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil && (errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM)) {
		return -1, false, nil
	}
	return fd, true, err
}
