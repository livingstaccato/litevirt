package grpcapi

import (
	"os"

	"golang.org/x/sys/unix"
)

// openImportSourceNoLinks opens p for reading with no symlink anywhere on the
// path (openat2 RESOLVE_NO_SYMLINKS): the path was authorized as resolved, and
// a link planted in any component since would reach another file. O_NONBLOCK
// keeps a FIFO from blocking the open; the caller refuses anything but a
// plain file.
func openImportSourceNoLinks(p string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, p, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	return os.NewFile(uintptr(fd), p), nil
}
