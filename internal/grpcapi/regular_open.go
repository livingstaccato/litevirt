package grpcapi

import (
	"fmt"
	"os"
	"syscall"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// openRegularNoFollow opens path for reading with no link followed at its
// final component and without blocking (O_NOFOLLOW|O_NONBLOCK: a FIFO or a
// device opens at once, it does not wait), and keeps it only when fstat shows
// a regular file. Whatever the caller then reads, it reads through the
// returned file, so the file judged is the file read.
func openRegularNoFollow(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, fi, nil
}

// infoNoFollow is qcow2.Info of the regular file at path, read through
// openRegularNoFollow.
func infoNoFollow(path string) (*qcow2.ImageInfo, error) {
	f, _, err := openRegularNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return qcow2.InfoFile(f)
}
