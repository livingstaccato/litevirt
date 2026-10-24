package qcow2

import (
	"fmt"
	"os"
	"syscall"
)

// openResolvedNoFollow opens a path that was already resolved through symlinks
// (and judged by the caller) without following any link now: O_NOFOLLOW on the
// final component, a regular file by fstat, and the open file must still be
// named by that path (readlink of /proc/self/fd/N), so a directory on the way
// swapped for a link after the judgement is refused as well. Where /proc cannot
// name the file it fails closed. Reads go through the returned file only.
func openResolvedNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	named, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil || named != path {
		f.Close()
		return nil, fmt.Errorf("%s changed while it was opened (now %q)", path, named)
	}
	return f, nil
}
