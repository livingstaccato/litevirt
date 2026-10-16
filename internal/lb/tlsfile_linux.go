//go:build linux

package lb

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openTLSForRead opens resolved, which path resolved to, for reading only
// once its descriptor shows a regular file outside litevirt's own dirs.
//
// The first open is O_PATH|O_NOFOLLOW: it grants no I/O and never runs the
// file's own open, so a device or FIFO swapped in after the resolve is not
// touched, and a symlink there is the descriptor's own type, not followed.
// The read open goes through /proc/self/fd/N, which names the inode already
// checked, never the path again.
func (m *Manager) openTLSForRead(path, resolved string) (*os.File, error) {
	beforeTLSOpen()
	fd, err := unix.Open(resolved, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: resolved, Err: err}
	}
	defer unix.Close(fd)
	self := fmt.Sprintf("/proc/self/fd/%d", fd)
	opened, err := os.Readlink(self)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot tell which file was opened: %w", path, err)
	}
	if opened != resolved {
		return nil, fmt.Errorf("%s: resolved to %s, but %s was opened (changed while it was opened)", path, resolved, opened)
	}
	if err := m.checkNotProtected(path, opened); err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s: %s is not a regular file", path, opened)
	}
	if st.Size > maxTLSFile {
		return nil, fmt.Errorf("%s: %d bytes, over the %d-byte limit", path, st.Size, maxTLSFile)
	}
	f, err := os.OpenFile(self, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if rs, ok := fi.Sys().(*syscall.Stat_t); !ok || uint64(rs.Dev) != uint64(st.Dev) || uint64(rs.Ino) != uint64(st.Ino) {
		f.Close()
		return nil, fmt.Errorf("%s: the file opened for reading is not the one checked", path)
	}
	return f, nil
}
