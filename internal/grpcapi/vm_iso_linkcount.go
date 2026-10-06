package grpcapi

import (
	"fmt"
	"os"
	"syscall"
)

// linkCount reports the file's hard-link count where the platform exposes it.
func linkCount(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}

// fileInode reports the file's inode number where the platform exposes it.
func fileInode(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true
}

// openNoFollow opens path read-only, refusing a symlink as its last component
// at the moment of the open (O_NOFOLLOW), and returns the open file and what
// it is. The path the kernel actually opened is reported where the platform
// can tell (/proc/self/fd), so a directory swapped for a link higher up shows
// too; elsewhere openedAs is "".
func openNoFollow(path string) (f *os.File, fi os.FileInfo, openedAs string, err error) {
	f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, "", err
	}
	fi, err = f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, "", err
	}
	if real, rerr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd())); rerr == nil {
		openedAs = real
	}
	return f, fi, openedAs, nil
}
