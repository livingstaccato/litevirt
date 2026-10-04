package lxc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"syscall"
)

// Guest rootfs writes.
//
// The daemon runs as root, and the contents of a container rootfs belong to
// whoever is root inside the container (or to whoever built the image it came
// from). Any path the daemon writes under a rootfs must therefore be resolved
// INSIDE that rootfs: a guest that replaces /etc/machine-id with a symlink to
// /etc/shadow, or /etc with a symlink to the host's /etc, must not be able to
// steer a host-side write. os.Root confines every component of the walk —
// absolute symlinks and ../ chains that would leave the root are errors — and
// the final component is replaced by rename, never opened through, so a
// symlink there is swapped for a regular file rather than followed.

// writeGuestFile replaces rel (slash-separated, relative to rootfs) with a
// regular file holding data. An existing regular file keeps its mode and
// owner; anything else at rel (a symlink, a fifo) is replaced, taking the
// owner of its parent directory so a uid-shifted container still owns it.
// With onlyIfExists, a missing rel is left missing.
func writeGuestFile(rootfs, rel string, data []byte, perm fs.FileMode, onlyIfExists bool) error {
	root, err := os.OpenRoot(rootfs)
	if err != nil {
		return fmt.Errorf("open guest rootfs %s: %w", rootfs, err)
	}
	defer root.Close()
	return writeRootFile(root, rel, data, perm, onlyIfExists)
}

func writeRootFile(root *os.Root, rel string, data []byte, perm fs.FileMode, onlyIfExists bool) error {
	uid, gid := -1, -1
	fi, err := root.Lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if onlyIfExists {
			return nil
		}
	case err != nil:
		return fmt.Errorf("guest %s: %w", rel, err)
	case fi.IsDir():
		return fmt.Errorf("guest %s is a directory", rel)
	case fi.Mode().IsRegular():
		perm = fi.Mode().Perm()
		uid, gid = ownerOf(fi)
	}
	if uid < 0 {
		if pfi, perr := root.Lstat(path.Dir(rel)); perr == nil {
			uid, gid = ownerOf(pfi)
		}
	}
	tmp := rel + ".litevirt-tmp"
	_ = root.Remove(tmp)
	// O_EXCL: os.Root never follows a final-component symlink under it.
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create guest %s: %w", tmp, err)
	}
	werr := func() error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		if uid >= 0 && os.Geteuid() == 0 {
			if err := f.Chown(uid, gid); err != nil {
				return err
			}
		}
		if err := f.Chmod(perm); err != nil { // undo umask
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		// rename(2) replaces the final component itself — a symlink at rel is
		// swapped out, never written through.
		werr = root.Rename(tmp, rel)
	}
	if werr != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("write guest %s: %w", rel, werr)
	}
	return nil
}

func ownerOf(fi fs.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
