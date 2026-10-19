//go:build linux

package libvirt

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// osSwtpmFDOps reads and writes inode flags with FS_IOC_GETFLAGS and
// FS_IOC_SETFLAGS (what chattr does) on an fd the walk already holds.
var osSwtpmFDOps = swtpmFDOps{
	get: func(fd int) (uint32, error) { return unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS) },
	set: func(fd int, flags uint32) error {
		return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags))
	},
	fs: func(fd int, path string) (int64, []string, error) {
		var sfs unix.Statfs_t
		if err := unix.Fstatfs(fd, &sfs); err != nil {
			return 0, nil, err
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return 0, nil, err
		}
		f, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			return int64(sfs.Type), nil, nil
		}
		defer f.Close()
		return int64(sfs.Type), mountOptions(bufio.NewScanner(f), unix.Major(st.Dev), unix.Minor(st.Dev), path), nil
	},
}

// mountOptions is the per-mount and superblock options of the mountinfo entry
// for device major:minor whose mount point is the longest prefix of path.
func mountOptions(sc *bufio.Scanner, major, minor uint32, path string) []string {
	want := fmt.Sprintf("%d:%d", major, minor)
	best, bestLen := []string(nil), -1
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		sep := -1
		for i, v := range f {
			if v == "-" {
				sep = i
				break
			}
		}
		if len(f) < 6 || sep < 0 || len(f) < sep+4 || f[2] != want {
			continue
		}
		mp := f[4]
		if mp != "/" && path != mp && !strings.HasPrefix(path, mp+"/") {
			continue
		}
		if len(mp) > bestLen {
			bestLen = len(mp)
			best = append(strings.Split(f[5], ","), strings.Split(f[sep+3], ",")...)
		}
	}
	return best
}

// openFlags opens an entry for the flag ioctls: never through a symlink, never
// blocking on a fifo, never acquiring a terminal.
const openFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOCTTY

// syncSwtpmTree walks base by file descriptor: every child is opened with
// openat relative to its parent's fd and O_NOFOLLOW, what was opened is
// fstat'ed, and the ioctls run on that same fd. A directory the swtpm user
// swaps for a symlink mid-pass therefore cannot steer the pass out of the
// tree, and a directory on another filesystem is reported, not entered.
func syncSwtpmTree(base string, on bool, marker string, ops swtpmFDOps) SwtpmSyncReport {
	rep := SwtpmSyncReport{Base: base}
	fail := func(state string, err error) SwtpmSyncReport {
		rep.State, rep.Err = state, err
		return rep
	}
	markerSet := false
	if marker != "" {
		_, err := os.Lstat(marker)
		markerSet = err == nil
	}
	if !on && !markerSet {
		rep.State = SwtpmSyncOff // litevirt never set it here: leave it alone
		return rep
	}
	if on {
		if err := os.Mkdir(base, 0o711); err != nil && !errors.Is(err, fs.ErrExist) {
			return fail(SwtpmSyncFailed, err)
		}
	}
	root, err := filepath.EvalSymlinks(base)
	if !on && errors.Is(err, fs.ErrNotExist) {
		if rerr := os.Remove(marker); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return fail(SwtpmSyncFailed, rerr)
		}
		rep.State = SwtpmSyncOff
		return rep
	}
	if err != nil {
		return fail(SwtpmSyncFailed, err)
	}
	rep.Base = root
	bfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(SwtpmSyncFailed, fmt.Errorf("%s: %w", root, err))
	}
	defer unix.Close(bfd)
	var bst unix.Stat_t
	if err := unix.Fstat(bfd, &bst); err != nil {
		return fail(SwtpmSyncFailed, fmt.Errorf("%s: %w", root, err))
	}
	magic, opts, err := ops.fs(bfd, root)
	if err != nil {
		return fail(SwtpmSyncFailed, fmt.Errorf("%s: %w", root, err))
	}
	rep.FS = swtpmFSName(magic)

	w := &swtpmWalk{ops: ops, on: on, dev: uint64(bst.Dev), rep: &rep}
	if on && marker != "" && !markerSet {
		w.beforeSet = func() error { return writeSwtpmMarker(marker) }
	}
	if err := w.apply(bfd, root, true); err != nil {
		var unsup *unsupportedErr
		if errors.As(err, &unsup) {
			return fail(SwtpmSyncUnsupported, err)
		}
		return fail(SwtpmSyncFailed, err)
	}
	if err := w.dir(bfd, root); err != nil {
		return fail(SwtpmSyncFailed, err)
	}
	if !on {
		if err := w.errs.err(); err != nil {
			return fail(SwtpmSyncFailed, err) // keep the marker: the next pass retries
		}
		if err := os.Remove(marker); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fail(SwtpmSyncFailed, err)
		}
		rep.State = SwtpmSyncOff
		return rep
	}

	// The attribute is only worth anything if swtpm's next state file, a new
	// file, gets it: create one the same way and look.
	inherited, err := probeInherit(bfd, ops)
	switch {
	case err != nil && flagUnsupported(err):
		return fail(SwtpmSyncUnsupported, fmt.Errorf("%s: %w", root, err))
	case err != nil:
		return fail(SwtpmSyncFailed, fmt.Errorf("%s: %w", root, err))
	case !inherited:
		return fail(SwtpmSyncNotInherited, fmt.Errorf("a file created in %s (%s) does not inherit the sync attribute", root, rep.FS))
	case !renameSynchronous(magic, opts):
		return fail(SwtpmSyncRenameNotSynchronous, fmt.Errorf("%s (%s, mount options %s) does not commit a rename synchronously "+
			"for the sync attribute", root, rep.FS, strings.Join(opts, ",")))
	}
	if err := w.errs.err(); err != nil {
		return fail(SwtpmSyncFailed, err)
	}
	rep.State = SwtpmSyncOn
	return rep
}

type swtpmWalk struct {
	ops       swtpmFDOps
	on        bool
	dev       uint64
	rep       *SwtpmSyncReport
	beforeSet func() error // once, before the first set
	errs      entryErrs
}

// apply sets or clears the attribute on fd. A refusal of the flags on the base
// is the filesystem's (unsupportedErr); anywhere else it is that entry's.
// Only a failure to write the marker stops the pass.
func (w *swtpmWalk) apply(fd int, path string, isBase bool) error {
	fl, err := w.ops.get(fd)
	if err == nil {
		want := fl &^ fsSyncFlag
		if w.on {
			want = fl | fsSyncFlag
		}
		if want == fl {
			return nil
		}
		if w.beforeSet != nil {
			if err := w.beforeSet(); err != nil {
				return fmt.Errorf("record that litevirt sets the sync attribute: %w", err)
			}
			w.beforeSet = nil
		}
		if err = w.ops.set(fd, want); err == nil {
			w.rep.Changed++
			return nil
		}
	}
	if isBase {
		if flagUnsupported(err) {
			return fmt.Errorf("%s: %w", path, &unsupportedErr{err})
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	w.errs.add(path, err)
	return nil
}

// dir lists the directory dfd holds and handles each entry through an fd
// opened relative to dfd.
func (w *swtpmWalk) dir(dfd int, path string) error {
	dup, err := unix.Dup(dfd)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), path)
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		w.errs.add(path, err)
		return nil
	}
	sort.Strings(names)
	if w.ops.afterList != nil {
		w.ops.afterList(path)
	}
	for _, name := range names {
		if err := w.entry(dfd, path, name); err != nil {
			return err
		}
	}
	return nil
}

func (w *swtpmWalk) entry(dfd int, dir, name string) error {
	path := filepath.Join(dir, name)
	fd, err := unix.Openat(dfd, name, openFlags, 0)
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENXIO):
		return nil // renamed away, or a symlink or socket now: never followed
	case err != nil:
		w.errs.add(path, err)
		return nil
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		w.errs.add(path, err)
		return nil
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		dev := uint64(st.Dev)
		if w.ops.devOf != nil {
			dev = w.ops.devOf(st.Ino, dev)
		}
		if dev != w.dev {
			w.errs.add(path, errors.New("on another filesystem than the base; not entered"))
			return nil
		}
		if err := w.apply(fd, path, false); err != nil {
			return err
		}
		return w.dir(fd, path)
	case unix.S_IFREG:
		return w.apply(fd, path, false)
	}
	return nil // fifo, device: not swtpm state
}

// probeInherit creates a file in the directory dfd holds, the way swtpm
// creates its state files, and reports whether it carries the attribute.
func probeInherit(dfd int, ops swtpmFDOps) (bool, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false, err
	}
	name := ".litevirt-sync-probe-" + hex.EncodeToString(b[:])
	fd, err := unix.Openat(dfd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return false, err
	}
	fl, gerr := ops.get(fd)
	unix.Close(fd)
	if err := unix.Unlinkat(dfd, name, 0); err != nil && gerr == nil {
		gerr = err
	}
	if gerr != nil {
		return false, gerr
	}
	return fl&fsSyncFlag != 0, nil
}
