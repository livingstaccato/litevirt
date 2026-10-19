//go:build linux

package libvirt

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
		mp := unescapeMountinfo(f[4])
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

// unescapeMountinfo decodes the octal escapes (\040 for a space, \011,
// \012, \134) mountinfo writes in a path.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
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
		if rerr := removeSwtpmMarker(marker); rerr != nil {
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
		w.beforeSet = func() error { return writeSwtpmMarker(marker, base) }
	}
	if err := w.apply(bfd, root, true); err != nil {
		var unsup *unsupportedErr
		if errors.As(err, &unsup) {
			return fail(SwtpmSyncUnsupported, err)
		}
		return fail(SwtpmSyncFailed, err)
	}
	if err := w.dir(bfd, root, 0); err != nil {
		return fail(SwtpmSyncFailed, err)
	}
	if !on {
		if err := w.errs.err(); err != nil {
			return fail(SwtpmSyncFailed, err) // keep the marker: the next pass retries
		}
		if err := removeSwtpmMarker(marker); err != nil {
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

// dir lists the directory dfd holds, depth levels below the base, and
// handles each entry through an fd opened relative to dfd.
func (w *swtpmWalk) dir(dfd int, path string, depth int) error {
	dup, err := unix.Dup(dfd)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), path)
	names, err := f.Readdirnames(maxSwtpmDirEntries + 1)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		w.errs.add(path, err)
		return nil
	}
	if len(names) > maxSwtpmDirEntries {
		w.errs.add(path, fmt.Errorf("more than %d entries; not entered", maxSwtpmDirEntries))
		return nil
	}
	sort.Strings(names)
	if w.ops.afterList != nil {
		w.ops.afterList(path)
	}
	for _, name := range names {
		if err := w.entry(dfd, path, name, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// entry handles one name in the directory dfd holds, depth levels below the
// base. Its type comes from fstatat before anything is opened, so a fifo or
// a device node is never opened; a directory deeper than libvirt's layout, a
// directory on another filesystem and a hard-linked file are reported and
// never opened; and what is opened must be the inode fstatat saw.
func (w *swtpmWalk) entry(dfd int, dir, name string, depth int) error {
	path := filepath.Join(dir, name)
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			w.errs.add(path, err)
		}
		return nil
	}
	kind := st.Mode & unix.S_IFMT
	switch kind {
	case unix.S_IFDIR:
		if depth > maxSwtpmDepth {
			w.errs.add(path, fmt.Errorf("deeper than %d levels below the base; not entered", maxSwtpmDepth))
			return nil
		}
		dev := uint64(st.Dev)
		if w.ops.devOf != nil {
			dev = w.ops.devOf(st.Ino, dev)
		}
		if dev != w.dev {
			w.errs.add(path, errors.New("on another filesystem than the base; not entered"))
			return nil
		}
	case unix.S_IFREG:
		if st.Nlink != 1 {
			w.errs.add(path, fmt.Errorf("hard link (%d links); not touched", st.Nlink))
			return nil
		}
	default:
		return nil // symlink, fifo, socket, device: not swtpm state, never opened
	}
	if w.ops.beforeOpen != nil {
		w.ops.beforeOpen(path)
	}
	fd, err := unix.Openat(dfd, name, openFlags, 0)
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENXIO):
		return nil // swapped or renamed away since fstatat: never followed
	case err != nil:
		w.errs.add(path, err)
		return nil
	}
	defer unix.Close(fd)
	var ost unix.Stat_t
	if err := unix.Fstat(fd, &ost); err != nil {
		w.errs.add(path, err)
		return nil
	}
	if ost.Dev != st.Dev || ost.Ino != st.Ino || ost.Mode&unix.S_IFMT != kind {
		return nil // swapped between fstatat and the open: not what was checked
	}
	if kind == unix.S_IFREG {
		if ost.Nlink != 1 {
			w.errs.add(path, fmt.Errorf("hard link (%d links); not touched", ost.Nlink))
			return nil
		}
		return w.apply(fd, path, false)
	}
	if err := w.apply(fd, path, false); err != nil {
		return err
	}
	return w.dir(fd, path, depth)
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
