package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// NFS mounts after a reboot. An nfs pool's export is mounted by the pool's
// Prepare (pool create, disk create, move, replicate), and nothing else
// mounted it: after a host reboot the mount point was an empty local
// directory, the pool still read active, and a VM start on it failed with
// "No such file". CheckNFSPoolMount and MountNFSPool are what the daemon runs,
// at start and periodically, for each nfs pool of the host (and before a VM
// with a disk on one starts on it).
//
// MountNFSPool mounts only onto an empty, real directory: never through a
// symlink (the mount would land wherever it points), and never over a
// directory holding anything, which the mount would hide (a file written
// there while the export was not mounted is local data, not the pool's).

// NFSPoolMountDir is where an nfs pool's export is mounted on this host: its
// Target, or <data_dir>/mounts/<source>.
func NFSPoolMountDir(dataDir string, cfg Config) string {
	if cfg.Target != "" {
		return filepath.Clean(cfg.Target)
	}
	return filepath.Join(dataDir, "mounts", NFSMountName(cfg.Source))
}

// NFSPoolMount is what this host's mount table says of an nfs pool's mount
// point.
type NFSPoolMount struct {
	// Dir is the pool's mount point.
	Dir string
	// Mounted: an NFS filesystem is mounted at Dir. It is the pool's export,
	// or (Other) another spelling of it or another export, mounted by hand:
	// its files are there, and the pool's own check at use judges whether it
	// is the pool's (CheckNFSMountHardened).
	Mounted bool
	// Other names the NFS mount at Dir when its source is not the pool's
	// export as the pool spells it; empty otherwise.
	Other string
	// Foreign names a mount at Dir that is not NFS at all; empty when there
	// is none.
	Foreign string
	// OnNFS: Dir is no mount point, but lies inside another NFS mount (an
	// operator mounted a parent export by hand). Such a pool is left as it
	// is: its files are reachable, and a mount there would hide them.
	OnNFS bool
}

// The bound on resolving the symlinks of a pool mount point's parent, and the
// resolver (a test seam). A parent whose path is lexically on no NFS mount
// can still reach one through a symlink, and following that symlink stats
// the NFS server, which may not answer.
var (
	nfsResolveBound  = newTestHook(5 * time.Second)
	resolveNFSParent = newTestHook(resolveExisting)
	nfsResolving     sync.Map // path -> *nfsResolveCall
)

type nfsResolveCall struct {
	done chan struct{}
	out  string
}

// boundedResolve resolves p's symlinks, giving up after nfsResolveBound. A
// resolution that blocks is not started again while it is still running, so
// a server that never answers leaves one stuck goroutine per path, not one
// per check.
func boundedResolve(p string) (string, error) {
	resolve, bound := resolveNFSParent.get(), nfsResolveBound.get()
	v, running := nfsResolving.LoadOrStore(p, &nfsResolveCall{done: make(chan struct{})})
	c := v.(*nfsResolveCall)
	if !running {
		go func() {
			c.out = resolve(p)
			close(c.done)
			nfsResolving.Delete(p)
		}()
	}
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-c.done:
		return c.out, nil
	case <-timer.C:
		return "", fmt.Errorf("resolving the symlinks of %s did not finish within %v (a symlink into an NFS mount whose server does not answer?)", p, bound)
	}
}

// CheckNFSPoolMount reads, from the mount table, whether an nfs pool's export
// is mounted at its mount point. Whether the mount point lies inside another
// NFS mount is judged from the path as written first, with no system call; only
// when that finds none are the symlinks of its parent resolved, and that is
// bounded (boundedResolve), so a server that does not answer cannot hang it
// for longer than nfsResolveBound.
func CheckNFSPoolMount(dataDir string, cfg Config) (NFSPoolMount, error) {
	out := NFSPoolMount{Dir: NFSPoolMountDir(dataDir, cfg)}
	if !strings.EqualFold(cfg.Driver, "nfs") {
		return out, fmt.Errorf("pool driver %q has no NFS mount", cfg.Driver)
	}
	t, err := ReadMountTable()
	if err != nil {
		return out, err
	}
	if t.judgeNFSPoolMount(&out, out.Dir, cfg.Source) {
		return out, nil
	}
	parent := filepath.Dir(out.Dir)
	r, err := boundedResolve(parent)
	if err != nil {
		return out, err
	}
	if r != parent {
		t.judgeNFSPoolMount(&out, filepath.Join(r, filepath.Base(out.Dir)), cfg.Source)
	}
	return out, nil
}

// judgeNFSPoolMount fills m from what the table has at, or around, dir (as
// written: no system call). It reports whether it found a mount at dir or
// an NFS mount containing it.
func (t MountTable) judgeNFSPoolMount(m *NFSPoolMount, dir, source string) bool {
	var top, under mountEntry
	found := false
	for _, e := range t.all {
		if e.dir == dir {
			top, found = e, true
		}
		// The deepest mount containing dir; the last of equal depth is on top.
		if e.dir != dir && within(e.dir, dir) && len(e.dir) >= len(under.dir) {
			under = e
		}
	}
	switch {
	case found && isNFSFstype(top.fstype):
		m.Mounted = true
		want, werr := ParseNFSExport(source)
		got, gerr := ParseNFSExport(top.source)
		if werr != nil || gerr != nil || got != want {
			m.Other = mountedWhat(top)
		}
		return true
	case found:
		m.Foreign = mountedWhat(top)
		return true
	case isNFSFstype(under.fstype):
		m.OnNFS = true
		return true
	}
	return false
}

// Test seams: the runner of MountNFSPool's commands (nil: the real ones), and
// how a mount point's entries are listed.
var (
	nfsRemountRun cmdRunner
	nfsListDir    = func(f *os.File) ([]string, error) {
		names, err := f.Readdirnames(6)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		return names, err
	}
)

// nfsRunner is the runner an nfs driver's commands use.
func nfsRunner() cmdRunner {
	if nfsRemountRun != nil {
		return nfsRemountRun
	}
	return realCmd
}

// MountNFSPool mounts an nfs pool's export at its mount point, with the
// options and hardening a pool create mounts it with (nfsDriver.Prepare). It
// refuses, with the reason, a mount point that is a symlink or not a
// directory, or a directory that holds anything: the mount would hide it.
//
// The mount point is opened (O_NOFOLLOW|O_DIRECTORY) and judged through that
// descriptor, which is kept across the mount. After the mount it must hold
// an NFS mount, and the directory under it — read through the descriptor —
// must still be empty; a file written there in between is unmounted again
// and refused. mount(8) takes a path, so a mount point replaced by a symlink
// between the open and the mount is not caught before the mount, only after
// it (the mount point then holds no mount, and the refusal says so).
func MountNFSPool(ctx context.Context, dataDir string, cfg Config) error {
	if !strings.EqualFold(cfg.Driver, "nfs") {
		return fmt.Errorf("pool driver %q has no NFS mount", cfg.Driver)
	}
	dir := NFSPoolMountDir(dataDir, cfg)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return fmt.Errorf("create the parent of mount point %s: %w", dir, err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create mount point %s: %w", dir, err)
	}
	f, err := openMountPoint(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	names, err := listMountPoint(f)
	if err != nil {
		return fmt.Errorf("inspect mount point %s: %w", dir, err)
	}
	if len(names) > 0 {
		// A concurrent Prepare may have mounted the export meanwhile: then
		// these are its files.
		if st, cerr := CheckNFSPoolMount(dataDir, cfg); cerr == nil && st.Mounted {
			return nil
		}
		return localFilesError(dir, names)
	}
	drv, err := New(dataDir, cfg)
	if err != nil {
		return err
	}
	d, ok := drv.(*nfsDriver)
	if !ok {
		return fmt.Errorf("pool driver %q has no NFS mount", cfg.Driver)
	}
	if err := d.Prepare(ctx); err != nil {
		return err
	}
	st, err := CheckNFSPoolMount(dataDir, cfg)
	if err == nil && !st.Mounted {
		return fmt.Errorf("after the mount, %s holds no NFS mount; the mount point was replaced while it was mounted (a symlink?), so the mount landed elsewhere: check `findmnt -S %s`", dir, cfg.Source)
	}
	if late, lerr := listMountPoint(f); lerr == nil && len(late) > 0 {
		// A fresh bound: the caller's context may be spent by the mount.
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultNFSCommandTimeout)
		out, uerr := nfsRunner()(uctx, "umount", "--", dir)
		invalidateMountCache()
		cancel()
		if uerr != nil {
			return fmt.Errorf("%w; it could not be unmounted again (%v: %s), so the export now hides them: umount %s",
				localFilesError(dir, late), uerr, trimmedNFSCommandOutput(out), dir)
		}
		return fmt.Errorf("%w (they were written while it was being mounted; unmounted again)", localFilesError(dir, late))
	}
	return nil
}

// AdoptionStagePrefix names the staging mount points an earlier test build
// made in <data_dir>/mounts to judge a pool it did not trust. No build
// mounts there now; SweepAdoptionStages removes what one left.
const AdoptionStagePrefix = ".adopt-"

// SweepAdoptionStages unmounts and removes the staging mount points an
// earlier test build left in <data_dir>/mounts (AdoptionStagePrefix): only
// entries directly in mounts/ with that name prefix that are real
// directories — a symlink is never followed, nor anything below mounts/
// touched. A mounted one is unmounted (umount --no-canonicalize, lazily when
// busy), then the directory is removed if empty. It returns what it could
// not clean, for the caller to log.
func SweepAdoptionStages(ctx context.Context, dataDir string) []error {
	mounts := filepath.Join(dataDir, "mounts")
	ents, err := os.ReadDir(mounts)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []error{fmt.Errorf("list %s: %w", mounts, err)}
	}
	var errs []error
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), AdoptionStagePrefix) || e.Type()&fs.ModeSymlink != 0 || !e.IsDir() {
			continue
		}
		dir := filepath.Join(mounts, e.Name())
		if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
			continue
		}
		if IsMountPoint(dir) {
			if err := umountStage(ctx, dir, false); err != nil {
				if lerr := umountStage(ctx, dir, true); lerr != nil {
					errs = append(errs, fmt.Errorf("unmount %s: %v; lazily: %v", dir, err, lerr))
					continue
				}
			}
		}
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s: %w", dir, err))
		}
	}
	return errs
}

func umountStage(ctx context.Context, dir string, lazy bool) error {
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultNFSCommandTimeout)
	defer cancel()
	args := []string{"--no-canonicalize", "--", dir}
	if lazy {
		args = append([]string{"-l"}, args...)
	}
	out, err := nfsRunner()(uctx, "umount", args...)
	invalidateMountCache()
	if err != nil {
		return fmt.Errorf("%v: %s", err, trimmedNFSCommandOutput(out))
	}
	return nil
}

// openMountPoint opens dir as a directory, following no symlink at its last
// component.
func openMountPoint(dir string) (*os.File, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOTDIR) {
		// Linux answers O_NOFOLLOW|O_DIRECTORY on a symlink with ENOTDIR.
		if fi, lerr := os.Lstat(dir); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			err = syscall.ELOOP
		}
	}
	switch {
	case err == nil:
		return f, nil
	case errors.Is(err, syscall.ELOOP):
		return nil, fmt.Errorf("mount point %s is a symlink; litevirt does not mount an NFS pool through one (the mount would land where it points): replace it with an empty directory", dir)
	case errors.Is(err, syscall.ENOTDIR):
		return nil, fmt.Errorf("mount point %s is not a directory", dir)
	}
	return nil, fmt.Errorf("open mount point %s: %w", dir, err)
}

// listMountPoint lists (some of) the entries of the directory f was opened
// on, from the start, through a duplicate of its descriptor: after a mount
// over it, that is still the directory under the mount.
func listMountPoint(f *os.File) ([]string, error) {
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	g := os.NewFile(uintptr(fd), f.Name())
	defer g.Close()
	if _, err := g.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return nfsListDir(g)
}

func localFilesError(dir string, names []string) error {
	sort.Strings(names)
	shown := names
	if len(shown) > 5 {
		shown = append(shown[:5:5], "…")
	}
	return fmt.Errorf("mount point %s is not mounted and holds local files (%s); litevirt does not mount the export over them, which would hide them: move them out of %s (they were written while the export was not mounted, so they are not on it)",
		dir, strings.Join(shown, ", "), dir)
}

// OverrideNFSMountCommandForTest replaces how an nfs driver runs mountpoint,
// mount and umount, for tests in other packages. It returns the restore
// function.
func OverrideNFSMountCommandForTest(run func(ctx context.Context, name string, args ...string) ([]byte, error)) func() {
	prev := nfsRemountRun
	nfsRemountRun = run
	return func() { nfsRemountRun = prev }
}

// OverrideNFSPathResolverForTest replaces how CheckNFSPoolMount resolves a
// mount point's parent, and its bound, for tests in other packages. It
// returns the restore function.
func OverrideNFSPathResolverForTest(resolve func(string) string, bound time.Duration) func() {
	restoreR, restoreB := resolveNFSParent.set(resolve), nfsResolveBound.set(bound)
	return func() { restoreR(); restoreB() }
}
