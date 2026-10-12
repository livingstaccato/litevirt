package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// Mounted: the pool's own export is mounted at Dir.
	Mounted bool
	// Foreign names what else is mounted at Dir (another export, another
	// filesystem); empty when nothing is, or the pool's export is.
	Foreign string
	// OnNFS: Dir is no mount point, but lies inside another NFS mount (an
	// operator mounted a parent export by hand). Such a pool is left as it
	// is: its files are reachable, and a mount there would hide them.
	OnNFS bool
}

// CheckNFSPoolMount reads, from the mount table only (nothing on the export
// is touched, so a server that does not answer cannot hang it), whether an
// nfs pool's export is mounted at its mount point.
func CheckNFSPoolMount(dataDir string, cfg Config) (NFSPoolMount, error) {
	out := NFSPoolMount{Dir: NFSPoolMountDir(dataDir, cfg)}
	if !strings.EqualFold(cfg.Driver, "nfs") {
		return out, fmt.Errorf("pool driver %q has no NFS mount", cfg.Driver)
	}
	t, err := ReadMountTable()
	if err != nil {
		return out, err
	}
	var top mountEntry
	found := false
	for _, e := range t.all {
		if e.dir == out.Dir {
			top, found = e, true
		}
	}
	if !found {
		if b, berr := t.NFSBackingOf(out.Dir); berr == nil && b != nil {
			out.OnNFS = true
		}
		return out, nil
	}
	want, werr := ParseNFSExport(cfg.Source)
	got, gerr := ParseNFSExport(top.source)
	if werr != nil || gerr != nil || got != want || !isNFSFstype(top.fstype) {
		out.Foreign = mountedWhat(top)
		return out, nil
	}
	out.Mounted = true
	return out, nil
}

// nfsRemountRun runs MountNFSPool's mount commands; tests replace it (nil:
// the real commands).
var nfsRemountRun cmdRunner

// MountNFSPool mounts an nfs pool's export at its mount point, with the
// options and hardening a pool create mounts it with (nfsDriver.Prepare). It
// refuses, with the reason, a mount point that is a symlink or not a
// directory, or a directory that holds anything: the mount would hide it.
func MountNFSPool(ctx context.Context, dataDir string, cfg Config) error {
	if !strings.EqualFold(cfg.Driver, "nfs") {
		return fmt.Errorf("pool driver %q has no NFS mount", cfg.Driver)
	}
	dir := NFSPoolMountDir(dataDir, cfg)
	if err := nfsMountPointUsable(dir); err != nil {
		return err
	}
	drv, err := New(dataDir, cfg)
	if err != nil {
		return err
	}
	d, ok := drv.(*nfsDriver)
	if !ok {
		return fmt.Errorf("pool driver %q has no NFS mount", cfg.Driver)
	}
	if nfsRemountRun != nil {
		d.run = nfsRemountRun
	}
	return d.Prepare(ctx)
}

// nfsMountPointUsable refuses a mount point a mount would hide something
// under, or that would put the mount somewhere else: a symlink, a
// non-directory, or a directory with entries. A missing one is fine (Prepare
// creates it).
func nfsMountPointUsable(dir string) error {
	fi, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect mount point %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("mount point %s is a symlink; litevirt does not mount an NFS pool through one (the mount would land where it points): replace it with an empty directory", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("mount point %s is not a directory", dir)
	}
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("inspect mount point %s: %w", dir, err)
	}
	names, err := f.Readdirnames(6)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("inspect mount point %s: %w", dir, err)
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	shown := names
	if len(shown) > 5 {
		shown = append(shown[:5:5], "…")
	}
	return fmt.Errorf("mount point %s is not mounted and holds local files (%s); litevirt does not mount the export over them, which would hide them: move them out of %s (they were written while the export was not mounted, so they are not on it)",
		dir, strings.Join(shown, ", "), dir)
}

// OverrideNFSMountCommandForTest replaces how MountNFSPool runs mountpoint
// and mount, for tests in other packages. It returns the restore function.
func OverrideNFSMountCommandForTest(run func(ctx context.Context, name string, args ...string) ([]byte, error)) func() {
	prev := nfsRemountRun
	nfsRemountRun = run
	return func() { nfsRemountRun = prev }
}
