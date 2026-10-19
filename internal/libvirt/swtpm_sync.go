package libvirt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// vTPM state durability. swtpm (through 0.10) writes a vTPM's state as a temp
// file renamed over the old one, with no fsync of either: a guest's TPM write
// waits in the host page cache until the next journal commit, and a host power
// cut loses it. The sync attribute (chattr +S, FS_SYNC_FL) on libvirt's swtpm
// tree, which a file or directory created there inherits, makes ext4 write the
// file and commit the rename before the call returns, so a TPM command
// completes only once its state is on disk. xfs honours it for the data but
// commits a create or rename synchronously only on a dirsync or wsync
// mount, so elsewhere it is reported, not trusted.

// SyncSwtpmState's outcomes.
const (
	// SwtpmSyncOn: the tree has the attribute, a new file inherits it, and the
	// filesystem then writes the file and the rename synchronously.
	SwtpmSyncOn = "synchronous"
	// SwtpmSyncOff: vtpm_state_sync is off, and the attribute litevirt set (if
	// any) is cleared.
	SwtpmSyncOff = "off"
	// SwtpmSyncUnsupported: the filesystem refuses the attribute (tmpfs, NFS,
	// ZFS).
	SwtpmSyncUnsupported = "unsupported"
	// SwtpmSyncNotInherited: the filesystem keeps the attribute but a file
	// created under it does not get it (btrfs), and swtpm writes every state
	// file as a new file.
	SwtpmSyncNotInherited = "not_inherited"
	// SwtpmSyncRenameNotSynchronous: the attribute is inherited and makes the
	// data synchronous, but the filesystem does not commit the rename that
	// replaces the state file synchronously (xfs without dirsync or
	// wsync; any filesystem not known to).
	SwtpmSyncRenameNotSynchronous = "rename_not_synchronous"
	// SwtpmSyncFailed: the pass could not read or set some entry, or could not
	// run at all.
	SwtpmSyncFailed = "failed"
)

// fsSyncFlag is FS_SYNC_FL.
const fsSyncFlag uint32 = 0x00000008

// Filesystem magics (statfs f_type) the pass names.
const (
	fsMagicExt4  = 0xef53
	fsMagicXFS   = 0x58465342
	fsMagicBtrfs = 0x9123683e
	fsMagicTmpfs = 0x01021994
	fsMagicNFS   = 0x6969
	fsMagicZFS   = 0x2fc12fc1
)

// swtpmFSName names a filesystem magic for the report and its remedy.
func swtpmFSName(magic int64) string {
	switch magic {
	case fsMagicExt4:
		return "ext4"
	case fsMagicXFS:
		return "xfs"
	case fsMagicBtrfs:
		return "btrfs"
	case fsMagicTmpfs:
		return "tmpfs"
	case fsMagicNFS:
		return "nfs"
	case fsMagicZFS:
		return "zfs"
	}
	return fmt.Sprintf("0x%x", magic)
}

// renameSynchronous reports whether a filesystem with the inherited
// attribute also commits a create and a rename before they return: ext4 does
// for a directory with it (IS_DIRSYNC); xfs only with its dirsync or wsync
// feature (its transactions never look at the inode flag; a mount-time sync
// sets wsync and shows it).
func renameSynchronous(magic int64, mountOpts []string) bool {
	switch magic {
	case fsMagicExt4:
		return true
	case fsMagicXFS:
		for _, o := range mountOpts {
			// Not a bare "sync": remount,sync sets it on the superblock but
			// not xfs's wsync feature, which mount-time sync also shows.
			if o == "dirsync" || o == "wsync" {
				return true
			}
		}
	}
	return false
}

// SwtpmSyncReport is one pass over the swtpm tree.
type SwtpmSyncReport struct {
	State string
	// Base is the tree's root, symlinks resolved.
	Base string
	// FS names the base's filesystem ("ext4", "xfs", ..., or its magic).
	FS string
	// Changed counts the entries whose attribute the pass set or cleared.
	Changed int
	// Err says why for any State but SwtpmSyncOn and SwtpmSyncOff, and carries
	// the entries the pass could not handle (it goes on past them).
	Err error
}

// SyncSwtpmState sets the sync attribute on libvirt's swtpm tree (on), or
// clears it (off). On creates the base (0711, as libvirt does) when it is
// missing, so the first vTPM VM's state directory inherits the attribute, and
// writes marker before it first sets anything. Off clears the tree only while
// marker says litevirt set it, then removes marker, so an attribute set by
// hand on a host litevirt never protected stays. Idempotent; it touches only
// entries whose attribute differs.
func SyncSwtpmState(on bool, marker string) SwtpmSyncReport {
	return syncSwtpmTree(libvirtSwtpmBase, on, marker, osSwtpmFDOps)
}

// swtpmFDOps is what the walk does to an fd it opened: read and write its
// inode flags, and name its filesystem.
type swtpmFDOps struct {
	get func(fd int) (uint32, error)
	set func(fd int, flags uint32) error
	// fs is the statfs magic and the mount options of the filesystem fd (at
	// path) is on.
	fs func(fd int, path string) (int64, []string, error)
	// afterList, for tests, runs once a directory's entries are listed.
	afterList func(dir string)
	// beforeOpen, for tests, runs between an entry's fstatat and its open.
	beforeOpen func(path string)
	// devOf, for tests, maps an opened directory's (inode, st_dev) to the
	// device the walk compares with the base's.
	devOf func(ino, dev uint64) uint64
}

type unsupportedErr struct{ error }

func (e *unsupportedErr) Unwrap() error { return e.error }

// flagUnsupported: the filesystem has no inode flags, or not this one.
func flagUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOTTY) || errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EINVAL) || errors.Is(err, errFlagsUnavailable)
}

// errFlagsUnavailable: this platform has no inode flags.
var errFlagsUnavailable = errors.New("inode flags are not available on this platform")

// writeSwtpmMarker records that litevirt set the attribute, durably.
func writeSwtpmMarker(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString("litevirt set the sync attribute on " + libvirtSwtpmBase + " (vtpm_state_sync)\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return syncDirFn(filepath.Dir(path))
}

// removeSwtpmMarker removes the marker and makes that durable.
func removeSwtpmMarker(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDirFn(filepath.Dir(path))
}

// syncDirFn fsyncs a directory; tests wrap it to see which ones are.
var syncDirFn = syncDir

// maxSwtpmDepth is how many directory levels below the base the pass enters:
// libvirt's layout is <base>/<uuid>/tpm2/<file>, two levels, plus one of
// margin. A deeper directory is reported and never opened, so the pass holds
// at most a few fds and a bounded path, however deep the swtpm user nests.
const maxSwtpmDepth = 3

// maxSwtpmDirEntries bounds what the pass lists of one directory: a host's
// base holds one entry per vTPM VM, a VM's directories a handful. A var so
// tests can lower it.
var maxSwtpmDirEntries = 100000

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// entryErrs collects the entries a pass could not handle; it reports the
// first few and the count.
type entryErrs struct {
	n     int
	first []string
}

func (e *entryErrs) add(path string, err error) {
	e.n++
	if len(e.first) < 5 {
		e.first = append(e.first, fmt.Sprintf("%s: %v", path, err))
	}
}

func (e *entryErrs) err() error {
	if e.n == 0 {
		return nil
	}
	msg := strings.Join(e.first, "; ")
	if e.n > len(e.first) {
		msg += fmt.Sprintf("; and %d more", e.n-len(e.first))
	}
	return errors.New(msg)
}
