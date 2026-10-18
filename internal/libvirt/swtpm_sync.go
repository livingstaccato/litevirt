package libvirt

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// vTPM state durability. swtpm (through 0.10) writes a vTPM's state as a temp
// file renamed over the old one, with no fsync of either: a guest's TPM write
// waits in the host page cache until the next journal commit, and a host power
// cut loses it. The sync attribute (chattr +S, FS_SYNC_FL) on libvirt's swtpm
// tree makes the filesystem write the file and the rename synchronously, so a
// TPM command completes only once its state is on disk. A file or directory
// created in a directory that has it inherits it on ext4 and xfs.

// SyncSwtpmState's outcomes.
const (
	// SwtpmSyncOn: the tree has the attribute and a new file inherits it.
	SwtpmSyncOn = "synchronous"
	// SwtpmSyncOff: the attribute is cleared (vtpm_state_sync: false).
	SwtpmSyncOff = "off"
	// SwtpmSyncUnsupported: the filesystem refuses the attribute (tmpfs, NFS).
	SwtpmSyncUnsupported = "unsupported"
	// SwtpmSyncNotInherited: the filesystem keeps the attribute but a file
	// created under it does not get it (btrfs), and swtpm writes every state
	// file as a new file.
	SwtpmSyncNotInherited = "not_inherited"
	// SwtpmSyncFailed: an entry could not be read or set.
	SwtpmSyncFailed = "failed"
)

// fsSyncFlag is FS_SYNC_FL.
const fsSyncFlag uint32 = 0x00000008

// SwtpmSyncReport is one pass over the swtpm tree.
type SwtpmSyncReport struct {
	State string
	// Base is the tree's root, symlinks resolved.
	Base string
	// Changed counts the entries whose attribute the pass set or cleared.
	Changed int
	// Err says why for any State but SwtpmSyncOn and SwtpmSyncOff.
	Err error
}

// swtpmFlagOps reads and writes an entry's inode flags.
type swtpmFlagOps struct {
	get func(path string) (uint32, error)
	set func(path string, flags uint32) error
}

// SyncSwtpmState sets the sync attribute on libvirt's swtpm tree (on), or
// clears it (off). On creates the base (0711, as libvirt does) when it is
// missing, so the first vTPM VM's state directory inherits the attribute. It
// is idempotent and touches only entries whose attribute differs.
func SyncSwtpmState(on bool) SwtpmSyncReport {
	return syncSwtpmTree(libvirtSwtpmBase, on, osSwtpmFlagOps)
}

func syncSwtpmTree(base string, on bool, ops swtpmFlagOps) SwtpmSyncReport {
	rep := SwtpmSyncReport{Base: base}
	fail := func(state string, err error) SwtpmSyncReport {
		rep.State, rep.Err = state, err
		return rep
	}
	if on {
		if err := os.Mkdir(base, 0o711); err != nil && !errors.Is(err, fs.ErrExist) {
			return fail(SwtpmSyncFailed, err)
		}
	}
	root, err := filepath.EvalSymlinks(base)
	switch {
	case !on && errors.Is(err, fs.ErrNotExist):
		rep.State = SwtpmSyncOff
		return rep
	case err != nil:
		return fail(SwtpmSyncFailed, err)
	}
	rep.Base = root

	var walkErr error
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path != root && errors.Is(err, fs.ErrNotExist) {
				return nil // swtpm renamed or removed it mid-pass
			}
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil // never through a symlink, never a socket or fifo
		}
		fl, err := ops.get(path)
		if err == nil {
			want := fl &^ fsSyncFlag
			if on {
				want = fl | fsSyncFlag
			}
			if want == fl {
				return nil
			}
			if err = ops.set(path, want); err == nil {
				rep.Changed++
				return nil
			}
		}
		switch {
		case path != root && errors.Is(err, fs.ErrNotExist):
			return nil
		case flagUnsupported(err):
			return fmt.Errorf("%s: %w", path, &unsupportedErr{err})
		default:
			walkErr = fmt.Errorf("%s: %w", path, err)
			return filepath.SkipAll
		}
	})
	var unsup *unsupportedErr
	switch {
	case errors.As(err, &unsup):
		return fail(SwtpmSyncUnsupported, err)
	case err != nil:
		return fail(SwtpmSyncFailed, err)
	case walkErr != nil:
		return fail(SwtpmSyncFailed, walkErr)
	}
	if !on {
		rep.State = SwtpmSyncOff
		return rep
	}

	// The attribute is only worth anything if swtpm's next state file, a new
	// file, gets it: create one the same way and look.
	probe, err := os.CreateTemp(root, ".litevirt-sync-probe-*")
	if err != nil {
		return fail(SwtpmSyncFailed, err)
	}
	name := probe.Name()
	probe.Close()
	fl, err := ops.get(name)
	os.Remove(name)
	switch {
	case flagUnsupported(err):
		return fail(SwtpmSyncUnsupported, fmt.Errorf("%s: %w", name, err))
	case err != nil:
		return fail(SwtpmSyncFailed, fmt.Errorf("%s: %w", name, err))
	case fl&fsSyncFlag == 0:
		return fail(SwtpmSyncNotInherited, fmt.Errorf("a file created in %s does not inherit the sync attribute", root))
	}
	rep.State = SwtpmSyncOn
	return rep
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
