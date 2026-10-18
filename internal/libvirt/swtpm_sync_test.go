package libvirt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// fakeFlags is an in-memory FS_IOC_GETFLAGS/SETFLAGS: the unit tests run on
// whatever filesystem holds t.TempDir(), which may not keep the flag.
type fakeFlags struct {
	flags   map[string]uint32
	inherit bool             // a file created during the pass takes its directory's sync flag (ext4, xfs)
	getErr  map[string]error // path → error from get
	setErr  error            // every set fails with this
	sets    []string
}

func newFakeFlags() *fakeFlags {
	return &fakeFlags{flags: map[string]uint32{}, getErr: map[string]error{}, inherit: true}
}

func (f *fakeFlags) get(path string) (uint32, error) {
	if err := f.getErr[path]; err != nil {
		return 0, err
	}
	if v, ok := f.flags[path]; ok {
		return v, nil
	}
	// Entries laid out before the pass hold no flags; the one file created
	// during it is the pass's inheritance probe.
	if f.inherit && strings.HasPrefix(filepath.Base(path), ".litevirt-sync-probe-") {
		if v, ok := f.flags[filepath.Dir(path)]; ok && v&fsSyncFlag != 0 {
			return fsSyncFlag, nil
		}
	}
	return 0, nil
}

func (f *fakeFlags) set(path string, v uint32) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.flags[path] = v
	f.sets = append(f.sets, path)
	return nil
}

func (f *fakeFlags) ops() swtpmFlagOps { return swtpmFlagOps{get: f.get, set: f.set} }

// swtpmTree lays out what libvirt and swtpm leave under the base: one VM's
// <uuid>/tpm2 with its state file and lock.
func swtpmTree(t *testing.T) (base, uuidDir, tpm2, state string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base = filepath.Join(dir, "swtpm")
	uuidDir = filepath.Join(base, "6362d835-f3cc-407e-946c-5067c4d007ef")
	tpm2 = filepath.Join(uuidDir, "tpm2")
	if err := os.MkdirAll(tpm2, 0o700); err != nil {
		t.Fatal(err)
	}
	state = filepath.Join(tpm2, "tpm2-00.permall")
	for _, f := range []string{state, filepath.Join(tpm2, ".lock")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return base, uuidDir, tpm2, state
}

func TestSwtpmSync_OnSetsTheFlagOnTheWholeTree(t *testing.T) {
	base, uuidDir, tpm2, state := swtpmTree(t)
	ff := newFakeFlags()
	ff.flags[state] = 0x80000 // an extents flag the pass must keep

	rep := syncSwtpmTree(base, true, ff.ops())
	if rep.State != SwtpmSyncOn || rep.Err != nil {
		t.Fatalf("report %+v, want %s with no error", rep, SwtpmSyncOn)
	}
	for _, p := range []string{base, uuidDir, tpm2, state, filepath.Join(tpm2, ".lock")} {
		if ff.flags[p]&fsSyncFlag == 0 {
			t.Errorf("%s has no sync flag after the pass", p)
		}
	}
	if ff.flags[state] != 0x80000|fsSyncFlag {
		t.Errorf("state file flags %#x, want the existing flags kept plus sync", ff.flags[state])
	}
	if rep.Changed != 5 {
		t.Errorf("changed %d entries, want 5", rep.Changed)
	}
}

func TestSwtpmSync_IsIdempotent(t *testing.T) {
	base, _, _, _ := swtpmTree(t)
	ff := newFakeFlags()
	syncSwtpmTree(base, true, ff.ops())
	ff.sets = nil
	rep := syncSwtpmTree(base, true, ff.ops())
	if rep.State != SwtpmSyncOn || rep.Changed != 0 || len(ff.sets) != 0 {
		t.Fatalf("second pass: report %+v, sets %v; want %s with nothing changed", rep, ff.sets, SwtpmSyncOn)
	}
}

// libvirt creates the base itself (0711) on a vTPM VM's first start; it must
// carry the flag before then, so the VM's <uuid>/tpm2 inherits it.
func TestSwtpmSync_OnCreatesAMissingBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "swtpm")
	ff := newFakeFlags()
	rep := syncSwtpmTree(base, true, ff.ops())
	if rep.State != SwtpmSyncOn {
		t.Fatalf("report %+v, want %s", rep, SwtpmSyncOn)
	}
	fi, err := os.Stat(base)
	if err != nil || !fi.IsDir() {
		t.Fatalf("base not created: %v", err)
	}
	if fi.Mode().Perm() != 0o711 {
		t.Errorf("base mode %v, want 0711 (libvirt's own)", fi.Mode().Perm())
	}
	if ff.flags[base]&fsSyncFlag == 0 {
		t.Errorf("created base has no sync flag")
	}
}

func TestSwtpmSync_OffClearsTheFlagAndCreatesNothing(t *testing.T) {
	base, uuidDir, tpm2, state := swtpmTree(t)
	ff := newFakeFlags()
	syncSwtpmTree(base, true, ff.ops())
	rep := syncSwtpmTree(base, false, ff.ops())
	if rep.State != SwtpmSyncOff || rep.Changed != 5 {
		t.Fatalf("report %+v, want %s with 5 changed", rep, SwtpmSyncOff)
	}
	for _, p := range []string{base, uuidDir, tpm2, state} {
		if ff.flags[p]&fsSyncFlag != 0 {
			t.Errorf("%s still has the sync flag", p)
		}
	}

	missing := filepath.Join(t.TempDir(), "swtpm")
	if rep := syncSwtpmTree(missing, false, newFakeFlags().ops()); rep.State != SwtpmSyncOff {
		t.Fatalf("off on a missing base: %+v", rep)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("off created the base: %v", err)
	}
}

// tmpfs and NFS refuse the flag: reported, and nothing below the base tried.
func TestSwtpmSync_UnsupportedFilesystemIsReported(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOTTY, syscall.EOPNOTSUPP, syscall.EINVAL} {
		base, _, _, _ := swtpmTree(t)
		ff := newFakeFlags()
		ff.getErr[base] = errno
		rep := syncSwtpmTree(base, true, ff.ops())
		if rep.State != SwtpmSyncUnsupported || !errors.Is(rep.Err, errno) {
			t.Errorf("%v: report %+v, want %s carrying the errno", errno, rep, SwtpmSyncUnsupported)
		}
		if len(ff.sets) != 0 {
			t.Errorf("%v: set %v on a filesystem that refused the flag", errno, ff.sets)
		}
	}
	base, _, _, _ := swtpmTree(t)
	ff := newFakeFlags()
	ff.setErr = syscall.EOPNOTSUPP
	if rep := syncSwtpmTree(base, true, ff.ops()); rep.State != SwtpmSyncUnsupported {
		t.Errorf("a set the filesystem refuses: report %+v, want %s", rep, SwtpmSyncUnsupported)
	}
}

// btrfs keeps the flag on a directory but a file created in it does not get
// it, and swtpm writes every state file as a new file.
func TestSwtpmSync_FlagNotInheritedIsReported(t *testing.T) {
	base, _, _, _ := swtpmTree(t)
	ff := newFakeFlags()
	ff.inherit = false
	rep := syncSwtpmTree(base, true, ff.ops())
	if rep.State != SwtpmSyncNotInherited || rep.Err == nil {
		t.Fatalf("report %+v, want %s with a reason", rep, SwtpmSyncNotInherited)
	}
	ents, _ := os.ReadDir(base)
	for _, e := range ents {
		if e.Name() != "6362d835-f3cc-407e-946c-5067c4d007ef" {
			t.Errorf("the inheritance probe left %s behind", e.Name())
		}
	}
}

// swtpm renames its state file while the pass walks: an entry gone between
// the listing and the ioctl is not a failure.
func TestSwtpmSync_EntryGoneMidPassIsSkipped(t *testing.T) {
	base, _, _, state := swtpmTree(t)
	ff := newFakeFlags()
	ff.getErr[state] = syscall.ENOENT
	if rep := syncSwtpmTree(base, true, ff.ops()); rep.State != SwtpmSyncOn {
		t.Fatalf("report %+v, want %s", rep, SwtpmSyncOn)
	}
}

func TestSwtpmSync_OtherErrorFails(t *testing.T) {
	base, _, _, state := swtpmTree(t)
	ff := newFakeFlags()
	ff.getErr[state] = syscall.EIO
	rep := syncSwtpmTree(base, true, ff.ops())
	if rep.State != SwtpmSyncFailed || !errors.Is(rep.Err, syscall.EIO) {
		t.Fatalf("report %+v, want %s carrying EIO", rep, SwtpmSyncFailed)
	}
}

// A symlink below the base is never followed; a base that is itself a symlink
// (state relocated to another volume) is walked at its target.
func TestSwtpmSync_Symlinks(t *testing.T) {
	base, _, tpm2, _ := swtpmTree(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tpm2, "link")); err != nil {
		t.Fatal(err)
	}
	ff := newFakeFlags()
	syncSwtpmTree(base, true, ff.ops())
	if _, touched := ff.flags[outside]; touched {
		t.Errorf("followed a symlink to %s", outside)
	}
	if _, touched := ff.flags[filepath.Join(tpm2, "link")]; touched {
		t.Errorf("set flags through a symlink")
	}

	linked := filepath.Join(t.TempDir(), "swtpm-link")
	if err := os.Symlink(base, linked); err != nil {
		t.Fatal(err)
	}
	ff = newFakeFlags()
	if rep := syncSwtpmTree(linked, true, ff.ops()); rep.State != SwtpmSyncOn {
		t.Fatalf("symlinked base: %+v", rep)
	}
	if ff.flags[tpm2]&fsSyncFlag == 0 {
		t.Errorf("symlinked base: its target's tree was not walked")
	}
}
