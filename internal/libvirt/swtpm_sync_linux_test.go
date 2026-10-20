//go:build linux

package libvirt

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeFlags is an in-memory FS_IOC_GETFLAGS/SETFLAGS keyed by inode: the unit
// tests run on whatever filesystem holds t.TempDir(), which may not keep the
// flag. The walk's opens, listings and fstats are real.
type fakeFlags struct {
	flags   map[uint64]uint32
	inherit bool // the probe file takes its directory's sync flag (ext4, xfs)
	getErr  map[uint64]error
	setErr  error
	sets    map[uint64]bool
	baseIno uint64
	magic   int64
	opts    []string
	after   func(dir string)
	before  func(path string)
	t       *testing.T
}

func newFakeFlags(t *testing.T) *fakeFlags {
	return &fakeFlags{t: t, flags: map[uint64]uint32{}, getErr: map[uint64]error{}, sets: map[uint64]bool{},
		inherit: true, magic: fsMagicExt4}
}

func ino(fd int) (uint64, string) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		panic(err)
	}
	p, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	return st.Ino, p
}

func pathIno(t *testing.T, p string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

func (f *fakeFlags) ops() swtpmFDOps {
	return swtpmFDOps{
		get: func(fd int) (uint32, error) {
			i, p := ino(fd)
			if err := f.getErr[i]; err != nil {
				return 0, err
			}
			if v, ok := f.flags[i]; ok {
				return v, nil
			}
			if f.inherit && strings.HasPrefix(filepath.Base(p), ".litevirt-sync-probe-") && f.flags[f.baseIno]&fsSyncFlag != 0 {
				return fsSyncFlag, nil
			}
			return 0, nil
		},
		set: func(fd int, v uint32) error {
			if f.setErr != nil {
				return f.setErr
			}
			i, _ := ino(fd)
			f.flags[i] = v
			f.sets[i] = true
			return nil
		},
		fs: func(fd int, path string) (int64, []string, error) {
			i, _ := ino(fd)
			f.baseIno = i
			return f.magic, f.opts, nil
		},
		afterList: func(dir string) {
			if f.after != nil {
				f.after(dir)
			}
		},
		beforeOpen: func(path string) {
			if f.before != nil {
				f.before(path)
			}
		},
	}
}

func (f *fakeFlags) has(t *testing.T, p string) bool {
	t.Helper()
	return f.flags[pathIno(t, p)]&fsSyncFlag != 0
}

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

func markerIn(t *testing.T) string { return filepath.Join(t.TempDir(), "vtpm-state-sync") }

func TestSwtpmSync_OnSetsTheFlagOnTheWholeTreeAndWritesTheMarker(t *testing.T) {
	base, uuidDir, tpm2, state := swtpmTree(t)
	ff := newFakeFlags(t)
	ff.flags[pathIno(t, state)] = 0x80000 // an extents flag the pass must keep
	marker := markerIn(t)

	rep := syncSwtpmTree(base, true, marker, ff.ops())
	if rep.State != SwtpmSyncOn || rep.Err != nil || rep.FS != "ext4" {
		t.Fatalf("report %+v, want %s on ext4 with no error", rep, SwtpmSyncOn)
	}
	for _, p := range []string{base, uuidDir, tpm2, state, filepath.Join(tpm2, ".lock")} {
		if !ff.has(t, p) {
			t.Errorf("%s has no sync flag after the pass", p)
		}
	}
	if got := ff.flags[pathIno(t, state)]; got != 0x80000|fsSyncFlag {
		t.Errorf("state file flags %#x, want the existing flags kept plus sync", got)
	}
	if rep.Changed != 5 {
		t.Errorf("changed %d entries, want 5", rep.Changed)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("no marker after a pass that set the attribute: %v", err)
	}
}

func TestSwtpmSync_IsIdempotent(t *testing.T) {
	base, _, _, _ := swtpmTree(t)
	ff := newFakeFlags(t)
	marker := markerIn(t)
	syncSwtpmTree(base, true, marker, ff.ops())
	ff.sets = map[uint64]bool{}
	rep := syncSwtpmTree(base, true, marker, ff.ops())
	if rep.State != SwtpmSyncOn || rep.Changed != 0 || len(ff.sets) != 0 {
		t.Fatalf("second pass: report %+v, sets %v; want %s with nothing changed", rep, ff.sets, SwtpmSyncOn)
	}
}

// libvirt creates the base itself (0711) on a vTPM VM's first start; it must
// carry the flag before then, so the VM's <uuid>/tpm2 inherits it.
func TestSwtpmSync_OnCreatesAMissingBase(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	base := filepath.Join(dir, "swtpm")
	ff := newFakeFlags(t)
	rep := syncSwtpmTree(base, true, markerIn(t), ff.ops())
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
	if !ff.has(t, base) {
		t.Errorf("created base has no sync flag")
	}
}

// Off clears only what litevirt recorded it set: with the marker, the whole
// tree and then the marker; without it, nothing (an attribute set by hand).
func TestSwtpmSync_OffClearsOnlyWhereTheMarkerSaysLitevirtSetIt(t *testing.T) {
	base, uuidDir, tpm2, state := swtpmTree(t)
	ff := newFakeFlags(t)
	marker := markerIn(t)
	syncSwtpmTree(base, true, marker, ff.ops())
	rep := syncSwtpmTree(base, false, marker, ff.ops())
	if rep.State != SwtpmSyncOff || rep.Changed != 5 {
		t.Fatalf("report %+v, want %s with 5 changed", rep, SwtpmSyncOff)
	}
	for _, p := range []string{base, uuidDir, tpm2, state} {
		if ff.has(t, p) {
			t.Errorf("%s still has the sync flag", p)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("marker kept after off cleared the tree: %v", err)
	}

	// Set by hand, never by litevirt: off leaves it.
	hand, _, _, _ := swtpmTree(t)
	ff = newFakeFlags(t)
	ff.flags[pathIno(t, hand)] = fsSyncFlag
	if rep := syncSwtpmTree(hand, false, markerIn(t), ff.ops()); rep.State != SwtpmSyncOff || rep.Changed != 0 || len(ff.sets) != 0 {
		t.Fatalf("off with no marker: report %+v, sets %v; want nothing touched", rep, ff.sets)
	}
	if !ff.has(t, hand) {
		t.Fatal("off cleared an attribute litevirt never set")
	}

	missing := filepath.Join(t.TempDir(), "swtpm")
	if rep := syncSwtpmTree(missing, false, markerIn(t), newFakeFlags(t).ops()); rep.State != SwtpmSyncOff {
		t.Fatalf("off on a missing base: %+v", rep)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("off created the base: %v", err)
	}
}

// tmpfs, NFS and ZFS refuse the flag: reported, and nothing below the base set.
func TestSwtpmSync_UnsupportedFilesystemIsReported(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ENOTTY, syscall.EOPNOTSUPP, syscall.EINVAL} {
		base, _, _, _ := swtpmTree(t)
		ff := newFakeFlags(t)
		ff.getErr[pathIno(t, base)] = errno
		rep := syncSwtpmTree(base, true, markerIn(t), ff.ops())
		if rep.State != SwtpmSyncUnsupported || !errors.Is(rep.Err, errno) {
			t.Errorf("%v: report %+v, want %s carrying the errno", errno, rep, SwtpmSyncUnsupported)
		}
		if len(ff.sets) != 0 {
			t.Errorf("%v: set %v on a filesystem that refused the flag", errno, ff.sets)
		}
	}
	base, _, _, _ := swtpmTree(t)
	ff := newFakeFlags(t)
	ff.setErr = syscall.EOPNOTSUPP
	if rep := syncSwtpmTree(base, true, markerIn(t), ff.ops()); rep.State != SwtpmSyncUnsupported {
		t.Errorf("a set the filesystem refuses: report %+v, want %s", rep, SwtpmSyncUnsupported)
	}
}

// An entry below the base that refuses the ioctl is that entry's problem: the
// pass goes on to every other VM and does not call the filesystem unsupported.
func TestSwtpmSync_ABadEntryDoesNotStopThePassOrMisnameTheFilesystem(t *testing.T) {
	base, _, tpm2, state := swtpmTree(t)
	other := filepath.Join(base, "ffffffff-0000-0000-0000-000000000000", "tpm2")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	ff := newFakeFlags(t)
	ff.getErr[pathIno(t, filepath.Join(tpm2, ".lock"))] = syscall.ENOTTY
	ff.getErr[pathIno(t, state)] = syscall.EIO
	rep := syncSwtpmTree(base, true, markerIn(t), ff.ops())
	if rep.State != SwtpmSyncFailed || !strings.Contains(rep.Err.Error(), "tpm2-00.permall") || !strings.Contains(rep.Err.Error(), ".lock") {
		t.Fatalf("report %+v, want %s naming both entries", rep, SwtpmSyncFailed)
	}
	if !ff.has(t, other) {
		t.Fatal("the pass stopped at the bad entry; a later VM's tree was not set")
	}
}

// btrfs keeps the flag on a directory but a file created in it does not get
// it, and swtpm writes every state file as a new file.
func TestSwtpmSync_FlagNotInheritedIsReported(t *testing.T) {
	base, _, _, _ := swtpmTree(t)
	ff := newFakeFlags(t)
	ff.inherit = false
	rep := syncSwtpmTree(base, true, markerIn(t), ff.ops())
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

// xfs inherits the flag but commits a rename synchronously only on a dirsync,
// sync or wsync mount; any filesystem not known to is not trusted either.
func TestSwtpmSync_RenameNotSynchronousIsReported(t *testing.T) {
	for _, tc := range []struct {
		magic int64
		opts  []string
		want  string
	}{
		{fsMagicXFS, []string{"rw", "relatime", "attr2", "inode64"}, SwtpmSyncRenameNotSynchronous},
		{fsMagicXFS, []string{"rw", "dirsync"}, SwtpmSyncOn},
		{fsMagicXFS, []string{"rw", "wsync"}, SwtpmSyncOn},
		// A bare sync is what remount,sync leaves: the superblock says sync but
		// xfs never set its wsync feature (lab 3: mountinfo shows "sync" with
		// no "wsync"). A mount-time sync also shows wsync and is trusted for it.
		{fsMagicXFS, []string{"rw", "sync"}, SwtpmSyncRenameNotSynchronous},
		{fsMagicXFS, []string{"rw", "sync", "wsync"}, SwtpmSyncOn},
		{0x12345678, []string{"rw"}, SwtpmSyncRenameNotSynchronous},
		{fsMagicExt4, []string{"rw", "commit=30"}, SwtpmSyncOn},
	} {
		base, _, _, _ := swtpmTree(t)
		ff := newFakeFlags(t)
		ff.magic, ff.opts = tc.magic, tc.opts
		if rep := syncSwtpmTree(base, true, markerIn(t), ff.ops()); rep.State != tc.want {
			t.Errorf("%s %v: report %+v, want %s", swtpmFSName(tc.magic), tc.opts, rep, tc.want)
		}
	}
}

// swtpm renames its state file while the pass walks: an entry gone between
// the listing and the open is not a failure.
func TestSwtpmSync_EntryGoneMidPassIsSkipped(t *testing.T) {
	base, _, tpm2, state := swtpmTree(t)
	ff := newFakeFlags(t)
	ff.after = func(dir string) {
		if dir == tpm2 {
			os.Remove(state)
		}
	}
	if rep := syncSwtpmTree(base, true, markerIn(t), ff.ops()); rep.State != SwtpmSyncOn {
		t.Fatalf("report %+v, want %s", rep, SwtpmSyncOn)
	}
}

// H1: the swtpm user owns <uuid>/ and can swap tpm2 for a symlink to anywhere
// between the pass listing <uuid>/ and opening tpm2. Nothing outside the tree
// may be touched, on or off.
func TestSwtpmSync_ASymlinkSwappedInMidPassIsNeverFollowed(t *testing.T) {
	for _, on := range []bool{true, false} {
		base, uuidDir, tpm2, _ := swtpmTree(t)
		outside := filepath.Join(t.TempDir(), "images")
		if err := os.MkdirAll(filepath.Join(outside, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outside, "disk.qcow2"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		ff := newFakeFlags(t)
		outsideInos := []uint64{pathIno(t, outside), pathIno(t, filepath.Join(outside, "sub")), pathIno(t, filepath.Join(outside, "disk.qcow2"))}
		for _, i := range outsideInos {
			ff.flags[i] = fsSyncFlag * map[bool]uint32{true: 0, false: 1}[on] // off would clear a set one
		}
		marker := markerIn(t)
		if !on {
			syncSwtpmTree(base, true, marker, ff.ops())
		}
		swapped := false
		ff.after = func(dir string) {
			if dir == uuidDir && !swapped {
				swapped = true
				if err := os.Rename(tpm2, tpm2+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, tpm2); err != nil {
					t.Fatal(err)
				}
			}
		}
		syncSwtpmTree(base, on, marker, ff.ops())
		if !swapped {
			t.Fatal("the swap never ran")
		}
		for _, i := range outsideInos {
			if ff.sets[i] {
				t.Errorf("on=%v: the pass changed an inode outside the tree (%d) through a swapped-in symlink", on, i)
			}
		}
	}
}

// The same swap after tpm2 itself is open and listed: a pass that opened its
// children by path would follow the new symlink to same-named files outside.
func TestSwtpmSync_ASymlinkSwappedInAfterListingIsNeverFollowed(t *testing.T) {
	base, _, tpm2, _ := swtpmTree(t)
	outside := filepath.Join(t.TempDir(), "images")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	var outsideInos []uint64
	for _, n := range []string{"tpm2-00.permall", ".lock"} {
		p := filepath.Join(outside, n)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		outsideInos = append(outsideInos, pathIno(t, p))
	}
	ff := newFakeFlags(t)
	swapped := false
	ff.after = func(dir string) {
		if dir == tpm2 && !swapped {
			swapped = true
			if err := os.Rename(tpm2, tpm2+".moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, tpm2); err != nil {
				t.Fatal(err)
			}
		}
	}
	syncSwtpmTree(base, true, markerIn(t), ff.ops())
	if !swapped {
		t.Fatal("the swap never ran")
	}
	for _, i := range outsideInos {
		if ff.sets[i] {
			t.Errorf("the pass changed an inode outside the tree (%d) through a swapped-in symlink", i)
		}
	}
	if !ff.has(t, filepath.Join(tpm2+".moved", "tpm2-00.permall")) {
		t.Error("the state file in the directory the pass had open was not set")
	}
}

// The tightest window: tpm2 swapped for a symlink (or a hard link put in place
// of the state file) after fstatat checked it and before the open. O_NOFOLLOW
// refuses the symlink, and the open must be the inode fstatat saw.
func TestSwtpmSync_ASwapBetweenTheCheckAndTheOpenIsNeverFollowed(t *testing.T) {
	for _, swapFile := range []bool{false, true} {
		base, _, tpm2, state := swtpmTree(t)
		outside := filepath.Join(t.TempDir(), "images")
		if err := os.MkdirAll(outside, 0o700); err != nil {
			t.Fatal(err)
		}
		outFile := filepath.Join(outside, "tpm2-00.permall")
		if err := os.WriteFile(outFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		other := filepath.Join(filepath.Dir(base), "state.db")
		if err := os.WriteFile(other, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		ff := newFakeFlags(t)
		swapped := false
		ff.before = func(path string) {
			switch {
			case swapped:
			case !swapFile && path == tpm2:
				swapped = true
				if err := os.Rename(tpm2, tpm2+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, tpm2); err != nil {
					t.Fatal(err)
				}
			case swapFile && path == state:
				swapped = true
				if err := os.Remove(state); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(other, state); err != nil {
					t.Fatal(err)
				}
			}
		}
		syncSwtpmTree(base, true, markerIn(t), ff.ops())
		if !swapped {
			t.Fatalf("swapFile=%v: the swap never ran", swapFile)
		}
		for _, p := range []string{outside, outFile, other} {
			if ff.sets[pathIno(t, p)] {
				t.Errorf("swapFile=%v: the pass changed %s, outside the tree, through a swap after its check", swapFile, p)
			}
		}
	}
}

// A second name for the state file made after the check (the same inode,
// now also reachable outside the tree): the open's own nlink says so.
func TestSwtpmSync_ALinkAddedAfterTheCheckIsNotTouched(t *testing.T) {
	base, _, _, state := swtpmTree(t)
	outsideName := filepath.Join(filepath.Dir(base), "elsewhere")
	ff := newFakeFlags(t)
	ff.before = func(path string) {
		if path == state {
			if err := os.Link(state, outsideName); err != nil {
				t.Fatal(err)
			}
		}
	}
	rep := syncSwtpmTree(base, true, markerIn(t), ff.ops())
	if ff.sets[pathIno(t, outsideName)] {
		t.Error("set the flags of an inode linked outside the tree after its check")
	}
	if rep.State != SwtpmSyncFailed || !strings.Contains(rep.Err.Error(), "hard link") {
		t.Fatalf("report %+v, want %s naming the hard link", rep, SwtpmSyncFailed)
	}
}

// A directory on another filesystem (a bind mount, a btrfs subvolume) is not
// entered: the base's inheritance probe says nothing about it. It is reported.
func TestSwtpmSync_AnotherFilesystemIsReportedNotEntered(t *testing.T) {
	base, uuidDir, tpm2, state := swtpmTree(t)
	ff := newFakeFlags(t)
	ops := ff.ops()
	other := pathIno(t, uuidDir)
	ops.devOf = func(ino, dev uint64) uint64 {
		if ino == other {
			return dev + 1
		}
		return dev
	}
	rep := syncSwtpmTree(base, true, markerIn(t), ops)
	if rep.State != SwtpmSyncFailed || !strings.Contains(rep.Err.Error(), "another filesystem") {
		t.Fatalf("report %+v, want %s naming the other filesystem", rep, SwtpmSyncFailed)
	}
	for _, p := range []string{uuidDir, tpm2, state} {
		if ff.sets[pathIno(t, p)] {
			t.Errorf("entered %s on another filesystem", p)
		}
	}
}

// A static symlink below the base is never followed; a base that is itself a
// symlink (state relocated to another volume) is walked at its target.
func TestSwtpmSync_Symlinks(t *testing.T) {
	base, _, tpm2, _ := swtpmTree(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tpm2, "link")); err != nil {
		t.Fatal(err)
	}
	ff := newFakeFlags(t)
	syncSwtpmTree(base, true, markerIn(t), ff.ops())
	if ff.sets[pathIno(t, outside)] {
		t.Errorf("followed a symlink to %s", outside)
	}

	dir, _ := filepath.EvalSymlinks(t.TempDir())
	linked := filepath.Join(dir, "swtpm-link")
	if err := os.Symlink(base, linked); err != nil {
		t.Fatal(err)
	}
	ff = newFakeFlags(t)
	if rep := syncSwtpmTree(linked, true, markerIn(t), ff.ops()); rep.State != SwtpmSyncOn {
		t.Fatalf("symlinked base: %+v", rep)
	}
	if !ff.has(t, tpm2) {
		t.Errorf("symlinked base: its target's tree was not walked")
	}
}

// N1: the swtpm user can nest directories without bound under <uuid>/. The
// pass enters no directory deeper than libvirt's layout allows, so it holds a
// bounded number of fds however deep the tree, and it reports the rest.
func TestSwtpmSync_ADeepTreeIsNotEnteredAndHoldsBoundedFDs(t *testing.T) {
	base, _, tpm2, _ := swtpmTree(t)
	deep := tpm2
	for i := 0; i < 60; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	bottom := filepath.Join(deep, "f")
	if err := os.WriteFile(bottom, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	openFDs := func() int {
		ents, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(ents)
	}
	before, peak := openFDs(), 0
	ff := newFakeFlags(t)
	ff.after = func(string) {
		if n := openFDs(); n > peak {
			peak = n
		}
	}
	rep := syncSwtpmTree(base, true, markerIn(t), ff.ops())
	if peak-before > 2*maxSwtpmDepth+4 {
		t.Errorf("the pass held %d fds at once (%d before), want at most a few per level of libvirt's layout", peak, before)
	}
	if ff.sets[pathIno(t, bottom)] {
		t.Error("the pass set a file 60 levels below tpm2")
	}
	if rep.State != SwtpmSyncFailed || !strings.Contains(rep.Err.Error(), "deeper than") {
		t.Fatalf("report %+v, want %s naming the directory too deep to enter", rep, SwtpmSyncFailed)
	}
	if !ff.has(t, filepath.Join(tpm2, "tpm2-00.permall")) {
		t.Error("the state file at libvirt's depth was not set")
	}
}

// A directory with more entries than any host has VMs is reported, not
// listed in full into the root daemon's memory.
func TestSwtpmSync_AHugeDirectoryIsNotListedInFull(t *testing.T) {
	base, _, tpm2, state := swtpmTree(t)
	old := maxSwtpmDirEntries
	maxSwtpmDirEntries = 8
	defer func() { maxSwtpmDirEntries = old }()
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(tpm2, "f"+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ff := newFakeFlags(t)
	rep := syncSwtpmTree(base, true, markerIn(t), ff.ops())
	if rep.State != SwtpmSyncFailed || !strings.Contains(rep.Err.Error(), "more than 8 entries") {
		t.Fatalf("report %+v, want %s naming the huge directory", rep, SwtpmSyncFailed)
	}
	if ff.sets[pathIno(t, state)] {
		t.Error("entered a directory over the entry cap")
	}
}

// N2: a hard link in the tree to a file outside it is a regular file to
// openat; the pass must not touch its inode, on or off, and reports it.
func TestSwtpmSync_AHardLinkIsNotTouched(t *testing.T) {
	for _, on := range []bool{true, false} {
		base, _, tpm2, _ := swtpmTree(t)
		outside := filepath.Join(filepath.Dir(base), "state.db")
		if err := os.WriteFile(outside, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, filepath.Join(tpm2, "x")); err != nil {
			t.Fatal(err)
		}
		ff := newFakeFlags(t)
		marker := markerIn(t)
		if !on {
			if err := writeSwtpmMarker(marker, base); err != nil {
				t.Fatal(err)
			}
			ff.flags[pathIno(t, outside)] = fsSyncFlag
		}
		rep := syncSwtpmTree(base, on, marker, ff.ops())
		if ff.sets[pathIno(t, outside)] {
			t.Errorf("on=%v: the pass changed the flags of a file outside the tree through a hard link", on)
		}
		if rep.State != SwtpmSyncFailed || !strings.Contains(rep.Err.Error(), "hard link") {
			t.Errorf("on=%v: report %+v, want %s naming the hard link", on, rep, SwtpmSyncFailed)
		}
	}
}

// L-a: the type is checked before the open, so a fifo (or a device node the
// swtpm user linked in) is never opened by the root daemon.
func TestSwtpmSync_ANonRegularEntryIsNeverOpened(t *testing.T) {
	base, _, tpm2, _ := swtpmTree(t)
	fifo := filepath.Join(tpm2, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(in)
	if _, err := unix.InotifyAddWatch(in, fifo, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	syncSwtpmTree(base, true, markerIn(t), newFakeFlags(t).ops())
	buf := make([]byte, 4096)
	if n, err := unix.Read(in, buf); err == nil && n > 0 {
		t.Fatal("the pass opened a fifo")
	}
}

// L-c: removing the marker is made durable, like writing it.
func TestSwtpmSync_MarkerRemovalIsFsynced(t *testing.T) {
	base, _, _, _ := swtpmTree(t)
	marker := markerIn(t)
	ff := newFakeFlags(t)
	syncSwtpmTree(base, true, marker, ff.ops())
	var synced []string
	old := syncDirFn
	syncDirFn = func(dir string) error { synced = append(synced, dir); return old(dir) }
	defer func() { syncDirFn = old }()
	if rep := syncSwtpmTree(base, false, marker, ff.ops()); rep.State != SwtpmSyncOff {
		t.Fatalf("off: %+v", rep)
	}
	if len(synced) == 0 || synced[len(synced)-1] != filepath.Dir(marker) {
		t.Fatalf("directory fsyncs %v, want %s after the marker's removal", synced, filepath.Dir(marker))
	}
}

func TestSwtpmSync_MountOptions(t *testing.T) {
	info := strings.Join([]string{
		"22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,commit=30",
		"40 22 7:3 / /var/lib/libvirt/swtpm rw,relatime shared:9 - xfs /dev/loop3 rw,attr2,inode64,wsync",
		"41 22 7:3 / /mnt/other rw,dirsync shared:10 - xfs /dev/loop3 rw,attr2",
	}, "\n")
	got := mountOptions(bufio.NewScanner(strings.NewReader(info)), 7, 3, "/var/lib/libvirt/swtpm")
	if strings.Join(got, ",") != "rw,relatime,rw,attr2,inode64,wsync" {
		t.Fatalf("options %v, want the swtpm mount's per-mount and superblock options", got)
	}
	if got := mountOptions(bufio.NewScanner(strings.NewReader(info)), 252, 1, "/var/lib/libvirt/swtpm"); strings.Join(got, ",") != "rw,relatime,rw,commit=30" {
		t.Fatalf("root options %v", got)
	}
	// A mount point with a space is written with an octal escape.
	esc := "50 22 7:4 / /srv/vm\\040state rw shared:11 - xfs /dev/loop4 rw,dirsync"
	if got := mountOptions(bufio.NewScanner(strings.NewReader(esc)), 7, 4, "/srv/vm state/swtpm"); strings.Join(got, ",") != "rw,rw,dirsync" {
		t.Fatalf("escaped mount point: options %v", got)
	}
}

// The real ioctls, on the filesystem that holds t.TempDir(): a state file
// swtpm writes after the pass (a new file renamed into place) carries the
// flag, and off clears it again.
func TestSwtpmSync_RealFilesystem(t *testing.T) {
	base, _, tpm2, state := swtpmTree(t)
	marker := markerIn(t)
	rep := syncSwtpmTree(base, true, marker, osSwtpmFDOps)
	switch rep.State {
	case SwtpmSyncOn, SwtpmSyncRenameNotSynchronous:
	case SwtpmSyncUnsupported, SwtpmSyncNotInherited:
		t.Skipf("the filesystem under %s does not keep an inherited sync flag (%s: %v); "+
			"the fake-backed tests cover the logic", base, rep.State, rep.Err)
	default:
		t.Fatalf("report %+v", rep)
	}

	tmp := filepath.Join(tpm2, "TMP2-00.permall")
	if err := os.WriteFile(tmp, []byte("new state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, state); err != nil {
		t.Fatal(err)
	}
	flags := func(p string) uint32 {
		fd, err := unix.Open(p, openFlags, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		fl, err := osSwtpmFDOps.get(fd)
		if err != nil {
			t.Fatal(err)
		}
		return fl
	}
	for _, p := range []string{base, tpm2, state} {
		if fl := flags(p); fl&fsSyncFlag == 0 {
			t.Errorf("%s: flags %#x, no sync flag", p, fl)
		}
	}
	if rep := syncSwtpmTree(base, false, marker, osSwtpmFDOps); rep.State != SwtpmSyncOff {
		t.Fatalf("off: %+v", rep)
	}
	for _, p := range []string{base, tpm2, state} {
		if fl := flags(p); fl&fsSyncFlag != 0 {
			t.Errorf("%s: off left the sync flag (%#x)", p, fl)
		}
	}
}
