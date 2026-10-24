//go:build unix

package libvirt

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/randid"
)

type chownCall struct {
	path     string
	uid, gid int
}

// recordChown stands in for os.Lchown (a test is not root) and records the
// owner each path is given; fail makes every call fail.
func recordChown(t *testing.T, fail bool) *[]chownCall {
	t.Helper()
	var calls []chownCall
	old := lchown
	lchown = func(p string, uid, gid int) error {
		calls = append(calls, chownCall{p, uid, gid})
		if fail {
			return errors.New("chown refused")
		}
		return nil
	}
	t.Cleanup(func() { lchown = old })
	return &calls
}

// asRoot makes the test's own uid stand for root, the owner a backup root
// must have, and returns a function that marks a directory as owned by
// someone else (a planted one).
func asRoot(t *testing.T) (plant func(dir string)) {
	t.Helper()
	planted := map[uint64]bool{} // by inode: a directory made afresh at the name is not the planted one
	old := backupOwnerOf
	backupOwnerOf = func(path string, fi fs.FileInfo) (int, bool) {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && planted[uint64(st.Ino)] {
			return 4242, true
		}
		uid, ok := old(path, fi)
		if ok && uid == os.Geteuid() {
			return 0, true
		}
		return uid, ok
	}
	t.Cleanup(func() { backupOwnerOf = old })
	return func(dir string) {
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		planted[uint64(fi.Sys().(*syscall.Stat_t).Ino)] = true
	}
}

// suffixes makes the session suffixes come from list, in order.
func suffixes(t *testing.T, list ...string) {
	t.Helper()
	old := sessionSuffix
	i := 0
	sessionSuffix = func() string {
		s := list[i%len(list)]
		i++
		return s
	}
	t.Cleanup(func() { sessionSuffix = old })
}

func backupDirsUmask022(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
}

func modeOf(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode() & (fs.ModePerm | fs.ModeSticky | fs.ModeSetuid | fs.ModeSetgid)
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range des {
		out = append(out, d.Name())
	}
	return out
}

// The backup session's scratch and NBD socket used to sit directly in
// backup-scratch/ and backup-sock/, which every session chmod-ed 0777 with no
// sticky bit: any local user could replace the socket the daemon reads the
// guest's disk from. Now both roots are root's and 0711, and every session
// makes a NEW directory of its own in each — an unguessable name, made with a
// mkdir that fails if the name exists, so nothing anyone planted is ever
// adopted — given to the uid qemu runs as for the domain, 0700.
//
// Mutations: the roots 0777 — red; the session directory not chowned — red;
// a fixed session name — the two sessions collide, red.
func TestBackupSessionPaths_FreshPrivateDirsPerSession(t *testing.T) {
	backupDirsUmask022(t)
	calls := recordChown(t, false)
	asRoot(t)
	base := t.TempDir()
	scratchRoot, sockRoot := filepath.Join(base, "backup-scratch"), filepath.Join(base, "backup-sock")
	owner := qemuOwner{UID: 64055, GID: 993, Known: true}
	scratch, socket, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "web-1-vda", owner)
	if err != nil {
		t.Fatalf("prepareBackupSessionPaths: %v", err)
	}
	for _, d := range []string{scratchRoot, sockRoot} {
		if got := modeOf(t, d); got != 0o711 {
			t.Errorf("%s is %04o, want 0711 (root's, searchable only)", d, got)
		}
	}
	for _, p := range []string{scratch, socket} {
		dir := filepath.Dir(p)
		if dir == scratchRoot || dir == sockRoot {
			t.Fatalf("%s is directly in a shared directory, not in a session directory of its own", p)
		}
		if got := modeOf(t, dir); got != 0o700 {
			t.Errorf("session directory %s is %04o, want 0700", dir, got)
		}
		owned := false
		for _, c := range *calls {
			if c.path == dir && c.uid == 64055 && c.gid == 993 {
				owned = true
			}
		}
		if !owned {
			t.Errorf("session directory %s was not given to qemu's uid:gid 64055:993 (chowns: %+v)", dir, *calls)
		}
	}
	scratch2, socket2, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "web-1-vda", owner)
	if err != nil {
		t.Fatalf("a second session: %v", err)
	}
	if filepath.Dir(scratch2) == filepath.Dir(scratch) || filepath.Dir(socket2) == filepath.Dir(socket) {
		t.Errorf("a second session of the same disk reused a session directory: %s %s", scratch2, socket2)
	}
	if !strings.HasPrefix(filepath.Base(filepath.Dir(scratch)), "web-1-vda.") {
		t.Errorf("the scratch session directory %s does not name its disk", filepath.Dir(scratch))
	}
}

// A unix socket path is at most 107 bytes. The socket's directory is the
// suffix alone, so the path's length does not depend on the VM's name:
// len("/var/lib/litevirt/backup-sock") + len("/") + 16 hex + len("/nbd")
// = 29 + 1 + 16 + 4 = 50 bytes, always. The old <sock>/<vm>-<disk>.sock was
// 35 + the name, so no VM whose backup opened before is refused now.
func TestBackupSessionPaths_SocketPathFitsWhateverTheName(t *testing.T) {
	backupDirsUmask022(t)
	recordChown(t, false)
	asRoot(t)
	base := t.TempDir()
	sockRoot := filepath.Join(base, "k")
	long := strings.Repeat("v", 80) + "-vda"
	_, socket, err := prepareBackupSessionPaths(filepath.Join(base, "s"), sockRoot, long, qemuOwner{UID: 1, GID: 1, Known: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := len(sockRoot) + 1 + 2*randid.Bytes + len("/nbd"); len(socket) != want {
		t.Errorf("socket %q is %d bytes, want %d", socket, len(socket), want)
	}
	if n := len(sessSocketDir) + 1 + 2*randid.Bytes + len("/nbd"); n != 50 || n > 107 {
		t.Errorf("the production socket path is %d bytes, want 50 (limit 107)", n)
	}
	// The 01733 fallback adds one 16-hex intermediate directory:
	// 29 + 1 + 16 + 1 + 16 + 4 = 67 bytes, still under 107.
	_, fsock, err := prepareBackupSessionPaths(filepath.Join(base, "s"), sockRoot, long, qemuOwner{})
	if err != nil {
		t.Fatal(err)
	}
	if want := len(sockRoot) + 2*(1+2*randid.Bytes) + len("/nbd"); len(fsock) != want {
		t.Errorf("fallback socket %q is %d bytes, want %d", fsock, len(fsock), want)
	}
	if n := len(sessSocketDir) + 2*(1+2*randid.Bytes) + len("/nbd"); n != 67 || n > 107 {
		t.Errorf("the production fallback socket path is %d bytes, want 67 (limit 107)", n)
	}
}

// Nothing at a session directory's name is ever adopted: a name that already
// exists (planted, or a collision) is skipped for a fresh one, and what was
// there is left exactly as it was.
//
// Mutation: adopt an existing directory — the planted one is chowned/used, red.
func TestBackupSessionPaths_NeverAdoptsAnExistingDirectory(t *testing.T) {
	backupDirsUmask022(t)
	calls := recordChown(t, false)
	asRoot(t)
	base := t.TempDir()
	scratchRoot, sockRoot := filepath.Join(base, "s"), filepath.Join(base, "k")
	if _, _, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{}); err != nil {
		t.Fatal(err)
	}
	taken, fresh := strings.Repeat("a", 16), strings.Repeat("b", 16)
	planted := filepath.Join(sockRoot, taken)
	if err := os.Mkdir(planted, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(scratchRoot, "v-vda."+taken), 0o777); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	// The scratch side takes the first two (both taken there), the socket side
	// the next three: taken, taken (planted), then a fresh one.
	suffixes(t, taken, taken, fresh)
	scratch, socket, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{UID: 1, GID: 1, Known: true})
	if err != nil {
		t.Fatalf("a taken name refused the backup: %v", err)
	}
	if filepath.Base(filepath.Dir(scratch)) == "v-vda."+taken {
		t.Fatalf("the session adopted the existing scratch directory %s", filepath.Dir(scratch))
	}
	if filepath.Dir(socket) == planted {
		t.Fatalf("the session adopted an existing directory %s", planted)
	}
	if got := modeOf(t, planted); got != 0o777 {
		t.Errorf("the existing directory was changed to %04o", got)
	}
	for _, c := range *calls {
		if c.path == planted {
			t.Errorf("the existing directory was chowned: %+v", c)
		}
	}
}

// A root that is another user's directory, a symlink, or not a directory at all
// (a file, which no chmod can make a directory) is renamed aside, kept with
// everything in it, and made afresh. The backup goes on.
//
// Mutations: accept the root as it is — red; delete instead of renaming — the
// kept content is gone, red; narrow another user's directory in place instead
// of setting it aside — red.
func TestBackupSessionPaths_ABadRootIsSetAsideAndMadeAfresh(t *testing.T) {
	cases := map[string]func(t *testing.T, root string, plant func(string)){
		"another user's directory": func(t *testing.T, root string, plant func(string)) {
			mustMkdirMode(t, root, 0o711)
			plant(root)
		},
		"symlink": func(t *testing.T, root string, _ func(string)) {
			target := t.TempDir()
			if err := os.Symlink(target, root); err != nil {
				t.Fatal(err)
			}
		},
		"file": func(t *testing.T, root string, _ func(string)) {
			if err := os.WriteFile(root, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"file of mode 0711": func(t *testing.T, root string, _ func(string)) {
			if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, 0o711); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			backupDirsUmask022(t)
			recordChown(t, false)
			plant := asRoot(t)
			base := t.TempDir()
			scratchRoot, sockRoot := filepath.Join(base, "backup-scratch"), filepath.Join(base, "backup-sock")
			setup(t, sockRoot, plant)
			if fi, err := os.Lstat(sockRoot); err == nil && fi.IsDir() {
				if err := os.WriteFile(filepath.Join(sockRoot, "kept"), []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, socket, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{})
			if err != nil {
				t.Fatalf("a bad root refused the backup: %v", err)
			}
			fi, err := os.Lstat(sockRoot)
			if err != nil || !fi.IsDir() || modeOf(t, sockRoot) != 0o711 {
				t.Fatalf("the root was not made afresh: %v %v", fi, err)
			}
			if !strings.HasPrefix(socket, sockRoot+"/") {
				t.Fatalf("socket %s is not in the fresh root", socket)
			}
			var aside []string
			for _, e := range entries(t, base) {
				if strings.HasPrefix(e, ".backup-sock.aside-") {
					aside = append(aside, e)
				}
			}
			if len(aside) != 1 {
				t.Fatalf("set-aside copies in %s: %v, want one", base, entries(t, base))
			}
			if name == "another user's directory" {
				if b, err := os.ReadFile(filepath.Join(base, aside[0], "kept")); err != nil || string(b) != "keep" {
					t.Errorf("the set-aside root lost its content: %q %v", b, err)
				}
			}
		})
	}
}

func mustMkdirMode(t *testing.T, p string, mode fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(p, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// When qemu's user cannot be read from the domain, or the chown is refused,
// the session directory is 01733 — writable by every local user, but its
// unguessable name sits in an unlistable 0711 root, so nobody else can find
// it. Never 0777.
//
// Mutations: the fallback 0777 — red; return the chown error — red.
func TestBackupSessionPaths_FallbackIsStickyInsideTheUnlistableRoot(t *testing.T) {
	for name, tc := range map[string]struct {
		owner qemuOwner
		fail  bool
	}{
		"unknown owner": {qemuOwner{}, false},
		"refused chown": {qemuOwner{UID: 64055, GID: 993, Known: true}, true},
	} {
		t.Run(name, func(t *testing.T) {
			backupDirsUmask022(t)
			calls := recordChown(t, tc.fail)
			asRoot(t)
			base := t.TempDir()
			scratch, socket, err := prepareBackupSessionPaths(filepath.Join(base, "s"), filepath.Join(base, "k"), "v-vda", tc.owner)
			if err != nil {
				t.Fatalf("prepareBackupSessionPaths: %v", err)
			}
			for _, p := range []string{scratch, socket} {
				if got := modeOf(t, filepath.Dir(p)); got != fs.ModeSticky|0o733 {
					t.Errorf("session directory of %s is %04o, want 01733", p, got)
				}
				if got := modeOf(t, filepath.Dir(filepath.Dir(p))); got != 0o711 {
					t.Errorf("its root is %04o, want 0711 (unlistable)", got)
				}
			}
			if !tc.owner.Known && len(*calls) != 0 {
				t.Errorf("chowned with no known owner: %+v", *calls)
			}
		})
	}
}

// When the socket's root cannot be made, the scratch session directory
// already made for the session goes again: nothing is left behind.
//
// Mutation: drop that cleanup — red.
func TestBackupSessionPaths_AFailedSessionLeavesNothing(t *testing.T) {
	backupDirsUmask022(t)
	recordChown(t, false)
	asRoot(t)
	base := t.TempDir()
	notADir := filepath.Join(base, "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	scratchRoot := filepath.Join(base, "s")
	if _, _, err := prepareBackupSessionPaths(scratchRoot, filepath.Join(notADir, "k"), "v-vda", qemuOwner{}); err == nil {
		t.Fatal("a socket root under a file was made")
	}
	if got := entries(t, scratchRoot); len(got) != 0 {
		t.Errorf("the failed session left %v in the scratch root", got)
	}
}

// A crashed session's scratch — tens of GiB, possibly — is removed by the
// next session of the same disk once that session holds the domain's backup
// job (libvirt allows one per domain, so no other session of the disk is
// live). Only <tag>.<16 hex> directories of that disk are touched, only their
// scratch file is removed, and a directory is removed only when that leaves it
// empty.
//
// Mutations: no sweep — red; RemoveAll — the extra file goes, red; match by
// prefix only — the other disk's directory goes, red.
func TestSweepStaleScratch_TakesOnlyThisDisksDeadSessions(t *testing.T) {
	base := t.TempDir()
	h := func(c string) string { return strings.Repeat(c, 16) }
	mk := func(name string, files ...string) string {
		d := filepath.Join(base, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(d, f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	dead := mk("v-vda."+h("a"), "scratch")
	deadExtra := mk("v-vda."+h("b"), "scratch", "operator-note")
	live := mk("v-vda."+h("c"), "scratch")
	otherDisk := mk("v-vda-x."+h("d"), "scratch")
	otherVM := mk("w-vda."+h("e"), "scratch")
	notOurs := mk("v-vda.notasuffix", "scratch")
	if err := os.Symlink(t.TempDir(), filepath.Join(base, "v-vda."+h("f"))); err != nil {
		t.Fatal(err)
	}

	sweepStaleScratch(base, "v-vda", live)

	if _, err := os.Lstat(dead); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a dead session's directory is left: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(deadExtra, "scratch")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a dead session's scratch is left: %v", err)
	}
	if _, err := os.Stat(filepath.Join(deadExtra, "operator-note")); err != nil {
		t.Errorf("a file that is no session's scratch was removed: %v", err)
	}
	for _, d := range []string{live, otherDisk, otherVM, notOurs} {
		if _, err := os.Stat(filepath.Join(d, "scratch")); err != nil {
			t.Errorf("%s's scratch was removed: %v", filepath.Base(d), err)
		}
	}
	if _, err := os.Lstat(filepath.Join(base, "v-vda."+h("f"))); err != nil {
		t.Errorf("a symlink was removed or followed: %v", err)
	}
}

// qemu's uid:gid is the domain's DAC label: "+64055:+993" in the live XML of
// a dynamic label, or names ("libvirt-qemu:kvm") in a static one, which are
// resolved through the user and group databases.
//
// Mutation: names not resolved — red.
func TestDomainQEMUOwner_ReadsTheDACLabel(t *testing.T) {
	oldU, oldG := lookupUserID, lookupGroupID
	lookupUserID = func(name string) (string, error) {
		if name == "libvirt-qemu" {
			return "64055", nil
		}
		return "", errors.New("unknown user")
	}
	lookupGroupID = func(name string) (string, error) {
		if name == "kvm" {
			return "993", nil
		}
		return "", errors.New("unknown group")
	}
	t.Cleanup(func() { lookupUserID, lookupGroupID = oldU, oldG })

	dyn := `<domain type='kvm' id='3'><name>v</name>
<seclabel type='dynamic' model='apparmor' relabel='yes'><label>libvirt-abc</label></seclabel>
<seclabel type='dynamic' model='dac' relabel='yes'><label>+64055:+993</label><imagelabel>+64055:+993</imagelabel></seclabel>
</domain>`
	want := qemuOwner{UID: 64055, GID: 993, Known: true}
	if got := domainQEMUOwner(dyn); got != want {
		t.Fatalf("dynamic label: owner = %+v, want 64055:993", got)
	}
	static := func(label string) string {
		return `<domain><seclabel type='static' model='dac'><label>` + label + `</label></seclabel></domain>`
	}
	if got := domainQEMUOwner(static("libvirt-qemu:kvm")); got != want {
		t.Errorf("name label: owner = %+v, want 64055:993", got)
	}
	if got := domainQEMUOwner(static("libvirt-qemu:+993")); got != want {
		t.Errorf("mixed label: owner = %+v, want 64055:993", got)
	}
	for _, label := range []string{"", "nobody-here:kvm", "libvirt-qemu:nogroup", "+1", "+a:+b", "-1:-1"} {
		if got := domainQEMUOwner(static(label)); got.Known {
			t.Errorf("label %q read as %+v, want unknown", label, got)
		}
	}
	if got := domainQEMUOwner(`<domain><name>v</name></domain>`); got.Known {
		t.Errorf("no DAC label read as %+v", got)
	}
}

// At daemon start, an existing backup root that is not root's own 0711
// directory (an earlier build's 0777) is set aside and made afresh; one that
// does not exist is left for the first session to make.
//
// Mutation: skip the existing root — it stays 0777, red; make a missing one —
// red.
func TestPrepareBackupRoots_NarrowsAnEarlierBuildsRootsAtStart(t *testing.T) {
	backupDirsUmask022(t)
	asRoot(t)
	base := t.TempDir()
	old, missing := filepath.Join(base, "backup-scratch"), filepath.Join(base, "backup-sock")
	mustMkdirMode(t, old, 0o777)
	prepareBackupRoots(old, missing)
	if got := modeOf(t, old); got != 0o711 {
		t.Errorf("%s is %04o after start, want 0711", old, got)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing root was made at start: %v", err)
	}
}

// Fix round 2: an earlier build's root — root's own real directory, left 0777
// — is narrowed to 0711 in place: no aside copy, and what is in it stays. That
// is safe because a session never adopts an existing entry (random names,
// exclusive mkdir).
//
// Mutations: set it aside instead — an aside copy appears, red; leave the mode
// — red.
func TestBackupSessionPaths_AnEarlierBuildsRootIsNarrowedInPlace(t *testing.T) {
	backupDirsUmask022(t)
	recordChown(t, false)
	asRoot(t)
	base := t.TempDir()
	scratchRoot, sockRoot := filepath.Join(base, "backup-scratch"), filepath.Join(base, "backup-sock")
	for _, d := range []string{scratchRoot, sockRoot} {
		mustMkdirMode(t, d, 0o777)
		if err := os.WriteFile(filepath.Join(d, "kept"), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{}); err != nil {
		t.Fatalf("prepareBackupSessionPaths: %v", err)
	}
	for _, d := range []string{scratchRoot, sockRoot} {
		if got := modeOf(t, d); got != 0o711 {
			t.Errorf("%s is %04o, want narrowed to 0711", d, got)
		}
		if b, err := os.ReadFile(filepath.Join(d, "kept")); err != nil || string(b) != "keep" {
			t.Errorf("%s lost its content: %q %v", d, b, err)
		}
	}
	for _, e := range entries(t, base) {
		if strings.Contains(e, ".aside-") {
			t.Errorf("an earlier build's root was set aside (%s), not narrowed in place", e)
		}
	}
}

// Fix round 2: only another owner or a symlink is set aside, at daemon start
// too; root's own 0777 directory is narrowed in place there as well.
func TestPrepareBackupRoots_SetsAsideOnlyAnotherOwnerOrASymlink(t *testing.T) {
	backupDirsUmask022(t)
	plant := asRoot(t)
	base := t.TempDir()
	old, foreign, link := filepath.Join(base, "a"), filepath.Join(base, "b"), filepath.Join(base, "c")
	mustMkdirMode(t, old, 0o777)
	mustMkdirMode(t, foreign, 0o711)
	plant(foreign)
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	prepareBackupRoots(old, foreign, link)
	aside := map[string]bool{}
	for _, e := range entries(t, base) {
		if i := strings.Index(e, ".aside-"); i > 0 {
			aside[e[1:i]] = true
		}
	}
	if aside["a"] {
		t.Error("root's own 0777 directory was set aside, not narrowed in place")
	}
	if !aside["b"] || !aside["c"] {
		t.Errorf("set aside: %v, want another user's directory (b) and the symlink (c)", aside)
	}
	for _, d := range []string{old, foreign, link} {
		if fi, err := os.Lstat(d); err != nil || !fi.IsDir() || modeOf(t, d) != 0o711 {
			t.Errorf("%s is not a 0711 directory afterwards: %v %v", d, fi, err)
		}
	}
}

// Fix round 3, m2: in the 01733 fallback, the session directory is not made
// in the root itself but in a fresh, root-owned 0711 directory of its own
// (unguessable name, exclusive mkdir) inside the root. A directory fd or an
// inotify watch opened on the root while an earlier build left it 0777 can
// learn the intermediate's name, but cannot list it or watch it: that inode
// was never readable by anyone but root. The normal, qemu-owned 0700 session
// directory needs no intermediate.
//
// Mutation: make the fallback session directory directly in the root — red;
// an intermediate that is not 0711 — red.
func TestBackupSessionPaths_FallbackSitsInAFreshUnlistableDirectory(t *testing.T) {
	backupDirsUmask022(t)
	recordChown(t, false)
	asRoot(t)
	base := t.TempDir()
	scratchRoot, sockRoot := filepath.Join(base, "s"), filepath.Join(base, "k")
	scratch, socket, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{})
	if err != nil {
		t.Fatal(err)
	}
	for p, root := range map[string]string{scratch: scratchRoot, socket: sockRoot} {
		session := filepath.Dir(p)
		mid := filepath.Dir(session)
		if mid == root {
			t.Fatalf("the fallback session directory %s is directly in the root", session)
		}
		if filepath.Dir(mid) != root {
			t.Fatalf("%s is not one directory below the root %s", mid, root)
		}
		if got := modeOf(t, mid); got != 0o711 {
			t.Errorf("intermediate %s is %04o, want 0711", mid, got)
		}
		if uid, ok := backupOwnerOf(mid, mustLstat(t, mid)); !ok || uid != 0 {
			t.Errorf("intermediate %s is owned by uid %d, want root", mid, uid)
		}
		if !isSessionSuffix(filepath.Base(session)) {
			t.Errorf("the session directory's name %q is not an unguessable suffix", filepath.Base(session))
		}
	}
	// The known-owner session needs none.
	ks, kk, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{UID: 1, GID: 1, Known: true})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(filepath.Dir(ks)) != scratchRoot || filepath.Dir(filepath.Dir(kk)) != sockRoot {
		t.Errorf("a qemu-owned session got an intermediate: %s %s", ks, kk)
	}
	// Removing the session removes the intermediate too, and never the root.
	removeBackupSessionPaths(scratch, socket)
	if got := entries(t, scratchRoot); len(got) != 1 {
		t.Errorf("scratch root after removing the fallback session: %v, want only the qemu-owned session's", got)
	}
	if got := entries(t, sockRoot); len(got) != 1 {
		t.Errorf("socket root after removing the fallback session: %v, want only the qemu-owned session's", got)
	}
	removeBackupSessionPaths(ks, kk)
	for _, r := range []string{scratchRoot, sockRoot} {
		if _, err := os.Stat(r); err != nil {
			t.Errorf("removing a session removed the root %s: %v", r, err)
		}
	}
}

func mustLstat(t *testing.T, p string) fs.FileInfo {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// A crashed fallback session's scratch, one directory deeper, is swept too.
func TestSweepStaleScratch_TakesACrashedFallbackSession(t *testing.T) {
	base := t.TempDir()
	mid := filepath.Join(base, "v-vda."+strings.Repeat("a", 16))
	inner := filepath.Join(mid, strings.Repeat("b", 16))
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "scratch"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sweepStaleScratch(base, "v-vda", "")
	if _, err := os.Lstat(mid); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a crashed fallback session is left: %v", err)
	}
}

// Fix round 3, m1: two sessions that find the root missing at the same moment
// both go on: one makes it, the other finds it made and validates it. Nothing
// fails, and the root is made once.
//
// Mutation: return the EEXIST from the root's mkdir — red. (The mutex is pinned
// by the set-aside test below.)
func TestEnsureBackupRoot_AConcurrentlyMadeRootIsValidatedNotFailed(t *testing.T) {
	backupDirsUmask022(t)
	asRoot(t)
	base := t.TempDir()
	root := filepath.Join(base, "backup-sock")
	// Another maker wins between this one's check and its mkdir.
	old := beforeRootMkdir
	beforeRootMkdir = func(r string) {
		if r == root {
			_ = os.Mkdir(r, 0o711)
			_ = os.Chmod(r, 0o711)
		}
	}
	err := ensureBackupRoot(root)
	beforeRootMkdir = old
	if err != nil {
		t.Fatalf("a root another session made meanwhile failed this one: %v", err)
	}

	root2 := filepath.Join(base, "backup-scratch")
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- ensureBackupRoot(root2)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a concurrent session failed: %v", err)
		}
	}
	for _, e := range entries(t, base) {
		if strings.Contains(e, ".aside-") {
			t.Errorf("concurrent sessions set a fresh root aside: %s", e)
		}
	}
}

// Fix round 3, m1: sessions that find a bad root (another user's) at the same
// moment set it aside once: no session sets aside the fresh root another has
// just made, and none fails.
//
// Mutation: drop the mutex — several set-aside copies or a failed session, red.
func TestEnsureBackupRoot_ConcurrentSessionsSetABadRootAsideOnce(t *testing.T) {
	backupDirsUmask022(t)
	plant := asRoot(t)
	base := t.TempDir()
	root := filepath.Join(base, "backup-sock")
	mustMkdirMode(t, root, 0o711)
	plant(root)
	old := beforeRootMkdir
	beforeRootMkdir = func(string) { time.Sleep(2 * time.Millisecond) } // widen the window
	t.Cleanup(func() { beforeRootMkdir = old })
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- ensureBackupRoot(root)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a concurrent session failed: %v", err)
		}
	}
	n := 0
	for _, e := range entries(t, base) {
		if strings.Contains(e, ".aside-") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d set-aside copies, want 1", n)
	}
}

// Fix round 4, I1: BeginBackup sweeps while its own session is live — qemu
// has the scratch open — and passes the session's directory as keep. A
// fallback session's directory is one level below the root entry the sweep
// walks (<root>/<tag>.<hex>/<hex>), so keep must protect the root entry that
// CONTAINS it, not only one equal to it: comparing the two for equality
// unlinked the live scratch and removed both of its directories mid-job.
// Crashed sessions of the same disk, of both shapes, are still swept.
//
// Mutation: keep compared for equality only — the fallback case red.
func TestSweepStaleScratch_NeverTouchesTheLiveSession(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner qemuOwner
	}{
		{"fallback", qemuOwner{}},
		{"qemu-owned", qemuOwner{UID: 1, GID: 1, Known: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backupDirsUmask022(t)
			recordChown(t, false)
			asRoot(t)
			base := t.TempDir()
			scratchRoot, sockRoot := filepath.Join(base, "s"), filepath.Join(base, "k")
			write := func(p string) {
				t.Helper()
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// Two crashed sessions of this disk, one of each shape.
			deadFB, _, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{})
			if err != nil {
				t.Fatal(err)
			}
			deadQ, _, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{UID: 1, GID: 1, Known: true})
			if err != nil {
				t.Fatal(err)
			}
			write(deadFB)
			write(deadQ)

			scratch, _, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", tc.owner)
			if err != nil {
				t.Fatal(err)
			}
			write(scratch) // qemu has created it and holds it open

			sweepStaleScratch(scratchRoot, "v-vda", filepath.Dir(scratch)) // as BeginBackup calls it

			for p := scratch; p != scratchRoot; p = filepath.Dir(p) {
				if _, err := os.Lstat(p); err != nil {
					t.Errorf("the live session's %s was removed by the sweep: %v", p, err)
				}
			}
			for _, d := range []string{deadFB, deadQ} {
				// The crashed session's root-level entry is gone.
				rel, err := filepath.Rel(scratchRoot, d)
				if err != nil {
					t.Fatal(err)
				}
				top := filepath.Join(scratchRoot, strings.Split(rel, string(os.PathSeparator))[0])
				if _, err := os.Lstat(top); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("a crashed session %s is left: %v", top, err)
				}
			}
		})
	}
}

// keep protects the root entry it is in or equal to — an ancestor check on
// path elements, not a string prefix: a keep whose path merely starts with an
// entry's name (<entry>x) does not protect that entry.
//
// Mutation: a bare strings.HasPrefix(keep, dir) — the second sweep red.
func TestSweepStaleScratch_KeepIsAnAncestorNotANamePrefix(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, "v-vda."+strings.Repeat("a", 16))
	inner := filepath.Join(live, strings.Repeat("b", 16))
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "scratch"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dead := filepath.Join(base, "v-vda."+strings.Repeat("c", 16))
	if err := os.Mkdir(dead, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dead, "scratch"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// keep is the live fallback session's INNER directory.
	sweepStaleScratch(base, "v-vda", inner)
	if _, err := os.Stat(filepath.Join(inner, "scratch")); err != nil {
		t.Errorf("the live fallback scratch was removed: %v", err)
	}
	if _, err := os.Lstat(dead); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a crashed session is left: %v", err)
	}
	sweepStaleScratch(base, "v-vda", live+"x")
	if _, err := os.Lstat(live); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a keep that only shares a name prefix protected %s: %v", live, err)
	}
}
