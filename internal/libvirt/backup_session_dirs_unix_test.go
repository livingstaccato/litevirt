//go:build unix

package libvirt

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

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
	_, socket, err := prepareBackupSessionPaths(filepath.Join(base, "s"), sockRoot, long, qemuOwner{})
	if err != nil {
		t.Fatal(err)
	}
	if want := len(sockRoot) + 1 + 2*randid.Bytes + len("/nbd"); len(socket) != want {
		t.Errorf("socket %q is %d bytes, want %d", socket, len(socket), want)
	}
	if n := len(sessSocketDir) + 1 + 2*randid.Bytes + len("/nbd"); n != 50 || n > 107 {
		t.Errorf("the production socket path is %d bytes, want 50 (limit 107)", n)
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

// A root that is not a root-owned, real 0711 directory — an earlier build's
// 0777, a planted symlink or directory, a file — is renamed aside, kept with
// everything in it, and made afresh. The backup goes on.
//
// Mutations: accept the root as it is — red; delete instead of renaming — the
// kept content is gone, red.
func TestBackupSessionPaths_ABadRootIsSetAsideAndMadeAfresh(t *testing.T) {
	cases := map[string]func(t *testing.T, root string, plant func(string)){
		"earlier build 0777": func(t *testing.T, root string, _ func(string)) {
			mustMkdirMode(t, root, 0o777)
		},
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
			if name == "earlier build 0777" || name == "another user's directory" {
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
