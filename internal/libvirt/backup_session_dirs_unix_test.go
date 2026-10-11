//go:build unix

package libvirt

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
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
	return fi.Mode() & (fs.ModePerm | fs.ModeSticky)
}

// The backup session's scratch and NBD socket used to sit directly in
// backup-scratch/ and backup-sock/, which every session chmod-ed 0777 with no
// sticky bit: any local user could replace the socket the daemon reads the
// guest's disk from, or the scratch name. Now the two directories are root's
// and searchable only (0711, narrowed from an earlier build's 0777), and each
// session's files are in a directory of their own owned by the uid qemu runs
// as for the domain, 0700: qemu creates the scratch and binds the socket there,
// the daemon (root) dials it, and nobody else can reach either.
//
// Mutations: the roots left 0777 (or the base's flat layout) — red; the
// session directory not chowned to qemu's uid — red; the session directory
// 0777 — red.
func TestBackupSessionPaths_AreQEMUsAndRootsOnly(t *testing.T) {
	backupDirsUmask022(t)
	calls := recordChown(t, false)
	base := t.TempDir()
	scratchRoot, sockRoot := filepath.Join(base, "backup-scratch"), filepath.Join(base, "backup-sock")
	// An earlier build left both 0777.
	for _, d := range []string{scratchRoot, sockRoot} {
		if err := os.Mkdir(d, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	tag := "web-1-vda"
	scratch, socket, err := prepareBackupSessionPaths(scratchRoot, sockRoot, tag, qemuOwner{UID: 64055, GID: 993, Known: true})
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
	// A unix socket path is at most 107 bytes; the new one is never longer
	// than the old <sock>/<tag>.sock, so no VM whose backup opened before
	// is refused now.
	if old := len(filepath.Join(sockRoot, tag+".sock")); len(socket) > old {
		t.Errorf("socket path %q is %d bytes, longer than the old layout's %d", socket, len(socket), old)
	}
}

// When qemu's uid cannot be read from the domain, the session directory is
// still not world-listable or replaceable: 01733 (sticky, no read for others)
// in a root-only 0711 parent. Nothing is chowned.
//
// Mutation: the fallback 0777 — red.
func TestBackupSessionPaths_UnknownQEMUUserIsStickyNotListable(t *testing.T) {
	backupDirsUmask022(t)
	calls := recordChown(t, false)
	base := t.TempDir()
	scratch, socket, err := prepareBackupSessionPaths(filepath.Join(base, "s"), filepath.Join(base, "k"), "v-vda", qemuOwner{})
	if err != nil {
		t.Fatalf("prepareBackupSessionPaths: %v", err)
	}
	for _, p := range []string{scratch, socket} {
		if got := modeOf(t, filepath.Dir(p)); got != fs.ModeSticky|0o733 {
			t.Errorf("session directory of %s is %04o, want 01733", p, got)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("chowned with no known owner: %+v", *calls)
	}
}

// A chown that fails (a filesystem that refuses it) never fails the backup:
// the directory falls back to 01733, as for an unknown owner.
//
// Mutation: return the chown error — red.
func TestBackupSessionPaths_ARefusedChownFallsBack(t *testing.T) {
	backupDirsUmask022(t)
	recordChown(t, true)
	base := t.TempDir()
	scratch, _, err := prepareBackupSessionPaths(filepath.Join(base, "s"), filepath.Join(base, "k"), "v-vda", qemuOwner{UID: 64055, GID: 993, Known: true})
	if err != nil {
		t.Fatalf("a refused chown failed the session: %v", err)
	}
	if got := modeOf(t, filepath.Dir(scratch)); got != fs.ModeSticky|0o733 {
		t.Errorf("session directory is %04o after a refused chown, want 01733", got)
	}
}

// A crashed session's leftovers — in its session directory, and at the names
// an earlier build used directly in the shared directories — are removed,
// as the earlier build removed its own. Nothing else is.
//
// Mutation: drop the removal of the earlier build's names — red.
func TestBackupSessionPaths_StaleLeftoversGoAndNothingElse(t *testing.T) {
	backupDirsUmask022(t)
	recordChown(t, false)
	base := t.TempDir()
	scratchRoot, sockRoot := filepath.Join(base, "s"), filepath.Join(base, "k")
	tag := "v-vda"
	owner := qemuOwner{UID: 64055, GID: 993, Known: true}
	scratch, socket, err := prepareBackupSessionPaths(scratchRoot, sockRoot, tag, owner)
	if err != nil {
		t.Fatal(err)
	}
	legacy := []string{filepath.Join(scratchRoot, tag+".scratch"), filepath.Join(sockRoot, tag+".sock")}
	other := filepath.Join(scratchRoot, "other-vda.scratch.keep")
	for _, p := range append([]string{scratch, socket, other}, legacy...) {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scratch2, socket2, err := prepareBackupSessionPaths(scratchRoot, sockRoot, tag, owner)
	if err != nil {
		t.Fatalf("a second session: %v", err)
	}
	if scratch2 != scratch || socket2 != socket {
		t.Fatalf("a second session of the same disk got other paths: %s %s", scratch2, socket2)
	}
	for _, p := range append([]string{scratch, socket}, legacy...) {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale %s was not removed (err=%v)", p, err)
		}
	}
	if _, err := os.Lstat(other); err != nil {
		t.Errorf("another session's file was removed: %v", err)
	}
}

// A session directory name that is not a directory — planted while an earlier
// build left the parent 0777 — is never followed or used.
func TestBackupSessionPaths_ASymlinkAtTheSessionNameIsRefused(t *testing.T) {
	backupDirsUmask022(t)
	recordChown(t, false)
	base := t.TempDir()
	scratchRoot, sockRoot := filepath.Join(base, "s"), filepath.Join(base, "k")
	for _, d := range []string{scratchRoot, sockRoot} {
		if err := os.Mkdir(d, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	elsewhere := t.TempDir()
	before := modeOf(t, elsewhere)
	if err := os.Symlink(elsewhere, filepath.Join(sockRoot, "v-vda")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareBackupSessionPaths(scratchRoot, sockRoot, "v-vda", qemuOwner{UID: 1, GID: 1, Known: true}); err == nil {
		t.Fatal("a symlink at the session directory's name was used")
	}
	if got := modeOf(t, elsewhere); got != before {
		t.Errorf("the symlink's target was changed from %04o to %04o", before, got)
	}
}

// qemu's uid:gid is the domain's DAC label, which libvirt puts in the live
// XML ("+64055:+993").
func TestDomainQEMUOwner_ReadsTheDACLabel(t *testing.T) {
	xml := `<domain type='kvm' id='3'><name>v</name>
<seclabel type='dynamic' model='apparmor' relabel='yes'><label>libvirt-abc</label></seclabel>
<seclabel type='dynamic' model='dac' relabel='yes'><label>+64055:+993</label><imagelabel>+64055:+993</imagelabel></seclabel>
</domain>`
	if got := domainQEMUOwner(xml); got != (qemuOwner{UID: 64055, GID: 993, Known: true}) {
		t.Fatalf("owner = %+v, want 64055:993", got)
	}
	for _, label := range []string{"", "libvirt-qemu:kvm", "+1", "+a:+b", "-1:-1"} {
		x := `<domain><seclabel type='static' model='dac'><label>` + label + `</label></seclabel></domain>`
		if got := domainQEMUOwner(x); got.Known {
			t.Errorf("label %q read as %+v, want unknown", label, got)
		}
	}
	if got := domainQEMUOwner(`<domain><name>v</name></domain>`); got.Known {
		t.Errorf("no DAC label read as %+v", got)
	}
}
