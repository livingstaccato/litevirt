//go:build linux

package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func stagingCfg(entries ...string) string {
	var b strings.Builder
	b.WriteString("lxc.uts.name = c1\n" + mountBlockBegin + "\nlxc.hook.pre-start = /x __lxc-hook\n")
	for _, e := range entries {
		b.WriteString("# litevirt:mount ro dir /srv/a data\nlxc.mount.entry = " + e + " srv none bind,ro,nosuid,nodev,create=dir 0 0\n")
	}
	b.WriteString(mountBlockEnd + "\n")
	return b.String()
}

// Every entry must name exactly its own staging path under stagingRoot, in
// order; an entry under any other root, out of order, or another
// container's is refused.
//
// Mutation: accept any path in checkStagingPaths — red.
func TestCheckStagingPaths(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		ok      bool
	}{
		{"current", []string{stagingRoot + "/c1/m0", stagingRoot + "/c1/m1"}, true},
		{"another root", []string{"/run/litevirt/ct/c1/m0"}, false},
		{"out of order", []string{stagingRoot + "/c1/m1"}, false},
		{"another container's", []string{stagingRoot + "/c2/m0"}, false},
		{"no root", []string{"/srv/a/data"}, false},
	} {
		ms, err := hookMounts(stagingCfg(tc.entries...))
		if err == nil {
			err = checkStagingPaths("c1", ms)
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v; want ok=%v", tc.name, err, tc.ok)
		}
	}
	if err := checkStagingPaths("c1", nil); err != nil {
		t.Errorf("no mounts: %v", err)
	}
}

// The staging root and a container's staging directory are root's, mode
// 0711 — traverse only: an unprivileged container's mapped root must reach
// its staged mounts through them when LXC binds the entries (I-2), and
// nobody but root can list, create or rename in them. They are never
// followed through a symlink: one planted where either goes fails the start
// instead of staging host trees wherever it points.
//
// Mutation: make ensureStagingDir MkdirAll without the Lstat check, or set
// 0700 — red.
func TestEnsureStagingDir_RefusesASymlinkAndTightensTheMode(t *testing.T) {
	base := t.TempDir()
	d := filepath.Join(base, "root")
	if err := ensureStagingDir(d); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := ensureStagingDir(d); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(d); st == nil || st.Mode().Perm() != 0o711 {
		t.Errorf("staging dir mode = %v; want 0711", st.Mode())
	}
	elsewhere := filepath.Join(base, "elsewhere")
	_ = os.Mkdir(elsewhere, 0o755)
	link := filepath.Join(base, "link")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureStagingDir(link); err == nil {
		t.Error("a symlink planted at the staging path was followed")
	}
	f := filepath.Join(base, "file")
	_ = os.WriteFile(f, nil, 0o600)
	if err := ensureStagingDir(f); err == nil {
		t.Error("a file at the staging path was accepted")
	}
}

// m-4. post-stop never follows a symlink at a container's staging
// directory: the entries of whatever it points at are left alone.
//
// Mutation: drop the Lstat check from clearStaging — red.
func TestClearStaging_RefusesASymlinkedDir(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	precious := filepath.Join(target, "precious")
	if err := os.WriteFile(precious, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "c1")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	clearStaging(link)
	if _, err := os.Stat(precious); err != nil {
		t.Errorf("clearStaging followed a symlinked staging dir and removed what it points at: %v", err)
	}
}

// N-4. Taking a staging entry down never follows a symlink planted there:
// every unmount is MNT_DETACH|UMOUNT_NOFOLLOW, so a symlink entry pointing at
// a host mount detaches nothing.
//
// Mutation: drop UMOUNT_NOFOLLOW from unmountAll — red.
func TestUnmountAll_NeverFollowsASymlink(t *testing.T) {
	var flags []int
	prev := unmount
	unmount = func(_ string, f int) error {
		flags = append(flags, f)
		if len(flags) > 2 {
			return unix.EINVAL
		}
		return nil
	}
	t.Cleanup(func() { unmount = prev })
	unmountAll("/var/lib/lxc/.litevirt+staging/c1/m0")
	if len(flags) == 0 {
		t.Fatal("unmountAll unmounted nothing")
	}
	for _, f := range flags {
		if f&unix.UMOUNT_NOFOLLOW == 0 || f&unix.MNT_DETACH == 0 {
			t.Errorf("unmount flags %#x; want MNT_DETACH|UMOUNT_NOFOLLOW", f)
		}
	}
}
