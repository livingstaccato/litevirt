//go:build linux

package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// A config rendered by an earlier build names the old staging root: its
// in-container reboot (no daemon in the loop to render it again) is staged
// where it says, as before, never refused for it. A daemon-driven start
// renders the new root. An entry under neither root, entries split between
// them, or an entry out of order are refused.
//
// Mutation: drop the legacy root from hookMounts or hookStagingRoot — red.
func TestHookStagingRoot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		want    string
	}{
		{"current", []string{stagingRoot + "/c1/m0", stagingRoot + "/c1/m1"}, stagingRoot},
		{"earlier build's", []string{"/run/litevirt/ct/c1/m0", "/run/litevirt/ct/c1/m1"}, "/run/litevirt/ct"},
		{"split between roots", []string{stagingRoot + "/c1/m0", "/run/litevirt/ct/c1/m1"}, ""},
		{"out of order", []string{stagingRoot + "/c1/m1"}, ""},
		{"another container's", []string{stagingRoot + "/c2/m0"}, ""},
		{"no root", []string{"/srv/a/data"}, ""},
	} {
		ms, err := hookMounts(stagingCfg(tc.entries...))
		if err == nil {
			var root string
			root, err = hookStagingRoot("c1", ms)
			if err == nil && root != tc.want {
				t.Errorf("%s: root = %s; want %s", tc.name, root, tc.want)
			}
		}
		if (err == nil) != (tc.want != "") {
			t.Errorf("%s: err = %v; want refused=%v", tc.name, err, tc.want == "")
		}
	}
	if root, err := hookStagingRoot("c1", nil); err != nil || root != stagingRoot {
		t.Errorf("no mounts: %s, %v; want %s", root, err, stagingRoot)
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
