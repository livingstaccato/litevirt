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

// The staging root and a container's staging directory are made root-only
// and never followed through a symlink: one planted where either goes fails
// the start instead of staging host trees wherever it points.
//
// Mutation: make ensureStagingDir MkdirAll without the Lstat check — red.
func TestEnsureStagingDir_RefusesASymlinkAndTightensTheMode(t *testing.T) {
	base := t.TempDir()
	d := filepath.Join(base, "root")
	if err := ensureStagingDir(d); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureStagingDir(d); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(d); st == nil || st.Mode().Perm() != 0o700 {
		t.Errorf("staging dir mode = %v; want 0700", st.Mode())
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
