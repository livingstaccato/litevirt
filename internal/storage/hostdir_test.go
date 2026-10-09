package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckReadDir(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	pki := filepath.Join(base, "pki")
	ok := filepath.Join(base, "rootfs")
	lib := filepath.Join(dataDir, OCILibraryDir, "img")
	pool := filepath.Join(dataDir, "pools", "p", "r")
	state := filepath.Join(dataDir, "vms")
	for _, d := range []string{ok, lib, pool, state, pki} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(state, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p    string
		want bool
	}{
		{ok, true}, {lib, true}, {pool, true},
		{"/", false}, {"/etc", false}, {"/var", false}, {"/var/lib/lxc/x", false}, {"/var/lib/libvirt", false},
		{state, false}, {dataDir, false}, {base, false}, {pki, false}, {link, false},
		{"/home", false}, {file, false}, {filepath.Join(base, "missing"), false},
		{"rel/x", false}, {ok + "/../rootfs", false},
	} {
		err := CheckReadDir(c.p, dataDir, pki)
		if (err == nil) != c.want {
			t.Errorf("CheckReadDir(%q) = %v, want ok=%v", c.p, err, c.want)
		}
	}
}

func TestOCILibraryItem(t *testing.T) {
	dataDir := t.TempDir()
	lib := filepath.Join(dataDir, OCILibraryDir)
	if err := os.MkdirAll(filepath.Join(lib, "img", "rootfs", "srv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(lib, "out")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p    string
		want bool
	}{
		{filepath.Join(lib, "img"), true},
		{filepath.Join(lib, "img", "rootfs"), true},
		{filepath.Join(lib, "fresh"), true}, // not pulled yet: judged lexically
		{lib, false},
		{filepath.Join(lib, "img", "rootfs", "srv"), false},
		{filepath.Join(lib, "img", "config.json"), false},
		{filepath.Join(lib, "out"), false},
		{filepath.Join(lib, "..", "vms"), false},
		{filepath.Join(dataDir, "vms"), false},
	} {
		if got := OCILibraryItem(c.p, dataDir); got != c.want {
			t.Errorf("OCILibraryItem(%q) = %v, want %v", c.p, got, c.want)
		}
	}
}

// The data-directory rule for a container's rootfs template or OCI source is
// the one pools and file reads use (final whole-branch review M1): the
// daemon's own state (dataDirOwned), disks/ apart from disks/uploads/, and the
// roots of pools/ and mounts/ are refused; any other child of the data
// directory — a main-era <data_dir>/rc5pool an admin pulled into — is an
// ordinary host path.
func TestCheckReadDir_DataDirChildrenFollowThePoolRule(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	pki := filepath.Join(base, "pki")
	mk := func(rel string) string {
		p := filepath.Join(dataDir, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		rel  string
		want bool
	}{
		{"rc5pool/img/rootfs", true},
		{"rc5pool", true},
		{"isos", true},
		{"pools/p/r", true},
		{"mounts/nfs_a/r", true},
		{"disks/uploads/u", true},
		{OCILibraryDir + "/img", true},
		{"pools", false},
		{"mounts", false},
		{"disks", false},
		{"disks/vm-a", false},
		{"vms", false},
		{"vms/x", false},
		{"backup-scratch/x", false},
		{"ct-snapshots/c", false},
		{"opjournal", false},
		{".tmpdir", false},
	} {
		p := mk(c.rel)
		err := CheckReadDir(p, dataDir, pki)
		if (err == nil) != c.want {
			t.Errorf("CheckReadDir(<data>/%s) = %v, want ok=%v", c.rel, err, c.want)
		}
	}
}

// The default data directory is judged even when data_dir is elsewhere, as
// the pool rule does: the daemon hardcodes backup-scratch and backup-sock
// under /var/lib/litevirt. The refusal comes from the rule, before the
// existence check, so it holds on a host without that directory.
func TestCheckReadDir_JudgesTheDefaultDataDirToo(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "srv-lv")
	for _, p := range []string{"/var/lib/litevirt/backup-scratch", "/var/lib/litevirt/backup-scratch/x",
		"/var/lib/litevirt/vms", "/var/lib/litevirt/disks/a", "/var/lib/litevirt"} {
		err := CheckReadDir(p, dataDir, "")
		if err == nil || !strings.Contains(err.Error(), "data directory") {
			t.Errorf("CheckReadDir(%q) with data_dir %s = %v, want a data-directory refusal", p, dataDir, err)
		}
		if err := CheckTemplateDir(p, dataDir, "", "", ""); err == nil || !strings.Contains(err.Error(), "data directory") {
			t.Errorf("CheckTemplateDir(%q) with data_dir %s = %v, want a data-directory refusal", p, dataDir, err)
		}
	}
}
