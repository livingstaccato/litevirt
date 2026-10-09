package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// A container template may be read from inside the LXC store — LXC's own
// template cache, another container's rootfs an Admin names — but never the
// store itself, the container being created, or anything else secret. A VM's
// CD-ROM (CheckReadFile) is not given the LXC store.
func TestCheckTemplateDir_LXCStore(t *testing.T) {
	lxc := t.TempDir()
	restore := SetSecretRootsForTest(append(append([]string{}, secretRoots...), lxc))
	defer restore()
	base := filepath.Join(lxc, "base", "rootfs")
	own := filepath.Join(lxc, "web", "rootfs")
	for _, d := range []string{base, own} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	iso := filepath.Join(lxc, "base", "x.iso")
	if err := os.WriteFile(iso, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p    string
		want bool
	}{
		{base, true},
		{filepath.Join(lxc, "base"), true},
		{lxc, false},
		{own, false},
		{filepath.Join(lxc, "web"), false},
		{"/etc", false},
	} {
		err := CheckTemplateDir(c.p, "", "", lxc, filepath.Join(lxc, "web"))
		if (err == nil) != c.want {
			t.Errorf("CheckTemplateDir(%q) = %v, want ok=%v", c.p, err, c.want)
		}
	}
	if err := CheckReadDir(base, "", ""); err == nil {
		t.Error("CheckReadDir took the LXC store without the template rule")
	}
	if err := CheckReadFile(iso, "", ""); err == nil {
		t.Error("a VM was given a file in the LXC store")
	}
}

// A store at a non-default lxcpath is not a secret root, and is still never a
// template itself (every container at once), nor is a parent of it.
func TestCheckTemplateDir_StoreElsewhere(t *testing.T) {
	parent := t.TempDir()
	store := filepath.Join(parent, "lxc")
	if err := os.MkdirAll(filepath.Join(store, "base", "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{store, parent} {
		if err := CheckTemplateDir(p, "", "", store, filepath.Join(store, "web")); err == nil {
			t.Errorf("CheckTemplateDir(%q) took the store", p)
		}
	}
	if err := CheckTemplateDir(filepath.Join(store, "base", "rootfs"), "", "", store, filepath.Join(store, "web")); err != nil {
		t.Errorf("template in the store: %v", err)
	}
}
