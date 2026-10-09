package storage

import (
	"os"
	"path/filepath"
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
