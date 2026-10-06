package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// What an installer ISO may be, read side: the refused places are refused to
// everyone, ordinary locations (including /usr/share, where virtio-win lives)
// are not.
func TestCheckReadFile_RefusedAndAllowed(t *testing.T) {
	data := t.TempDir()
	pki := filepath.Join(t.TempDir(), "pki")
	for _, d := range []string{pki, filepath.Join(data, "disks"), filepath.Join(data, "cloudinit")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string) string {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key := write(filepath.Join(pki, "host.key"))
	pool := write(filepath.Join(data, "disks", "debian.iso"))
	ci := write(filepath.Join(data, "cloudinit", "vm.iso"))
	plain := write(filepath.Join(t.TempDir(), "x.iso"))

	for _, p := range []string{pool, plain} {
		if err := CheckReadFile(p, data, pki); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	for _, p := range []string{key, ci, "/etc/hostname", "/proc/self/environ", "rel.iso", plain + "/.."} {
		if err := CheckReadFile(p, data, pki); err == nil {
			t.Errorf("%s allowed", p)
		}
	}
	if err := CheckReadPathLexical("/usr/share/virtio-win/virtio-win.iso", data, pki); err != nil {
		t.Errorf("/usr/share refused: %v", err)
	}
	// Stored paths: only the protected places are refused.
	if err := CheckRefusedReadPath(key, data, pki); err == nil {
		t.Error("stored PKI path allowed")
	}
	if err := CheckRefusedReadPath("/srv/isos//old.iso", data, pki); err != nil {
		t.Errorf("an unclean but harmless stored path refused: %v", err)
	}
}

// The built-in global ISO library lives at <data_dir>/pools/isos, and a guest
// may be given a file there; the rest of the data directory stays refused.
func TestCheckReadFile_TheGlobalISOLibraryDirectory(t *testing.T) {
	data := t.TempDir()
	for _, d := range []string{filepath.Join(data, ISOLibraryDir), filepath.Join(data, "isos"), filepath.Join(data, "pools", "other")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	lib := filepath.Join(data, ISOLibraryDir, "debian.iso")
	for _, p := range []string{lib, filepath.Join(data, "isos", "x.iso"), filepath.Join(data, "pools", "other", "x.iso")} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckReadFile(lib, data, ""); err != nil {
		t.Errorf("the global library file refused: %v", err)
	}
	if err := CheckReadFile(filepath.Join(data, "isos", "x.iso"), data, ""); err == nil {
		t.Error("<data_dir>/isos allowed; the library is pools/isos")
	}
	if err := CheckWriteRoot(filepath.Join(data, ISOLibraryDir), data, ""); err == nil {
		t.Error("a pool may be created over the global library's directory")
	}
}
