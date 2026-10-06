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
	for _, d := range []string{pki, filepath.Join(data, "pools", "isos"), filepath.Join(data, "disks"), filepath.Join(data, "cloudinit")} {
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
	pool := write(filepath.Join(data, "pools", "isos", "debian.iso"))
	// disks/ holds every VM's local disks across projects; it is not a pool.
	disks := write(filepath.Join(data, "disks", "other.iso"))
	ci := write(filepath.Join(data, "cloudinit", "vm.iso"))
	plain := write(filepath.Join(t.TempDir(), "x.iso"))

	for _, p := range []string{pool, plain} {
		if err := CheckReadFile(p, data, pki); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	for _, p := range []string{key, ci, disks, "/etc/hostname", "/proc/self/environ", "rel.iso", plain + "/.."} {
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
