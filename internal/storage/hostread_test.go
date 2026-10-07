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

// opticalImage is a file with an ISO 9660 volume descriptor at sector 16.
func opticalImage(body string) []byte {
	b := make([]byte, 0x8800)
	copy(b[0x8000:], "\x01CD001\x01")
	return append(b, body...)
}

// udfImage is a file with a UDF volume recognition sequence at sector 16.
func udfImage() []byte {
	b := make([]byte, 0x9800)
	copy(b[0x8000:], "\x00BEA01\x01")
	copy(b[0x8800:], "\x00NSR02\x01")
	copy(b[0x9000:], "\x00TEA01\x01")
	return b
}

// Under /home and /run (user-data roots) a guest may be given an optical disc
// image outside any dot-directory — an ISO a user downloaded, a USB stick under
// /run/media — and nothing else: not a key, not a key renamed .iso, not an ISO
// inside ~/.cache, not through a link.
func TestCheckReadFile_UserDataRoots(t *testing.T) {
	// The real roots are user-data roots: open to an ISO, not to anything.
	if !UnderUserDataRoot("/home/u/x.iso") || !UnderUserDataRoot("/run/media/u/S/x.iso") || !UnderUserDataRoot("/var/run/media/u/S/x.iso") {
		t.Error("/home and /run are not user-data roots")
	}
	if err := CheckReadPathLexical("/home/u/.ssh/id_rsa", "", ""); err == nil {
		t.Error("/home/u/.ssh/id_rsa allowed lexically")
	}
	base := t.TempDir()
	home, run := filepath.Join(base, "home"), filepath.Join(base, "run")
	defer SetUserDataRootsForTest([]string{home, run})()
	data := t.TempDir()
	mk := func(p string, b []byte) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	virtio := mk(filepath.Join(home, "u", "isos", "virtio-win.iso"), opticalImage("virtio"))
	stick := mk(filepath.Join(run, "media", "u", "STICK", "x.iso"), opticalImage("stick"))
	udf := mk(filepath.Join(home, "u", "isos", "win11.iso"), udfImage())
	key := mk(filepath.Join(home, "u", ".ssh", "id_rsa"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
	renamed := mk(filepath.Join(home, "u", "isos", "id_rsa.iso"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
	dotISO := mk(filepath.Join(home, "u", ".cache", "x.iso"), opticalImage("cached"))
	beaOnly := mk(filepath.Join(home, "u", "isos", "bea.iso"), append(make([]byte, 0x8000), "\x00BEA01\x01"...))
	link := filepath.Join(home, "u", "isos", "key.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	dotLink := filepath.Join(home, "u", "isos", "cached.iso")
	if err := os.Symlink(dotISO, dotLink); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{virtio, stick, udf} {
		if err := CheckReadFile(p, data, ""); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	for _, p := range []string{key, renamed, dotISO, beaOnly, link, dotLink} {
		if err := CheckReadFile(p, data, ""); err == nil {
			t.Errorf("%s allowed", p)
		}
	}
	if err := CheckReadPathLexical(virtio, data, ""); err != nil {
		t.Errorf("lexical: %s refused: %v", virtio, err)
	}
	if err := CheckReadPathLexical(dotISO, data, ""); err == nil {
		t.Errorf("lexical: %s allowed", dotISO)
	}
	if err := CheckRefusedReadPath(filepath.Join(home, "u", ".gnupg", "gone.iso"), data, ""); err == nil {
		t.Error("stored path in a dot-directory under a user-data root allowed")
	}
	if err := CheckRefusedReadPath(filepath.Join(home, "u", "isos", "gone.iso"), data, ""); err != nil {
		t.Errorf("stored path under a user-data root refused: %v", err)
	}
}
