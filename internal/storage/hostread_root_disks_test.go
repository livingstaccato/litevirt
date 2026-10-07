package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// C-1: on main an older cluster's default pool kept its ISOs directly in
// <data_dir>/disks, beside the VM disks. A file there is readable as an
// optical image with a single link, and nothing else is: a qcow2 disk, an
// image with a second name, a file in a directory below disks/, and a link
// from disks/ to the daemon's state stay refused.
//
// Mutation: make refuseSecretPath refuse disks/ files again — the ISO goes
// red; drop SingleLink — the hard-linked image goes red; drop the optical
// check for disks/ — the qcow2 goes red.
func TestCheckReadFile_DataDirDisksISOs(t *testing.T) {
	data := t.TempDir()
	disks := filepath.Join(data, "disks")
	for _, d := range []string{filepath.Join(disks, "sub"), filepath.Join(data, "cloudinit")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(p string, b []byte) string {
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	iso := mk(filepath.Join(disks, "win11.iso"), opticalImage("win"))
	udf := mk(filepath.Join(disks, "udf.iso"), udfImage())
	qcow := mk(filepath.Join(disks, "vm-root.qcow2"), append([]byte("QFI\xfb"), make([]byte, 0x9000)...))
	renamed := mk(filepath.Join(disks, "vm-data.iso"), []byte("QFI\xfb not an image"))
	twice := mk(filepath.Join(disks, "twice.iso"), opticalImage("twice"))
	if err := os.Link(twice, filepath.Join(data, "cloudinit", "second-name")); err != nil {
		t.Fatal(err)
	}
	deeper := mk(filepath.Join(disks, "sub", "x.iso"), opticalImage("deeper"))
	seed := mk(filepath.Join(data, "cloudinit", "vm.iso"), opticalImage("seed"))
	link := filepath.Join(disks, "seed.iso")
	if err := os.Symlink(seed, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{iso, udf} {
		if err := CheckReadFile(p, data, ""); err != nil {
			t.Errorf("an ISO directly in disks/ refused: %v", err)
		}
		if !DataDirDisksFile(p, data) {
			t.Errorf("%s is not reported as a file directly in disks/", p)
		}
	}
	for _, p := range []string{qcow, renamed, twice, deeper, link} {
		if err := CheckReadFile(p, data, ""); err == nil {
			t.Errorf("%s allowed", p)
		}
	}
	if err := CheckReadPathLexical(iso, data, ""); err != nil {
		t.Errorf("lexical: an ISO path directly in disks/ refused: %v", err)
	}
	if err := CheckReadPathLexical(deeper, data, ""); err == nil {
		t.Error("lexical: a path below disks/ allowed")
	}
	if DataDirDisksFile(deeper, data) || DataDirDisksFile(disks, data) || DataDirDisksFile(filepath.Join(disks, "uploads", "x.iso"), data) {
		t.Error("a path that is not directly in disks/ is reported as one")
	}
}

// C-2: /root is root's home, where an Admin logged in as root downloads an
// installer ISO. It gets /home's rule: an optical image passes, a key, a key
// renamed .iso and a link into ~/.ssh do not.
//
// Mutation: put /root back in secretRoots — the lexical check and the
// user-data root membership go red.
func TestCheckReadFile_RootIsAUserDataRoot(t *testing.T) {
	if !UnderUserDataRoot("/root/debian-12.iso") {
		t.Error("/root is not a user-data root")
	}
	if err := CheckReadPathLexical("/root/debian-12.iso", t.TempDir(), ""); err != nil {
		t.Errorf("an ISO path in root's home refused: %v", err)
	}
	if err := CheckRefusedReadPath("/root/isos/gone.iso", t.TempDir(), ""); err != nil {
		t.Errorf("a stored ISO path in root's home refused: %v", err)
	}
	// The rule itself, on a stand-in for /root.
	root := filepath.Join(t.TempDir(), "root")
	defer SetUserDataRootsForTest([]string{root})()
	data := t.TempDir()
	mk := func(p string, b []byte) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	deb := mk(filepath.Join(root, "debian-12.iso"), opticalImage("debian"))
	key := mk(filepath.Join(root, ".ssh", "id_ed25519"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
	renamed := mk(filepath.Join(root, "id_ed25519.iso"), []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
	link := filepath.Join(root, "key.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckReadFile(deb, data, ""); err != nil {
		t.Errorf("an ISO in root's home refused: %v", err)
	}
	for _, p := range []string{key, renamed, link} {
		if err := CheckReadFile(p, data, ""); err == nil {
			t.Errorf("%s allowed", p)
		}
	}
}
