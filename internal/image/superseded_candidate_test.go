package image

import (
	"os"
	"path/filepath"
	"testing"
)

// M1: a copy a failover set aside in a legacy per-VM directory is never a
// candidate for the sweep of that VM's disks (`lv rebuild`, create's debris
// pass): while the VM exists it is retained, and only an operator removes it
// (`lv host superseded-disks --remove`).
//
// Mutation: drop the set-aside-name skip in VMDiskCandidates — the copy is a
// candidate and the test is red.
func TestVMDiskCandidates_NeverListsASetAsideCopy(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	legacyDir := filepath.Join(dir, "disks", "vm1")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(legacyDir, "root.qcow2")
	aside := disk + ".superseded-20261001T000000.000000000Z"
	for _, p := range []string{disk, aside} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.VMDiskCandidates("vm1")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c == aside {
			t.Fatalf("candidates %v include the set-aside copy", got)
		}
	}
	if len(got) != 1 || got[0] != disk {
		t.Fatalf("candidates = %v, want only %s", got, disk)
	}
}
