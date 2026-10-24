package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// (re-review rr1 N4) A resolved area root counts only where a pool could be:
// a pools/ linked to a system directory does not make what is under it the
// daemon's area, while a pools/ linked to an ordinary volume does.
//
// Mutation: accept every resolved root outside the data directory (drop
// CheckWriteRoot in rootOK) — red.
func TestInDataDirPoolArea_AResolvedRootMustBeAPoolPlace(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	pki := filepath.Join(root, "pki")
	big := filepath.Join(root, "big", "pools")
	for _, d := range []string{filepath.Join(data, "disks"), pki, filepath.Join(big, "ok")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(big, filepath.Join(data, "pools")); err != nil {
		t.Fatal(err)
	}
	if in, err := InDataDirPoolArea(filepath.Join(data, "pools", "ok"), data, pki); err != nil || !in {
		t.Fatalf("a pools/ linked to an ordinary volume: in=%t err=%v, want in", in, err)
	}

	data2 := filepath.Join(root, "data2")
	if err := os.MkdirAll(filepath.Join(data2, "disks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(data2, "pools")); err != nil {
		t.Fatal(err)
	}
	if in, _ := InDataDirPoolArea(filepath.Join(data2, "pools", "ssh"), data2, pki); in {
		t.Fatal("a pools/ linked to /etc made /etc/ssh the daemon's area")
	}
}
