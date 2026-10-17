package cloudinit

import (
	"os"
	"path/filepath"
	"testing"
)

// A seed's stamp is written durably: its bytes are synced before the rename
// makes it the stamp, and the directory after it. Without, a power cut left
// a 0-byte stamp (lab 2, abort proof, surprise 1).
//
// Mutations: drop the file sync, or the directory sync — red.
func TestStampSeed_IsDurable(t *testing.T) {
	var synced []string
	prevF, prevD := fileSync, dirSync
	fileSync = func(f *os.File) error { synced = append(synced, "file:"+f.Name()); return f.Sync() }
	dirSync = func(f *os.File) error { synced = append(synced, "dir:"+f.Name()); return f.Sync() }
	t.Cleanup(func() { fileSync, dirSync = prevF, prevD })

	dir := t.TempDir()
	iso := filepath.Join(dir, "vm.iso")
	if err := os.WriteFile(iso, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StampSeed(iso, "uuid-1"); err != nil {
		t.Fatal(err)
	}
	if o, ok, err := SeedOwner(iso); err != nil || !ok || o != "uuid-1" {
		t.Fatalf("SeedOwner = %q, %v, %v; want uuid-1", o, ok, err)
	}
	if len(synced) != 2 || synced[0][:5] != "file:" || synced[1] != "dir:"+dir {
		t.Fatalf("syncs = %v; want the stamp's temp file, then %s", synced, dir)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(matches) != 0 {
		t.Errorf("temp files left: %v", matches)
	}
}
