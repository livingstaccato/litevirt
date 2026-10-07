package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// Users' uploads into a pool on <data_dir>/disks land in disks/uploads: pool
// content a guest may be given (whose it is, the caller decides by record).
// The VM disks beside it in disks/ stay refused.
func TestCheckReadFile_DiskUploadsArePoolContent(t *testing.T) {
	data := t.TempDir()
	up := filepath.Join(data, DataDirDiskUploads)
	if err := os.MkdirAll(up, 0o755); err != nil {
		t.Fatal(err)
	}
	iso, disk := filepath.Join(up, "x.iso"), filepath.Join(data, "disks", "vm-root.qcow2")
	for _, p := range []string{iso, disk} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckReadFile(iso, data, ""); err != nil {
		t.Errorf("an upload in disks/uploads refused: %v", err)
	}
	if err := CheckReadFile(disk, data, ""); err == nil {
		t.Error("a VM disk in disks/ is readable")
	}
}
