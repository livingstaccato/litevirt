package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A pool directory can be shared by every project, and "<vm>-<disk>.qcow2" is
// ambiguous across hyphens (VM "a" disk "b-root" is VM "a-b" disk "root").
// Creating a disk never replaces the file already at that name.
func TestLocalCreateDisk_NeverReplacesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "a-b-root.qcow2")
	if err := os.WriteFile(victim, []byte("project B's disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &localDriver{dataDir: dir}
	for _, opts := range []DiskOptions{
		{VMName: "a", DiskName: "b-root", SizeBytes: 1 << 20},
		{VMName: "a", DiskName: "b-root", SizeBytes: 1 << 20, SourceImage: filepath.Join(dir, "base.qcow2")},
	} {
		if _, err := d.CreateDisk(context.Background(), opts); err == nil {
			t.Errorf("CreateDisk(%+v) over an existing file succeeded", opts)
		}
		if got, _ := os.ReadFile(victim); string(got) != "project B's disk" {
			t.Fatalf("the existing file was replaced (%d bytes)", len(got))
		}
	}
}
