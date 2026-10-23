package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// CreateDiskPath names the file each file driver's CreateDisk writes: the
// kept-create guard refuses a create by it before the driver runs.
func TestCreateDiskPath_IsWhereCreateDiskWrites(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "disks"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	for name, c := range map[string]struct {
		cfg Config
		drv Driver
	}{
		"local":           {Config{Driver: "local"}, nil},
		"local at target": {Config{Driver: "local", Target: target}, nil},
		"dir":             {Config{Driver: "dir", Target: target}, nil},
		"nfs at target":   {Config{Driver: "nfs", Source: "nas:/vm", Target: target}, &nfsDriver{mountDir: target}},
	} {
		t.Run(name, func(t *testing.T) {
			drv := c.drv
			if drv == nil {
				var err error
				if drv, err = New(dataDir, c.cfg); err != nil {
					t.Fatal(err)
				}
			}
			vm := "vm-" + filepath.Base(t.Name())
			want, ok, err := CreateDiskPath(dataDir, c.cfg, vm, "root")
			if err != nil || !ok {
				t.Fatalf("CreateDiskPath = %q, %v, %v", want, ok, err)
			}
			got, err := drv.CreateDisk(context.Background(), DiskOptions{VMName: vm, DiskName: "root", SizeBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			if filepath.Clean(got) != want {
				t.Fatalf("CreateDisk wrote %s; CreateDiskPath says %s", got, want)
			}
		})
	}
	for _, d := range []string{"ceph", "iscsi"} {
		if p, ok, err := CreateDiskPath(dataDir, Config{Driver: d, Source: "x"}, "vm", "root"); ok || err != nil {
			t.Errorf("%s: CreateDiskPath = %q, %v, %v; want no file", d, p, ok, err)
		}
	}
}
