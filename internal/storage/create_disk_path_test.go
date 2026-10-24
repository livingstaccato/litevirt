package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// The drivers the test above cannot run as they are: the block ones (zfs,
// lvm-thin, either spelling), whose commands run through volumeRunner; btrfs,
// which makes a subvolume per disk (a fake btrfs on PATH makes a directory);
// and nfs at its default mount point under the data directory, whose mount
// runs through nfsRemountRun. Each driver's own CreateDisk (and Prepare for
// nfs) runs with those faked, and its path must be CreateDiskPath's.
// (Adopted from the write-paths review, N4.)
//
// Mutations: CreateDiskPath names a zvol under /dev/zvol/<pool> without the
// dataset, an LV without its VG, a btrfs disk beside its subvolume instead of
// inside it, or nfs's default mount point under another name: each red.
func TestCreateDiskPath_MatchesTheDriversThatNeedTheirCommandsFaked(t *testing.T) {
	dataDir := t.TempDir()
	prev := volumeRunner
	volumeRunner = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { volumeRunner = prev })
	prevN := nfsRemountRun
	nfsRemountRun = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { nfsRemountRun = prevN })

	bin := t.TempDir()
	fakeBtrfs := "#!/bin/sh\nfor a; do last=$a; done\n[ \"$1 $2\" = \"subvolume create\" ] && mkdir -p \"$last\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "btrfs"), []byte(fakeBtrfs), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	for name, cfg := range map[string]Config{
		"zfs":      {Driver: "zfs", Source: "tank/lv"},
		"lvm-thin": {Driver: "lvm-thin", Source: "vg0", Options: map[string]string{"thinpool": "tp"}},
		"LVMTHIN":  {Driver: "LVMTHIN", Source: "vg0", Options: map[string]string{"thinpool": "tp"}},
		"btrfs":    {Driver: "btrfs", Source: t.TempDir()},
	} {
		t.Run(name, func(t *testing.T) {
			drv, err := New(dataDir, cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := drv.CreateDisk(context.Background(), DiskOptions{VMName: "web", DiskName: "root", SizeBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			want, ok, err := CreateDiskPath(dataDir, cfg, "web", "root")
			if err != nil || !ok || filepath.Clean(got) != want {
				t.Fatalf("CreateDisk wrote %s; CreateDiskPath = %q, %v, %v", got, want, ok, err)
			}
		})
	}

	t.Run("nfs at its default mount point", func(t *testing.T) {
		cfg := Config{Driver: "nfs", Source: "nas:/exports/vm"}
		drv, err := New(dataDir, cfg)
		if err != nil {
			t.Fatal(err)
		}
		nd := drv.(*nfsDriver)
		nd.run = nfsRemountRun
		_ = nd.Prepare(context.Background()) // makes the mount point; the faked mount mounts nothing
		want, ok, err := CreateDiskPath(dataDir, cfg, "web", "root")
		if err != nil || !ok {
			t.Fatalf("CreateDiskPath = %q, %v, %v", want, ok, err)
		}
		if got := filepath.Join(nd.mountDir, "web-root.qcow2"); got != want {
			t.Fatalf("the driver mounts at %s and writes %s; CreateDiskPath says %s", nd.mountDir, got, want)
		}
		if !strings.HasPrefix(want, filepath.Join(dataDir, "mounts")+string(filepath.Separator)) {
			t.Fatalf("the default mount point %s is not under %s/mounts", want, dataDir)
		}
	})
}
