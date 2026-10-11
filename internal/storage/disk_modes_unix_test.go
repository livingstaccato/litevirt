//go:build unix

package storage

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A disk a pool driver creates — qcow2 or raw, on a local/dir pool (nfs and
// btrfs create through the same code) — is the owner's alone (0600), and a pool
// directory the driver makes is searchable but not listable (0711): qemu,
// running as its own user after libvirt's label on the FILE, must still resolve
// the path through it. Before, the files were 0644 and the directory 0755.
//
// Mutations: CreateExclusive at 0o644 — the raw case goes red; Prepare at 0755
// — the directory goes red.
func TestLocalDriver_NewDisksAndPoolDirAreNotWorldReadable(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	pool := filepath.Join(t.TempDir(), "pool")
	d := &localDriver{dataDir: pool}
	if err := d.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(pool); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("new pool dir: %v %v, want 0711", fi.Mode().Perm(), err)
	}
	for _, format := range []string{"qcow2", "raw"} {
		p, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: format, SizeBytes: 1 << 20, Format: format})
		if err != nil {
			t.Fatalf("CreateDisk %s: %v", format, err)
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s disk: %v %v, want 0600", format, fi.Mode().Perm(), err)
		}
	}
}

// No backfill: a pool directory that already exists keeps its mode.
//
// Mutation: chmod the pool dir to 0711 in Prepare — this goes red.
func TestLocalDriver_PrepareLeavesAnExistingDirAlone(t *testing.T) {
	pool := t.TempDir()
	if err := os.Chmod(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (&localDriver{dataDir: pool}).Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(pool); fi.Mode().Perm() != 0o755 {
		t.Errorf("an existing pool dir was changed to %04o", fi.Mode().Perm())
	}
}

// A btrfs pool's disk lives in a subvolume of its own, which `btrfs subvolume
// create` makes 0755; the driver narrows the NEW subvolume to 0711 (qemu still
// resolves the path through it) and the disk in it is 0600. A stand-in btrfs
// on PATH makes the directory as the real one does.
//
// Mutation: drop the chmod of the new subvolume — this goes red.
func TestBtrfsCreateDisk_TheNewSubvolumeIsSearchableOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	bin := t.TempDir()
	script := "#!/bin/sh\n[ \"$1 $2\" = \"subvolume create\" ] && shift 3 && exec mkdir -m 0755 \"$1\"\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "btrfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	root := t.TempDir()
	d := &btrfsDriver{subvolRoot: root}
	p, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "root", SizeBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Dir(p)); err != nil || fi.Mode().Perm() != 0o711 {
		t.Errorf("new subvolume: %v %v, want 0711", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("disk: %v %v, want 0600", fi.Mode().Perm(), err)
	}
}
