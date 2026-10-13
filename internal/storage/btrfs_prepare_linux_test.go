//go:build linux

package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// Lab 2 S-1: a btrfs pool whose source is a directory or subvolume below the
// filesystem's mount point (the driver's own example, /mnt/btrfs/litevirt)
// was refused, because `btrfs filesystem show` (btrfs-progs 6.6) accepts a
// mount point only. Prepare now asks the kernel which filesystem the path is
// on. The stand-in btrfs refuses `filesystem show` as btrfs-progs 6.6 does
// for such a path.
//
// Mutation: Prepare runs `btrfs filesystem show` again — the subdirectory is
// refused: red. The magic not checked — the ext4 path is accepted: red.
func TestBtrfsPrepare_ASubdirectoryOfABtrfsFilesystemIsAccepted(t *testing.T) {
	standInBtrfs(t)
	root := filepath.Join(t.TempDir(), "btrfs", "litevirt")
	t.Cleanup(statfsInfo.set(func(string) (uint32, string, error) { return btrfsSuperMagic, "0000000100000002", nil }))
	if err := (&btrfsDriver{subvolRoot: root}).Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare of a directory on btrfs: %v", err)
	}

	t.Cleanup(statfsInfo.set(func(string) (uint32, string, error) { return 0xEF53, "0000000100000002", nil }))
	err := (&btrfsDriver{subvolRoot: root}).Prepare(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not on a btrfs filesystem") {
		t.Fatalf("Prepare of a directory on ext4 = %v, want it refused as not on btrfs", err)
	}
}

// Review m-2: Prepare still refuses a host without the btrfs tool, which the
// old `btrfs filesystem show` check did as a side effect; every disk
// operation runs it.
//
// Mutation: drop the LookPath — a pool is prepared with no btrfs tool: red.
func TestBtrfsPrepare_AHostWithoutTheBtrfsToolIsRefused(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Cleanup(statfsInfo.set(func(string) (uint32, string, error) { return btrfsSuperMagic, "0000000100000002", nil }))
	err := (&btrfsDriver{subvolRoot: filepath.Join(t.TempDir(), "litevirt")}).Prepare(context.Background())
	if err == nil || !strings.Contains(err.Error(), "btrfs-progs") {
		t.Fatalf("Prepare without the btrfs tool = %v, want it refused naming btrfs-progs", err)
	}
}
