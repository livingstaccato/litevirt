//go:build linux

package storage

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/litevirt/litevirt/internal/diskmode"
)

// standInBtrfs puts a btrfs on PATH that creates and deletes subvolumes as
// plain directories.
func standInBtrfs(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\ncase \"$1 $2\" in\n\"subvolume create\") exec mkdir -m 0755 \"$4\";;\n\"subvolume delete\") exec rm -rf \"$4\";;\nesac\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "btrfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// M2: a btrfs disk is created although the new subvolume's chmod is refused,
// and that is logged.
//
// Mutation: CreateDisk fails on the refused chmod — this goes red.
func TestBtrfsCreateDisk_ARefusedChmodNeverFailsTheCreate(t *testing.T) {
	standInBtrfs(t)
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	t.Cleanup(diskmode.SetFchmodForTest(func(*os.File, fs.FileMode) error { return syscall.EPERM }))
	d := &btrfsDriver{subvolRoot: t.TempDir()}
	if _, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "root", SizeBytes: 1 << 20}); err != nil {
		t.Fatalf("the create failed on a refused chmod: %v", err)
	}
	if !strings.Contains(buf.String(), "operation not permitted") {
		t.Errorf("no warning:\n%s", buf.String())
	}
}

// M6: a btrfs disk create that fails after its subvolume exists removes the
// subvolume (it is the call's own and holds no disk), so nothing is orphaned
// and a retry finds the name free.
//
// Mutation: drop the subvolume delete — the subvolume stays: red.
func TestBtrfsCreateDisk_AFailedCreateLeavesNoSubvolume(t *testing.T) {
	standInBtrfs(t)
	root := t.TempDir()
	d := &btrfsDriver{subvolRoot: root}
	if _, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "root", SizeBytes: -1, Format: "raw"}); err == nil {
		t.Fatal("a raw disk of -1 bytes was created")
	}
	if _, err := os.Lstat(filepath.Join(root, "vm-root")); !os.IsNotExist(err) {
		t.Errorf("the failed create left its subvolume: %v", err)
	}
}

// F-5 (lab 2): a disk's own subvolume that `btrfs subvolume delete` could not
// delete was only logged, and the VM delete reported the disk removed with
// the subvolume left. A subvolume that is still there is an error to the
// caller; a file not in a subvolume of its own is still removed quietly.
//
// Mutation: return nil on a failed subvolume delete again — red.
func TestBtrfsDeleteDisk_ASubvolumeLeftBehindIsAnError(t *testing.T) {
	bin := t.TempDir()
	// "subvolume delete" fails; "subvolume show" answers for a directory
	// named like a disk's subvolume only.
	script := "#!/bin/sh\ncase \"$1 $2\" in\n\"subvolume delete\") echo busy >&2; exit 1;;\n\"subvolume show\") case \"$4\" in *-root) exit 0;; esac; exit 1;;\nesac\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "btrfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	root := t.TempDir()
	d := &btrfsDriver{subvolRoot: root}

	own := filepath.Join(root, "vm-root")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(own, "vm-root.qcow2")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteDisk(context.Background(), file); err == nil {
		t.Error("a disk whose subvolume could not be deleted was reported deleted")
	}
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Errorf("the disk file itself was not removed: %v", err)
	}

	plain := filepath.Join(root, "staging")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	pf := filepath.Join(plain, "copy.qcow2")
	if err := os.WriteFile(pf, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteDisk(context.Background(), pf); err != nil {
		t.Errorf("a file in a plain directory: %v, want it removed quietly", err)
	}
}
