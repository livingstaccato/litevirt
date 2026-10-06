package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An NFS export's server decides what is on it. Every NFS pool is mounted
// nosuid,nodev,noexec and, where the kernel has it, nosymfollow — whatever
// options the pool asks for — and its source and mount point follow "--".
func TestNFSMountIsHardened(t *testing.T) {
	for name, opts := range map[string]map[string]string{
		"default":              {},
		"admin options":        {"options": "vers=4.2,hard"},
		"options undoing them": {"options": "vers=3,suid,dev,exec,symfollow"},
	} {
		t.Run(name, func(t *testing.T) {
			var mount []string
			d := &nfsDriver{source: "server:/export", targetOverride: t.TempDir(), opts: opts,
				run: func(_ context.Context, cmd string, args ...string) ([]byte, error) {
					if cmd == "mountpoint" {
						return nil, errors.New("not mounted")
					}
					mount = args
					return nil, nil
				}}
			if err := d.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(mount) < 6 || mount[0] != "-t" || mount[2] != "-o" || mount[4] != "--" || mount[5] != "server:/export" {
				t.Fatalf("mount args = %q, want -t nfs -o <opts> -- <source> <dir>", mount)
			}
			got := strings.Split(mount[3], ",")
			for _, want := range []string{"nosuid", "nodev", "noexec", "nosymfollow"} {
				if !hasOpt(got, want) {
					t.Errorf("mount options %q lack %s", mount[3], want)
				}
			}
			for _, undo := range []string{"suid", "dev", "exec", "symfollow"} {
				if hasOpt(got, undo) {
					t.Errorf("mount options %q keep %s", mount[3], undo)
				}
			}
		})
	}
}

// A kernel without nosymfollow refuses it; the mount is retried without it
// (the rest of the hardening stays) rather than failing every NFS pool.
func TestNFSMountFallsBackWithoutNosymfollow(t *testing.T) {
	var mounts []string
	d := &nfsDriver{source: "server:/export", targetOverride: t.TempDir(), opts: map[string]string{},
		run: func(_ context.Context, cmd string, args ...string) ([]byte, error) {
			if cmd == "mountpoint" {
				return nil, errors.New("not mounted")
			}
			mounts = append(mounts, args[3])
			if strings.Contains(args[3], "nosymfollow") {
				return []byte("mount.nfs: an incorrect mount option was specified"), errors.New("exit 32")
			}
			return nil, nil
		}}
	if err := d.Prepare(context.Background()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(mounts) != 2 || strings.Contains(mounts[1], "nosymfollow") || !strings.Contains(mounts[1], "nosuid,nodev,noexec") {
		t.Fatalf("mounts = %q, want a retry without nosymfollow keeping the rest", mounts)
	}
}

func hasOpt(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// The temp a qcow2 disk is written through has a predictable name in the pool
// directory. A symlink planted there (by an NFS server, say) must not make
// creating a disk truncate the file it points at.
func TestCreateDiskNeverWritesThroughAPlantedSymlink(t *testing.T) {
	for _, format := range []string{"qcow2", "raw"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}
			planted := filepath.Join(dir, "vm-root.qcow2")
			if format == "qcow2" {
				planted += ".tmp"
			}
			if err := os.Symlink(victim, planted); err != nil {
				t.Fatal(err)
			}
			d := &localDriver{dataDir: dir}
			_, _ = d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "root", SizeBytes: 1 << 20, Format: format})
			if got, _ := os.ReadFile(victim); string(got) != "keep" {
				t.Fatalf("the symlink's target was written: %q", got)
			}
		})
	}
}

// rbd's positional pool/image spec follows "--".
func TestCephCreatePutsSpecAfterDoubleDash(t *testing.T) {
	var args []string
	d := &cephDriver{pool: "litevirt", opts: map[string]string{}, run: func(_ context.Context, _ string, a ...string) ([]byte, error) {
		args = a
		return nil, nil
	}}
	if _, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm", DiskName: "root", SizeBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if n := len(args); n < 2 || args[n-2] != "--" || args[n-1] != "litevirt/vm-root" {
		t.Fatalf("rbd args = %q, want ... -- litevirt/vm-root", args)
	}
}
