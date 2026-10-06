package storage

import (
	"context"
	"errors"
	"fmt"
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

// nosymfollow is required. A kernel or mount.nfs that refuses it gets no NFS
// pool: the mount fails with a message naming why, and is not retried weaker.
func TestNFSMountRequiresNosymfollow(t *testing.T) {
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
	err := d.Prepare(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nosymfollow") {
		t.Fatalf("Prepare = %v, want a refusal naming nosymfollow", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("mounts = %q, want exactly one attempt and no weaker retry", mounts)
	}
}

// fakeMountInfo makes mountFlags see dir → per-mount options.
func fakeMountInfo(t *testing.T, mounts map[string]string) *map[string]string {
	t.Helper()
	cur := mounts
	prev := readMountInfo
	readMountInfo = func() ([]byte, error) {
		var b strings.Builder
		i := 100
		for dir, opts := range cur {
			fmt.Fprintf(&b, "%d 1 0:50 / %s %s shared:1 - nfs4 server:/export rw\n", i, strings.ReplaceAll(dir, " ", "\\040"), opts)
			i++
		}
		return []byte(b.String()), nil
	}
	t.Cleanup(func() { readMountInfo = prev })
	return &cur
}

// An export already mounted without the hardening (by hand, or by an earlier
// build) is refused, not remounted: Prepare fails and runs no mount command.
func TestNFSExistingWeakMountIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   string
		wantErr bool
	}{
		{"weak mount", "rw,relatime", true},
		{"missing only nosymfollow", "rw,nosuid,nodev,noexec", true},
		{"hardened mount", "rw,nosuid,nodev,noexec,nosymfollow,relatime", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fakeMountInfo(t, map[string]string{dir: tc.flags})
			var other []string
			d := &nfsDriver{source: "server:/export", targetOverride: dir, opts: map[string]string{},
				run: func(_ context.Context, cmd string, args ...string) ([]byte, error) {
					if cmd != "mountpoint" {
						other = append(other, cmd+" "+strings.Join(args, " "))
					}
					return nil, nil // mounted
				}}
			err := d.Prepare(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("Prepare = %v, wantErr %v", err, tc.wantErr)
			}
			if len(other) != 0 {
				t.Fatalf("ran %q on an existing mount; nothing is remounted", other)
			}
		})
	}
}

// CheckNFSMountHardened — the pool check and the daemon-start report — refuses
// a weak existing mount and passes an unmounted pool (Prepare mounts it).
func TestCheckNFSMountHardened(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Driver: "nfs", Source: "server:/export", Target: dir}
	mi := fakeMountInfo(t, map[string]string{dir: "rw"})
	if err := CheckNFSMountHardened(t.TempDir(), cfg); err == nil {
		t.Fatalf("a weak mount was accepted")
	}
	(*mi)[dir] = "rw,nosuid,nodev,noexec,nosymfollow"
	if err := CheckNFSMountHardened(t.TempDir(), cfg); err != nil {
		t.Fatalf("a hardened mount: %v", err)
	}
	delete(*mi, dir)
	if err := CheckNFSMountHardened(t.TempDir(), cfg); err != nil {
		t.Fatalf("an unmounted pool: %v", err)
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
