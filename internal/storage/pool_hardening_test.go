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
	kernelNosymfollow(t, true)
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
			for _, want := range []string{"nosuid", "nodev", "noexec", "nosymfollow", "nosharecache"} {
				if !hasOpt(got, want) {
					t.Errorf("mount options %q lack %s", mount[3], want)
				}
			}
			for _, undo := range []string{"suid", "dev", "exec", "symfollow", "sharecache"} {
				if hasOpt(got, undo) {
					t.Errorf("mount options %q keep %s", mount[3], undo)
				}
			}
		})
	}
}

// nosymfollow is asked for on a kernel that has it (5.10+). A mount.nfs that
// refuses the option mounts the pool without it, as on an older kernel, once;
// any other failure is not retried.
func TestNFSMountRetriesWithoutNosymfollowOnlyForTheOption(t *testing.T) {
	kernelNosymfollow(t, true)
	for _, tc := range []struct {
		name    string
		out     string
		wantErr bool
		mounts  int
	}{
		{"option refused", "mount.nfs: an incorrect mount option was specified", false, 2},
		{"server down", "mount.nfs: Connection timed out", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mounts []string
			d := &nfsDriver{source: "server:/export", targetOverride: t.TempDir(), opts: map[string]string{},
				run: func(_ context.Context, cmd string, args ...string) ([]byte, error) {
					if cmd == "mountpoint" {
						return nil, errors.New("not mounted")
					}
					mounts = append(mounts, args[3])
					if tc.wantErr || strings.Contains(args[3], "nosymfollow") {
						return []byte(tc.out), errors.New("exit 32")
					}
					return nil, nil
				}}
			err := d.Prepare(context.Background())
			if (err != nil) != tc.wantErr || len(mounts) != tc.mounts {
				t.Fatalf("Prepare = %v, mounts %q; want err %v after %d attempts", err, mounts, tc.wantErr, tc.mounts)
			}
			for _, want := range []string{"nosuid", "nodev", "noexec"} {
				if !hasOpt(strings.Split(mounts[len(mounts)-1], ","), want) {
					t.Errorf("mount options %q lack %s", mounts[len(mounts)-1], want)
				}
			}
		})
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
// build) is hardened in place (nfs_inplace_test.go); when that remount fails
// the pool is refused, and nothing but the remount is run — never an unmount
// or a fresh mount over it.
func TestNFSExistingWeakMountIsRefusedWhenItCannotBeHardened(t *testing.T) {
	kernelNosymfollow(t, true)
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
					if cmd == "mountpoint" {
						return nil, nil // mounted
					}
					other = append(other, cmd+" "+strings.Join(args, " "))
					return []byte("mount: permission denied"), errors.New("exit status 32")
				}}
			err := d.Prepare(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("Prepare = %v, wantErr %v", err, tc.wantErr)
			}
			for _, c := range other {
				if !strings.HasPrefix(c, "mount -o remount,bind,") {
					t.Fatalf("ran %q on an existing mount; only an in-place remount is", c)
				}
			}
			if !tc.wantErr && len(other) != 0 {
				t.Fatalf("ran %q on a hardened mount", other)
			}
		})
	}
}

// CheckNFSMountHardened — the pool check and the daemon-start report — refuses
// a weak existing mount it cannot harden in place, and passes an unmounted
// pool (Prepare mounts it).
func TestCheckNFSMountHardened(t *testing.T) {
	kernelNosymfollow(t, true)
	defer OverrideNFSRemountForTest(func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("remount refused")
	})()
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
