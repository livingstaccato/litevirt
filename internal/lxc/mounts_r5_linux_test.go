//go:build linux

package lxc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// m-2. A lookup that is an answer (the path is not there) is a refusal; one
// that failed (a network filesystem that does not answer) is not.
func TestDefiniteLookup(t *testing.T) {
	for _, err := range []error{fs.ErrNotExist, syscall.ENOENT, syscall.ENOTDIR, syscall.ELOOP} {
		if !definiteLookup(fmt.Errorf("host path: %w", err)) {
			t.Errorf("%v read as a failed lookup; want an answer", err)
		}
	}
	for _, err := range []error{syscall.ESTALE, syscall.ETIMEDOUT, syscall.EIO} {
		if definiteLookup(fmt.Errorf("host path: %w", err)) {
			t.Errorf("%v read as an answer; want a failed lookup", err)
		}
	}
}

// m-2. A mount table that cannot be read, and VM disks that cannot be read,
// leave a running container's last policy in place: neither is a verdict on
// its grant.
func TestRefreshHookPolicies_UnreadableReadsKeepTheLastPolicy(t *testing.T) {
	root, access := hostTree(t)
	dir := t.TempDir()
	oldMI, oldSys, oldProc, oldSwaps, oldLstat := mountinfoPath, sysDevBlock, procRoot, swapsPath, lstatDevice
	t.Cleanup(func() {
		mountinfoPath, sysDevBlock, procRoot, swapsPath, lstatDevice = oldMI, oldSys, oldProc, oldSwaps, oldLstat
	})
	sysDevBlock, procRoot, swapsPath = filepath.Join(dir, "sys"), filepath.Join(dir, "proc"), filepath.Join(dir, "swaps")
	_ = os.WriteFile(swapsPath, []byte("Filename\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(sysDevBlock, "8:16"), 0o755)
	const dev = "/dev/fake-sdb"
	lstatDevice = func(p string) (fs.FileInfo, error) {
		if p == dev {
			return fakeDevInfo{name: "fake-sdb", rdev: unix.Mkdev(8, 16)}, nil
		}
		return os.Lstat(p)
	}
	access.DevicePaths = []string{dev}
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	containerDir(t, r, "d1", "lxc.uts.name = d1\n")
	if err := r.SetHostAccess("c1", []Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/srv"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.SetHostAccess("d1", nil, []Device{{HostPath: dev}}); err != nil {
		t.Fatal(err)
	}

	mountinfoPath = filepath.Join(dir, "missing")
	r.HostAccess.BlockInUse = func(uint32, uint32) (string, error) { return "", errors.New("database is locked") }
	_ = r.RefreshHookPolicies()
	if p, err := readHookPolicy("c1"); err != nil || len(p.Mounts) != 1 {
		t.Errorf("an unreadable mount table revoked c1's mount: %+v (%v)", p, err)
	}
	if p, err := readHookPolicy("d1"); err != nil || len(p.Devices) != 1 {
		t.Errorf("unreadable VM disks revoked d1's device: %+v (%v)", p, err)
	}
	// A judgment that could not be made is no grant: the device is refused,
	// as one that could not be judged (so a start refuses it).
	if _, _, err := resolveHostAccess(nil, []Device{{HostPath: dev}}, r.hostAccess(), false); err == nil || !isTransient(err) {
		t.Errorf("a device judged while the VM disks could not be read = %v; want a judgment that could not be made", err)
	}
}

// m-1. On a superblock that mounts of two exports share, a mount whose root
// names no tail of its own export (a bind of a subdirectory) has no certain
// path within the filesystem: identity is not used for it, and the
// resolved-path check alone decides — never a verdict that depends on the
// dentry cache.
func TestDeniedTreeByIdentity_AmbiguousBindOnASharedSuperblock(t *testing.T) {
	root, access := hostTree(t)
	_ = os.MkdirAll(filepath.Join(root, "allowed", "bind", "y"), 0o755)
	access.DenyFunc = func() ([]string, error) { return []string{"/srv/pools/x"}, nil }
	withMountinfo(t, root,
		"20 1 8:1 / / rw - ext4 /dev/sda1 rw",
		"41 20 0:50 / /srv/pools rw - nfs srv:/export/pools rw",
		"42 20 0:50 / /srv/share rw - nfs srv:/export/share rw",
		"43 20 0:50 /x ROOT/allowed/bind rw - nfs srv:/export/pools rw",
	)
	src := []Mount{{HostPath: filepath.Join(root, "allowed", "bind", "y"), ContainerPath: "/m"}}
	if _, _, err := ResolveHostAccess(src, nil, access); err != nil {
		t.Errorf("an ambiguous identity refused a source the path check passes: %v", err)
	}
}
