//go:build linux

package lxc

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeDevInfo is a device node's FileInfo for a node that does not exist.
type fakeDevInfo struct {
	name string
	rdev uint64
}

func (f fakeDevInfo) Name() string       { return f.name }
func (f fakeDevInfo) Size() int64        { return 0 }
func (f fakeDevInfo) Mode() fs.FileMode  { return fs.ModeDevice | 0o660 }
func (f fakeDevInfo) ModTime() time.Time { return time.Time{} }
func (f fakeDevInfo) IsDir() bool        { return false }
func (f fakeDevInfo) Sys() any           { return &syscall.Stat_t{Rdev: f.rdev} }

// R3-I2. The periodic refresh judges a granted device on what it is — still
// listed, not a host-trust node, the same number, not a VM's disk — and never
// on who holds it now: a running container holding its own granted block
// device open keeps it in its policy, so the container's next in-container
// reboot is not refused. The refresh runs no exclusive-open probe. The hook's
// pre-start judgment, which runs when nothing in the container is alive,
// still refuses a device the host holds.
func TestRefreshHookPolicies_KeepsARunningContainersOwnDevice(t *testing.T) {
	_, access := hostTree(t)
	dir := t.TempDir()
	oldMI, oldSys, oldProc, oldSwaps, oldStat, oldLstat := mountinfoPath, sysDevBlock, procRoot, swapsPath, statRdev, lstatDevice
	t.Cleanup(func() {
		mountinfoPath, sysDevBlock, procRoot, swapsPath, statRdev, lstatDevice = oldMI, oldSys, oldProc, oldSwaps, oldStat, oldLstat
	})
	mountinfoPath, sysDevBlock, procRoot, swapsPath = filepath.Join(dir, "mi"), filepath.Join(dir, "sys"), filepath.Join(dir, "proc"), filepath.Join(dir, "swaps")
	_ = os.WriteFile(mountinfoPath, []byte("20 1 8:1 / / rw - ext4 /dev/sda1 rw\n"), 0o644)
	_ = os.WriteFile(swapsPath, []byte("Filename\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(sysDevBlock, "8:16"), 0o755)
	const dev = "/dev/fake-sdb"
	lstatDevice = func(p string) (fs.FileInfo, error) {
		if p == dev {
			return fakeDevInfo{name: "fake-sdb", rdev: unix.Mkdev(8, 16)}, nil
		}
		return os.Lstat(p)
	}
	statRdev = func(p string) (byte, uint32, uint32, bool) {
		if p == dev {
			return 'b', 8, 16, true
		}
		return 0, 0, 0, false
	}
	busy, probes := false, 0
	exclusiveOpenBusy = func(string) bool { probes++; return busy }
	access.DevicePaths = []string{dev}
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	containerDir(t, r, "db1", "lxc.uts.name = db1\n")
	if err := r.SetHostAccess("db1", nil, []Device{{HostPath: dev}}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// db1 runs, and a process inside it holds the device open (exclusively).
	_ = os.MkdirAll(filepath.Join(procRoot, "4242", "fd"), 0o755)
	_ = os.Symlink(dev, filepath.Join(procRoot, "4242", "fd", "3"))
	busy, probes = true, 0
	if err := r.RefreshHookPolicies(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	p, err := readHookPolicy("db1")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.coversDevice(hookDevice{kind: 'b', major: 8, minor: 16, source: dev}); err != nil {
		t.Errorf("the refresh revoked a running container's own device: %v", err)
	}
	if probes != 0 {
		t.Errorf("the refresh probed the device with an exclusive open %d times", probes)
	}
	// A daemon-driven start (the container stopped) still judges who holds
	// it: a holder now is the host's.
	if err := r.checkHostAccessForStart("db1"); err == nil || !strings.Contains(err.Error(), "holds it open") {
		t.Errorf("a daemon-driven start passed a device a process holds: %v", err)
	}
	// Pre-start (the hook): a holder that is still there is the host's.
	if err := p.judgeDevice(dev, 'b', 8, 16); err == nil || !strings.Contains(err.Error(), "holds it open") {
		t.Errorf("the hook's pre-start judgment passed a held device: %v", err)
	}
	_ = os.Remove(filepath.Join(procRoot, "4242", "fd", "3"))
	busy = false
	if err := p.judgeDevice(dev, 'b', 8, 16); err != nil {
		t.Errorf("the hook refused the device once nothing held it: %v", err)
	}
}

// R3-m1. An unreadable mount table refuses a mount on Linux: filesystem
// identity is what the protected-tree check rests on.
func TestResolveHostAccess_UnreadableMountTableRefuses(t *testing.T) {
	root, access := hostTree(t)
	old := mountinfoPath
	t.Cleanup(func() { mountinfoPath = old })
	mountinfoPath = filepath.Join(t.TempDir(), "missing")
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/m"}}, nil, access); err == nil {
		t.Error("a mount was allowed with no mount table to judge it by")
	}
}

// R3-m1 on a real fd: the hook judges what it opened by the fd's own mount,
// which the mount table lists; a source on an ordinary directory passes.
func TestOpenedMountID_IsInTheMountTable(t *testing.T) {
	allowed := t.TempDir()
	allowed, _ = filepath.EvalSymlinks(allowed)
	_ = os.MkdirAll(filepath.Join(allowed, "share"), 0o755)
	fd, err := openBeneath(allowed, "share")
	if err != nil {
		t.Skipf("openat2 unavailable: %v", err)
	}
	defer unix.Close(fd)
	id, err := openedMountID(fd)
	if err != nil {
		t.Fatalf("openedMountID: %v", err)
	}
	mounts, err := readMountTable()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := identityByMount(mounts, id, filepath.Join(allowed, "share")); !ok {
		t.Fatalf("mount id %d of the opened source is not in the mount table", id)
	}
	opened, _ := openedPath(fd)
	if err := (hookPolicy{MountPaths: []string{allowed}}).judgeOpened(allowed, opened, id); err != nil {
		t.Errorf("an ordinary source was refused by its mount: %v", err)
	}
}
