package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// rebootMounts is a host's mount table after a reboot: what a fake
// `mount -t nfs -o <opts> -- <src> <dir>` adds, mountinfo lists.
type rebootMounts struct {
	mu       sync.Mutex
	entries  []string // "dir|fstype|source|flags"
	calls    []string
	mountErr string
	onMount  func(dir string) // runs after a mount, outside the lock
	umounts  int
	landAt   string // set: a mount lands there instead of its mount point
}

func installRebootMounts(t *testing.T) *rebootMounts {
	t.Helper()
	kernelNosymfollow(t, false)
	m := &rebootMounts{}
	prevRun := nfsRemountRun
	restoreInfo := readMountInfo.set(m.info)
	nfsRemountRun = m.run
	t.Cleanup(func() { restoreInfo(); nfsRemountRun = prevRun })
	return m
}

func (m *rebootMounts) add(dir, fstype, source, flags string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, dir+"|"+fstype+"|"+source+"|"+flags)
}

func (m *rebootMounts) info() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	b.WriteString("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n")
	for i, e := range m.entries {
		f := strings.Split(e, "|")
		fmt.Fprintf(&b, "%d 22 0:%d / %s %s - %s %s rw\n", 100+i, 50+i, f[0], f[3], f[1], f[2])
	}
	return []byte(b.String()), nil
}

func (m *rebootMounts) run(_ context.Context, name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	m.calls = append(m.calls, name+" "+strings.Join(args, " "))
	mountErr := m.mountErr
	m.mu.Unlock()
	switch name {
	case "mountpoint":
		dir := args[len(args)-1]
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, e := range m.entries {
			if strings.HasPrefix(e, dir+"|") {
				return nil, nil
			}
		}
		return nil, exitStatusError(32)
	case "mount":
		if len(args) != 7 || args[0] != "-t" || args[1] != "nfs" || args[4] != "--" {
			return nil, fmt.Errorf("unexpected mount %q", args)
		}
		if mountErr != "" {
			return []byte(mountErr), errors.New("exit status 32")
		}
		at := args[6]
		if m.landAt != "" {
			at = m.landAt // the mount point was swapped for a symlink
		}
		m.add(at, "nfs4", args[5], "rw,nosuid,nodev,noexec,relatime")
		if m.onMount != nil {
			m.onMount(args[6])
		}
		return nil, nil
	case "umount":
		dir := args[len(args)-1]
		m.mu.Lock()
		defer m.mu.Unlock()
		for i, e := range m.entries {
			if strings.HasPrefix(e, dir+"|") {
				m.entries = append(m.entries[:i:i], m.entries[i+1:]...)
				m.umounts++
				return nil, nil
			}
		}
		return []byte("not mounted"), errors.New("exit status 32")
	}
	return nil, fmt.Errorf("unexpected %s %q", name, args)
}

func (m *rebootMounts) mounts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if strings.HasPrefix(c, "mount -t nfs") {
			n++
		}
	}
	return n
}

func nfsCfg(target string) Config {
	return Config{Name: "shared", Driver: "nfs", Source: "10.0.0.21:/srv/lv", Target: target}
}

// N-1: after a reboot the mount point is an empty directory. The check reads
// it as not mounted; the mount puts the pool's export there, hardened, and
// the check then reads it as mounted.
func TestMountNFSPool_MountsTheExportAfterAReboot(t *testing.T) {
	m := installRebootMounts(t)
	dataDir := t.TempDir()
	cfg := nfsCfg("")
	dir := NFSPoolMountDir(dataDir, cfg)
	if want := filepath.Join(dataDir, "mounts", "10.0.0.21__srv_lv"); dir != want {
		t.Fatalf("mount dir %q, want %q", dir, want)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := CheckNFSPoolMount(dataDir, cfg)
	if err != nil || st.Mounted || st.Foreign != "" || st.OnNFS {
		t.Fatalf("before the mount: %+v err=%v; want not mounted", st, err)
	}
	if err := MountNFSPool(context.Background(), dataDir, cfg); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if m.mounts() != 1 {
		t.Fatalf("%d mounts, want 1; calls %v", m.mounts(), m.calls)
	}
	for _, opt := range []string{"nosuid", "nodev", "noexec"} {
		if !strings.Contains(m.calls[len(m.calls)-1], opt) {
			t.Fatalf("mount without %s: %q", opt, m.calls[len(m.calls)-1])
		}
	}
	st, err = CheckNFSPoolMount(dataDir, cfg)
	if err != nil || !st.Mounted {
		t.Fatalf("after the mount: %+v err=%v; want mounted", st, err)
	}
}

// Never over local data: a mount point that holds anything is refused with
// the names, and no mount is run.
func TestMountNFSPool_RefusesANonEmptyMountPoint(t *testing.T) {
	m := installRebootMounts(t)
	dir := filepath.Join(t.TempDir(), "pool")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vm-root.qcow2"), []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := MountNFSPool(context.Background(), t.TempDir(), nfsCfg(dir))
	if err == nil || !strings.Contains(err.Error(), "vm-root.qcow2") || !strings.Contains(err.Error(), "hide") {
		t.Fatalf("err = %v; want a refusal naming the local file", err)
	}
	if len(m.calls) != 0 {
		t.Fatalf("commands run on a refused mount point: %v", m.calls)
	}
}

// Never through a symlink: the mount would land where it points.
func TestMountNFSPool_RefusesASymlinkedMountPoint(t *testing.T) {
	m := installRebootMounts(t)
	base := t.TempDir()
	real := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "pool")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	err := MountNFSPool(context.Background(), t.TempDir(), nfsCfg(link))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v; want a symlink refusal", err)
	}
	if len(m.calls) != 0 {
		t.Fatalf("commands run on a refused mount point: %v", m.calls)
	}
}

// A mount that fails returns mount's own words.
func TestMountNFSPool_FailureCarriesTheReason(t *testing.T) {
	m := installRebootMounts(t)
	m.mountErr = "mount.nfs: Connection timed out"
	err := MountNFSPool(context.Background(), t.TempDir(), nfsCfg(""))
	if err == nil || !strings.Contains(err.Error(), "Connection timed out") {
		t.Fatalf("err = %v; want the mount's reason", err)
	}
}

// What is at the mount point is told apart: the pool's export, another NFS
// mount (a hand mount spelled differently is still a mount, with its files
// there), a mount that is not NFS (even one whose source string is the
// pool's), and a pool directory inside another NFS mount.
func TestCheckNFSPoolMount_WhatIsAtTheMountPoint(t *testing.T) {
	m := installRebootMounts(t)
	base := t.TempDir()
	other := filepath.Join(base, "a")
	m.add(other, "nfs4", "nas.example:/srv/lv", "rw,nosuid,nodev,noexec")
	st, err := CheckNFSPoolMount(base, nfsCfg(other))
	if err != nil || !st.Mounted || !strings.Contains(st.Other, "nas.example:/srv/lv") || st.Foreign != "" {
		t.Fatalf("another spelling of an NFS export: %+v err=%v; want mounted, named", st, err)
	}
	notNFS := filepath.Join(base, "b")
	m.add(notNFS, "ext4", "10.0.0.21:/srv/lv", "rw")
	st, err = CheckNFSPoolMount(base, nfsCfg(notNFS))
	if err != nil || st.Mounted || !strings.Contains(st.Foreign, "ext4") {
		t.Fatalf("a non-NFS mount with the pool's source: %+v err=%v; want foreign", st, err)
	}
	parent := filepath.Join(base, "p")
	m.add(parent, "nfs4", "10.0.0.21:/srv", "rw,nosuid,nodev,noexec")
	t.Cleanup(OverrideNFSPathResolverForTest(func(p string) string {
		t.Errorf("resolved %s for a mount point lexically inside an NFS mount", p)
		return p
	}, time.Second))
	st, err = CheckNFSPoolMount(base, nfsCfg(filepath.Join(parent, "lv")))
	if err != nil || st.Mounted || st.Foreign != "" || !st.OnNFS {
		t.Fatalf("inside a parent NFS mount: %+v err=%v", st, err)
	}
	if _, err := CheckNFSPoolMount(base, Config{Driver: "iscsi"}); err == nil {
		t.Fatal("a non-nfs pool was checked for a mount")
	}
}

// A parent that reaches an NFS mount through a symlink is found by resolving
// it; a resolution that blocks (a server that does not answer) is given up on
// within the bound, with the reason.
func TestCheckNFSPoolMount_SymlinkedParentIsResolvedWithinABound(t *testing.T) {
	m := installRebootMounts(t)
	base := t.TempDir()
	nfsDir := filepath.Join(base, "nfs")
	m.add(nfsDir, "nfs4", "10.0.0.21:/srv", "rw,nosuid,nodev,noexec")
	link := filepath.Join(base, "link")
	t.Cleanup(OverrideNFSPathResolverForTest(func(p string) string {
		if p == link {
			return nfsDir
		}
		return p
	}, time.Second))
	st, err := CheckNFSPoolMount(base, nfsCfg(filepath.Join(link, "lv")))
	if err != nil || !st.OnNFS {
		t.Fatalf("through a symlink into an NFS mount: %+v err=%v; want OnNFS", st, err)
	}

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	hung := filepath.Join(base, "hung")
	t.Cleanup(OverrideNFSPathResolverForTest(func(p string) string {
		if p == hung {
			<-release
		}
		return p
	}, 200*time.Millisecond))
	done := make(chan error, 1)
	go func() {
		_, err := CheckNFSPoolMount(base, nfsCfg(filepath.Join(hung, "lv")))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "did not finish") {
			t.Fatalf("err = %v; want the resolution given up on", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the check hung on a resolution that does not finish")
	}
}

// Mount points the mount would hide something under, or land elsewhere
// through, are refused: a regular file, and a directory whose entries cannot
// be listed (it is not known to be empty).
func TestMountNFSPool_RefusesWhatItCannotJudge(t *testing.T) {
	m := installRebootMounts(t)
	file := filepath.Join(t.TempDir(), "pool")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MountNFSPool(context.Background(), t.TempDir(), nfsCfg(file)); err == nil || err.Error() != "mount point "+file+" is not a directory" {
		t.Fatalf("a regular file: err = %v; want refused", err)
	}
	prev := nfsListDir
	nfsListDir = func(*os.File) ([]string, error) { return nil, errors.New("input/output error") }
	t.Cleanup(func() { nfsListDir = prev })
	if err := MountNFSPool(context.Background(), t.TempDir(), nfsCfg("")); err == nil || !strings.Contains(err.Error(), "input/output error") {
		t.Fatalf("an unlistable mount point: err = %v; want refused", err)
	}
	if m.mounts() != 0 {
		t.Fatalf("mounted onto a mount point it could not judge; calls %v", m.calls)
	}
}

// A file written into the mount point while it is being mounted is found
// under the mount (through the descriptor held across it): the export is
// unmounted again and the mount refused.
func TestMountNFSPool_FilesWrittenDuringTheMountAreNotHidden(t *testing.T) {
	m := installRebootMounts(t)
	dataDir := t.TempDir()
	cfg := nfsCfg("")
	m.onMount = func(dir string) {
		// The fake mount covers nothing: the file lands in the directory
		// itself, as one written just before the kernel's mount would.
		if err := os.WriteFile(filepath.Join(dir, "late.qcow2"), []byte("x"), 0o600); err != nil {
			t.Error(err)
		}
	}
	err := MountNFSPool(context.Background(), dataDir, cfg)
	if err == nil || !strings.Contains(err.Error(), "late.qcow2") || !strings.Contains(err.Error(), "unmounted again") {
		t.Fatalf("err = %v; want the late file named and the mount undone", err)
	}
	if st, _ := CheckNFSPoolMount(dataDir, cfg); st.Mounted || m.umounts != 1 {
		t.Fatalf("after the refusal: %+v, %d umounts; want it unmounted once", st, m.umounts)
	}
}

// A non-empty mount point that a concurrent Prepare has just mounted holds
// the export's files, not local ones: that is not refused.
func TestMountNFSPool_AConcurrentMountIsNotLocalFiles(t *testing.T) {
	m := installRebootMounts(t)
	dataDir := t.TempDir()
	cfg := nfsCfg("")
	dir := NFSPoolMountDir(dataDir, cfg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vm-root.qcow2"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m.add(dir, "nfs4", cfg.Source, "rw,nosuid,nodev,noexec")
	if err := MountNFSPool(context.Background(), dataDir, cfg); err != nil {
		t.Fatalf("err = %v; want none (the export is mounted)", err)
	}
	if m.mounts() != 0 {
		t.Fatal("mounted again over a mounted export")
	}
}

// A mount that lands somewhere else (the mount point swapped for a symlink
// between the open and the mount) leaves no NFS mount at the mount point,
// and is refused saying so.
func TestMountNFSPool_AMountThatLandedElsewhereIsRefused(t *testing.T) {
	m := installRebootMounts(t)
	m.landAt = filepath.Join(t.TempDir(), "elsewhere")
	err := MountNFSPool(context.Background(), t.TempDir(), nfsCfg(""))
	if err == nil || !strings.Contains(err.Error(), "holds no NFS mount") {
		t.Fatalf("err = %v; want the landed-elsewhere refusal", err)
	}
}

// A resolution that does not finish is run once per path, however many
// checks ask meanwhile: a server that never answers leaves one stuck
// goroutine, not one per check.
func TestCheckNFSPoolMount_AStuckResolutionIsNotStartedAgain(t *testing.T) {
	installRebootMounts(t)
	base := t.TempDir()
	hung := filepath.Join(base, "hung")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var mu sync.Mutex
	calls := 0
	t.Cleanup(OverrideNFSPathResolverForTest(func(p string) string {
		if p == hung {
			mu.Lock()
			calls++
			mu.Unlock()
			<-release
		}
		return p
	}, 100*time.Millisecond))
	for i := 0; i < 3; i++ {
		if _, err := CheckNFSPoolMount(base, nfsCfg(filepath.Join(hung, "lv"))); err == nil {
			t.Fatal("a check whose resolution does not finish returned no error")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("the stuck resolution was started %d times, want once", calls)
	}
}

// throughTheCache serves m's table through the mount table cache, as the
// host's is served, with a kernel change mark that never fires (a missed
// mark, bug B1).
func (m *rebootMounts) throughTheCache(t *testing.T) {
	t.Helper()
	t.Cleanup(readMountInfo.set(nil))
	t.Cleanup(procMountInfo.set(m.info))
	t.Cleanup(mountTableChanged.set(func() bool { return false }))
	resetMountCache()
	t.Cleanup(resetMountCache)
}

// litevirt's own mount is seen by the check right after it, whatever the
// kernel's change mark says: the check before the mount cached a table
// without it, and the age bound does not help a check made a moment later.
// This is where B1 showed on the lab ("after the mount, … holds no NFS
// mount").
//
// Mutation "no invalidation after the mount command" (nfsDriver.Prepare):
// the mount is refused as landed elsewhere, red.
func TestMountNFSPool_TheCheckAfterTheMountSeesItWithoutTheMark(t *testing.T) {
	m := installRebootMounts(t)
	m.throughTheCache(t)
	dataDir := t.TempDir()
	cfg := nfsCfg("")
	dir := NFSPoolMountDir(dataDir, cfg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if st, err := CheckNFSPoolMount(dataDir, cfg); err != nil || st.Mounted {
		t.Fatalf("before the mount: %+v err=%v; want not mounted", st, err)
	}
	if err := MountNFSPool(context.Background(), dataDir, cfg); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if st, err := CheckNFSPoolMount(dataDir, cfg); err != nil || !st.Mounted {
		t.Fatalf("after the mount: %+v err=%v; want mounted", st, err)
	}
}

// litevirt's own unmount is seen by the next check, whatever the mark says.
//
// Mutation "no invalidation after the umount command" (nfsDriver.Teardown):
// the export still reads as mounted, red.
func TestNFSTeardown_TheUnmountIsSeenWithoutTheMark(t *testing.T) {
	m := installRebootMounts(t)
	m.throughTheCache(t)
	dataDir := t.TempDir()
	cfg := nfsCfg("")
	dir := NFSPoolMountDir(dataDir, cfg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := MountNFSPool(context.Background(), dataDir, cfg); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if st, err := CheckNFSPoolMount(dataDir, cfg); err != nil || !st.Mounted {
		t.Fatalf("after the mount: %+v err=%v; want mounted", st, err)
	}
	drv, err := New(dataDir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := drv.(*nfsDriver).Teardown(context.Background()); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if st, err := CheckNFSPoolMount(dataDir, cfg); err != nil || st.Mounted {
		t.Fatalf("after the unmount: %+v err=%v; want not mounted", st, err)
	}
}
