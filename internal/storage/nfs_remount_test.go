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
)

// rebootMounts is a host's mount table after a reboot: what a fake
// `mount -t nfs -o <opts> -- <src> <dir>` adds, mountinfo lists.
type rebootMounts struct {
	mu       sync.Mutex
	entries  []string // "dir|fstype|source|flags"
	calls    []string
	mountErr string
}

func installRebootMounts(t *testing.T) *rebootMounts {
	t.Helper()
	kernelNosymfollow(t, false)
	m := &rebootMounts{}
	prevInfo, prevRun := readMountInfo, nfsRemountRun
	readMountInfo = m.info
	nfsRemountRun = m.run
	t.Cleanup(func() { readMountInfo, nfsRemountRun = prevInfo, prevRun })
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
		m.add(args[6], "nfs4", args[5], "rw,nosuid,nodev,noexec,relatime")
		return nil, nil
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

// What else is at the mount point is told apart from the pool's export, and
// a pool directory inside another NFS mount is recognised as such.
func TestCheckNFSPoolMount_ForeignAndParentMounts(t *testing.T) {
	m := installRebootMounts(t)
	base := t.TempDir()
	foreign := filepath.Join(base, "a")
	m.add(foreign, "nfs4", "10.0.0.99:/other", "rw,nosuid,nodev,noexec")
	st, err := CheckNFSPoolMount(base, nfsCfg(foreign))
	if err != nil || st.Mounted || !strings.Contains(st.Foreign, "10.0.0.99:/other") {
		t.Fatalf("foreign: %+v err=%v", st, err)
	}
	parent := filepath.Join(base, "p")
	m.add(parent, "nfs4", "10.0.0.21:/srv", "rw,nosuid,nodev,noexec")
	st, err = CheckNFSPoolMount(base, nfsCfg(filepath.Join(parent, "lv")))
	if err != nil || st.Mounted || st.Foreign != "" || !st.OnNFS {
		t.Fatalf("inside a parent NFS mount: %+v err=%v", st, err)
	}
	if _, err := CheckNFSPoolMount(base, Config{Driver: "iscsi"}); err == nil {
		t.Fatal("a non-nfs pool was checked for a mount")
	}
}
