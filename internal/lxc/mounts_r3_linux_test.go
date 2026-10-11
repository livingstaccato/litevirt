//go:build linux

package lxc

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// m-7. A source on another filesystem mounted beneath an allowed prefix (a
// NAS) works; what the hook opened is judged by its resolved path against the
// protected trees instead.
func TestJudgeOpened(t *testing.T) {
	allowed := t.TempDir()
	_ = os.MkdirAll(filepath.Join(allowed, "nas", "share"), 0o755)
	fd, err := openBeneath(allowed, "nas/share")
	if err != nil {
		t.Skipf("openat2 unavailable: %v", err)
	}
	defer unix.Close(fd)
	got, err := openedPath(fd)
	if err != nil || got != filepath.Join(allowed, "nas", "share") {
		t.Fatalf("openedPath = %q, %v", got, err)
	}
	p := hookPolicy{MountPaths: []string{allowed}}
	if err := p.judgeOpened(allowed, got, 0); err != nil {
		t.Errorf("an opened source beneath its prefix was refused: %v", err)
	}
	p.Deny = []string{filepath.Join(allowed, "nas")}
	if err := p.judgeOpened(allowed, got, 0); err == nil {
		t.Error("an opened source inside a protected tree passed")
	}
	if err := (hookPolicy{MountPaths: []string{allowed}}).judgeOpened(allowed, "/etc", 0); err == nil {
		t.Error("an opened source outside its prefix passed")
	}
}

// m-7 on a real kernel: a filesystem mounted beneath an allowed prefix is
// opened and staged like any other source. Needs root (a mount).
func TestOpenBeneath_CrossesAMountBelowThePrefix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount a filesystem beneath the prefix")
	}
	allowed := t.TempDir()
	nas := filepath.Join(allowed, "nas")
	_ = os.MkdirAll(nas, 0o755)
	if err := unix.Mount("tmpfs", nas, "tmpfs", 0, ""); err != nil {
		t.Skipf("mount tmpfs: %v", err)
	}
	defer unix.Unmount(nas, unix.MNT_DETACH)
	_ = os.MkdirAll(filepath.Join(nas, "share"), 0o755)
	fd, err := openBeneath(allowed, "nas/share")
	if err != nil {
		t.Fatalf("a source on a filesystem mounted beneath the prefix was refused: %v", err)
	}
	unix.Close(fd)
}
