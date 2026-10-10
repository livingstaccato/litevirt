//go:build linux

package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The fd-based open the start hook mounts from: a symlink swapped into the
// allowed tree AFTER every check is refused by the kernel, not followed.
func TestOpenBeneath_SwappedSymlinkIsNotFollowed(t *testing.T) {
	if err := hostAccessSupported(); err != nil {
		t.Skipf("kernel lacks openat2: %v", err)
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	prefix := filepath.Join(root, "allowed")
	_ = os.MkdirAll(filepath.Join(prefix, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "secret"), 0o700)

	fd, err := openBeneath(prefix, "data")
	if err != nil {
		t.Fatalf("open of the authorized tree: %v", err)
	}
	unix.Close(fd)

	// The race the start check cannot close: rename the tree away and put a
	// symlink to a secret in its place.
	_ = os.Rename(filepath.Join(prefix, "data"), filepath.Join(prefix, "data.old"))
	if err := os.Symlink(filepath.Join(root, "secret"), filepath.Join(prefix, "data")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openBeneath(prefix, "data"); err == nil {
		unix.Close(fd)
		t.Fatal("a symlink swapped in after the check was followed")
	}
	// A symlink that stays INSIDE the prefix is refused too: it would hand
	// the container another tree the admin did not name (another container's).
	_ = os.Remove(filepath.Join(prefix, "data"))
	_ = os.MkdirAll(filepath.Join(prefix, "other"), 0o755)
	if err := os.Symlink("other", filepath.Join(prefix, "data")); err != nil {
		t.Fatal(err)
	}
	if fd, err := openBeneath(prefix, "data"); err == nil {
		unix.Close(fd)
		t.Fatal("a symlink to another tree inside the prefix was followed")
	}
	// A symlink in a deeper component, an escape and an absolute rel too.
	_ = os.MkdirAll(filepath.Join(prefix, "d2"), 0o755)
	_ = os.Symlink("../../secret", filepath.Join(prefix, "d2", "up"))
	for _, rel := range []string{"d2/up", "../secret", "/" + filepath.Join(root, "secret")} {
		if fd, err := openBeneath(prefix, rel); err == nil {
			unix.Close(fd)
			t.Errorf("openBeneath(%q) escaped the prefix", rel)
		}
	}
	// A prefix that is itself a symlink is refused too.
	_ = os.Symlink(prefix, filepath.Join(root, "link"))
	if fd, err := openBeneath(filepath.Join(root, "link"), "d2"); err == nil {
		unix.Close(fd)
		t.Error("a symlinked prefix was followed")
	}
}

func TestHookMounts(t *testing.T) {
	cfg := "lxc.uts.name = c1\n" + mountBlockBegin + "\nlxc.hook.pre-start = /x __lxc-hook\n" +
		"# litevirt:mount ro dir /srv/a data\nlxc.mount.entry = " + stagingRoot + "/c1/m0 srv none bind,ro,nosuid,nodev,create=dir 0 0\n" +
		mountBlockEnd + "\n"
	ms, err := hookMounts(cfg)
	if err != nil || len(ms) != 1 || !ms[0].ro || ms[0].prefix != "/srv/a" || ms[0].rel != "data" || ms[0].staging != stagingRoot+"/c1/m0" {
		t.Fatalf("hookMounts = %+v, %v", ms, err)
	}
	bad := strings.Replace(cfg, stagingRoot+"/c1/m0", "/srv/a/data", 1)
	if _, err := hookMounts(bad); err == nil {
		t.Error("a mount entry naming the user tree, not a staging path, was accepted")
	}
}

// The whole hook, as root: the staged mount is the authorized tree, read-only,
// and a swapped symlink fails the start. Skipped unless the suite runs as
// root (lab 2 runs it).
func TestStageMount_AsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	old := stagingRoot
	stagingRoot = filepath.Join(root, "run")
	t.Cleanup(func() { stagingRoot = old })
	prefix := filepath.Join(root, "allowed")
	_ = os.MkdirAll(filepath.Join(prefix, "data"), 0o755)
	_ = os.WriteFile(filepath.Join(prefix, "data", "f"), []byte("ok"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "secret"), 0o700)
	m := hookMount{ro: true, prefix: prefix, rel: "data", staging: stagingPath("c1", 0)}
	pol := hookPolicy{MountPaths: []string{prefix}}
	_ = os.MkdirAll(filepath.Dir(m.staging), 0o700)
	if err := stageMount(m, pol); err != nil {
		t.Fatalf("stageMount: %v", err)
	}
	defer unmountAll(m.staging)
	if b, err := os.ReadFile(filepath.Join(m.staging, "f")); err != nil || string(b) != "ok" {
		t.Fatalf("staged tree = %q, %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(m.staging, "w"), []byte("x"), 0o644); err == nil {
		t.Fatal("a read-only staged mount was writable")
	}
	unmountAll(m.staging)
	_ = os.Rename(filepath.Join(prefix, "data"), filepath.Join(prefix, "data.old"))
	_ = os.Symlink(filepath.Join(root, "secret"), filepath.Join(prefix, "data"))
	if err := stageMount(m, pol); err == nil {
		t.Fatal("stageMount followed a swapped-in symlink")
	}
}

// m-a. post-stop and a failed pre-start remove each staging entry by
// itself: a host tree still there (an unmount that failed) is never walked
// and deleted.
func TestClearStaging_NeverDeletesThroughAnEntry(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c1")
	if err := os.MkdirAll(filepath.Join(dir, "m0", "precious"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m0", "precious", "data"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "m1"), 0o700); err != nil {
		t.Fatal(err)
	}
	clearStaging(dir)
	if _, err := os.Stat(filepath.Join(dir, "m0", "precious", "data")); err != nil {
		t.Fatalf("clearing the staging dir deleted what lay beneath an entry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "m1")); !os.IsNotExist(err) {
		t.Errorf("an empty staging entry was not removed: %v", err)
	}
}

// m-b. The hook re-judges each device against this host's policy now.
func TestHookPolicy_JudgesDevices(t *testing.T) {
	p := hookPolicy{DevicePaths: []string{"/dev/null"}}
	if err := p.judgeDevice("/dev/null", 'c', 1, 3); err != nil {
		t.Errorf("a listed device was refused: %v", err)
	}
	if err := (hookPolicy{}).judgeDevice("/dev/null", 'c', 1, 3); err == nil {
		t.Error("a device no longer listed passed")
	}
	if err := p.judgeDevice("/dev/null", 'c', 1, 5); err == nil {
		t.Error("a node whose number changed passed")
	}
	cfg := renderHostAccessBlock("c1", "/opt/lv/litevirt", nil, []resolvedDevice{{Source: "/dev/null", Target: "/dev/null", Kind: 'c', Major: 1, Minor: 3}})
	ds, err := hookDevices(cfg)
	if err != nil || len(ds) != 1 || ds[0] != (hookDevice{kind: 'c', major: 1, minor: 3, source: "/dev/null"}) {
		t.Errorf("hookDevices = %+v, %v", ds, err)
	}
}
