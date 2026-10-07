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

// kernelNosymfollow makes the kernel appear to have nosymfollow (5.10+) or not.
func kernelNosymfollow(t *testing.T, has bool) {
	t.Helper()
	prev := kernelHasNosymfollow
	kernelHasNosymfollow = func() bool { return has }
	t.Cleanup(func() { kernelHasNosymfollow = prev })
}

// liveMountTable is a mount table with one NFS mount of nas:/x at dir whose
// per-mount flags a fake `mount -o remount,bind,<flags> -- dir` replaces, as
// the kernel does.
type liveMountTable struct {
	dir, flags string
	remounts   []string
	failRemnt  bool
}

func newLiveMountTable(t *testing.T, dir, flags string) *liveMountTable {
	t.Helper()
	m := &liveMountTable{dir: dir, flags: flags}
	prev := readMountInfo
	readMountInfo = func() ([]byte, error) {
		return []byte(fmt.Sprintf("40 1 0:60 / %s %s - nfs4 nas:/x rw,vers=4.2\n", m.dir, m.flags)), nil
	}
	t.Cleanup(func() { readMountInfo = prev })
	return m
}

func (m *liveMountTable) run(_ context.Context, cmd string, args ...string) ([]byte, error) {
	if cmd == "mountpoint" {
		return nil, nil // mounted
	}
	if cmd != "mount" || len(args) != 4 || args[0] != "-o" || args[2] != "--" || args[3] != m.dir {
		return nil, fmt.Errorf("unexpected %s %q", cmd, args)
	}
	m.remounts = append(m.remounts, args[1])
	if m.failRemnt {
		return []byte("mount: permission denied"), errors.New("exit status 32")
	}
	opts, ok := strings.CutPrefix(args[1], "remount,bind,")
	if !ok {
		return nil, fmt.Errorf("not a bind remount: %q", args[1])
	}
	m.flags = opts
	return nil, nil
}

// C1: an NFS pool main mounted (vers=4,hard,intr: no hardening) is hardened in
// place by a bind remount of that mount — no unmount, so the VMs running from
// it are untouched — and keeps working. The remount keeps the mount's own
// flags (a read-only mount stays read-only).
func TestNFSMainStyleMountIsHardenedInPlace(t *testing.T) {
	kernelNosymfollow(t, true)
	for _, tc := range []struct{ name, flags, want string }{
		{"main's mount", "rw,relatime", "remount,bind,rw,nosuid,nodev,noexec,relatime,nosymfollow"},
		{"missing only nosymfollow", "rw,nosuid,nodev,noexec", "remount,bind,rw,nosuid,nodev,noexec,nosymfollow"},
		{"read-only, noatime", "ro,noatime", "remount,bind,ro,nosuid,nodev,noexec,noatime,nosymfollow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			m := newLiveMountTable(t, dir, tc.flags)
			d := &nfsDriver{source: "nas:/x", targetOverride: dir, opts: map[string]string{}, run: m.run}
			if err := d.Prepare(context.Background()); err != nil {
				t.Fatalf("Prepare on %s: %v", tc.flags, err)
			}
			if len(m.remounts) != 1 || m.remounts[0] != tc.want {
				t.Fatalf("remounts = %q, want exactly [%s]", m.remounts, tc.want)
			}
			// The pool check (every use) now passes and runs nothing more.
			restore := OverrideNFSRemountForTest(m.run)
			defer restore()
			if err := CheckNFSMountHardened(t.TempDir(), Config{Driver: "nfs", Source: "nas:/x", Target: dir}); err != nil {
				t.Fatalf("pool check after the in-place hardening: %v", err)
			}
			if len(m.remounts) != 1 {
				t.Fatalf("remounted again: %q", m.remounts)
			}
		})
	}
}

// C1: the pool check itself (the first use after an upgrade, and the daemon's
// start) hardens main's mount in place; a remount that fails refuses the pool,
// and a hardened mount runs nothing.
func TestCheckNFSMountHardenedRemountsInPlace(t *testing.T) {
	kernelNosymfollow(t, true)
	dir := t.TempDir()
	cfg := Config{Driver: "nfs", Source: "nas:/x", Target: dir}
	m := newLiveMountTable(t, dir, "rw,relatime")
	defer OverrideNFSRemountForTest(m.run)()

	m.failRemnt = true
	if err := CheckNFSMountHardened(t.TempDir(), cfg); err == nil || !strings.Contains(err.Error(), "nosymfollow") {
		t.Fatalf("a mount that cannot be hardened: %v, want a refusal naming what is missing", err)
	}
	m.failRemnt = false
	if err := CheckNFSMountHardened(t.TempDir(), cfg); err != nil {
		t.Fatalf("main's mount, hardened in place: %v", err)
	}
	if m.flags != "rw,nosuid,nodev,noexec,relatime,nosymfollow" {
		t.Fatalf("flags after the remount = %q", m.flags)
	}
	n := len(m.remounts)
	if err := CheckNFSMountHardened(t.TempDir(), cfg); err != nil || len(m.remounts) != n {
		t.Fatalf("a hardened mount: err %v, remounts %q (want none more)", err, m.remounts[n:])
	}
}

// A remount the kernel accepts but that leaves a flag off (a mount.nfs or
// kernel that drops nosymfollow on 5.10+) is refused, not trusted.
func TestNFSInPlaceRemountIsVerified(t *testing.T) {
	kernelNosymfollow(t, true)
	dir := t.TempDir()
	m := newLiveMountTable(t, dir, "rw,relatime")
	run := func(ctx context.Context, cmd string, args ...string) ([]byte, error) {
		if _, err := m.run(ctx, cmd, args...); err != nil {
			return nil, err
		}
		m.flags = strings.ReplaceAll(m.flags, ",nosymfollow", "")
		return nil, nil
	}
	d := &nfsDriver{source: "nas:/x", targetOverride: dir, opts: map[string]string{}, run: run}
	if err := d.Prepare(context.Background()); err == nil || !strings.Contains(err.Error(), "nosymfollow") {
		t.Fatalf("Prepare after a remount that dropped nosymfollow = %v, want a refusal", err)
	}
}

// C1, kernels before 5.10 (RHEL 8, Ubuntu 20.04, Debian 10): there is no
// nosymfollow, so the pool is mounted — and main's mount hardened — with the
// other options, and accepted; a fresh mount is not refused for it.
func TestNFSWithoutNosymfollowKernelIsAccepted(t *testing.T) {
	kernelNosymfollow(t, false)
	t.Run("fresh mount", func(t *testing.T) {
		var mount []string
		d := &nfsDriver{source: "nas:/x", targetOverride: t.TempDir(), opts: map[string]string{},
			run: func(_ context.Context, cmd string, args ...string) ([]byte, error) {
				if cmd == "mountpoint" {
					return nil, exitStatusError(32)
				}
				mount = args
				if strings.Contains(strings.Join(args, " "), "nosymfollow") {
					return []byte("mount: unknown option"), errors.New("exit 32")
				}
				return nil, nil
			}}
		if err := d.Prepare(context.Background()); err != nil {
			t.Fatalf("fresh mount on a pre-5.10 kernel: %v", err)
		}
		got := strings.Split(mount[3], ",")
		for _, want := range []string{"nosuid", "nodev", "noexec"} {
			if !hasOpt(got, want) {
				t.Errorf("mount options %q lack %s", mount[3], want)
			}
		}
	})
	t.Run("main's mount", func(t *testing.T) {
		dir := t.TempDir()
		m := newLiveMountTable(t, dir, "rw,relatime")
		d := &nfsDriver{source: "nas:/x", targetOverride: dir, opts: map[string]string{}, run: m.run}
		if err := d.Prepare(context.Background()); err != nil {
			t.Fatalf("main's mount on a pre-5.10 kernel: %v", err)
		}
		if len(m.remounts) != 1 || m.remounts[0] != "remount,bind,rw,nosuid,nodev,noexec,relatime" {
			t.Fatalf("remounts = %q, want the other options only", m.remounts)
		}
		if err := CheckNFSMountHardened(t.TempDir(), Config{Driver: "nfs", Source: "nas:/x", Target: dir}); err != nil {
			t.Fatalf("pool check: %v", err)
		}
	})
	t.Run("directory pool on such a mount", func(t *testing.T) {
		dir := t.TempDir()
		mountInfoWith(t, dir, "rw,nosuid,nodev,noexec,relatime", "nfs4", "nas:/x")
		if err := CheckNFSBackingHardened(filepath.Join(dir, "pool")); err != nil {
			t.Fatalf("a directory pool on a mount with every option this kernel has: %v", err)
		}
	})
}

// realTempDir is t.TempDir with symlinks resolved, so a fake mount table
// names the mount point as the resolver reaches it.
func realTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// C1: on an export mounted without nosymfollow, the daemon's own opens of pool
// content follow no symlink on the export — final component or directory,
// through openat2 or the O_NOFOLLOW walk — while the host's own symlinks on
// the way to the mount point still resolve.
func TestPoolOpensFollowNoSymlinkOnAnUnhardenedExport(t *testing.T) {
	mnt := realTempDir(t)
	outside := realTempDir(t)
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(mnt, "evil.qcow2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(mnt, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(mnt, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mnt, "real", "ok.qcow2"), []byte("pool data"), 0o600); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(realTempDir(t), "pools")
	if err := os.Symlink(mnt, local); err != nil { // the host's own symlink to the mount
		t.Fatal(err)
	}
	mountInfoWith(t, mnt, "rw,nosuid,nodev,noexec,relatime", "nfs4", "nas:/x")

	for _, walk := range []bool{false, true} {
		t.Run(fmt.Sprintf("walk=%v", walk), func(t *testing.T) {
			openat2Disabled = walk
			defer func() { openat2Disabled = false }()
			for _, base := range []string{mnt, local} {
				for _, p := range []string{filepath.Join(base, "evil.qcow2"), filepath.Join(base, "sub", "victim")} {
					if b, err := ReadPoolFile(p); err == nil {
						t.Errorf("ReadPoolFile(%s) followed a symlink on the export: %q", p, b)
					}
					if err := CheckPoolPathNoSymlinks(p); err == nil {
						t.Errorf("CheckPoolPathNoSymlinks(%s) passed a symlink on the export", p)
					}
				}
				if f, err := CreatePoolTemp(filepath.Join(base, "sub"), ".x-*.tmp"); err == nil {
					f.Close()
					t.Errorf("CreatePoolTemp created %s through a symlinked directory on the export", f.Name())
				}
				if f, err := OpenPoolFile(filepath.Join(base, "evil.qcow2"), os.O_WRONLY|os.O_TRUNC, 0); err == nil {
					f.Close()
					t.Errorf("OpenPoolFile opened the symlink for writing")
				}
				if b, err := ReadPoolFile(filepath.Join(base, "real", "ok.qcow2")); err != nil || string(b) != "pool data" {
					t.Errorf("a real pool file through %s: %q, %v", base, b, err)
				}
				f, err := CreatePoolTemp(filepath.Join(base, "real"), ".x-*.tmp")
				if err != nil {
					t.Fatalf("CreatePoolTemp in a real directory: %v", err)
				}
				if filepath.Dir(f.Name()) != filepath.Join(base, "real") {
					t.Errorf("temp name %s is not in the directory asked for", f.Name())
				}
				f.Close()
				os.Remove(f.Name())
			}
			if b, _ := os.ReadFile(victim); string(b) != "host secret" {
				t.Fatalf("the host file was changed: %q", b)
			}
		})
	}

	// On a hardened export (the kernel refuses the symlinks there) and on no
	// export, the opens are the plain ones: nothing changes for those pools.
	mountInfoWith(t, mnt, "rw,nosuid,nodev,noexec,nosymfollow,relatime", "nfs4", "nas:/x")
	if b, err := ReadPoolFile(filepath.Join(mnt, "evil.qcow2")); err != nil || string(b) != "host secret" {
		t.Errorf("on a hardened mount the open is a plain one (here, through the fake table): %q, %v", b, err)
	}
	if err := CheckPoolPathNoSymlinks(filepath.Join(mnt, "evil.qcow2")); err != nil {
		t.Errorf("CheckPoolPathNoSymlinks on a hardened mount: %v", err)
	}
}

func TestKernelAtLeast(t *testing.T) {
	for rel, want := range map[string]bool{
		"4.18.0-553.el8_10.x86_64": false,
		"5.4.0-150-generic":        false,
		"5.9.16":                   false,
		"5.10.0-28-amd64":          true,
		"6.8.0-45-generic":         true,
		"7.0.0-34-generic":         true,
		"garbage":                  true,
	} {
		if got := kernelAtLeast(rel, 5, 10); got != want {
			t.Errorf("kernelAtLeast(%q, 5, 10) = %v, want %v", rel, got, want)
		}
	}
}
