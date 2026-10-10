package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withMountinfo points the mount table at a fixture for one test. "ROOT" in
// lines is replaced by root.
func withMountinfo(t *testing.T, root string, lines ...string) {
	t.Helper()
	old := mountinfoPath
	t.Cleanup(func() { mountinfoPath = old })
	mountinfoPath = filepath.Join(t.TempDir(), "mountinfo")
	body := strings.ReplaceAll(strings.Join(lines, "\n")+"\n", "ROOT", root)
	if err := os.WriteFile(mountinfoPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// R3-m3. Device-mapper control (dm targets over any host disk), the CPU MSRs
// and the hibernation image (host RAM) are never passed through, by name or
// by number.
func TestDeniedHostTrustNodes_DmMsrSnapshot(t *testing.T) {
	for _, p := range []string{"/dev/mapper/control", "/dev/cpu/0/msr", "/dev/cpu/17/msr", "/dev/snapshot"} {
		if !deniedDeviceName(p) {
			t.Errorf("%s not denied by name", p)
		}
	}
	for _, tc := range []struct{ maj, min uint32 }{{10, 236}, {202, 0}, {202, 31}, {10, 231}} {
		if !deniedDeviceNumber('c', tc.maj, tc.min) {
			t.Errorf("deniedDeviceNumber(c %d:%d) = false; want true", tc.maj, tc.min)
		}
	}
	if deniedDeviceName("/dev/mapper/vg-data") {
		t.Error("a device-mapper volume (not the control node) was denied by name")
	}
}

// R3-m1. A protected tree is the same tree wherever the host mounts it: a
// source under an allowed prefix that is a bind of /var/lib/litevirt, or a
// second mount of the NFS export a pool lives on, is refused by filesystem
// identity (device and the path within that filesystem), not by its path.
func TestResolveHostAccess_ProtectedTreeByFilesystemIdentity(t *testing.T) {
	root, access := hostTree(t)
	for _, d := range []string{"allowed/lv/x", "allowed/nas/pools/x/d", "allowed/nas/other"} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	withMountinfo(t, root,
		"20 1 8:1 / / rw - ext4 /dev/sda1 rw",
		"40 20 8:1 /var/lib/litevirt ROOT/allowed/lv rw - ext4 /dev/sda1 rw",
		"41 20 0:50 / ROOT/allowed/nas rw - nfs srv:/exp rw",
		"43 20 0:50 / /srv/nfs rw - nfs srv:/exp rw",
	)
	access.DenyFunc = func() ([]string, error) { return []string{"/srv/nfs/pools/x"}, nil }
	for _, rel := range []string{"allowed/lv/x", "allowed/nas/pools/x/d", "allowed/nas/pools"} {
		if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, rel), ContainerPath: "/m"}}, nil, access); err == nil {
			t.Errorf("%s, a protected tree under another path, was allowed", rel)
		}
	}
	for _, rel := range []string{"allowed/nas/other", "allowed/data"} {
		if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, rel), ContainerPath: "/m"}}, nil, access); err != nil {
			t.Errorf("%s, disjoint from every protected tree, was refused: %v", rel, err)
		}
	}
}

// R3-m1 in the hook: what was opened is judged by the mount the fd is on
// (its mount id), so an NFS source shadowed by a later mount at the same
// path is still recognised as the pool's filesystem; an unknown mount id
// refuses.
func TestJudgeOpened_ByMountID(t *testing.T) {
	root := t.TempDir()
	withMountinfo(t, root,
		"20 1 8:1 / / rw - ext4 /dev/sda1 rw",
		"41 20 0:50 / ROOT/nas rw - nfs srv:/exp rw",
		"44 20 0:60 / ROOT/nas rw - tmpfs tmpfs rw",
		"43 20 0:50 / /srv/nfs rw - nfs srv:/exp rw",
	)
	p := hookPolicy{MountPaths: []string{root}, Deny: []string{"/srv/nfs/pools"}}
	src := filepath.Join(root, "nas", "pools", "a")
	if err := p.judgeOpened(root, src, 41); err == nil {
		t.Error("a source opened on the pool's NFS filesystem passed")
	}
	if err := p.judgeOpened(root, src, 44); err != nil {
		t.Errorf("a source opened on an unrelated tmpfs was refused: %v", err)
	}
	if err := p.judgeOpened(root, src, 99); err == nil {
		t.Error("a source on a mount the table does not list passed")
	}
}

// R3-m4. A policy whose container directory is gone (deleted, migrated away)
// is removed by the refresh; a live container's stays.
func TestRefreshHookPolicies_RemovesOrphans(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	if err := r.SetHostAccess("c1", []Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/srv"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.writeHookPolicy("gone", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.RefreshHookPolicies(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hookPolicyFile("gone")); !os.IsNotExist(err) {
		t.Errorf("the policy of a container that no longer exists was kept (%v)", err)
	}
	if _, err := os.Stat(hookPolicyFile("c1")); err != nil {
		t.Errorf("a live container's policy was removed: %v", err)
	}
}

// R3-m4. The refresh and SetHostAccess do not interleave: a refresh that
// read the record before a SetHostAccess cannot write its older policy over
// the newer one.
func TestRefreshHookPolicies_NoStaleOverwrite(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	data := Mount{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/srv"}
	file := Mount{HostPath: filepath.Join(root, "allowed", "file.txt"), ContainerPath: "/etc/app.conf"}
	if err := r.SetHostAccess("c1", []Mount{data}, nil); err != nil {
		t.Fatal(err)
	}
	var pending chan error
	t.Cleanup(func() { refreshPauseHook = nil })
	refreshPauseHook = func(name string) {
		if name != "c1" || pending != nil {
			return
		}
		pending = make(chan error, 1)
		go func() { pending <- r.SetHostAccess("c1", []Mount{data, file}, nil) }()
		// Give the concurrent SetHostAccess every chance to finish first.
		time.Sleep(300 * time.Millisecond)
	}
	if err := r.RefreshHookPolicies(); err != nil {
		t.Fatal(err)
	}
	if pending == nil {
		t.Fatal("the refresh never reached c1")
	}
	if err := <-pending; err != nil {
		t.Fatal(err)
	}
	p, err := readHookPolicy("c1")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.coversMount(hookMount{ro: true, file: true, prefix: filepath.Join(root, "allowed"), rel: "file.txt"}); err != nil {
		t.Errorf("a refresh overwrote a newer SetHostAccess's policy: %v", err)
	}
}
