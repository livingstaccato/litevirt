package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// N1. A rebuilt config's network comes only from the authorized NICs: an
// archive's phys, none, macvlan and router-mode lines are dropped — and
// reported — and the spec's veth NICs rendered in their place.
func TestRebuildConfig_NetworkOnlyFromTheSpec(t *testing.T) {
	_, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	archived := strings.Join([]string{
		"lxc.uts.name = c1",
		"lxc.net.0.type = phys",
		"lxc.net.0.link = eth0",
		"lxc.net.1.type = none",
		"lxc.net.2.type = macvlan",
		"lxc.net.2.link = bond0",
		"lxc.net.3.type = veth",
		"lxc.net.3.veth.mode = router",
		"lxc.net.3.link = br-other-tenant",
	}, "\n") + "\n"
	containerDir(t, r, "c1", archived)
	dropped, err := r.RebuildConfig("c1", ConfinementDefault, 1_000_065_536,
		[]NetworkAttach{{Name: "eth0", Bridge: "br-mine", MAC: "02:00:00:00:00:01"}}, nil, nil)
	if err != nil {
		t.Fatalf("RebuildConfig: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(r.Lxcpath, "c1", "config"))
	cfg := string(b)
	for _, gone := range []string{"phys", "type = none", "macvlan", "veth.mode", "br-other-tenant", "bond0", "lxc.net.1", "lxc.net.2", "lxc.net.3"} {
		if strings.Contains(cfg, gone) {
			t.Errorf("rebuilt config kept the archive's %q:\n%s", gone, cfg)
		}
	}
	for _, want := range []string{"lxc.net.0.type = veth", "lxc.net.0.link = br-mine", "lxc.net.0.hwaddr = 02:00:00:00:00:01"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rebuilt config lacks the spec's %q:\n%s", want, cfg)
		}
	}
	joined := strings.Join(dropped, " ")
	for _, k := range []string{"lxc.net.0.type", "lxc.net.1.type", "lxc.net.2.type", "lxc.net.3.veth.mode"} {
		if !strings.Contains(joined, k) {
			t.Errorf("dropped %v does not report %s", dropped, k)
		}
	}
}

// m-h. Includes are only the fragments litevirt's own create writes.
func TestSanitize_IncludesOnlyCommonAndUserns(t *testing.T) {
	out, _ := SanitizeImportedConfig("lxc.include = /usr/share/lxc/config/common.conf\n" +
		"lxc.include = /usr/share/lxc/config/debian.common.conf\n" +
		"lxc.include = /usr/share/lxc/config/userns.conf\n" +
		"lxc.include = /usr/share/lxc/config/nesting.conf\n" +
		"lxc.include = /usr/share/lxc/config/oci.common.conf.d\n")
	for _, keep := range []string{"/common.conf", "debian.common.conf", "userns.conf"} {
		if !strings.Contains(out, keep) {
			t.Errorf("dropped %s:\n%s", keep, out)
		}
	}
	if strings.Contains(out, "nesting.conf") || strings.Contains(out, "common.conf.d") {
		t.Errorf("kept a fragment litevirt never writes:\n%s", out)
	}
}

// N3. The host's dynamic stores — pools, repos, image store — are protected
// trees too, judged at resolve (so at every start), both ways.
func TestResolveHostAccess_DynamicDenyTrees(t *testing.T) {
	root, access := hostTree(t)
	pool := filepath.Join(root, "allowed", "pools", "a")
	_ = os.MkdirAll(pool, 0o755)
	access.DenyFunc = func() ([]string, error) { return []string{pool}, nil }
	for _, p := range []string{pool, filepath.Join(root, "allowed", "pools")} {
		if _, _, err := ResolveHostAccess([]Mount{{HostPath: p, ContainerPath: "/m"}}, nil, access); err == nil ||
			!strings.Contains(err.Error(), "protected tree") {
			t.Errorf("mount of %s = %v; want a protected-tree refusal", p, err)
		}
	}
	// A symlink into the pool resolves into it and is refused too.
	_ = os.Symlink(pool, filepath.Join(root, "allowed", "pool-link"))
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed", "pool-link"), ContainerPath: "/m"}}, nil, access); err == nil {
		t.Error("a symlink into a pool was allowed")
	}
}

// m-c. The hook binary is never inside a mounted tree.
func TestResolveHostAccess_HookBinaryIsProtected(t *testing.T) {
	root, access := hostTree(t)
	bin := filepath.Join(root, "allowed", "opt", "litevirt")
	_ = os.MkdirAll(filepath.Dir(bin), 0o755)
	_ = os.WriteFile(bin, []byte("#!"), 0o755)
	access.HookBinary = bin
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed", "opt"), ContainerPath: "/m"}}, nil, access); err == nil {
		t.Fatal("a mount containing the start hook's binary was allowed")
	}
}

// N4. Raw-disk character nodes are never passed through.
func TestDeniedRawDiskCharNodes(t *testing.T) {
	dir := t.TempDir()
	old := procDevicesPath
	t.Cleanup(func() { procDevicesPath = old })
	procDevicesPath = filepath.Join(dir, "devices")
	_ = os.WriteFile(procDevicesPath, []byte("Character devices:\n  1 mem\n 21 sg\n241 nvme-generic\n242 bsg\n243 nvme\n\nBlock devices:\n  8 sd\n"), 0o644)
	for _, tc := range []struct {
		maj, min uint32
		deny     bool
	}{{21, 0, true}, {241, 1, true}, {242, 0, true}, {243, 0, true}, {188, 0, false}, {4, 64, false}} {
		if got := deniedDeviceNumber('c', tc.maj, tc.min); got != tc.deny {
			t.Errorf("deniedDeviceNumber(c %d:%d) = %v; want %v", tc.maj, tc.min, got, tc.deny)
		}
	}
	for _, p := range []string{"/dev/sg0", "/dev/bsg/0:0:0:0", "/dev/ng0n1", "/dev/nvme0"} {
		if !deniedDeviceName(p) {
			t.Errorf("%s not denied by name", p)
		}
	}
	if deniedDeviceName("/dev/nvme0n1") || deniedDeviceName("/dev/ttyUSB0") {
		t.Error("a namespace block node or a serial port was denied by name")
	}
}

// N4. In use, by device NUMBER: a device any process holds open (qemu's VM
// disks), swap, an attached loop or nbd, and a partition of a disk in use.
func TestBlockDeviceInUse_ByNumber(t *testing.T) {
	dir := t.TempDir()
	oldMI, oldSys, oldProc, oldSwaps, oldStat, oldExcl := mountinfoPath, sysDevBlock, procRoot, swapsPath, statRdev, exclusiveOpenBusy
	t.Cleanup(func() {
		mountinfoPath, sysDevBlock, procRoot, swapsPath, statRdev, exclusiveOpenBusy = oldMI, oldSys, oldProc, oldSwaps, oldStat, oldExcl
	})
	mountinfoPath = filepath.Join(dir, "mountinfo")
	sysDevBlock = filepath.Join(dir, "sys")
	procRoot = filepath.Join(dir, "proc")
	swapsPath = filepath.Join(dir, "swaps")
	_ = os.WriteFile(mountinfoPath, []byte("29 1 8:2 / / rw - ext4 /dev/sda2 rw\n"), 0o644)
	_ = os.WriteFile(swapsPath, []byte("Filename Type Size Used Priority\n/dev/fake-swap partition 1 0 -2\n"), 0o644)
	exclusiveOpenBusy = func(string) bool { return false }
	// Device numbers by path, as stat would report them.
	numbers := map[string][2]uint32{"/dev/fake-swap": {8, 48}, "/dev/fake-vmdisk": {8, 64}}
	statRdev = func(p string) (byte, uint32, uint32, bool) { n, ok := numbers[p]; return 'b', n[0], n[1], ok }
	// A qemu holding the VM disk open.
	_ = os.MkdirAll(filepath.Join(procRoot, "4242", "fd"), 0o755)
	_ = os.Symlink("/dev/fake-vmdisk", filepath.Join(procRoot, "4242", "fd", "17"))
	mk := func(p string) { _ = os.MkdirAll(filepath.Join(sysDevBlock, p), 0o755) }
	mk("7:0/loop")
	_ = os.WriteFile(filepath.Join(sysDevBlock, "7:0/loop/backing_file"), []byte("/var/img\n"), 0o644)
	mk("43:0")
	_ = os.WriteFile(filepath.Join(sysDevBlock, "43:0/pid"), []byte("99\n"), 0o644)
	mk("8:64/sde1")
	_ = os.WriteFile(filepath.Join(sysDevBlock, "8:64/sde1/partition"), []byte("1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(sysDevBlock, "8:64/sde1/dev"), []byte("8:65\n"), 0o644)
	mk("8:80")
	for _, tc := range []struct {
		name     string
		maj, min uint32
		inUse    bool
	}{
		{"swap", 8, 48, true},
		{"held open by a process", 8, 64, true},
		{"loop with a backing file", 7, 0, true},
		{"nbd connected", 43, 0, true},
		{"partition of a held disk", 8, 65, true},
		{"unused disk", 8, 80, false},
	} {
		if why := blockDeviceInUse(tc.maj, tc.min); (why != "") != tc.inUse {
			t.Errorf("%s: blockDeviceInUse(%d:%d) = %q; want in use %v", tc.name, tc.maj, tc.min, why, tc.inUse)
		}
	}
	exclusiveOpenBusy = func(string) bool { return true }
	if why := blockDeviceInUse(8, 80); why == "" {
		t.Error("a device the kernel will not open exclusively (btrfs, ZFS, md) is not in use")
	}
}

// m-d. The record is the authority: a block that differs from its render —
// tampered, or a renumbered device — is re-rendered, never kept.
func TestCheckHostAccessForStart_ReRendersFromTheRecord(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	dir := containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	if err := r.SetHostAccess("c1", []Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv"}}, nil); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(filepath.Join(dir, "config"))
	_ = os.WriteFile(filepath.Join(dir, "config"), []byte(strings.Replace(string(good), "bind,ro,nosuid,nodev", "rbind,rw", 1)+"lxc.cgroup2.devices.allow = a\n"), 0o644)
	if err := r.checkHostAccessForStart("c1"); err != nil {
		t.Fatalf("a re-renderable block refused the start: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config"))
	if strings.Contains(string(b), "rbind,rw") || !strings.Contains(string(b), "bind,ro,nosuid,nodev") {
		t.Fatalf("the tampered block survived the start check:\n%s", b)
	}
}

// m-b / m-5. The start hook re-judges against this host's policy as it is
// now, bounded by the container's own record: the per-container policy file
// the daemon writes.
func TestHookPolicy_RoundTripAndJudging(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	if err := r.writeHookPolicy("c1", nil, nil); err != nil {
		t.Fatalf("writeHookPolicy: %v", err)
	}
	p, err := readHookPolicy("c1")
	if err != nil {
		t.Fatalf("readHookPolicy: %v", err)
	}
	allowed := filepath.Join(root, "allowed")
	if err := p.judgeMount(allowed, filepath.Join(allowed, "data")); err != nil {
		t.Errorf("an allowed source was refused by the hook: %v", err)
	}
	if err := p.judgeMount(filepath.Join(root, "secret"), filepath.Join(root, "secret")); err == nil {
		t.Error("a prefix no longer allowed passed the hook")
	}
	_ = os.Remove(hookPolicyFile("c1"))
	if _, err := readHookPolicy("c1"); err == nil {
		t.Error("a missing policy read as allowing")
	}
}

// N4. A VM disk on this host is litevirt's by number, and so are its
// partitions and, for a partition, the disk it belongs to.
func TestLitevirtBlockUse_CoversTheFamily(t *testing.T) {
	old := sysDevBlock
	t.Cleanup(func() { sysDevBlock = old })
	sysDevBlock = filepath.Join(t.TempDir(), "sys")
	_ = os.MkdirAll(filepath.Join(sysDevBlock, "8:64/sde1"), 0o755)
	_ = os.WriteFile(filepath.Join(sysDevBlock, "8:64/sde1/partition"), []byte("1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(sysDevBlock, "8:64/sde1/dev"), []byte("8:65\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(sysDevBlock, "8:80"), 0o755)
	a := HostAccess{BlockInUse: func(ma, mi uint32) (string, error) {
		if ma == 8 && mi == 64 {
			return "the disk of VM db", nil
		}
		return "", nil
	}}
	if why, _ := litevirtBlockUse(a, 8, 65); why == "" {
		t.Error("a partition of a VM's disk was not litevirt's")
	}
	a.BlockInUse = func(ma, mi uint32) (string, error) {
		if ma == 8 && mi == 65 {
			return "the disk of VM db", nil
		}
		return "", nil
	}
	if why, _ := litevirtBlockUse(a, 8, 64); why == "" {
		t.Error("the disk holding a VM's partition was not litevirt's")
	}
	if why, _ := litevirtBlockUse(a, 8, 80); why != "" {
		t.Errorf("an unrelated disk was litevirt's: %s", why)
	}
}

// m-c. The start hook's binary must be one root alone can change: a path a
// config line cannot carry, or a file in a tree that is not root-owned and
// closed to group and others, is refused.
func TestValidateHookBinary_RefusesAnOpenTree(t *testing.T) {
	if err := validateHookBinary("/opt/lv;rm -rf /"); err == nil {
		t.Error("a hook path with shell characters passed")
	}
	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Owned by the test's user, or (as root) beneath the world-writable /tmp.
	if err := validateHookBinary(bin); err == nil {
		t.Errorf("a hook binary in an open tree (%s) passed", bin)
	}
}

// m-b. The hook refuses a source that now lies in a protected tree, even
// beneath an allowed prefix.
func TestHookPolicy_JudgesProtectedTrees(t *testing.T) {
	allowed := t.TempDir()
	p := hookPolicy{MountPaths: []string{allowed}, Deny: []string{filepath.Join(allowed, "pool")}}
	if err := p.judgeMount(allowed, filepath.Join(allowed, "pool", "disk")); err == nil {
		t.Error("a source inside a protected store passed the hook")
	}
	// m-2: the prefix is not judged as a whole; a source disjoint from the
	// store beneath it keeps working.
	if err := p.judgeMount(allowed, filepath.Join(allowed, "data")); err != nil {
		t.Errorf("a source beside a protected store was refused: %v", err)
	}
	if err := p.judgeMount(allowed, allowed); err == nil {
		t.Error("a source containing a protected store passed the hook")
	}
	if err := (hookPolicy{MountPaths: []string{allowed}}).judgeMount(allowed, filepath.Join(allowed, "data")); err != nil {
		t.Errorf("an allowed source was refused: %v", err)
	}
}
