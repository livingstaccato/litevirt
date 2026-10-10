package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// m-2. A prefix is never refused as a whole: a pool created under an allowed
// prefix refuses only mounts whose resolved source lies in it or contains it,
// and a disjoint source beside it keeps working.
func TestResolveHostAccess_StoreUnderAPrefixRefusesOnlyItsSources(t *testing.T) {
	root, access := hostTree(t)
	pool := filepath.Join(root, "allowed", "pools", "x")
	_ = os.MkdirAll(filepath.Join(pool, "d"), 0o755)
	access.DenyFunc = func() []string { return []string{pool} }
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/m"}}, nil, access); err != nil {
		t.Errorf("a source beside a pool under the same prefix was refused: %v", err)
	}
	for _, p := range []string{filepath.Join(pool, "d"), filepath.Join(root, "allowed")} {
		if _, _, err := ResolveHostAccess([]Mount{{HostPath: p, ContainerPath: "/m"}}, nil, access); err == nil {
			t.Errorf("a source in or containing the pool (%s) was allowed", p)
		}
	}
}

// m-9. A container without mounts never queries the host's stores.
func TestResolveHostAccess_NoStoreQueryWithoutMounts(t *testing.T) {
	_, access := hostTree(t)
	calls := 0
	access.DenyFunc = func() []string { calls++; return nil }
	if _, _, err := ResolveHostAccess(nil, nil, access); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveHostAccess(nil, []Device{{HostPath: "/dev/null"}}, access); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("the store list was read %d times for a container with no mounts", calls)
	}
}

// m-4. Host-trust console and input nodes are never passed through, by name
// or by number; serial adapters still are.
func TestDeniedHostConsoleNodes(t *testing.T) {
	old := procDevicesPath
	t.Cleanup(func() { procDevicesPath = old })
	procDevicesPath = filepath.Join(t.TempDir(), "devices")
	_ = os.WriteFile(procDevicesPath, []byte("Character devices:\n  4 tty\n  5 /dev/tty\n  7 vcs\n 13 input\n188 ttyUSB\n248 watchdog\n\nBlock devices:\n  8 sd\n"), 0o644)
	for _, p := range []string{"/dev/uinput", "/dev/watchdog", "/dev/watchdog0", "/dev/tty", "/dev/tty1", "/dev/tty63",
		"/dev/console", "/dev/vcs", "/dev/vcs1", "/dev/vcsa2", "/dev/vcsu", "/dev/input/event0", "/dev/input/mice"} {
		if !deniedDeviceName(p) {
			t.Errorf("%s not denied by name", p)
		}
	}
	for _, p := range []string{"/dev/ttyUSB0", "/dev/ttyS0", "/dev/ttyACM0", "/dev/ttyAMA0"} {
		if deniedDeviceName(p) {
			t.Errorf("serial adapter %s denied by name", p)
		}
	}
	for _, tc := range []struct {
		maj, min uint32
		deny     bool
	}{{10, 223, true}, {10, 130, true}, {248, 0, true}, {4, 0, true}, {4, 63, true}, {5, 0, true}, {5, 1, true},
		{7, 1, true}, {7, 129, true}, {13, 64, true}, {4, 64, false}, {188, 0, false}, {166, 0, false}} {
		if got := deniedDeviceNumber('c', tc.maj, tc.min); got != tc.deny {
			t.Errorf("deniedDeviceNumber(c %d:%d) = %v; want %v", tc.maj, tc.min, got, tc.deny)
		}
	}
}

// m-8. In-use detection matches the device KIND: a char node held open with
// the same numbers as a block device does not make the block device in use.
func TestBlockDeviceInUse_KindMatters(t *testing.T) {
	dir := t.TempDir()
	oldMI, oldSys, oldProc, oldSwaps, oldStat, oldExcl := mountinfoPath, sysDevBlock, procRoot, swapsPath, statRdev, exclusiveOpenBusy
	t.Cleanup(func() {
		mountinfoPath, sysDevBlock, procRoot, swapsPath, statRdev, exclusiveOpenBusy = oldMI, oldSys, oldProc, oldSwaps, oldStat, oldExcl
	})
	mountinfoPath, sysDevBlock, procRoot, swapsPath = filepath.Join(dir, "mi"), filepath.Join(dir, "sys"), filepath.Join(dir, "proc"), filepath.Join(dir, "swaps")
	_ = os.WriteFile(mountinfoPath, []byte(""), 0o644)
	_ = os.WriteFile(swapsPath, []byte("Filename\n/dev/charswap x 1 0 -2\n"), 0o644)
	exclusiveOpenBusy = func(string) bool { return false }
	statRdev = func(p string) (byte, uint32, uint32, bool) {
		switch p {
		case "/dev/null-like", "/dev/charswap":
			return 'c', 1, 3, true
		case "/dev/ram3":
			return 'b', 1, 3, true
		}
		return 0, 0, 0, false
	}
	_ = os.MkdirAll(filepath.Join(procRoot, "77", "fd"), 0o755)
	_ = os.Symlink("/dev/null-like", filepath.Join(procRoot, "77", "fd", "3"))
	_ = os.MkdirAll(filepath.Join(sysDevBlock, "1:3"), 0o755)
	if why := blockDeviceInUse(1, 3); why != "" {
		t.Errorf("a char node c 1:3 held open made block 1:3 in use: %s", why)
	}
	_ = os.Symlink("/dev/ram3", filepath.Join(procRoot, "77", "fd", "4"))
	if why := blockDeviceInUse(1, 3); why == "" {
		t.Error("the block device held open was not in use")
	}
}

// m-6. A container with devices and no mounts runs the start hook too, so an
// in-container reboot judges its devices again.
func TestRenderHostAccessBlock_DevicesRunTheHook(t *testing.T) {
	block := renderHostAccessBlock("c1", "/opt/lv/litevirt", nil, []resolvedDevice{{Source: "/dev/null", Target: "/dev/null", Kind: 'c', Major: 1, Minor: 3}})
	for _, want := range []string{"lxc.hook.pre-start = /opt/lv/litevirt __lxc-hook", "lxc.hook.post-stop = /opt/lv/litevirt __lxc-hook"} {
		if !strings.Contains(block, want) {
			t.Errorf("device-only block lacks %q:\n%s", want, block)
		}
	}
	_, access := hostTree(t)
	validateHookBinary = func(string) error { return os.ErrPermission }
	if _, _, err := ResolveHostAccess(nil, []Device{{HostPath: "/dev/null"}}, access); err == nil {
		t.Error("a device-only container was allowed with a hook binary that fails validation")
	}
}

// m-5. The policy is per container and bounded by its record: the hook
// stages only what the record authorized, and it is rewritten whenever the
// record or the host's policy changes — a withdrawn prefix leaves a policy
// that authorizes nothing.
func TestHookPolicy_PerContainerAndRefreshed(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	allowed := filepath.Join(root, "allowed")
	if err := r.SetHostAccess("c1", []Mount{{HostPath: filepath.Join(allowed, "data"), ContainerPath: "/srv"}}, []Device{{HostPath: "/dev/null"}}); err != nil {
		t.Fatal(err)
	}
	p, err := readHookPolicy("c1")
	if err != nil {
		t.Fatalf("SetHostAccess wrote no policy: %v", err)
	}
	if err := p.coversMount(hookMount{ro: true, prefix: allowed, rel: "data"}); err != nil {
		t.Errorf("the authorized mount is not in the policy: %v", err)
	}
	for _, m := range []hookMount{{ro: false, prefix: allowed, rel: "data"}, {ro: true, prefix: allowed, rel: "."}, {ro: true, prefix: root, rel: "secret"}} {
		if err := p.coversMount(m); err == nil {
			t.Errorf("a mount the record never authorized passed: %+v", m)
		}
	}
	if err := p.coversDevice(hookDevice{kind: 'c', major: 1, minor: 3, source: "/dev/null"}); err != nil {
		t.Errorf("the authorized device is not in the policy: %v", err)
	}
	if err := p.coversDevice(hookDevice{kind: 'c', major: 1, minor: 5, source: "/dev/zero"}); err == nil {
		t.Error("a device the record never authorized passed")
	}
	if _, err := readHookPolicy("c2"); err == nil {
		t.Error("another container's policy read as allowing")
	}
	// The host withdraws the prefix; the refresh leaves nothing authorized.
	r.HostAccess.MountPaths = nil
	if err := r.RefreshHookPolicies(); err != nil {
		t.Fatalf("RefreshHookPolicies: %v", err)
	}
	p, err = readHookPolicy("c1")
	if err != nil {
		t.Fatalf("the refresh removed the policy instead of narrowing it: %v", err)
	}
	if err := p.coversMount(hookMount{ro: true, prefix: allowed, rel: "data"}); err == nil {
		t.Error("a withdrawn prefix's mount still passes after the refresh")
	}
}
