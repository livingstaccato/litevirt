package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKernelSupport makes the kernel probe pass for a test.
func fakeKernelSupport(t *testing.T) {
	t.Helper()
	old := hostAccessSupported
	hostAccessSupported = func() error { return nil }
	t.Cleanup(func() { hostAccessSupported = old })
}

// hostTree builds an allowed tree and a secret outside it:
//
//	<root>/allowed/data/        (dir)
//	<root>/allowed/file.txt     (file)
//	<root>/allowed/escape  ->   <root>/secret
//	<root>/secret/
func hostTree(t *testing.T) (root string, access HostAccess) {
	t.Helper()
	fakeKernelSupport(t)
	root = t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	for _, d := range []string{"allowed/data", "secret"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "allowed/file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "secret"), filepath.Join(root, "allowed/escape")); err != nil {
		t.Fatal(err)
	}
	return root, HostAccess{MountPaths: []string{filepath.Join(root, "allowed")}, DevicePaths: []string{"/dev/null"}, HookBinary: "/opt/lv/litevirt"}
}

func TestResolveHostAccess_RendersStagedReadOnlyByDefault(t *testing.T) {
	root, access := hostTree(t)
	rm, _, err := ResolveHostAccess([]Mount{
		{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv/data"},
		{HostPath: filepath.Join(root, "allowed/file.txt"), ContainerPath: "/etc/app.conf", ReadWrite: true},
	}, nil, access)
	if err != nil {
		t.Fatalf("ResolveHostAccess: %v", err)
	}
	block := renderHostAccessBlock("c1", access.HookBinary, rm, nil)
	allowed := filepath.Join(root, "allowed")
	for _, want := range []string{
		"lxc.hook.pre-start = /opt/lv/litevirt __lxc-hook",
		"lxc.hook.post-stop = /opt/lv/litevirt __lxc-hook",
		"# litevirt:mount ro dir " + allowed + " data",
		"lxc.mount.entry = " + stagingRoot + "/c1/m0 srv/data none bind,ro,nosuid,nodev,create=dir 0 0",
		"# litevirt:mount rw file " + allowed + " file.txt",
		"lxc.mount.entry = " + stagingRoot + "/c1/m1 etc/app.conf none bind,nosuid,nodev,create=file 0 0",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q:\n%s", want, block)
		}
	}
	// The user's tree is never what LXC mounts.
	if strings.Contains(block, "lxc.mount.entry = "+allowed) {
		t.Errorf("a mount entry names the user tree, not the staging path:\n%s", block)
	}
}

// A symlink inside the allowed tree that points out of it is refused, not
// followed: the RESOLVED path is what is judged; and a sibling sharing a
// prefix's spelling is not under it.
func TestResolveHostAccess_RefusesSymlinkEscapeAndSiblings(t *testing.T) {
	root, access := hostTree(t)
	_, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed/escape"), ContainerPath: "/mnt"}}, nil, access)
	if err == nil || !strings.Contains(err.Error(), "outside every containers.bind_mount_paths") {
		t.Fatalf("symlink escape = %v; want an outside-the-prefix refusal", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "allowed2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed2"), ContainerPath: "/mnt"}}, nil, access); err == nil {
		t.Fatal("a sibling sharing the prefix's spelling was allowed")
	}
}

// The protected trees beat any allowed prefix, both ways: a source inside
// one, and a source that CONTAINS one.
func TestResolveHostAccess_DenylistBeatsAllowlist(t *testing.T) {
	root, access := hostTree(t)
	access.Deny = []string{filepath.Join(root, "allowed/data/store")}
	_ = os.MkdirAll(filepath.Join(root, "allowed/data/store/pki"), 0o700)
	for _, p := range []string{filepath.Join(root, "allowed/data/store/pki"), filepath.Join(root, "allowed/data"), filepath.Join(root, "allowed")} {
		if _, _, err := ResolveHostAccess([]Mount{{HostPath: p, ContainerPath: "/m"}}, nil, access); err == nil ||
			!strings.Contains(err.Error(), "protected tree") {
			t.Errorf("mount of %s = %v; want a protected-tree refusal", p, err)
		}
	}
	everything := HostAccess{MountPaths: []string{"/"}}
	for _, p := range []string{"/", "/etc", "/proc", "/sys/kernel", "/dev", "/run", "/var/lib/lxc", "/var"} {
		if _, _, err := ResolveHostAccess([]Mount{{HostPath: p, ContainerPath: "/m"}}, nil, everything); err == nil {
			t.Errorf("mount of %s allowed", p)
		}
	}
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/m"}}, nil, HostAccess{}); err == nil {
		t.Fatal("an empty allow list allowed a mount")
	}
}

func TestValidateHostAccess(t *testing.T) {
	root, _ := hostTree(t)
	for _, bad := range []HostAccess{
		{MountPaths: []string{"/"}},
		{MountPaths: []string{"/var"}},     // contains /var/lib/lxc
		{MountPaths: []string{"/etc/ssl"}}, // inside /etc
		{MountPaths: []string{"relative"}},
		{MountPaths: []string{root}, Deny: []string{filepath.Join(root, "allowed")}}, // ancestor of a store
		{DevicePaths: []string{"/dev"}},
		{DevicePaths: []string{"/dev/mem"}},
		{DevicePaths: []string{"/dev/kvm"}},
		{DevicePaths: []string{"/dev/vhost-net"}},
		{DevicePaths: []string{"/dev/net"}}, // a directory
		{DevicePaths: []string{"/srv/x"}},
	} {
		if err := ValidateHostAccess(bad); err == nil {
			t.Errorf("ValidateHostAccess accepted %+v", bad)
		}
	}
	if err := ValidateHostAccess(HostAccess{MountPaths: []string{filepath.Join(root, "allowed")}, DevicePaths: []string{"/dev/ttyUSB0"}}); err != nil {
		t.Errorf("a sound list was refused: %v", err)
	}
}

func TestResolveHostAccess_RefusesUnsafePaths(t *testing.T) {
	root, access := hostTree(t)
	good := filepath.Join(root, "allowed/data")
	for _, m := range []Mount{
		{HostPath: good + "\nlxc.mount.entry = / host none bind 0 0", ContainerPath: "/m"},
		{HostPath: good + " x", ContainerPath: "/m"},
		{HostPath: "relative/path", ContainerPath: "/m"},
		{HostPath: filepath.Join(root, "allowed") + "/../secret", ContainerPath: "/m"},
		{HostPath: good, ContainerPath: "/"},
		{HostPath: good, ContainerPath: "relative"},
		{HostPath: good, ContainerPath: "/a/../../b"},
		{HostPath: good, ContainerPath: "/a b"},
	} {
		if _, _, err := ResolveHostAccess([]Mount{m}, nil, access); err == nil {
			t.Errorf("unsafe mount %+v accepted", m)
		}
		if err := CheckHostAccessShape([]Mount{m}, nil); err == nil {
			t.Errorf("CheckHostAccessShape accepted unsafe mount %+v", m)
		}
	}
}

func TestResolveHostAccess_Devices(t *testing.T) {
	_, access := hostTree(t)
	_, rd, err := ResolveHostAccess(nil, []Device{{HostPath: "/dev/null"}}, access)
	if err != nil {
		t.Fatalf("ResolveHostAccess /dev/null: %v", err)
	}
	if len(rd) != 1 || rd[0].Kind != 'c' || rd[0].Major != 1 || rd[0].Minor != 3 || rd[0].Target != "dev/null" {
		t.Fatalf("device = %+v; want c 1:3 at dev/null", rd)
	}
	block := renderHostAccessBlock("c1", access.HookBinary, nil, rd)
	if !strings.Contains(block, "lxc.cgroup2.devices.allow = c 1:3 rwm") || !strings.Contains(block, "lxc.mount.entry = /dev/null dev/null none bind,create=file 0 0") {
		t.Fatalf("device block:\n%s", block)
	}
	if strings.Contains(block, "lxc.hook") {
		t.Errorf("a devices-only block carries the mount hook:\n%s", block)
	}
	// Exact listing only: /dev/zero is under /dev but not listed, and a
	// listed entry is never a prefix of another node's name.
	if _, _, err := ResolveHostAccess(nil, []Device{{HostPath: "/dev/zero"}}, access); err == nil {
		t.Error("a device not listed exactly was allowed")
	}
	if _, _, err := ResolveHostAccess(nil, []Device{{HostPath: "/dev/null"}}, HostAccess{DevicePaths: []string{"/dev/nul"}}); err == nil {
		t.Error("a listed name allowed every node it is a prefix of")
	}
	// Even listed, the kernel-memory and KVM nodes are refused.
	for _, p := range []string{"/dev/mem", "/dev/kmem", "/dev/port", "/dev/kvm", "/dev/vhost-net"} {
		if _, _, err := ResolveHostAccess(nil, []Device{{HostPath: p}}, HostAccess{DevicePaths: []string{p}}); err == nil {
			t.Errorf("%s was passed through", p)
		}
	}
	if !deniedDeviceNumber('c', 1, 1) || !deniedDeviceNumber('c', 10, 232) || deniedDeviceNumber('c', 188, 0) {
		t.Error("deniedDeviceNumber disagrees with the denylist")
	}
}

// A block device that holds a mounted filesystem, or that something is
// built on, or whose partition is mounted, is the host's.
func TestBlockDeviceInUse(t *testing.T) {
	dir := t.TempDir()
	oldMI, oldSys := mountinfoPath, sysDevBlock
	t.Cleanup(func() { mountinfoPath, sysDevBlock = oldMI, oldSys })
	mountinfoPath = filepath.Join(dir, "mountinfo")
	sysDevBlock = filepath.Join(dir, "sys")
	_ = os.WriteFile(mountinfoPath, []byte("29 1 8:2 / / rw - ext4 /dev/sda2 rw\n"), 0o644)
	mk := func(p string) { _ = os.MkdirAll(filepath.Join(sysDevBlock, p), 0o755) }
	mk("8:0/sda2")
	_ = os.WriteFile(filepath.Join(sysDevBlock, "8:0/sda2/partition"), []byte("2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(sysDevBlock, "8:0/sda2/dev"), []byte("8:2\n"), 0o644)
	mk("8:16/holders/dm-0")
	mk("8:32")
	if why := blockDeviceInUse(8, 2); why == "" {
		t.Error("a mounted block device is not in use")
	}
	if why := blockDeviceInUse(8, 0); why == "" {
		t.Error("a disk whose partition is mounted is not in use")
	}
	if why := blockDeviceInUse(8, 16); why == "" {
		t.Error("a disk a dm device is built on is not in use")
	}
	if why := blockDeviceInUse(8, 32); why != "" {
		t.Errorf("an unused disk is in use: %s", why)
	}
	mountinfoPath = filepath.Join(dir, "missing")
	if why := blockDeviceInUse(8, 32); why == "" {
		t.Error("an unreadable mount table did not fail closed")
	}
}

// containerDir lays a config down as the runner would find it.
func containerDir(t *testing.T, r *LxcRunner, name, cfg string) string {
	t.Helper()
	dir := filepath.Join(r.Lxcpath, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The start check renders the managed block from the AUTHORIZED record and
// refuses a config whose block is anything else — mount options, an extra
// devices.allow, a block nobody authorized, or a record that cannot be read.
func TestCheckHostAccessForStart(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	dir := containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	if err := r.SetHostAccess("c1", []Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv"}}, []Device{{HostPath: "/dev/null"}}); err != nil {
		t.Fatalf("SetHostAccess: %v", err)
	}
	if err := r.checkHostAccessForStart("c1"); err != nil {
		t.Fatalf("an authorized config failed its start check: %v", err)
	}
	good, _ := os.ReadFile(filepath.Join(dir, "config"))
	tamper := func(old, new string) {
		t.Helper()
		if !strings.Contains(string(good), old) {
			t.Fatalf("config lacks %q:\n%s", old, good)
		}
		_ = os.WriteFile(filepath.Join(dir, "config"), []byte(strings.Replace(string(good), old, new, 1)), 0o644)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"ro made rw", "bind,ro,nosuid,nodev,create=dir", "rbind,nosuid,nodev,create=dir"},
		{"devices.allow widened", "lxc.cgroup2.devices.allow = c 1:3 rwm", "lxc.cgroup2.devices.allow = b *:* rwm"},
		{"extra allow line", "lxc.cgroup2.devices.allow = c 1:3 rwm", "lxc.cgroup2.devices.allow = c 1:3 rwm\nlxc.cgroup2.devices.allow = a"},
		{"mount source changed", stagingRoot + "/c1/m0", "/"},
	} {
		tamper(tc.old, tc.new)
		if err := r.checkHostAccessForStart("c1"); err == nil {
			t.Errorf("%s: the start check passed a tampered block", tc.name)
		}
	}
	// A changed hook binary (an upgrade) is refreshed, not refused.
	tamper("/opt/lv/litevirt", "/old/litevirt")
	if err := r.checkHostAccessForStart("c1"); err != nil {
		t.Errorf("an old hook binary refused the start: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config")); !strings.Contains(string(b), "/opt/lv/litevirt __lxc-hook") {
		t.Errorf("the hook line was not refreshed:\n%s", b)
	}
	// A block with no authorized record behind it.
	_ = os.WriteFile(filepath.Join(dir, "config"), good, 0o644)
	_ = os.Rename(filepath.Join(dir, hostAccessFile), filepath.Join(dir, "saved"))
	if err := r.checkHostAccessForStart("c1"); err == nil {
		t.Error("a block nobody authorized passed")
	}
	// A record that cannot be read refuses; only a missing one reads as none —
	// even for a config with no block, which "none" would otherwise pass.
	_ = os.Mkdir(filepath.Join(dir, hostAccessFile), 0o700)
	if err := r.checkHostAccessForStart("c1"); err == nil {
		t.Error("an unreadable record read as nothing authorized")
	}
	r3 := &LxcRunner{Lxcpath: t.TempDir()}
	d3 := containerDir(t, r3, "c3", "lxc.uts.name = c3\n")
	_ = os.Mkdir(filepath.Join(d3, hostAccessFile), 0o700)
	if err := r3.checkHostAccessForStart("c3"); err == nil {
		t.Error("an unreadable record (no block) did not refuse the start")
	}
	_ = os.Remove(filepath.Join(dir, hostAccessFile))
	_ = os.WriteFile(filepath.Join(dir, hostAccessFile), []byte("{"), 0o600)
	if err := r.checkHostAccessForStart("c1"); err == nil {
		t.Error("a corrupt record passed")
	}
	_ = os.Rename(filepath.Join(dir, "saved"), filepath.Join(dir, hostAccessFile))
	// The host's allowed list no longer covers it.
	r.HostAccess = HostAccess{DevicePaths: access.DevicePaths, HookBinary: access.HookBinary}
	if err := r.checkHostAccessForStart("c1"); err == nil {
		t.Error("a mount outside this host's prefixes passed")
	}
	// Entries outside the managed block are not litevirt's and are left alone.
	r2 := &LxcRunner{Lxcpath: t.TempDir()}
	containerDir(t, r2, "c2", "lxc.mount.entry = /opt x none bind 0 0\n")
	if err := r2.checkHostAccessForStart("c2"); err != nil {
		t.Errorf("an unmanaged entry was judged: %v", err)
	}
}

// prepareStart runs the start check.
func TestPrepareStart_ChecksHostAccess(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	if err := r.SetHostAccess("c1", []Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.prepareStart("c1"); err != nil {
		t.Fatalf("an allowed mount failed prepareStart: %v", err)
	}
	r.HostAccess = HostAccess{HookBinary: access.HookBinary}
	if err := r.prepareStart("c1"); err == nil || !strings.Contains(err.Error(), "bind_mount_paths") {
		t.Fatalf("prepareStart on a host that allows nothing = %v; want a refusal naming bind_mount_paths", err)
	}
}

// An imported config keeps only what litevirt writes; everything that grants
// host access or overrides confinement goes, including a forged managed block
// and its authorized record.
func TestSanitizeImportedConfig(t *testing.T) {
	in := strings.Join([]string{
		"# Managed by litevirt",
		"lxc.include = /usr/share/lxc/config/common.conf",
		"lxc.include = /etc/evil.conf",
		"lxc.include = /usr/share/lxc/config/../../../../etc/evil.conf",
		"lxc.rootfs.path = dir:/var/lib/lxc/c1/rootfs",
		"lxc.uts.name = c1",
		"lxc.net.0.type = veth",
		"lxc.net.0.link = br0",
		"lxc.net.0.script.up = /tmp/x",
		"lxc.cgroup2.memory.max = 512M",
		"lxc.mount.entry = / host none rbind,rw 0 0",
		"lxc.mount.fstab = /etc/fstab",
		"lxc.mount.auto = proc:rw sys:rw",
		"lxc.hook.pre-start = /tmp/x",
		"lxc.cgroup2.devices.allow = a",
		"lxc.apparmor.profile = unconfined",
		"lxc.seccomp.profile = ",
		"lxc.cap.drop = ",
		"lxc.idmap = u 0 0 65536",
		"lxc.rootfs.options = idmap=/proc/1/ns/user",
		"lxc.init.cmd = /bin/sh",
		"lxc.environment = X=1",
		"lxc.namespace.keep = user",
		"lxc.sysctl.kernel.x = 1",
		"lxc.prlimit.nofile = 1",
		mountBlockBegin,
		"# litevirt:mount rw dir / .",
		"lxc.mount.entry = /run/litevirt/ct/c1/m0 host none bind 0 0",
		mountBlockEnd,
	}, "\n")
	out, dropped := SanitizeImportedConfig(in)
	for _, keep := range []string{"lxc.include = /usr/share/lxc/config/common.conf", "lxc.rootfs.path", "lxc.uts.name", "lxc.net.0.type", "lxc.net.0.link", "lxc.cgroup2.memory.max"} {
		if !strings.Contains(out, keep) {
			t.Errorf("sanitize dropped %q:\n%s", keep, out)
		}
	}
	for _, gone := range []string{"/etc/evil.conf", "script.up", "lxc.mount", "lxc.hook", "devices.allow", "apparmor", "seccomp", "cap.drop", "lxc.idmap", "rootfs.options", "init.cmd", "environment", "namespace", "sysctl", "prlimit", mountBlockBegin, "host none"} {
		if strings.Contains(out, gone) {
			t.Errorf("sanitize kept %q:\n%s", gone, out)
		}
	}
	if len(dropped) == 0 {
		t.Error("sanitize reported nothing dropped")
	}
}

// RebuildConfig renders security and host access from what it is given, and
// nothing from the config it found.
func TestRebuildConfig(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	dir := containerDir(t, r, "c1", "lxc.uts.name = c1\nlxc.idmap = u 0 0 65536\nlxc.apparmor.profile = unconfined\n"+
		mountBlockBegin+"\n# litevirt:mount rw dir / .\nlxc.mount.entry = /run/litevirt/ct/c1/m0 host none bind 0 0\n"+mountBlockEnd+"\n")
	_ = os.WriteFile(filepath.Join(dir, hostAccessFile), []byte(`{"mounts":[{"host_path":"/","container_path":"/h","read_write":true}]}`), 0o600)
	if err := r.RebuildConfig("c1", ConfinementDefault, 1_000_065_536, nil, nil); err != nil {
		t.Fatalf("RebuildConfig: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config"))
	cfg := string(b)
	if strings.Contains(cfg, "unconfined") || strings.Contains(cfg, "lxc.idmap = u 0 0 65536") || strings.Contains(cfg, "lxc.mount.entry") {
		t.Fatalf("rebuilt config kept the archive's lines:\n%s", cfg)
	}
	if !strings.Contains(cfg, "lxc.idmap = u 0 1000065536 65536") || !strings.Contains(cfg, "lxc.apparmor.allow_nesting = 0") {
		t.Fatalf("rebuilt config lacks the authorized security:\n%s", cfg)
	}
	if _, err := os.Stat(filepath.Join(dir, hostAccessFile)); !os.IsNotExist(err) {
		t.Fatalf("the forged record survived the rebuild: %v", err)
	}
	// An admin-authorized mount is carried.
	if err := r.RebuildConfig("c1", ConfinementDefault, 1_000_065_536, []Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv"}}, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config")); !strings.Contains(string(b), "srv none bind,ro,nosuid,nodev,create=dir") {
		t.Fatalf("an authorized mount was not rendered:\n%s", b)
	}
}

// An import strips the archive's config and its host-access record.
func TestSanitizeImportedDir(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config"), []byte("lxc.uts.name = c1\nlxc.mount.entry = / host none bind 0 0\n"+secBlockBegin+" confinement=default\nlxc.idmap = u 0 1000065536 65536\n"+secBlockEnd+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, hostAccessFile), []byte(`{}`), 0o600)
	if err := SanitizeImportedDir(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config"))
	if strings.Contains(string(b), "lxc.mount.entry") {
		t.Fatalf("an imported mount entry survived:\n%s", b)
	}
	if !strings.Contains(string(b), "lxc.idmap = u 0 1000065536 65536") {
		t.Fatalf("the security block was dropped at import (the rebuild renders it):\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, hostAccessFile)); !os.IsNotExist(err) {
		t.Fatalf("an imported host-access record survived: %v", err)
	}
}

// Create judges mounts before it writes anything: a refused mount leaves no
// container directory behind; an allowed one is recorded and rendered.
func TestCreate_HostAccess(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	rootfs := filepath.Join(root, "rootfs")
	_ = os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755)
	if _, err := r.Create(t.Context(), CreateOpts{Name: "c1", Template: rootfs,
		Mounts: []Mount{{HostPath: filepath.Join(root, "secret"), ContainerPath: "/s"}}}); err == nil {
		t.Fatal("Create accepted a mount no prefix allows")
	}
	if _, serr := os.Stat(filepath.Join(r.Lxcpath, "c1")); !os.IsNotExist(serr) {
		t.Fatalf("a refused create left %s behind (stat err %v)", filepath.Join(r.Lxcpath, "c1"), serr)
	}
	if _, err := r.Create(t.Context(), CreateOpts{Name: "c2", Template: rootfs,
		Mounts: []Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv"}}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(r.Lxcpath, "c2", "config"))
	if !strings.Contains(string(b), "lxc.mount.entry = "+stagingRoot+"/c2/m0 srv none bind,ro,nosuid,nodev,create=dir 0 0") {
		t.Fatalf("config lacks the staged entry:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(r.Lxcpath, "c2", hostAccessFile)); err != nil {
		t.Fatalf("no authorized record: %v", err)
	}
	if err := r.checkHostAccessForStart("c2"); err != nil {
		t.Fatalf("the written config fails its own start check: %v", err)
	}
}

func TestWithHostAccessBlock_ReplacesEarlierBlock(t *testing.T) {
	root, access := hostTree(t)
	rm, _, _ := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/a"}}, nil, access)
	cfg := withHostAccessBlock("k = v\n", renderHostAccessBlock("c", access.HookBinary, rm, nil))
	cfg = withHostAccessBlock(cfg, "")
	if strings.Contains(cfg, "lxc.mount.entry") || strings.Contains(cfg, mountBlockBegin) {
		t.Fatalf("an empty block left the old one:\n%s", cfg)
	}
	if !strings.Contains(cfg, "k = v") {
		t.Fatalf("unrelated lines lost:\n%s", cfg)
	}
}

// An import strips the archive it lays down: a container exported with a raw
// mount entry, a forged managed block and an authorized-host-access record
// comes back with none of them.
func TestImport_StripsHostAccessFromTheArchive(t *testing.T) {
	r := &LxcRunner{Lxcpath: filepath.Join(t.TempDir(), "src"), IDMappedRootfs: "off"}
	tpl := mkRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := r.Create(t.Context(), CreateOpts{Name: "c1", Template: tpl}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(r.Lxcpath, "c1")
	f, _ := os.OpenFile(filepath.Join(dir, "config"), os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("lxc.mount.entry = / host none rbind,rw 0 0\n" + mountBlockBegin + "\n# litevirt:mount rw dir / .\nlxc.mount.entry = /run/litevirt/ct/c1/m0 h none bind 0 0\n" + mountBlockEnd + "\n")
	f.Close()
	_ = os.WriteFile(filepath.Join(dir, hostAccessFile), []byte(`{"mounts":[{"host_path":"/","container_path":"/h"}]}`), 0o600)
	var archive strings.Builder
	w := &stringWriter{&archive}
	if err := r.ExportContainer(t.Context(), "c1", w); err != nil {
		t.Fatal(err)
	}
	dst := &LxcRunner{Lxcpath: filepath.Join(t.TempDir(), "dst"), IDMappedRootfs: "off"}
	if err := dst.ImportContainer(t.Context(), "c1", strings.NewReader(archive.String())); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dst.Lxcpath, "c1", "config"))
	if strings.Contains(string(b), "lxc.mount.entry") || strings.Contains(string(b), mountBlockBegin) {
		t.Fatalf("the imported config kept host access:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(dst.Lxcpath, "c1", hostAccessFile)); !os.IsNotExist(err) {
		t.Fatalf("the imported record survived: %v", err)
	}
}
