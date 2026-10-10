package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hostTree builds an allowed tree and a secret outside it:
//
//	<root>/allowed/data/        (dir)
//	<root>/allowed/file.txt     (file)
//	<root>/allowed/escape  ->   <root>/secret
//	<root>/secret/
func hostTree(t *testing.T) (root string, access HostAccess) {
	t.Helper()
	root = t.TempDir()
	// t.TempDir may itself sit under a symlinked /tmp; work in resolved terms.
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
	return root, HostAccess{MountPaths: []string{filepath.Join(root, "allowed")}, DevicePaths: []string{"/dev/null"}}
}

func TestResolveHostAccess_AllowsUnderPrefixReadOnlyByDefault(t *testing.T) {
	root, access := hostTree(t)
	rm, _, err := ResolveHostAccess([]Mount{
		{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv/data"},
		{HostPath: filepath.Join(root, "allowed/file.txt"), ContainerPath: "/etc/app.conf", ReadWrite: true},
	}, nil, access)
	if err != nil {
		t.Fatalf("ResolveHostAccess: %v", err)
	}
	block := renderHostAccessBlock(rm, nil)
	for _, want := range []string{
		"lxc.mount.entry = " + filepath.Join(root, "allowed/data") + " srv/data none bind,ro,nosuid,nodev,create=dir 0 0",
		"lxc.mount.entry = " + filepath.Join(root, "allowed/file.txt") + " etc/app.conf none bind,nosuid,nodev,create=file 0 0",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q:\n%s", want, block)
		}
	}
}

// A symlink inside the allowed tree that points out of it is refused, not
// followed: the RESOLVED path is what is judged.
func TestResolveHostAccess_RefusesSymlinkEscape(t *testing.T) {
	root, access := hostTree(t)
	_, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed/escape"), ContainerPath: "/mnt"}}, nil, access)
	if err == nil || !strings.Contains(err.Error(), "outside every containers.bind_mount_paths") {
		t.Fatalf("symlink escape = %v; want an outside-the-prefix refusal", err)
	}
	// A prefix match on the string alone is not a match: allowed2 is not under allowed.
	if err := os.MkdirAll(filepath.Join(root, "allowed2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed2"), ContainerPath: "/mnt"}}, nil, access); err == nil {
		t.Fatal("a sibling sharing the prefix's spelling was allowed")
	}
}

func TestResolveHostAccess_RefusesWhatNoPrefixAllows(t *testing.T) {
	root, _ := hostTree(t)
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/m"}}, nil, HostAccess{}); err == nil {
		t.Fatal("an empty allow list allowed a mount")
	}
	// The root, /proc, /sys and /dev are never mounted, even under a "/" prefix.
	everything := HostAccess{MountPaths: []string{"/"}}
	for _, p := range []string{"/", "/proc", "/sys/kernel", "/dev"} {
		if _, _, err := ResolveHostAccess([]Mount{{HostPath: p, ContainerPath: "/m"}}, nil, everything); err == nil {
			t.Errorf("mount of %s allowed", p)
		}
	}
}

func TestResolveHostAccess_RefusesUnsafePaths(t *testing.T) {
	root, access := hostTree(t)
	good := filepath.Join(root, "allowed/data")
	for _, m := range []Mount{
		{HostPath: good + "\nlxc.mount.entry = / host none bind 0 0", ContainerPath: "/m"}, // config injection
		{HostPath: good + " x", ContainerPath: "/m"},                                       // field split
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
	block := renderHostAccessBlock(nil, rd)
	if !strings.Contains(block, "lxc.cgroup2.devices.allow = c 1:3 rwm") || !strings.Contains(block, "lxc.mount.entry = /dev/null dev/null none bind,create=file 0 0") {
		t.Fatalf("device block:\n%s", block)
	}
	if _, _, err := ResolveHostAccess(nil, []Device{{HostPath: "/dev/zero"}}, access); err == nil {
		t.Error("a device outside containers.device_paths was allowed")
	}
	root, _ := hostTree(t)
	notDev := HostAccess{DevicePaths: []string{root}}
	if _, _, err := ResolveHostAccess(nil, []Device{{HostPath: filepath.Join(root, "allowed/file.txt")}}, notDev); err == nil {
		t.Error("a regular file was passed through as a device")
	}
}

// The start check re-judges the block as the host is now.
func TestVerifyHostAccess(t *testing.T) {
	root, access := hostTree(t)
	data := filepath.Join(root, "allowed/data")
	rm, rd, err := ResolveHostAccess([]Mount{{HostPath: data, ContainerPath: "/srv"}}, []Device{{HostPath: "/dev/null"}}, access)
	if err != nil {
		t.Fatal(err)
	}
	cfg := withHostAccessBlock("lxc.uts.name = c1\n", renderHostAccessBlock(rm, rd))
	if err := VerifyHostAccess(cfg, access); err != nil {
		t.Fatalf("a fresh config failed its start check: %v", err)
	}

	// The allowed list on this host no longer covers it (moved here, or the
	// operator narrowed it).
	if err := VerifyHostAccess(cfg, HostAccess{DevicePaths: access.DevicePaths}); err == nil {
		t.Error("a mount outside this host's prefixes passed the start check")
	}
	if err := VerifyHostAccess(cfg, HostAccess{MountPaths: access.MountPaths}); err == nil {
		t.Error("a device outside this host's prefixes passed the start check")
	}

	// The mounted directory was swapped for a symlink to the secret.
	if err := os.Rename(data, data+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "secret"), data); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHostAccess(cfg, access); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a swapped-in symlink = %v; want a symlink refusal", err)
	}

	// A hand-broken block fails closed.
	if err := VerifyHostAccess(mountBlockBegin+"\nlxc.mount.entry = / x none bind 0 0\n"+mountBlockEnd+"\n", access); err == nil {
		t.Error("a mount entry with no marker passed")
	}
	if err := VerifyHostAccess(mountBlockBegin+"\n", access); err == nil {
		t.Error("an unclosed block passed")
	}
	// Entries OUTSIDE the managed block are not litevirt's and are left alone
	// (a hand-written config an earlier workflow relies on).
	if err := VerifyHostAccess("lxc.mount.entry = /opt x none bind 0 0\n", HostAccess{}); err != nil {
		t.Errorf("an unmanaged entry was judged: %v", err)
	}
}

func TestWithHostAccessBlock_ReplacesEarlierBlock(t *testing.T) {
	root, access := hostTree(t)
	rm, _, _ := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/a"}}, nil, access)
	cfg := withHostAccessBlock("k = v\n", renderHostAccessBlock(rm, nil))
	cfg = withHostAccessBlock(cfg, "")
	if strings.Contains(cfg, "lxc.mount.entry") || strings.Contains(cfg, mountBlockBegin) {
		t.Fatalf("an empty block left the old one:\n%s", cfg)
	}
	if !strings.Contains(cfg, "k = v") {
		t.Fatalf("unrelated lines lost:\n%s", cfg)
	}
}

// prepareStart runs the start check: a container whose managed mount this
// host does not allow is refused before lxc-start.
func TestPrepareStart_VerifiesHostAccess(t *testing.T) {
	root, access := hostTree(t)
	rm, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv"}}, nil, access)
	if err != nil {
		t.Fatal(err)
	}
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	dir := filepath.Join(r.Lxcpath, "c1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := withHostAccessBlock("lxc.uts.name = c1\n", renderHostAccessBlock(rm, nil))
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.prepareStart("c1"); err != nil {
		t.Fatalf("an allowed mount failed prepareStart: %v", err)
	}
	r.HostAccess = HostAccess{}
	if err := r.prepareStart("c1"); err == nil || !strings.Contains(err.Error(), "bind_mount_paths") {
		t.Fatalf("prepareStart on a host that allows nothing = %v; want a refusal naming bind_mount_paths", err)
	}
}

// Create judges mounts before it writes anything: a refused mount leaves no
// container directory behind.
func TestCreate_RefusedMountLeavesNothing(t *testing.T) {
	root, _ := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir()}
	rootfs := filepath.Join(root, "rootfs")
	for _, d := range []string{"etc", "bin"} {
		_ = os.MkdirAll(filepath.Join(rootfs, d), 0o755)
	}
	_, err := r.Create(t.Context(), CreateOpts{Name: "c1", Template: rootfs,
		Mounts: []Mount{{HostPath: filepath.Join(root, "secret"), ContainerPath: "/s"}}})
	if err == nil {
		t.Fatal("Create accepted a mount no prefix allows")
	}
	if _, serr := os.Stat(filepath.Join(r.Lxcpath, "c1")); !os.IsNotExist(serr) {
		t.Fatalf("a refused create left %s behind (stat err %v)", filepath.Join(r.Lxcpath, "c1"), serr)
	}
}

// An allowed mount reaches the container's config as the resolved path.
func TestCreate_AllowedMountWrittenToConfig(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	rootfs := filepath.Join(root, "rootfs")
	_ = os.MkdirAll(filepath.Join(rootfs, "etc"), 0o755)
	if _, err := r.Create(t.Context(), CreateOpts{Name: "c1", Template: rootfs,
		Mounts: []Mount{{HostPath: filepath.Join(root, "allowed/data"), ContainerPath: "/srv"}}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(r.Lxcpath, "c1", "config"))
	if err != nil {
		t.Fatal(err)
	}
	want := "lxc.mount.entry = " + filepath.Join(root, "allowed/data") + " srv none bind,ro,nosuid,nodev,create=dir 0 0"
	if !strings.Contains(string(b), want) {
		t.Fatalf("config lacks %q:\n%s", want, b)
	}
	if err := VerifyHostAccess(string(b), access); err != nil {
		t.Fatalf("the written config fails its own start check: %v", err)
	}
}
