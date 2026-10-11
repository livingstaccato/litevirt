package lxc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// m-1. On NFSv3 two mounts of DIFFERENT exports of one server filesystem can
// share a superblock, and each mount's root reads "/" in mountinfo until a
// lookup splices it, so the root column cannot tell them apart and a verdict
// on it would depend on the dentry cache. Their identity is the export path
// the mount names (srv:/export/share), which does not change: a share beside
// the pool's export passes, a share inside it is refused, and the verdict is
// the same whether or not the kernel has spliced the root.
func TestDeniedTreeByIdentity_NFSSharedSuperblockIsDeterministic(t *testing.T) {
	root, access := hostTree(t)
	_ = os.MkdirAll(filepath.Join(root, "allowed", "share", "x"), 0o755)
	src := []Mount{{HostPath: filepath.Join(root, "allowed", "share", "x"), ContainerPath: "/m"}}
	access.DenyFunc = func() ([]string, error) { return []string{"/srv/pools"}, nil }
	for _, shareRoot := range []string{"/", "/share"} {
		withMountinfo(t, root,
			"20 1 8:1 / / rw - ext4 /dev/sda1 rw",
			"41 20 0:50 / /srv/pools rw - nfs srv:/export/pools rw",
			"42 20 0:50 "+shareRoot+" ROOT/allowed/share rw - nfs srv:/export/share rw",
		)
		if _, _, err := ResolveHostAccess(src, nil, access); err != nil {
			t.Errorf("share root %q: a share beside the pool's export was refused: %v", shareRoot, err)
		}
		withMountinfo(t, root,
			"20 1 8:1 / / rw - ext4 /dev/sda1 rw",
			"41 20 0:50 / /srv/pools rw - nfs srv:/export rw",
			"42 20 0:50 "+shareRoot+" ROOT/allowed/share rw - nfs srv:/export/share rw",
		)
		if _, _, err := ResolveHostAccess(src, nil, access); err == nil {
			t.Errorf("share root %q: a share inside the pool's export was allowed", shareRoot)
		}
	}
	// A mount whose source names no export path is ambiguous: identity is not
	// used for it (not even beside a pool on the server's whole filesystem),
	// and the resolved-path check decides alone.
	withMountinfo(t, root,
		"20 1 8:1 / / rw - ext4 /dev/sda1 rw",
		"41 20 0:50 / /srv/pools rw - nfs srv:/ rw",
		"42 20 0:50 / ROOT/allowed/share rw - nfs share-without-a-path rw",
	)
	if _, _, err := ResolveHostAccess(src, nil, access); err != nil {
		t.Errorf("an ambiguous NFS identity refused a source the path check passes: %v", err)
	}
}

// m-2. A refresh that cannot judge a container's grant now — a read or
// lookup failed — keeps the policy it last wrote, so an in-container reboot
// in that minute is not stopped over a transient error. A definite refusal
// (the prefix withdrawn) still empties it.
func TestRefreshHookPolicies_TransientErrorKeepsTheLastPolicy(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	if err := r.SetHostAccess("c1", []Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/srv"}}, nil); err != nil {
		t.Fatal(err)
	}
	r.HostAccess.DenyFunc = func() ([]string, error) { return nil, errors.New("database is locked") }
	_ = r.RefreshHookPolicies()
	if p, err := readHookPolicy("c1"); err != nil || len(p.Mounts) != 1 {
		t.Fatalf("a store list that could not be read revoked c1's mount: policy %+v (%v)", p, err)
	}
	r.HostAccess.DenyFunc = nil
	r.HostAccess.MountPaths = nil
	_ = r.RefreshHookPolicies()
	if p, err := readHookPolicy("c1"); err != nil || len(p.Mounts) != 0 {
		t.Fatalf("a withdrawn prefix left c1's mount in its policy: %+v (%v)", p, err)
	}
}

// m-5. A container whose lock is held (a start judging a device on a dead
// iSCSI LUN, say) is skipped by the refresh, which goes on to every other
// container; it is refreshed at the next run.
func TestRefreshHookPolicies_SkipsAContainerWhoseLockIsHeld(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	m := []Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/srv"}}
	for _, n := range []string{"c1", "c2"} {
		containerDir(t, r, n, "lxc.uts.name = "+n+"\n")
		if err := r.SetHostAccess(n, m, nil); err != nil {
			t.Fatal(err)
		}
	}
	release := r.lockHostAccess("c1")
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	r.HostAccess.MountPaths = nil
	done := make(chan error, 1)
	go func() { done <- r.RefreshHookPolicies() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh stalled behind one container's held lock")
	}
	if p, _ := readHookPolicy("c2"); len(p.Mounts) != 0 {
		t.Errorf("c2 was not refreshed while c1's lock was held: %+v", p)
	}
	if p, _ := readHookPolicy("c1"); len(p.Mounts) != 1 {
		t.Errorf("c1's policy was rewritten while its lock was held: %+v", p)
	}
	release()
	released = true
	if err := r.RefreshHookPolicies(); err != nil {
		t.Fatal(err)
	}
	if p, _ := readHookPolicy("c1"); len(p.Mounts) != 0 {
		t.Errorf("c1 was not refreshed once its lock was free: %+v", p)
	}
}

// m-6. A bind_mount_paths prefix on a filesystem that also holds a protected
// tree (data_dir mounted from the same disk) loaded before filesystem
// identity was checked, so it still loads: the overlap is reported, for a
// warning and a health condition, and a mount source inside the protected
// tree is still refused when it is resolved.
func TestValidateHostAccess_IdentityOverlapWarnsAndLoads(t *testing.T) {
	root, _ := hostTree(t)
	withMountinfo(t, root,
		"20 1 8:1 / / rw - ext4 /dev/sda1 rw",
		"30 20 8:2 / /var/lib/litevirt rw - ext4 /dev/sdb1 rw",
		"31 20 8:2 / ROOT/allowed rw - ext4 /dev/sdb1 rw",
	)
	a := HostAccess{MountPaths: []string{filepath.Join(root, "allowed")}, Deny: []string{"/var/lib/litevirt"}, HookBinary: "/opt/lv/litevirt"}
	if err := ValidateHostAccess(a); err != nil {
		t.Fatalf("a prefix that loaded before identity was checked now refuses to load: %v", err)
	}
	over := HostAccessOverlaps(a)
	if len(over) != 1 || !strings.Contains(over[0], filepath.Join(root, "allowed")) || !strings.Contains(over[0], "/var/lib/litevirt") {
		t.Errorf("overlaps = %q; want the prefix and the protected tree it shares a filesystem with", over)
	}
	if _, _, err := ResolveHostAccess([]Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/m"}}, nil, a); err == nil {
		t.Error("a source inside the protected tree, reached through the overlapping prefix, was allowed")
	}
	// A path-level overlap is still refused at load, as before.
	if err := ValidateHostAccess(HostAccess{MountPaths: []string{"/var/lib"}}); err == nil {
		t.Error("a prefix that contains /var/lib/litevirt by path loaded")
	}
}

// R4-I1. The NICs a config configures that litevirt itself renders — a veth
// on a bridge — in index order; a host NIC moved in (phys), a NIC on the
// host's interface (macvlan), a routed veth or an empty namespace are not.
func TestBridgeNICs(t *testing.T) {
	cfg := strings.Join([]string{
		"lxc.uts.name = c1",
		"lxc.net.0.type = veth",
		"lxc.net.0.link = br0",
		"lxc.net.0.flags = up",
		"lxc.net.0.name = eth0",
		"lxc.net.0.hwaddr = 02:00:00:00:00:01",
		"lxc.net.0.veth.pair = lvc0",
		"lxc.net.0.ipv4.address = 10.0.0.5/24",
		"lxc.net.0.ipv4.gateway = 10.0.0.1",
		"lxc.net.1.type = phys",
		"lxc.net.1.link = eth9",
		"lxc.net.2.type = veth",
		"lxc.net.2.veth.mode = router",
		"lxc.net.2.link = br0",
		"lxc.net.3.type = macvlan",
		"lxc.net.3.link = bond0",
		"lxc.net.10.type = veth",
		"lxc.net.10.link = br1",
		"lxc.net.4.type = none",
	}, "\n")
	got := BridgeNICs(cfg)
	want := []NetworkAttach{
		{Name: "eth0", Bridge: "br0", MAC: "02:00:00:00:00:01", Veth: "lvc0", IP: "10.0.0.5/24", Gateway: "10.0.0.1"},
		{Bridge: "br1"},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("BridgeNICs = %+v; want %+v", got, want)
	}
}
