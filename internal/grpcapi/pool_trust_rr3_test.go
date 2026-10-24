package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// rr3Host is an upgraded host (the adoption has run) with the forged nfs
// rows the re-review's probes used, written before the upgrade, and the
// mount command recorded.
func rr3Host(t *testing.T, rows ...corrosion.StoragePoolRecord) (*Server, *hostMounts) {
	t.Helper()
	s, _ := provableCreateServer(t)
	s.pkiDir = t.TempDir()
	ctx := context.Background()
	for _, r := range rows {
		r.HostName = s.hostName
		if r.State == "" {
			r.State = "active"
		}
		if err := corrosion.UpsertStoragePool(ctx, s.db, r); err != nil {
			t.Fatal(err)
		}
	}
	m := installHostMounts(t)
	pt, err := pooltrust.Open(s.dataDir, s.pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	a, err := pt.AdoptOnUpgrade(ctx, s.db, s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("adoption: adopted=%v held=%v", a.Adopted, a.Held)
	s.SetPoolTrust(pt)
	return s, m
}

// (re-review rr3 1, its probe TestRR3Probe_PendingStagingNameTraversal) A
// forged nfs row whose NAME holds "/" and "..", unmounted at the upgrade:
// the host mounts nothing for it and creates no directory anywhere, however
// many mount passes run.
//
// Mutation: bring back any mount of an untrusted row's export (judging it
// by mounting) — red.
func TestPoolTrust_ATraversalNamedNFSRowIsNeverMounted(t *testing.T) {
	probe, _ := provableCreateServer(t)
	depth := strings.Count(filepath.Clean(probe.dataDir), "/")
	name := "x/" + strings.Repeat("../", depth+2) + "tmp/rr3-polkit-rules.d-" + filepath.Base(t.TempDir())
	escaped := filepath.Join("/", "tmp", filepath.Base(name))
	s, m := rr3Host(t, corrosion.StoragePoolRecord{Name: name, Driver: "nfs", Source: "attacker:/x"})
	for i := 0; i < 5; i++ {
		s.ReconcileNFSMounts(context.Background())
	}
	if m.count() != 0 {
		t.Fatalf("%d mounts for a forged row", m.count())
	}
	if _, err := os.Lstat(escaped); err == nil {
		t.Fatalf("a directory was created at %s", escaped)
	}
	ents, _ := os.ReadDir(filepath.Join(s.dataDir, "mounts"))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".adopt-") {
			t.Fatalf("a staging point %s was created", e.Name())
		}
	}
}

// (re-review rr3 2, its probes …PendingStagingOptions, …PendingRetriesForever
// and …PendingUnmountFailureLeavesStage) Forged nfs rows with hostile
// options, or aimed at a blackhole, written after the upgrade: twenty mount
// passes run no mount at all, so there are no retries to bound, no options
// to constrain and no staging mount to leave behind. (A target-less nfs row
// that was already there at the upgrade is adopted — its mount point is the
// daemon's own mounts/ area, as rc6 mounted it — and is mounted there and
// nowhere else; one with a target outside is held and never mounted.)
//
// Mutation: as above — red.
func TestPoolTrust_ForgedNFSRowsCostTheMountLoopNothing(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "x")
	s, m := rr3Host(t,
		corrosion.StoragePoolRecord{Name: "preinarea", Driver: "nfs", Source: "nas:/pre"},
		corrosion.StoragePoolRecord{Name: "preoutside", Driver: "nfs", Source: "blackhole:/pre", Target: outside},
	)
	ctx := context.Background()
	for _, r := range []corrosion.StoragePoolRecord{
		{Name: "withopts", Driver: "nfs", Source: "attacker:/a", Options: map[string]string{"options": "hard,timeo=6000,retrans=100,rw,suid"}},
		{Name: "forgeda", Driver: "nfs", Source: "blackhole:/a"},
		{Name: "forgedb", Driver: "nfs", Source: "blackhole:/b", Target: filepath.Join(t.TempDir(), "y")},
	} {
		r.HostName, r.State = s.hostName, "active"
		if err := corrosion.UpsertStoragePool(ctx, s.db, r); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		s.ReconcileNFSMounts(ctx)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mounts != 1 {
		t.Fatalf("%d mounts in 20 passes, want only the pre-upgrade in-area pool's", m.mounts)
	}
	for dir, src := range m.dirs {
		if src != "nas:/pre" || filepath.Dir(dir) != filepath.Join(s.dataDir, "mounts") {
			t.Fatalf("mounted %s at %s", src, dir)
		}
	}
}

// (re-review rr3 3, its probe …PendingAdoptionFromForgedRowsOnly) Forged rows
// alone — an nfs pool whose target is outside the data dir, a vms and a
// vm_disks row of this host naming <target>/x.qcow2, and that file present
// with a qcow2 header, as if the attacker's export were mounted there at the
// upgrade — do not get the pool adopted: for nfs neither the header nor the
// rows are evidence. It stays untrusted and is never mounted.
//
// Mutation: accept the qcow2 evidence for an nfs pool outside mounts/ — red.
func TestPoolTrust_ForgedRowsDoNotAdoptAnNFSPoolOutsideMounts(t *testing.T) {
	target := filepath.Join(t.TempDir(), "etc-like", "50-local.d")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "x.qcow2"), append([]byte{'Q', 'F', 'I', 0xfb}, make([]byte, 60)...), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := provableCreateServer(t)
	s.pkiDir = t.TempDir()
	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "evil", Driver: "nfs", Source: "attacker:/evil", Target: target, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "ghost", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "ghost", DiskName: "root", HostName: s.hostName, Path: filepath.Join(target, "x.qcow2"), StorageType: "nfs", StorageVolume: "evil"}}); err != nil {
		t.Fatal(err)
	}
	m := installHostMounts(t)
	m.dirs[target] = "attacker:/evil" // mounted at the upgrade
	pt, err := pooltrust.Open(s.dataDir, s.pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pt.AdoptOnUpgrade(ctx, s.db, s.hostName); err != nil {
		t.Fatal(err)
	}
	s.SetPoolTrust(pt)
	if v := pt.Judge("evil", pooltrust.BindingOf("nfs", "attacker:/evil", target, nil)); v.Trusted {
		t.Fatalf("forged rows and an attacker-served qcow2 header adopted an nfs pool mounted at %s: %+v", target, v)
	}
	delete(m.dirs, target)
	s.ReconcileNFSMounts(ctx)
	if m.count() != 0 {
		t.Fatal("the held nfs pool was mounted")
	}
}
