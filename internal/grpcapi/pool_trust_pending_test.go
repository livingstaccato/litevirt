package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
	"github.com/litevirt/litevirt/internal/storage"
)

// pendingNFSFixture is an upgraded host whose nfs pool (target outside the
// data directory) held a disk of its VM, but whose export was not mounted at
// the adoption — an upgrade together with a reboot — so it is pending.
type pendingNFSFixture struct {
	s       *Server
	target  string
	disk    string
	mounts  []string
	unmount []string
	// export is what the mounted export holds: file name -> content.
	export  map[string][]byte
	failNow bool
}

func newPendingNFSFixture(t *testing.T) *pendingNFSFixture {
	t.Helper()
	s, _ := provableCreateServer(t)
	s.pkiDir = t.TempDir()
	ctx := context.Background()
	f := &pendingNFSFixture{s: s, target: filepath.Join(t.TempDir(), "nfsext")}
	f.disk = filepath.Join(f.target, "vm3-root.qcow2")
	if err := os.MkdirAll(f.target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "nfsext", Driver: "nfs", Source: "nas:/export/ext", Target: f.target,
		Options: map[string]string{"options": "vers=4.2,hard"}, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm3", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm3", DiskName: "root", HostName: s.hostName, Path: f.disk, StorageType: "nfs", StorageVolume: "nfsext"}}); err != nil {
		t.Fatal(err)
	}
	pt, err := pooltrust.Open(s.dataDir, s.pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pt.AdoptOnUpgrade(ctx, s.db, s.hostName); err != nil {
		t.Fatal(err)
	}
	if _, ok := pt.PendingNFS()["nfsext"]; !ok {
		t.Fatalf("the unmounted nfs pool is not pending: %v", pt.PendingNFS())
	}
	s.SetPoolTrust(pt)
	qcow := append([]byte{'Q', 'F', 'I', 0xfb}, make([]byte, 508)...)
	f.export = map[string][]byte{"vm3-root.qcow2": qcow}
	prevM, prevU := nfsAdoptionMount, nfsAdoptionUnmount
	t.Cleanup(func() { nfsAdoptionMount, nfsAdoptionUnmount = prevM, prevU })
	nfsAdoptionMount = func(_ context.Context, dataDir string, cfg storage.Config) error {
		dir := storage.NFSPoolMountDir(dataDir, cfg)
		f.mounts = append(f.mounts, dir)
		if f.failNow {
			return errors.New("mount: server not answering")
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		for n, b := range f.export {
			if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	nfsAdoptionUnmount = func(_ context.Context, dir string) error {
		f.unmount = append(f.unmount, dir)
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
		return nil
	}
	return f
}

// (re-review rr2 2) An nfs pool held at the upgrade because its export was
// not mounted is judged once more on the first successful mount: mounted at a
// staging point in mounts/ — never at the target the untrusted row names —
// its export holds this host's VM disk at the recorded name, so it is
// adopted. A failed mount is retried on the next pass; after the judgement it
// is never mounted for adoption again.
//
// Mutations: do not resolve the pending entry after judging — the second pass
// mounts again, red; mount at the row's target — red; adopt without the
// evidence (ResolvePending with true) — the empty-export case is adopted, red.
func TestPoolTrust_APendingNFSPoolIsAdoptedOnItsFirstMount(t *testing.T) {
	f := newPendingNFSFixture(t)
	ctx := context.Background()
	f.failNow = true
	f.s.ReconcileNFSMounts(ctx)
	if _, ok := f.s.PoolTrust().PendingNFS()["nfsext"]; !ok || len(f.mounts) != 1 {
		t.Fatalf("after a failed mount: pending=%v mounts=%v, want still pending after one try", f.s.PoolTrust().PendingNFS(), f.mounts)
	}
	f.failNow = false
	f.s.ReconcileNFSMounts(ctx)
	if e, ok := f.s.PoolTrust().Entry("nfsext"); !ok || e.How != pooltrust.HowUpgrade {
		t.Fatalf("the pending nfs pool was not adopted on its first mount: %+v %t", e, ok)
	}
	for _, d := range f.mounts {
		if filepath.Clean(d) == filepath.Clean(f.target) || filepath.Dir(d) != filepath.Join(f.s.dataDir, "mounts") {
			t.Fatalf("mounted for adoption at %s, want a staging point in <data_dir>/mounts", d)
		}
	}
	if len(f.unmount) != 1 {
		t.Fatalf("staging unmounts = %v, want one", f.unmount)
	}
	if len(f.s.PoolTrust().PendingNFS()) != 0 {
		t.Fatalf("still pending after the judgement: %v", f.s.PoolTrust().PendingNFS())
	}
	n := len(f.mounts)
	f.s.ReconcileNFSMounts(ctx)
	if len(f.mounts) != n {
		t.Fatal("mounted for adoption again after the judgement")
	}
	// A restart keeps it judged.
	pt, err := pooltrust.Open(f.s.dataDir, f.s.pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt.PendingNFS()) != 0 {
		t.Fatal("the pending entry came back after a restart")
	}
}

// The first mount shows none of this host's disks: the pool is held for good,
// judged exactly once.
func TestPoolTrust_APendingNFSPoolWithoutEvidenceIsHeldOnce(t *testing.T) {
	f := newPendingNFSFixture(t)
	ctx := context.Background()
	f.export = map[string][]byte{"other.qcow2": f.export["vm3-root.qcow2"]}
	f.s.ReconcileNFSMounts(ctx)
	if _, ok := f.s.PoolTrust().Entry("nfsext"); ok {
		t.Fatal("a pending nfs pool whose export holds none of this host's disks was adopted")
	}
	if len(f.s.PoolTrust().PendingNFS()) != 0 || len(f.mounts) != 1 {
		t.Fatalf("pending=%v mounts=%v, want judged once", f.s.PoolTrust().PendingNFS(), f.mounts)
	}
	f.s.ReconcileNFSMounts(ctx)
	if len(f.mounts) != 1 {
		t.Fatal("judged again")
	}
}

// A pending row that changed meanwhile (a forger retargeting it) is dropped,
// never mounted for adoption.
func TestPoolTrust_AChangedPendingNFSRowIsDropped(t *testing.T) {
	f := newPendingNFSFixture(t)
	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, f.s.db, corrosion.StoragePoolRecord{
		HostName: f.s.hostName, Name: "nfsext", Driver: "nfs", Source: "attacker:/x", Target: f.target, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	f.s.ReconcileNFSMounts(ctx)
	if len(f.mounts) != 0 || len(f.s.PoolTrust().PendingNFS()) != 0 {
		t.Fatalf("mounts=%v pending=%v, want dropped without a mount", f.mounts, f.s.PoolTrust().PendingNFS())
	}
}
