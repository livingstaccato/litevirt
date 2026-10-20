package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// enforceSharedStorageFence makes s enforce the shared-storage fence, as a
// cluster made by lv host init does, with an execution gate that passes.
func enforceSharedStorageFence(s *Server) {
	s.enfSharedStorageFence.Store(true)
	s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.SharedStorageFenceV1: true}})
}

// R2-I1: with the shared-storage fence enforced, a promotion that arrives
// over peer transport without a proof — an operator's through another node,
// local-root lv — has had no fence verified here, so it gets the manual rule:
// an owner offline, in maintenance, or active (with --force) leaves the
// shared disk unattached.
//
// Mutation "enforced fence trusted without a proof" (fenceProven set from
// sharedStorageFenceActive alone) — red.
func TestPromote_AProoflessRelayedPromotionNeverReattachesWithoutAFencedOwner(t *testing.T) {
	for _, c := range []struct {
		owner string
		force bool
	}{{"offline", false}, {"maintenance", false}, {"offline", true}, {"maintenance", true}, {"active", true}} {
		s := testServer(t)
		enforceSharedStorageFence(s)
		nfsDisk := nfsPromoteVM(t, s, c.owner)
		ctx := relayedAdmin(t, s, "entry-node") // relayed by an entry node, or local-root
		stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
		err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: c.force, NoLocalize: true}, stream)
		if !c.force {
			// Without --force the split-brain guard refuses first: the
			// owner is not fenced or removed (ccguard review I2).
			if err == nil || !strings.Contains(err.Error(), "may still run on its host") {
				t.Fatalf("owner %s, force false: PromoteReplica = %v; want the split-brain refusal", c.owner, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("owner %s, force %v: PromoteReplica: %v", c.owner, c.force, err)
		}
		assertSharedUnattached(t, s, nfsDisk, "its owner dead-host is "+c.owner+", not fenced")
	}
}

// R2-I1: a relay the coordinator marked automated, without a verified fence,
// never reattaches — even with the owner recorded fenced (a best-effort SSH
// fence leaves a partitioned host's qemu writing).
//
// Mutation "automated mark ignored" (the executor drops req.Automated) — red.
func TestPromote_AnAutomatedRelayWithoutAVerifiedFenceNeverReattaches(t *testing.T) {
	s := testServer(t)
	nfsDisk := nfsPromoteVM(t, s, "fenced")
	ctx := relayedAdmin(t, s, "coordinator")
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Automated: true}, stream); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
	assertSharedUnattached(t, s, nfsDisk, "no proof-grade fence of dead-host was verified")
}

// R2-I1: a promotion carrying a proof whose fence this executor verified as
// proof-grade reattaches the shared disk as-is.
//
// Mutation "never reattach" (fenceProven never set) — red.
func TestPromote_AVerifiedProofGradeFenceReattachesTheSharedDisk(t *testing.T) {
	s := testServer(t)
	enforceSharedStorageFence(s)
	nfsDisk := nfsPromoteVM(t, s, "fenced")
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx, `INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail)
		VALUES ('ipmi1', 'dead-host', 'ipmi', 'fenced', ?, '')`, now); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "db")
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "db")
	src := pickReplicaSource(disks)
	recs, _ := listReplicaRecords(replicaPoolDirOfPool(t, s, "dr"), "", "db")
	var root string
	for _, r := range recs {
		if r.Disk == "root" {
			root = r.File
		}
	}
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Proof: &pb.RuntimeActionProof{
		Id: "p-fence", Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: "db",
		Coordinator: "coord", LeaseHolder: "coord", DestHost: s.hostName,
		FenceEpoch: corrosion.FenceEpochRef{Host: "dead-host", FenceID: "ipmi1", TS: now}.String(),
	}}
	if err := s.doPromoteLocal(peerCtxFor(t, s, "coord"), req, vm, src, "dr", root, false, func(*pb.PromoteReplicaProgress) error { return nil }); err != nil {
		t.Fatalf("doPromoteLocal with a proof-grade fence: %v", err)
	}
	if xml := s.virt.(*libvirtfake.Fake).DefinedXML("db"); !strings.Contains(xml, nfsDisk) {
		t.Errorf("a proven fence's shared disk was not reattached: %s", xml)
	}
	if r := diskRowsOf(t, s, "db")["data1"]; r.Path != nfsDisk {
		t.Errorf("data1 row = %+v, want it untouched", r)
	}
}

// R2-m1: the executor's shared-disk fence gate counts a disk shared by its
// pool's driver, as the reattach does: a promotion whose proof's fence is
// not proof-grade is refused for such a disk.
//
// Mutation "storage type only" (the gate uses VMHasWritableSharedDisk) — red.
func TestPromote_TheFenceGateSeesADiskSharedByItsPool(t *testing.T) {
	s := testServer(t)
	enforceSharedStorageFence(s)
	ctx := context.Background()
	poolDir := setPromoteVMRows(t, s, "db", []corrosion.DiskRecord{
		{DiskName: "data1", HostName: "dead-host", Path: "/nas/db-data1.qcow2", SizeBytes: 1 << 20, StorageType: "local", StorageVolume: "nas", TargetDev: "vdb", Bus: "virtio"},
	})
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{HostName: "dead-host", Name: "nas", Driver: "nfs", Source: "nas:/vm", State: "active"}); err != nil {
		t.Fatal(err)
	}
	root := seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	vm, _ := corrosion.GetVM(ctx, s.db, "db")
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "db")
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Proof: &pb.RuntimeActionProof{
		Id: "p-nofence", Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: "db",
		Coordinator: "coord", LeaseHolder: "coord", DestHost: s.hostName,
	}}
	err := s.doPromoteLocal(peerCtxFor(t, s, "coord"), req, vm, pickReplicaSource(disks), "dr", root, false, func(*pb.PromoteReplicaProgress) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "storage_unverified") {
		t.Fatalf("doPromoteLocal of a VM with a pool-shared disk and no proof-grade fence = %v, want storage_unverified", err)
	}
}

func replicaPoolDirOfPool(t *testing.T, s *Server, pool string) string {
	t.Helper()
	d, err := s.replicaPoolDir(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// relayedAdmin is a call that arrived over peer transport (an entry node's
// host certificate, or local-root) on behalf of an admin.
func relayedAdmin(t *testing.T, s *Server, cn string) context.Context {
	t.Helper()
	ctx := peerCtxFor(t, s, cn)
	ctx = context.WithValue(ctx, ctxKeyUsername, "admin")
	return context.WithValue(ctx, ctxKeyRole, "admin")
}

// R2-m2: on a retry under one proof, a disk's recorded live file is reused
// only when it was built from the replica chosen now; one built from another
// replica is left alone and a new live disk built beside it.
//
// Mutation "source ignored" (the recorded file is reused whatever replica it
// came from) — red.
func TestPromote_ARetryRebuildsADiskWhoseRecordedFileCameFromAnotherReplica(t *testing.T) {
	s := testServer(t)
	enforceSharedStorageFence(s) // a gate, for the carried proof
	ctx := context.Background()
	poolDir := setPromoteVM(t, s, "db", map[string]string{"data1": "local"})
	run := stamp(10 * time.Minute)
	root := seedReplica(t, poolDir, "", "db", "root", run, "raw", 1<<20)
	now := seedReplica(t, poolDir, "", "db", "data1", run, "raw", 1<<20)
	// An earlier attempt of this proof built data1 from another replica.
	stale := "db-promoted-data1-earlier.qcow2"
	if err := os.WriteFile(filepath.Join(poolDir, stale), []byte("built from another replica"), 0o600); err != nil {
		t.Fatal(err)
	}
	proof := &pb.RuntimeActionProof{
		Id: "p-retry", Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: "db",
		Coordinator: "coord", LeaseHolder: "coord", DestHost: s.hostName,
	}
	if err := corrosion.WriteActionProofValidated(ctx, s.db, proofFromPB(proof)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.AppendProofStep(ctx, s.db, "p-retry", builtStep("data1", stale, "data1-20200101-000000.raw")); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "db")
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "db")
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true, Proof: proof}
	if err := s.doPromoteLocal(peerCtxFor(t, s, "coord"), req, vm, pickReplicaSource(disks), "dr", root, false, func(*pb.PromoteReplicaProgress) error { return nil }); err != nil {
		t.Fatalf("doPromoteLocal: %v", err)
	}
	r := diskRowsOf(t, s, "db")["data1"]
	if filepath.Base(r.Path) == stale || r.HostName != s.hostName {
		t.Errorf("data1 = %+v: reused a file built from another replica than %s", r, now)
	}
	if b, err := os.ReadFile(filepath.Join(poolDir, stale)); err != nil || string(b) != "built from another replica" {
		t.Errorf("the earlier attempt's file was touched: %q, %v", b, err)
	}
}
