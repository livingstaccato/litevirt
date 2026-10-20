package fleet

// Before failover_scope_v1 latches, no placement generation is kept, and a
// failover's reschedule moves a VM back to an earlier owner without changing
// its owner or epoch: the stub record a target made for an earlier move then
// matches again. Such a record is never honoured (round-13 coordinator
// ruling): every file at a disk path reads as one the target did not create,
// and a copy over it is refused naming it.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// newPartitionStubABA is liveStubABA on independent replicas, with the
// cluster-policy gate (the failover_scope_v1 latch) as given on every node.
func newPartitionStubABA(t *testing.T, latched bool) *liveStubABA {
	t.Helper()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	t.Cleanup(c.Stop)
	sc := &liveStubABA{c: c, a: c.Nodes[0], b: c.Nodes[1]}
	pool := filepath.Join(c.tmpRoot, "pool")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		n.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"local-dir": {Driver: "dir", Target: pool}})
		l := latched
		n.DB.SetClusterPolicyGate(func() bool { return l })
	}
	sc.p = filepath.Join(pool, "pp1-root.qcow2")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), sc.a.DB, corrosion.VMRecord{
		Name: "pp1", HostName: sc.a.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pp1", DiskName: "root", HostName: sc.a.Name, Path: sc.p,
		SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatal(err)
	}
	sc.a.Virt.SetState("pp1", "running")
	c.WaitConverged(t, convergeTimeout)
	return sc
}

// partitionFailoverBack moves pp1 A→B live with its storage, partitions B
// off, puts pp1 back on A as failover's reschedule does (no epoch bump, and
// no generation while unlatched), and lets B rejoin.
func (sc *liveStubABA) partitionFailoverBack(t *testing.T) {
	t.Helper()
	if err := migrateWithStorageAt(t, sc.c, sc.a, "pp1", sc.b.Name); err != nil {
		t.Fatalf("A->B: %v", err)
	}
	sc.c.WaitConverged(t, convergeTimeout)
	sc.c.Isolate(sc.b)
	if err := corrosion.RescheduleVMHost(context.Background(), sc.a.DB, "pp1", sc.a.Name, "running"); err != nil {
		t.Fatalf("failover reschedule of pp1 to %s: %v", sc.a.Name, err)
	}
	sc.a.Virt.SetState("pp1", "running")
	sc.c.ClearLinkFaults()
	sc.c.WaitConverged(t, convergeTimeout)
	if vm, err := corrosion.GetVM(context.Background(), sc.b.DB, "pp1"); err != nil || vm == nil || vm.HostName != sc.a.Name {
		t.Fatalf("pp1 on %s's replica after it rejoined = %+v (%v), want on %s", sc.b.Name, vm, err, sc.a.Name)
	}
}

// Live A→B, B partitioned, failover back to A, B rejoins, then A→B onto a
// stray file at the disk path on B — all with failover_scope_v1 unlatched.
// The move is refused naming the file, and the file is untouched.
//
// Mutation: honour a record while the gate is closed (stubMark ignores the
// gate) — B reuses the stray as its own stub, red.
func TestFleet_UnlatchedAStubRecordIsNeverHonouredAfterAFailoverBack(t *testing.T) {
	sc := newPartitionStubABA(t, false)
	sc.partitionFailoverBack(t)
	sc.thirdMoveIsRefused(t)
}

// The latched control: the same failover back ends B's record (the
// reschedule advanced the placement generation), the move over the stray is
// refused, and with the stray moved aside the move goes ahead and moves back
// again.
func TestFleet_LatchedMovesAfterAFailoverBackStillWork(t *testing.T) {
	sc := newPartitionStubABA(t, true)
	sc.partitionFailoverBack(t)
	sc.thirdMoveIsRefused(t)
	if err := os.Rename(sc.p, sc.p+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := migrateWithStorageAt(t, sc.c, sc.a, "pp1", sc.b.Name); err != nil {
		t.Fatalf("A->B with the stray moved aside: %v", err)
	}
	sc.c.WaitConverged(t, convergeTimeout)
	if h := sc.host(t); h != sc.b.Name {
		t.Fatalf("pp1 after the move is on %s, want %s", h, sc.b.Name)
	}
	_ = os.Remove(sc.p) // separate filesystems in production
	sc.b.Virt.SetState("pp1", "running")
	if err := migrateWithStorageAt(t, sc.c, sc.b, "pp1", sc.a.Name); err != nil {
		t.Fatalf("B->A: %v", err)
	}
	sc.c.WaitConverged(t, convergeTimeout)
	if h := sc.host(t); h != sc.a.Name {
		t.Fatalf("pp1 after the move back is on %s, want %s", h, sc.a.Name)
	}
}
