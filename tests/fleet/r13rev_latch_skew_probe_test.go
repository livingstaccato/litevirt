package fleet

// Reviewer probe (round 13): latch skew. B's failover_scope_v1 latch has formed
// (it records and honours stub records); A's has not yet (its host-changing
// writes advance no placement generation, failback.go placementGenStmts).
// A drives A->B live with storage, B is partitioned, A puts pp1 back on itself
// with the legacy reschedule (no epoch bump), B rejoins, then A->B onto a
// stray file at the disk path on B.

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

func TestR13Rev_LatchSkewAStubRecordIsHonouredAfterAFailoverBack(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	t.Cleanup(c.Stop)
	sc := &liveStubABA{c: c, a: c.Nodes[0], b: c.Nodes[1]}
	pool := filepath.Join(c.tmpRoot, "pool")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		n.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"local-dir": {Driver: "dir", Target: pool}})
	}
	sc.a.DB.SetClusterPolicyGate(func() bool { return false }) // A: latch not formed yet
	sc.b.DB.SetClusterPolicyGate(func() bool { return true })  // B: latch formed
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
	mark := func(n *Node) string {
		m, _, _ := corrosion.VMPlacementMark(context.Background(), n.DB, "pp1")
		return m
	}
	sc.partitionFailoverBack(t)
	t.Logf("mark on B after the failover back: %s", mark(sc.b))
	sc.thirdMoveIsRefused(t)
}
