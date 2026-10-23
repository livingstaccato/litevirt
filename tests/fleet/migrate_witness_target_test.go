// Fleet scenarios for a migration whose target is a witness.
//
// A witness is `active` and answers every request, but it runs no workloads:
// the execution gate (local_not_active_worker) refuses a start or a move on it.
// A cold `lv migrate <vm> <witness> --cold --with-storage` used to be accepted -
// nothing checked the target's role - and left the VM on a host where it could
// neither start nor be moved off (rc5 lab 1 drill, node-6).
//
// The gate is ENFORCED here (enforceGate), as it is on a real cluster: without
// it the harness fails open and a stranded VM would start anywhere.

package fleet

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// enforceGateWithWitness is enforceGate for a cluster that has a witness: the
// witness's own ExecutionGate is not asked to pass (it never does, which is
// the point), every other node's must.
func enforceGateWithWitness(t *testing.T, c *Cluster, witness *Node) {
	t.Helper()
	ctx := context.Background()
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		peers := map[string]bool{}
		for _, o := range c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.SplitBrainGateV1) {
			t.Fatalf("%s: split_brain_gate_v1 did not latch", n.Name)
		}
		if n == witness {
			if g := gates[n.Name].ExecutionGate(ctx); g.OK {
				t.Fatalf("%s: the witness's ExecutionGate admitted it; the scenario is not a witness", n.Name)
			}
			continue
		}
		if g := gates[n.Name].ExecutionGate(ctx); !g.OK {
			t.Fatalf("%s: ExecutionGate refused an active worker with quorum: %s", n.Name, g.Reason)
		}
	}
}

func (sc *coldStoppedScenario) makeWitness(t *testing.T, n *Node) {
	t.Helper()
	// Through the RPC, so the write replicates in its ledgered shape. It is
	// refused for a host that still holds VMs, so only an empty host is made one.
	if _, err := sc.c.SelfClient(sc.src).ConfigureHost(context.Background(), &pb.ConfigureHostRequest{Name: n.Name, Role: "witness"}); err != nil {
		t.Fatalf("make %s a witness: %v", n.Name, err)
	}
	sc.c.WaitConverged(t, convergeTimeout)
}

func (sc *coldStoppedScenario) migrateFrom(t *testing.T, from *Node, to *Node, strat pb.MigrateStrategy) error {
	t.Helper()
	st, err := sc.c.SelfClient(from).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "os1", TargetHost: to.Name, Strategy: strat, WithStorage: strat == pb.MigrateStrategy_MIGRATE_COLD,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

// The lab sequence: a cold migration with storage to a witness. It is refused
// at the request, naming the host and its role, before the disk is copied or a
// domain is defined: the VM stays on its source, with its disk and its domain,
// and the witness holds nothing of it.
//
// Red on f04bc6725: the move is accepted and the VM is stranded.
//
// Mutations: drop the role check in migrateOwnedVM (nonWorkloadTargetError
// back to the state check alone) - the move goes through and this goes red.
func TestFleet_AColdMigrationToAWitnessIsRefusedBeforeAnythingMoves(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeWitness(t, sc.dst)
	enforceGateWithWitness(t, sc.c, sc.dst)

	err := sc.migrateFrom(t, sc.src, sc.dst, pb.MigrateStrategy_MIGRATE_COLD)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), sc.dst.Name) || !strings.Contains(err.Error(), "witness") {
		t.Fatalf("cold migrate to the witness %s: got %v, want FailedPrecondition naming the host and its role", sc.dst.Name, err)
	}

	if vm := sc.vm(t); vm.HostName != sc.src.Name || vm.State != "stopped" {
		t.Fatalf("VM row = host %s state %s, want host %s state stopped", vm.HostName, vm.State, sc.src.Name)
	}
	for name, host := range sc.diskHosts(t) {
		if host != sc.src.Name {
			t.Errorf("disk %s row names %s, want %s", name, host, sc.src.Name)
		}
	}
	if got, err := os.ReadFile(sc.file(sc.src, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("the source's disk is not intact (err %v)", err)
	}
	if _, err := os.Stat(sc.file(sc.dst, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("the witness holds a copy of the disk (stat: %v): the refusal came after the copy", err)
	}
	if sc.dst.Virt.DomainExists("os1") {
		t.Errorf("a domain was defined on the witness")
	}
	if !sc.src.Virt.DomainExists("os1") {
		t.Errorf("the source lost its domain")
	}
	// The VM is not stranded: it starts where it is.
	if _, err := sc.c.SelfClient(sc.src).StartVM(context.Background(), &pb.StartVMRequest{Name: "os1"}); err != nil {
		t.Errorf("start on the source after the refused move: %v", err)
	}
}

// A live migration of a running VM to a witness is refused the same way.
func TestFleet_ALiveMigrationToAWitnessIsRefused(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeWitness(t, sc.dst)
	sc.makeRunning(t)
	enforceGateWithWitness(t, sc.c, sc.dst)

	err := sc.migrateFrom(t, sc.src, sc.dst, pb.MigrateStrategy_MIGRATE_LIVE)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "witness") {
		t.Fatalf("live migrate to the witness: got %v, want FailedPrecondition naming the role", err)
	}
	sc.assertRunningOnSource(t)
}

// A VM already stranded on a witness (accepted by an older source, or left
// there by a role change) can be moved off: the witness admits a migration
// AWAY from it, though not a start, and the refusal of the start says how.
//
// The sequence is the lab's: the VM reaches the host while it is a worker, the
// host becomes a witness (the role is replicated configuration; written here
// directly, since ConfigureHost refuses a host that holds VMs), `lv start` is
// refused local_not_active_worker, and `lv migrate <vm> <worker> --cold` from
// the witness then succeeds with the disk intact, after which the VM starts.
//
// Red on f04bc6725: the move off is refused local_not_active_worker.
//
// Mutations: drop the witness branch of health.localHostIsEvacuatingWorker -
// the move off is refused and this goes red; drop the witness hint in
// gateRefusal - the start refusal says nothing of the way out and goes red.
func TestFleet_AVMStrandedOnAWitnessCanBeMovedOff(t *testing.T) {
	sc := newColdStoppedScenario(t)
	a, w := sc.src, sc.dst
	// The disk's directory is a disk-artifact root on both hosts, so the VM
	// can move there and back.
	for _, n := range []*Node{a, w} {
		n.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"local-dir": {Driver: "dir", Target: filepath.Dir(sc.disk)}})
	}
	if err := sc.migrateColdBetween(a, w); err != nil {
		t.Fatalf("move to %s while it is a worker: %v", w.Name, err)
	}
	ctx := context.Background()
	if err := a.DB.Execute(ctx, `UPDATE hosts SET role = 'witness', updated_at = ? WHERE name = ?`, a.DB.NowWallTS(), w.Name); err != nil {
		t.Fatalf("make %s a witness: %v", w.Name, err)
	}
	enforceGateWithWitness(t, sc.c, sc.dst)

	_, err := sc.c.SelfClient(w).StartVM(ctx, &pb.StartVMRequest{Name: "os1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "local_not_active_worker") {
		t.Fatalf("start on the witness: got %v, want the local_not_active_worker refusal", err)
	}
	if !strings.Contains(err.Error(), "witness") || !strings.Contains(err.Error(), "lv migrate") {
		t.Errorf("the refusal %q does not say the host is a witness or how to move the VM off", err)
	}

	if err := sc.migrateFrom(t, w, a, pb.MigrateStrategy_MIGRATE_COLD); err != nil {
		t.Fatalf("migrate off the witness: %v", err)
	}
	vm, gerr := corrosion.GetVM(ctx, a.DB, "os1")
	if gerr != nil || vm == nil || vm.HostName != a.Name || vm.State != "stopped" {
		t.Fatalf("after the move off, VM = %+v (err %v), want it stopped on %s", vm, gerr, a.Name)
	}
	if got, err := os.ReadFile(sc.file(a, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("the disk did not come back intact (err %v)", err)
	}
	if _, err := os.Stat(sc.file(w, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("the witness still holds the disk (stat: %v)", err)
	}
	if _, err := sc.c.SelfClient(a).StartVM(ctx, &pb.StartVMRequest{Name: "os1"}); err != nil {
		t.Errorf("start on the worker after the move off: %v", err)
	}
}

// A host that is draining is no target either: it is `not active`, and the
// request says so (the same helper that refuses a witness).
func TestFleet_AColdMigrationToADrainingHostIsRefused(t *testing.T) {
	sc := newColdStoppedScenario(t)
	if err := corrosion.UpdateHostState(context.Background(), sc.src.DB, sc.dst.Name, "draining"); err != nil {
		t.Fatal(err)
	}
	err := sc.migrateFrom(t, sc.src, sc.dst, pb.MigrateStrategy_MIGRATE_COLD)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "not active") || !strings.Contains(err.Error(), sc.dst.Name) {
		t.Fatalf("cold migrate to a draining host: got %v, want FailedPrecondition 'not active' naming it", err)
	}
}
