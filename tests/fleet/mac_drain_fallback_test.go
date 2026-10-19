package fleet

import (
	"context"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// Independent replicas. A cold drain moves os1 to the target and starts it;
// the move's terminal step has not reached the target (held back in its
// replica), so the target still sees the move open. Another VM there holds
// os1's MAC.
//
//   - the move's own handoff (at the journaled epoch + 1, stopped, no stop
//     intent) still resumes on an ordinary unmarked start;
//   - after an operator stops os1, an unmarked start and a replay of the
//     move's marker are both refused for the shared MAC, and os1 stays
//     stopped;
//   - at a later placement on the target (epoch + 3), the same.
//
// Mutation: the journal fallback ignores the VM's epoch and stop intent (the
// e4c38889e code) — the operator-stopped and later-placement starts go
// through: red.
func TestFleet_MAC_AnOldOpenDrainExemptsNoLaterStart(t *testing.T) {
	const dup = "52:54:00:7a:07:01"
	sc := newColdStoppedScenarioWith(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 97})
	ctx := context.Background()
	if err := sc.src.Virt.StartDomain("os1"); err != nil {
		t.Fatalf("start os1's domain: %v", err)
	}
	if err := corrosion.UpdateVMState(ctx, sc.src.DB, "os1", "running", ""); err != nil {
		t.Fatalf("record os1 running: %v", err)
	}
	if err := corrosion.InsertInterface(ctx, sc.src.DB, corrosion.InterfaceRecord{VMName: "os1", NetworkName: "lan", MAC: dup}); err != nil {
		t.Fatal(err)
	}
	sc.c.WaitConverged(t, convergeTimeout)
	journaled, err := corrosion.GetVM(ctx, sc.src.DB, "os1")
	if err != nil || journaled == nil {
		t.Fatalf("os1: %v", err)
	}
	sc.dst.Server.SetBridgeEnsure(func(string) error { return nil })
	if progress, err := sc.drain(t); err != nil || progress["os1"] == nil || progress["os1"].Status != "done" {
		t.Fatalf("drain: %v (%+v)", err, progress["os1"])
	}
	sc.c.WaitConverged(t, convergeTimeout)

	// The move's terminal step is held back from the target's replica.
	if err := localExec(ctx, sc.dst.DB, `DELETE FROM operation_steps WHERE step_name = ? AND operation_id IN
		(SELECT id FROM operations WHERE operation_kind = ? AND resource_id = 'os1')`,
		corrosion.OpStepCompleted, string(corrosion.OpDrainColdMove)); err != nil {
		t.Fatal(err)
	}
	if open, err := corrosion.DrainColdMoveOpenTo(ctx, sc.dst.DB, "os1", sc.dst.Name); err != nil || !open {
		t.Fatalf("premise: the target sees the old move open (%v, %v)", open, err)
	}
	// Another VM on the target holds os1's MAC.
	if err := localExec(ctx, sc.dst.DB, `INSERT INTO vms (name, host_name, state, spec, created_at, updated_at) VALUES ('late', ?, 'running', '{}', 't', 't')`, sc.dst.Name); err != nil {
		t.Fatal(err)
	}
	if err := localExec(ctx, sc.dst.DB, `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at) VALUES ('late', 'lan', 0, ?, 't')`, dup); err != nil {
		t.Fatal(err)
	}

	cl := sc.c.SelfClient(sc.dst)
	peer := sc.c.PeerClient(sc.src, sc.dst)
	markerAt := func(epoch int64) context.Context {
		return metadata.AppendToOutgoingContext(ctx, grpcapi.DrainResumeFromMDKey, sc.src.Name,
			grpcapi.DrainResumeEpochMDKey, strconv.FormatInt(epoch, 10))
	}
	stopOS1 := func(detail string) {
		t.Helper()
		_ = sc.dst.Virt.DestroyDomain("os1")
		if err := localExec(ctx, sc.dst.DB, `UPDATE vms SET state = 'stopped', state_detail = ? WHERE name = 'os1'`, detail); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(what string, c pb.LiteVirtClient, cctx context.Context) {
		t.Helper()
		if _, err := c.StartVM(cctx, &pb.StartVMRequest{Name: "os1"}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: got %v, want the shared-MAC refusal", what, err)
		}
		if active, _ := sc.dst.Virt.DomainIsActive("os1"); active {
			t.Errorf("%s: os1 was started", what)
		}
	}

	// The move's own handoff: an ordinary unmarked start resumes it.
	stopOS1("")
	if vm, _ := corrosion.GetVM(ctx, sc.dst.DB, "os1"); vm == nil || vm.OwnerEpoch != journaled.OwnerEpoch+1 || vm.HostName != sc.dst.Name {
		t.Fatalf("premise: os1 on %s at the handoff's epoch %d: %+v", sc.dst.Name, journaled.OwnerEpoch+1, vm)
	}
	if _, err := cl.StartVM(ctx, &pb.StartVMRequest{Name: "os1"}); err != nil {
		t.Fatalf("the move's own handoff, unmarked: %v", err)
	}

	// An operator's stop since.
	stopOS1("operator-stop")
	refused("operator-stopped, unmarked", cl, ctx)
	refused("operator-stopped, the move's marker replayed", peer, markerAt(journaled.OwnerEpoch+1))

	// A later placement on the target.
	stopOS1("")
	if err := localExec(ctx, sc.dst.DB, `UPDATE vms SET vm_owner_epoch = vm_owner_epoch + 2 WHERE name = 'os1'`); err != nil {
		t.Fatal(err)
	}
	refused("a later placement, unmarked", cl, ctx)
	refused("a later placement, the move's marker replayed", peer, markerAt(journaled.OwnerEpoch+1))
}
