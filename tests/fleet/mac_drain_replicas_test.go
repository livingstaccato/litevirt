package fleet

import (
	"context"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// A cold drain between nodes with independent replicas: the target's copy of
// the VM row arrives by replication, and it carries the new host and the new
// owner epoch together — the epoch the source's marker names, read from the
// transfer the source wrote. The drain's start is honoured on the target with
// no drain journal in its replica (hidden for the call, as replication lag
// would leave it) while a holder of the guest's MAC appeared after the
// preflight: the guest runs on the target.
//
// Mutation: have the source send the epoch from before the transfer — the
// marker no longer matches the target's row, the start is refused for the
// shared MAC, and the guest is left stopped: red.
func TestFleet_MAC_DrainResumeEpochArrivesWithTheRowOnIndependentReplicas(t *testing.T) {
	const dup = "52:54:00:7a:06:01"
	sc := newColdStoppedScenarioWith(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 93})
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
	before, err := corrosion.GetVM(ctx, sc.src.DB, "os1")
	if err != nil || before == nil {
		t.Fatalf("os1 on %s: %v", sc.src.Name, err)
	}
	sc.dst.Server.SetBridgeEnsure(func(string) error { return nil })

	var marker, epoch []string
	var rowHost string
	var rowEpoch int64 = -1
	sc.dst.HookUnary("StartVM", func(hctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		if md, ok := metadata.FromIncomingContext(hctx); ok {
			marker = md.Get(grpcapi.DrainResumeFromMDKey)
			epoch = md.Get(grpcapi.DrainResumeEpochMDKey)
		}
		if vm, _ := corrosion.GetVM(ctx, sc.dst.DB, "os1"); vm != nil {
			rowHost, rowEpoch = vm.HostName, vm.OwnerEpoch
		}
		// A holder of os1's MAC appears after the preflight.
		if err := corrosion.InsertVM(ctx, sc.dst.DB, corrosion.VMRecord{Name: "late", HostName: sc.dst.Name, State: "running"},
			[]corrosion.InterfaceRecord{{VMName: "late", NetworkName: "lan", MAC: dup}}, nil); err != nil {
			t.Error(err)
		}
		// The drain journal has not reached the target (this replica only).
		hide := `UPDATE operations SET desired_ref = desired_ref || '#lag' WHERE operation_kind = ? AND resource_id = 'os1'`
		show := `UPDATE operations SET desired_ref = replace(desired_ref, '#lag', '') WHERE operation_kind = ? AND resource_id = 'os1'`
		if err := localExec(ctx, sc.dst.DB, hide, string(corrosion.OpDrainColdMove)); err != nil {
			t.Error(err)
		}
		defer func() {
			if err := localExec(ctx, sc.dst.DB, show, string(corrosion.OpDrainColdMove)); err != nil {
				t.Error(err)
			}
		}()
		if open, _ := corrosion.DrainColdMoveOpenTo(ctx, sc.dst.DB, "os1", sc.dst.Name); open {
			t.Error("premise: the drain journal is visible on the target")
		}
		return handler(hctx, req)
	})

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if rowHost != sc.dst.Name || rowEpoch != before.OwnerEpoch+1 {
		t.Fatalf("the target's replicated row at its StartVM: host %q epoch %d, want host %q epoch %d (the transfer's, together)",
			rowHost, rowEpoch, sc.dst.Name, before.OwnerEpoch+1)
	}
	if len(marker) != 1 || marker[0] != sc.src.Name || len(epoch) != 1 || epoch[0] != strconv.FormatInt(rowEpoch, 10) {
		t.Fatalf("the marker = %v epoch %v, want [%s] [%d]", marker, epoch, sc.src.Name, rowEpoch)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done with no error", p)
	}
	if active, _ := sc.dst.Virt.DomainIsActive("os1"); !active {
		t.Fatalf("os1, running before the drain, is not running on %s: left stopped", sc.dst.Name)
	}
}
