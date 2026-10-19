package fleet

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
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
	moves, err := corrosion.ListDrainColdMoves(ctx, sc.dst.DB, sc.src.Name)
	if err != nil || len(moves) != 1 {
		t.Fatalf("premise: the old move on %s: %v %v", sc.dst.Name, moves, err)
	}
	markerAt := func(epoch int64) context.Context {
		return metadata.AppendToOutgoingContext(ctx, grpcapi.DrainResumeFromMDKey, sc.src.Name,
			grpcapi.DrainResumeEpochMDKey, strconv.FormatInt(epoch, 10), grpcapi.DrainResumeOpMDKey, moves[0].OperationID)
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

// Codex's schedule, on independent replicas. Drain m0 moves os1 A→B and
// starts it there; m0's terminal step is held back from B's replica, so B
// still sees m0 open with os1 at m0's epoch + 1. A later drain m1 of B to C
// passes its preflight, shuts os1 down (its row now names m1's stop), fails
// its copy, and fails to start os1 again on B: m1 is finished, os1 is
// stopped on B at the same epoch with m1's stop intent. B is undrained, the
// runtime recovers, and another VM on B takes os1's MAC. An ordinary
// unmarked start of os1 must be refused for the shared MAC: m1's stop is not
// m0's handoff.
//
// Mutation: accept any drain stop intent, not the open move's own (the
// 7bf74eb00 code) — the start goes through: red.
func TestFleet_MAC_AnOldOpenDrainDoesNotCoverALaterDrainsStop(t *testing.T) {
	const dup = "52:54:00:7a:08:01"
	sc := newColdStoppedScenarioWith(t, Options{Nodes: 3, IndependentReplicas: true, SharedDataDir: true, FaultSeed: 101})
	a, b, cNode := sc.src, sc.dst, sc.c.Nodes[2]
	ctx := context.Background()
	if err := a.Virt.StartDomain("os1"); err != nil {
		t.Fatalf("start os1's domain: %v", err)
	}
	if err := corrosion.UpdateVMState(ctx, a.DB, "os1", "running", ""); err != nil {
		t.Fatalf("record os1 running: %v", err)
	}
	if err := corrosion.InsertInterface(ctx, a.DB, corrosion.InterfaceRecord{VMName: "os1", NetworkName: "lan", MAC: dup}); err != nil {
		t.Fatal(err)
	}
	sc.c.WaitConverged(t, convergeTimeout)
	for _, n := range sc.c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	// C is out of the way for m0 (drained, holding nothing), so m0 lands on B.
	if _, err := drainHost(t, sc.c, cNode); err != nil {
		t.Fatalf("drain the empty %s: %v", cNode.Name, err)
	}
	sc.c.WaitConverged(t, convergeTimeout)

	// m0: A→B, and its terminal step held back from B.
	if progress, err := drainHost(t, sc.c, a); err != nil || progress["os1"] == nil || progress["os1"].Status != "done" || progress["os1"].TargetHost != b.Name {
		t.Fatalf("drain m0 of %s: %v (%+v)", a.Name, err, progress["os1"])
	}
	sc.c.WaitConverged(t, convergeTimeout)
	if err := localExec(ctx, b.DB, `DELETE FROM operation_steps WHERE step_name = ? AND operation_id IN
		(SELECT id FROM operations WHERE operation_kind = ? AND resource_id = 'os1' AND desired_ref = ?)`,
		corrosion.OpStepCompleted, string(corrosion.OpDrainColdMove), b.Name); err != nil {
		t.Fatal(err)
	}
	if open, err := corrosion.DrainColdMoveOpenTo(ctx, b.DB, "os1", b.Name); err != nil || !open {
		t.Fatalf("premise: %s sees m0 open (%v, %v)", b.Name, open, err)
	}
	m0Epoch, err := corrosion.GetVM(ctx, b.DB, "os1")
	if err != nil || m0Epoch == nil || m0Epoch.HostName != b.Name {
		t.Fatalf("premise: os1 on %s after m0: %+v %v", b.Name, m0Epoch, err)
	}

	// m1: B→C (A is drained), whose copy fails (C refuses the define) and
	// whose restart on B fails too.
	if _, err := sc.c.SelfClient(cNode).UndrainHost(ctx, &pb.UndrainHostRequest{Name: cNode.Name}); err != nil {
		t.Fatalf("undrain %s: %v", cNode.Name, err)
	}
	// Not WaitConverged: B's replica deliberately differs (m0's held step).
	eventually(t, convergeTimeout, b.Name+" to see "+cNode.Name+" undrained", func() bool {
		h, err := corrosion.GetHost(ctx, b.DB, cNode.Name)
		return err == nil && h != nil && h.State == "active"
	})
	cNode.Virt.FailDefineDomain = func(string) error { return errors.New("injected define failure") }
	b.Virt.FailStartDomain = func(string) error { return errors.New("injected start failure") }
	progress, err := drainHost(t, sc.c, b)
	if err == nil || progress["os1"] == nil || progress["os1"].Status != "error" {
		t.Fatalf("premise: drain m1 of %s ends with os1 left stopped: %v (%+v)", b.Name, err, progress["os1"])
	}
	b.Virt.FailStartDomain = nil
	vm, err := corrosion.GetVM(ctx, b.DB, "os1")
	if err != nil || vm == nil || vm.HostName != b.Name || vm.State != "stopped" || vm.OwnerEpoch != m0Epoch.OwnerEpoch ||
		!strings.HasPrefix(vm.StateDetail, health.DrainStopDetailPrefix) {
		t.Fatalf("premise: os1 stopped on %s at epoch %d with m1's drain stop: %+v %v", b.Name, m0Epoch.OwnerEpoch, vm, err)
	}
	if open, err := corrosion.DrainColdMoveOpenTo(ctx, b.DB, "os1", b.Name); err != nil || !open {
		t.Fatalf("premise: %s still sees m0 open (%v, %v)", b.Name, open, err)
	}
	if _, err := sc.c.SelfClient(b).UndrainHost(ctx, &pb.UndrainHostRequest{Name: b.Name}); err != nil {
		t.Fatalf("undrain %s: %v", b.Name, err)
	}

	// The late collision on B.
	if err := localExec(ctx, b.DB, `INSERT INTO vms (name, host_name, state, spec, created_at, updated_at) VALUES ('late', ?, 'running', '{}', 't', 't')`, b.Name); err != nil {
		t.Fatal(err)
	}
	if err := localExec(ctx, b.DB, `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at) VALUES ('late', 'lan', 0, ?, 't')`, dup); err != nil {
		t.Fatal(err)
	}
	_, err = sc.c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "os1"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "mac_duplicate") {
		t.Fatalf("an unmarked start of os1 after m1's failed drain: got %v, want the shared-MAC refusal", err)
	}
	if active, _ := b.Virt.DomainIsActive("os1"); active {
		t.Fatal("os1 was started")
	}
	if after, _ := corrosion.GetVM(ctx, b.DB, "os1"); after == nil || after.State != "stopped" || after.StateDetail != vm.StateDetail {
		t.Fatalf("os1's row changed: %+v", after)
	}
}

// drainHost drains host n through its own RPC, returning each VM's last
// progress frame.
func drainHost(t *testing.T, c *Cluster, n *Node) (map[string]*pb.DrainProgress, error) {
	t.Helper()
	st, err := c.SelfClient(n).DrainHost(context.Background(), &pb.DrainHostRequest{Name: n.Name})
	if err != nil {
		return nil, err
	}
	out := map[string]*pb.DrainProgress{}
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			return out, nil
		}
		if rerr != nil {
			return out, rerr
		}
		out[p.VmName] = p
	}
}

// Codex's marked schedule, on independent replicas. Drain m0 moves os1 A→B
// and starts it there, but A dies before recording m0 finished (both
// replicas still hold m0 open), and B's writes do not reach A: A still sees
// os1 handed over to B, stopped. A later drain m1 of B to C stops os1, fails
// its copy and its restart: os1 is stopped on B at m0's epoch + 1 with m1's
// stop intent. B is undrained and another VM there takes os1's MAC. A's
// startup recovery then finishes m0 by starting os1 on B, with a genuine
// drain-resume marker for m0 at that epoch. B must refuse it for the shared
// MAC: os1's stop is m1's, not m0's handoff.
//
// Mutation: a marked start accepts any drain stop intent (the 2d183545f
// rule) — os1 is started on B: red.
func TestFleet_MAC_AStaleRecoveryMarkerDoesNotCoverALaterDrainsStop(t *testing.T) {
	const dup = "52:54:00:7a:09:01"
	sc := newColdStoppedScenarioWith(t, Options{Nodes: 3, IndependentReplicas: true, SharedDataDir: true, FaultSeed: 103})
	a, b, cNode := sc.src, sc.dst, sc.c.Nodes[2]
	ctx := context.Background()
	if err := a.Virt.StartDomain("os1"); err != nil {
		t.Fatalf("start os1's domain: %v", err)
	}
	if err := corrosion.UpdateVMState(ctx, a.DB, "os1", "running", ""); err != nil {
		t.Fatalf("record os1 running: %v", err)
	}
	if err := corrosion.InsertInterface(ctx, a.DB, corrosion.InterfaceRecord{VMName: "os1", NetworkName: "lan", MAC: dup}); err != nil {
		t.Fatal(err)
	}
	for _, n := range sc.c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	if _, err := drainHost(t, sc.c, cNode); err != nil {
		t.Fatalf("drain the empty %s: %v", cNode.Name, err)
	}
	sc.c.WaitConverged(t, convergeTimeout)

	// From here nothing B or C writes reaches A.
	sc.c.SetLinkFault(b, a, LinkFault{Block: true})
	sc.c.SetLinkFault(cNode, a, LinkFault{Block: true})

	// m0: A→B, started on B; A "dies" before recording it finished.
	if progress, err := drainHost(t, sc.c, a); err != nil || progress["os1"] == nil || progress["os1"].Status != "done" || progress["os1"].TargetHost != b.Name {
		t.Fatalf("drain m0 of %s: %v (%+v)", a.Name, err, progress["os1"])
	}
	unfinish := `DELETE FROM operation_steps WHERE step_name = ? AND operation_id IN
		(SELECT id FROM operations WHERE operation_kind = ? AND resource_id = 'os1' AND desired_ref = ?)`
	eventually(t, convergeTimeout, b.Name+" to hold m0", func() bool {
		open, _ := corrosion.DrainColdMoveOpenTo(ctx, b.DB, "os1", b.Name)
		rows, _ := b.DB.Query(ctx, `SELECT 1 FROM operations WHERE operation_kind = ? AND resource_id = 'os1'`, string(corrosion.OpDrainColdMove))
		return open || len(rows) > 0
	})
	for _, n := range []*Node{a, b} {
		if err := localExec(ctx, n.DB, unfinish, corrosion.OpStepCompleted, string(corrosion.OpDrainColdMove), b.Name); err != nil {
			t.Fatal(err)
		}
	}
	aView, err := corrosion.GetVM(ctx, a.DB, "os1")
	if err != nil || aView == nil || aView.HostName != b.Name || aView.State != "stopped" || aView.StateDetail != "" {
		t.Fatalf("premise: %s still sees os1 handed over to %s, stopped: %+v %v", a.Name, b.Name, aView, err)
	}

	// m1: B→C, whose copy and restart both fail.
	if _, err := sc.c.SelfClient(cNode).UndrainHost(ctx, &pb.UndrainHostRequest{Name: cNode.Name}); err != nil {
		t.Fatalf("undrain %s: %v", cNode.Name, err)
	}
	eventually(t, convergeTimeout, b.Name+" to see "+cNode.Name+" undrained", func() bool {
		h, err := corrosion.GetHost(ctx, b.DB, cNode.Name)
		return err == nil && h != nil && h.State == "active"
	})
	cNode.Virt.FailDefineDomain = func(string) error { return errors.New("injected define failure") }
	b.Virt.FailStartDomain = func(string) error { return errors.New("injected start failure") }
	if progress, err := drainHost(t, sc.c, b); err == nil || progress["os1"] == nil || progress["os1"].Status != "error" {
		t.Fatalf("premise: drain m1 of %s leaves os1 stopped: %v (%+v)", b.Name, err, progress["os1"])
	}
	b.Virt.FailStartDomain = nil
	bView, err := corrosion.GetVM(ctx, b.DB, "os1")
	if err != nil || bView == nil || bView.HostName != b.Name || bView.State != "stopped" || bView.OwnerEpoch != aView.OwnerEpoch ||
		!strings.HasPrefix(bView.StateDetail, health.DrainStopDetailPrefix) {
		t.Fatalf("premise: os1 stopped on %s at epoch %d with m1's stop: %+v %v", b.Name, aView.OwnerEpoch, bView, err)
	}
	if _, err := sc.c.SelfClient(b).UndrainHost(ctx, &pb.UndrainHostRequest{Name: b.Name}); err != nil {
		t.Fatalf("undrain %s: %v", b.Name, err)
	}
	if err := localExec(ctx, b.DB, `INSERT INTO vms (name, host_name, state, spec, created_at, updated_at) VALUES ('late', ?, 'running', '{}', 't', 't')`, b.Name); err != nil {
		t.Fatal(err)
	}
	if err := localExec(ctx, b.DB, `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at) VALUES ('late', 'lan', 0, ?, 't')`, dup); err != nil {
		t.Fatal(err)
	}

	// A's stale startup recovery finishes m0, with its genuine marker.
	var marker []string
	b.HookUnary("StartVM", func(hctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		if md, ok := metadata.FromIncomingContext(hctx); ok {
			marker = md.Get(grpcapi.DrainResumeFromMDKey)
		}
		return handler(hctx, req)
	})
	_, _ = a.Server.ResumeDrainColdMoves(ctx)
	if len(marker) != 1 || marker[0] != a.Name {
		t.Fatalf("premise: A's recovery start carried marker %v, want [%s]", marker, a.Name)
	}
	if active, _ := b.Virt.DomainIsActive("os1"); active {
		t.Fatal("os1 was started on its shared MAC by a stale recovery marker")
	}
	if after, _ := corrosion.GetVM(ctx, b.DB, "os1"); after == nil || after.State != "stopped" || after.StateDetail != bView.StateDetail {
		t.Fatalf("os1's row changed: %+v", after)
	}
}

// An earlier build's drain source names no operation in its marker (from and
// epoch only). Its genuine handoff — os1 stopped on the target at the
// transfer's epoch with the empty detail the handoff writes — must start
// although the target's replica holds no drain journal yet and another VM
// there took os1's MAC after the preflight: that source does not retry, and
// would leave the guest stopped. A row stopped with another drain's intent
// is still refused for such a marker.
//
// Mutation: an operation-less marker counts as absent (the 5721e646f rule) —
// the genuine handoff is refused and os1 left stopped: red.
func TestFleet_MAC_AnEarlierBuildsResumeNeedsNoJournal(t *testing.T) {
	const dup = "52:54:00:7a:0a:01"
	sc := newColdStoppedScenarioWith(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 107})
	a, b := sc.src, sc.dst
	ctx := context.Background()
	if err := a.Virt.StartDomain("os1"); err != nil {
		t.Fatalf("start os1's domain: %v", err)
	}
	if err := corrosion.UpdateVMState(ctx, a.DB, "os1", "running", ""); err != nil {
		t.Fatalf("record os1 running: %v", err)
	}
	if err := corrosion.InsertInterface(ctx, a.DB, corrosion.InterfaceRecord{VMName: "os1", NetworkName: "lan", MAC: dup}); err != nil {
		t.Fatal(err)
	}
	sc.c.WaitConverged(t, convergeTimeout)
	b.Server.SetBridgeEnsure(func(string) error { return nil })

	var gotOp []string
	b.HookUnary("StartVM", func(hctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		// The earlier build's marker: from and epoch, no operation.
		md, _ := metadata.FromIncomingContext(hctx)
		md = md.Copy()
		gotOp = md.Get(grpcapi.DrainResumeOpMDKey)
		md.Delete(grpcapi.DrainResumeOpMDKey)
		hctx = metadata.NewIncomingContext(hctx, md)
		// The drain journal has not reached B (this replica only), and a
		// holder of os1's MAC appears after the preflight.
		hide := `UPDATE operations SET desired_ref = desired_ref || '#lag' WHERE operation_kind = ? AND resource_id = 'os1'`
		show := `UPDATE operations SET desired_ref = replace(desired_ref, '#lag', '') WHERE operation_kind = ? AND resource_id = 'os1'`
		if err := localExec(ctx, b.DB, hide, string(corrosion.OpDrainColdMove)); err != nil {
			t.Error(err)
		}
		defer func() { _ = localExec(ctx, b.DB, show, string(corrosion.OpDrainColdMove)) }()
		if err := localExec(ctx, b.DB, `INSERT INTO vms (name, host_name, state, spec, created_at, updated_at) VALUES ('late', ?, 'running', '{}', 't', 't')`, b.Name); err != nil {
			t.Error(err)
		}
		if err := localExec(ctx, b.DB, `INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at) VALUES ('late', 'lan', 0, ?, 't')`, dup); err != nil {
			t.Error(err)
		}
		return handler(hctx, req)
	})
	progress, err := drainHost(t, sc.c, a)
	if len(gotOp) != 1 {
		t.Fatalf("premise: this build's marker names its operation (%v)", gotOp)
	}
	if err != nil || progress["os1"] == nil || progress["os1"].Status != "done" || progress["os1"].Error != "" {
		t.Fatalf("drain with an earlier build's marker: %v (%+v)", err, progress["os1"])
	}
	if active, _ := b.Virt.DomainIsActive("os1"); !active {
		t.Fatalf("os1, running before the drain, is left stopped on %s", b.Name)
	}

	// The same kind of marker on a row stopped with another drain's intent.
	_ = b.Virt.DestroyDomain("os1")
	if err := localExec(ctx, b.DB, `UPDATE vms SET state = 'stopped', state_detail = ? WHERE name = 'os1'`, health.DrainStopDetail("m-other")); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(ctx, b.DB, "os1")
	old := metadata.AppendToOutgoingContext(ctx, grpcapi.DrainResumeFromMDKey, a.Name,
		grpcapi.DrainResumeEpochMDKey, strconv.FormatInt(vm.OwnerEpoch, 10))
	if _, err := sc.c.PeerClient(a, b).StartVM(old, &pb.StartVMRequest{Name: "os1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an earlier build's marker on another drain's stop: got %v, want the shared-MAC refusal", err)
	}
	if active, _ := b.Virt.DomainIsActive("os1"); active {
		t.Fatal("os1 was started on another drain's stop")
	}
}
