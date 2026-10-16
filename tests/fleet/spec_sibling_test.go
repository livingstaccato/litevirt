package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// Two desired-spec writes at one spec_generation, one on each side of a full
// partition. Both MutateDesiredSpec and BeginVMOperation replicate a
// compare-and-swap (`WHERE spec_generation = E`, `SET spec_generation =
// spec_generation + 1`). Before spec_conflict_v1 a receiver already holding
// the other sibling at E+1 applied it as a zero-row no-op, so each replica
// kept whichever reached it first, and anti-entropy later kept the newer row
// by timestamp — over an operation's barrier too.

// latchSpecConflict drives spec_conflict_v1 on every node through real
// checkers and wires each node's corrosion gate to its durable latch, as the
// daemon does. withhold, when set, is a node whose advertisement lacks the
// token while it reads true: a host on the previous build.
func latchSpecConflict(t *testing.T, c *Cluster, withhold *Node, held *atomic.Bool) map[string]*health.Checker {
	t.Helper()
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		node := n
		g := gates[node.Name]
		if withhold != nil {
			g.SetPeerPinger(func(ctx context.Context, host string) ([]string, time.Time, error) {
				caps, wall, err := node.Server.PeerCapabilities(ctx, host)
				if held.Load() && host == withhold.Name {
					caps = withoutToken(caps, capabilities.SpecConflictV1)
				}
				return caps, wall, err
			})
		}
		node.DB.SetSpecConflictGate(func() bool { return g.DurablyLatched(capabilities.SpecConflictV1) })
	}
	for _, n := range c.Nodes {
		if n == withhold {
			continue
		}
		latched := gates[n.Name].Enforced(context.Background(), capabilities.SpecConflictV1)
		if withhold == nil && !latched {
			t.Fatalf("%s: spec_conflict_v1 did not latch with every host advertising it", n.Name)
		}
		if withhold != nil && latched {
			t.Fatalf("%s latched spec_conflict_v1 while %s runs a build without it", n.Name, withhold.Name)
		}
	}
	return gates
}

// cutOffFully partitions b from everyone, the owner's forward included.
func cutOffFully(c *Cluster, b *Node) {
	c.Isolate(b)
	for _, o := range c.Nodes {
		if o != b {
			c.SetLinkFaultBoth(o, b, LinkFault{Block: true, BlockAll: true})
		}
	}
}

// siblingEdits makes the split: the owner a edits, then b, cut off, sets a
// label. Both land at spec_generation 1. The cut is healed on return.
func siblingEdits(t *testing.T, c *Cluster, owner func(ctx context.Context, a *Node)) {
	t.Helper()
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	insertVM(t, a, "vm-sib", a.Name)
	c.WaitConverged(t, convergeTimeout)

	cutOffFully(c, b)
	owner(ctx, a)
	time.Sleep(20 * time.Millisecond) // b's edit is the later one by updated_at
	if _, err := c.SelfClient(b).SetVMLabels(ctx, &pb.SetVMLabelsRequest{Name: "vm-sib", Labels: map[string]string{"tier": "front"}}); err != nil {
		t.Fatalf("SetVMLabels via %s: %v", b.Name, err)
	}
	for _, n := range []*Node{a, b} {
		if vm := vmOn(t, n, "vm-sib"); vm.SpecGeneration != 1 {
			t.Fatalf("premise: %s holds vm-sib at generation %d, want both edits at 1", n.Name, vm.SpecGeneration)
		}
	}
	c.ClearLinkFaults()
}

func ownerCPU4(t *testing.T) func(context.Context, *Node) {
	return func(ctx context.Context, a *Node) {
		if _, _, err := corrosion.MutateDesiredSpec(ctx, a.DB, "vm-sib", func(old string) (string, error) {
			var m map[string]any
			if err := json.Unmarshal([]byte(old), &m); err != nil {
				return "", err
			}
			m["cpu"] = 4
			out, err := json.Marshal(m)
			return string(out), err
		}); err != nil {
			t.Fatalf("owner edit: %v", err)
		}
	}
}

func droppedEventsOn(t *testing.T, n *Node, vm string) []corrosion.VMEventRecord {
	t.Helper()
	all, err := corrosion.ListVMEvents(context.Background(), n.DB, vm, 100, "")
	if err != nil {
		t.Fatalf("ListVMEvents on %s: %v", n.Name, err)
	}
	var out []corrosion.VMEventRecord
	for _, e := range all {
		if e.Type == corrosion.SpecEditDroppedEvent {
			out = append(out, e)
		}
	}
	return out
}

// After the latch: the replicas agree over the WAL alone, on the later edit,
// and the owner's dropped cpu edit is recorded on every node.
//
// Red on 5434f2ed (no latch, no resolution): "did not converge within 20s;
// tables apart: vms" — node-0 kept its cpu edit, node-1 its label, node-2
// whichever came first.
func TestFleet_SameGenerationSpecEditsConvergeOverTheWAL(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	latchSpecConflict(t, c, nil, nil)
	siblingEdits(t, c, ownerCPU4(t))
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if vm := vmOn(t, n, "vm-sib"); !strings.Contains(vm.Spec, `"tier":"front"`) || vm.SpecGeneration != 1 {
			t.Errorf("%s holds %s@%d, want node-1's later edit at 1", n.Name, vm.Spec, vm.SpecGeneration)
		}
	}
	for _, n := range c.Nodes {
		n := n
		eventually(t, convergeTimeout, n.Name+" to hold the record of the dropped cpu edit", func() bool {
			evs := droppedEventsOn(t, n, "vm-sib")
			return len(evs) == 1 && strings.Contains(evs[0].Detail, `"cpu":4`)
		})
	}
}

// After the latch: the owner begins an operation (barrier + generation bump)
// while a cut-off node edits labels at the same generation, later. Neither the
// WAL nor anti-entropy lets the later edit overwrite the barrier: every node
// holds the operation's claim, and the owner completes it.
//
// Red on 5434f2ed: anti-entropy took the later label row everywhere, the owner
// included — active_operation_id="" mid-operation, its desired spec replaced,
// and CompleteVMOperation ok=false.
func TestFleet_AnOutOfBandSpecEditDoesNotClearAnOperationsBarrier(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	latchSpecConflict(t, c, nil, nil)
	siblingEdits(t, c, func(ctx context.Context, a *Node) {
		op := corrosion.OperationRecord{ID: "op-1", Method: "UpdateVM", ResourceKind: "vm", ResourceID: "vm-sib",
			OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h"}
		if ok, err := a.DB.BeginVMOperation(ctx, op, `{"cpu":4,"on_host_failure":"restart-any"}`, 0, 0); err != nil || !ok {
			t.Fatalf("BeginVMOperation: %v %v", ok, err)
		}
	})
	ctx := context.Background()
	c.WaitConverged(t, convergeTimeout)
	for i := 0; i < 2; i++ {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
	}
	for _, n := range c.Nodes {
		if vm := vmOn(t, n, "vm-sib"); vm.ActiveOperationID != "op-1" || strings.Contains(vm.Spec, "tier") {
			t.Errorf("%s lost op-1's barrier mid-operation: active_operation_id=%q spec=%s", n.Name, vm.ActiveOperationID, vm.Spec)
		}
	}
	owner := c.Nodes[0]
	if ok, err := owner.DB.CompleteVMOperation(ctx, "vm-sib", "op-1", 0, 1); err != nil || !ok {
		t.Errorf("the owner cannot complete op-1: ok=%v err=%v", ok, err)
	}
	c.WaitConverged(t, convergeTimeout)
	eventually(t, convergeTimeout, "the dropped label edit to be recorded on node-1", func() bool {
		evs := droppedEventsOn(t, c.Nodes[1], "vm-sib")
		return len(evs) == 1 && strings.Contains(evs[0].Detail, `"tier":"front"`)
	})
}

// Mixed versions: node-2 runs a build without spec_conflict_v1, so the token
// does not latch anywhere and nothing changes — every edit keeps the previous
// release's shape (which node-2 decodes), replication into node-2 is not held
// up, and the conflict is left to anti-entropy, as before.
//
// Mutation: emit the epoch-carrying shape whatever the latch — the shape
// appears in the log (and would stall node-2's stream on its real build).
func TestFleet_BeforeTheLatchSpecEditsKeepThePreviousShape(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	var held atomic.Bool
	held.Store(true)
	latchSpecConflict(t, c, c.Nodes[2], &held)
	siblingEdits(t, c, ownerCPU4(t))

	waitWritesApplied(t, c, convergeTimeout)
	ctx := context.Background()
	// The previous release's WAL: each side keeps its own edit.
	if vm := vmOn(t, c.Nodes[0], "vm-sib"); !strings.Contains(vm.Spec, `"cpu":4`) || strings.Contains(vm.Spec, "tier") {
		t.Errorf("before the latch node-0 resolved the conflict on the WAL: %s", vm.Spec)
	}
	if vm := vmOn(t, c.Nodes[1], "vm-sib"); strings.Contains(vm.Spec, `"cpu":4`) || !strings.Contains(vm.Spec, "tier") {
		t.Errorf("before the latch node-1 resolved the conflict on the WAL: %s", vm.Spec)
	}
	for _, n := range c.Nodes {
		if n.DB.SpecConflictOn() {
			t.Errorf("%s resolves spec conflicts with spec_conflict_v1 unlatched", n.Name)
		}
		rows, err := n.DB.Query(ctx, `SELECT stmts FROM mutation_log`)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if strings.Contains(r.String("stmts"), "vm_owner_epoch = ? AND spec_generation = ? AND active_operation_id = ''") {
				t.Errorf("%s logged the epoch-carrying spec edit before the latch: %s", n.Name, r.String("stmts"))
			}
		}
	}
	// As before: the WAL leaves the split, anti-entropy settles it.
	for i := 0; i < 2; i++ {
		for _, n := range c.Nodes {
			corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
		}
	}
	c.WaitConverged(t, convergeTimeout)
}

// waitWritesApplied waits until every node has applied (or refused) every
// replicated write every other node has made so far — none held back.
func waitWritesApplied(t *testing.T, c *Cluster, timeout time.Duration) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	for _, origin := range c.Nodes {
		rows, err := origin.DB.Query(ctx, `SELECT hlc FROM mutation_log WHERE origin = ?`, origin.Name)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range c.Nodes {
			if n == origin {
				continue
			}
			for _, r := range rows {
				for {
					seen, err := n.DB.Query(ctx, `SELECT 1 FROM mutation_seen WHERE origin = ? AND hlc = ?`, origin.Name, r.String("hlc"))
					if err != nil {
						t.Fatal(err)
					}
					if len(seen) > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("%s has not applied %s's write %s within %s", n.Name, origin.Name, r.String("hlc"), timeout)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
		}
	}
}

// The review's C1 across a real partition: the owner edits, node-1 (cut off)
// edits later, and the owner then writes the VM's state, which moves the row
// clock past node-1's edit. The replicas agree over the WAL on node-1's later
// edit, and the owner's cpu edit is the only one recorded as dropped.
//
// Red on 58f7754f: the owner keeps its edit on the strength of the state
// write's clock, node-1 keeps its own, and anti-entropy leaves the tie.
func TestFleet_AStateWriteBetweenTheEditsDoesNotSplitTheSpec(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	latchSpecConflict(t, c, nil, nil)
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	insertVM(t, a, "vm-sib", a.Name)
	c.WaitConverged(t, convergeTimeout)
	cutOffFully(c, b)
	ownerCPU4(t)(ctx, a)
	time.Sleep(20 * time.Millisecond)
	if _, err := c.SelfClient(b).SetVMLabels(ctx, &pb.SetVMLabelsRequest{Name: "vm-sib", Labels: map[string]string{"tier": "front"}}); err != nil {
		t.Fatalf("SetVMLabels via %s: %v", b.Name, err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := corrosion.UpdateVMState(ctx, a.DB, "vm-sib", "stopped", ""); err != nil {
		t.Fatalf("the owner's state write: %v", err)
	}
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if vm := vmOn(t, n, "vm-sib"); !strings.Contains(vm.Spec, `"tier":"front"`) || vm.State != "stopped" {
			t.Errorf("%s holds %s (%s), want node-1's later edit and the owner's state", n.Name, vm.Spec, vm.State)
		}
	}
	for _, n := range c.Nodes {
		n := n
		eventually(t, convergeTimeout, n.Name+" to record the owner's dropped cpu edit, and only it", func() bool {
			evs := droppedEventsOn(t, n, "vm-sib")
			return len(evs) == 1 && strings.Contains(evs[0].Detail, `"cpu":4`) && !strings.Contains(evs[0].Detail, "tier")
		})
	}
}
