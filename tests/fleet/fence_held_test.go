// Fleet scenarios: a failed host with nothing to recover is recorded offline,
// not fenced (B2, the lab 2 full-disk RCA, 2026-10-20).
//
// Lab 2's node-4 lost its daemon to a full root disk. The majority fenced it
// within 13 s, and the power-off killed a healthy on_host_failure: none VM
// that nothing would ever restart elsewhere. Now the coordinator holds such a
// fence: the host is recorded offline, ha.fence_held is raised so `lv health`
// shows it, and whatever runs there keeps running. A host with something
// recoverable is fenced exactly as before, and the hold is re-decided every
// cycle, so a workload that becomes recoverable is fenced for and recovered
// once — never started while its old copy may still run.
//
// Multi-node by construction: the victim's guest lives in its own libvirt
// fake, the decision is a peer's coordinator, the operator reads it through a
// third node's `lv health`, and a successor on another node takes the
// recovery over.
package fleet

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const fenceHeldCode = "ha.fence_held"

// heldCluster is three nodes; the victim runs mtl (on_host_failure: none),
// its guest running in the victim's libvirt fake, and two peers fail it.
func fhCluster(t *testing.T) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	c = New(t, Options{Nodes: 3, SharedCRDT: true})
	a, b, victim = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	fhPutVM(t, a, "mtl", victim.Name, "none")
	victim.Virt.SetState("mtl", libvirtfake.StateRunning)
	fhFailVictim(t, victim, a, b)
	return c, a, b, victim
}

func fhPutVM(t *testing.T, n *Node, name, host, policy string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"` + name + `","cpu":1,"memory_mib":256,"on_host_failure":"` + policy + `"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// failVictim has each observer report victim down, fresh.
func fhFailVictim(t *testing.T, victim *Node, observers ...*Node) {
	t.Helper()
	now := time.Now().UTC()
	for _, o := range observers {
		PublishHealth(t, o, victim.Name, 5, now)
	}
}

// heldCoordinator is n's coordinator; its fencer counts the fences and powers
// the victim's guests off, as a real fence does.
func fhCoordinator(n, victim *Node, fences *int, guests ...string) *failover.Coordinator {
	coord := failover.NewCoordinator(n.Name, n.DB)
	// The split-brain gate's proof-linked recovery, so each recovery leaves
	// a proof to count.
	coord.Gate = quorateGate{}
	coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		if h.Name == victim.Name {
			*fences++
			for _, g := range guests {
				victim.Virt.SetState(g, libvirtfake.StateShutdown)
			}
		}
		return fence.Result{Method: "fleet-test", Success: true}
	})
	return coord
}

func fhRunning(t *testing.T, n *Node, vm string) bool {
	t.Helper()
	st, err := n.Virt.DomainState(vm)
	return err == nil && st == "running"
}

// fenceHeldOpen reports whether n's replica holds an open ha.fence_held for host.
func fhOpen(t *testing.T, n *Node, host string) bool {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB, failover.RefenceEvaluator, fenceHeldCode, "host", host)
	if err != nil {
		t.Fatalf("%s: read %s: %v", n.Name, fenceHeldCode, err)
	}
	return ok && row.Lifecycle != corrosion.ConditionResolved
}

func fhHostState(t *testing.T, n *Node, host string) string {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), n.DB, host)
	if err != nil || h == nil {
		t.Fatalf("%s: read host %s: %+v %v", n.Name, host, h, err)
	}
	return h.State
}

// TestFleet_ANothingRecoverableHostIsHeldNotFenced: the victim's only VM is
// on_host_failure: none. Over several cycles the fencer never fires, the
// guest keeps running on the victim and nowhere else, the victim is recorded
// offline with no fencing_log row, and a third node's `lv health` lists
// ha.fence_held for it. A start of the VM through a peer, with the victim's
// daemon unreachable, starts no second copy.
//
// Mutation: make holdUnneededFence return false — the fencer fires and the
// guest is powered off.
func TestFleet_ANothingRecoverableHostIsHeldNotFenced(t *testing.T) {
	c, a, b, victim := fhCluster(t)
	ctx := context.Background()
	fences := 0
	coord := fhCoordinator(a, victim, &fences, "mtl")
	for i := 0; i < 3; i++ {
		coord.RunOnce(ctx)
	}

	if fences != 0 {
		t.Fatalf("the fencer fired %d times; nothing on %s needs a fence", fences, victim.Name)
	}
	if !fhRunning(t, victim, "mtl") {
		t.Fatal("mtl's guest no longer runs on the victim; a hold must leave it running")
	}
	if st := fhHostState(t, b, victim.Name); st != "offline" {
		t.Fatalf("%s reads %s as %q, want offline", b.Name, victim.Name, st)
	}
	rows, err := b.DB.Query(ctx, `SELECT id FROM fencing_log WHERE host_name = ?`, victim.Name)
	if err != nil || len(rows) != 0 {
		t.Fatalf("fencing_log rows for %s: %d (%v); a hold records no fence", victim.Name, len(rows), err)
	}
	if !fhOpen(t, b, victim.Name) {
		t.Fatalf("%s holds no open %s for %s", b.Name, fenceHeldCode, victim.Name)
	}
	resp, err := c.SelfClient(b).GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, cond := range resp.GetConditions() {
		if cond.GetCode() == fenceHeldCode && cond.GetSubjectId() == victim.Name {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("`lv health` on %s does not list %s for %s: %v", b.Name, fenceHeldCode, victim.Name, resp.GetConditions())
	}

	// The victim's daemon is gone: an `lv start mtl` through b reaches nothing
	// that may run it, and no second copy starts anywhere — the hold is no
	// licence to start it elsewhere (a start lease the victim held reads as
	// stale on an offline host, staleStartLease, but the start still belongs
	// to the host the row names).
	victim.HookUnary("StartVM", func(context.Context, any, grpc.UnaryHandler) (any, error) {
		return nil, status.Error(codes.Unavailable, "the victim's daemon is down")
	})
	if _, err := c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "mtl"}); err == nil {
		t.Fatalf("lv start mtl through %s succeeded with the victim's daemon down", b.Name)
	}
	for _, n := range []*Node{a, b} {
		if fhRunning(t, n, "mtl") {
			t.Fatalf("a second copy of mtl runs on %s while the held victim still runs it", n.Name)
		}
	}
	if vm, _ := corrosion.GetVM(ctx, b.DB, "mtl"); vm == nil || vm.HostName != victim.Name {
		t.Fatalf("mtl = %+v, want it still recorded on %s", vm, victim.Name)
	}
}

// TestFleet_ARecoverableHostIsStillFenced: the same victim with a restart-any
// VM beside mtl is fenced once, the restart-any VM is recovered once, and mtl
// stays recorded on the victim; no fence-held condition is raised.
func TestFleet_ARecoverableHostIsStillFenced(t *testing.T) {
	_, a, b, victim := fhCluster(t)
	ctx := context.Background()
	fhPutVM(t, a, "rv", victim.Name, "restart-any")
	victim.Virt.SetState("rv", libvirtfake.StateRunning)
	fences := 0
	coord := fhCoordinator(a, victim, &fences, "mtl", "rv")
	coord.RunOnce(ctx)
	coord.RunOnce(ctx)

	if fences != 1 {
		t.Fatalf("the fencer fired %d times, want 1", fences)
	}
	if vm, _ := corrosion.GetVM(ctx, b.DB, "rv"); vm == nil || vm.HostName == victim.Name || vm.State != "pending" {
		t.Fatalf("rv = %+v, want it pending on a survivor", vm)
	}
	if got := proofsFor(t, b, "rv"); len(got) != 1 {
		t.Fatalf("rv has %d recovery proofs, want exactly 1: %v", len(got), got)
	}
	if vm, _ := corrosion.GetVM(ctx, b.DB, "mtl"); vm == nil || vm.HostName != victim.Name {
		t.Fatalf("mtl = %+v, want it left on %s (on_host_failure: none)", vm, victim.Name)
	}
	if fhOpen(t, b, victim.Name) {
		t.Fatalf("%s raised for a host that was fenced", fenceHeldCode)
	}
}

// TestFleet_AWorkloadThatBecomesRecoverableDuringAHoldIsFencedForOnce: the
// race. The victim is held; then, while it is held, mtl's policy becomes
// restart-any and a placement that had not yet seen the victim offline records
// a second restart-any VM, late, on it. The lease passes to b, whose
// coordinator never saw the hold. Its first cycle fences the victim — the hold
// is a decision re-made every cycle, not a terminal state — powering both
// guests off BEFORE any recovery proof exists, and each VM is recovered once.
//
// Mutation: drop `!held` from the terminal-state skip — the successor caches
// the offline victim as handled and never fences it.
func TestFleet_AWorkloadThatBecomesRecoverableDuringAHoldIsFencedForOnce(t *testing.T) {
	_, a, b, victim := fhCluster(t)
	ctx := context.Background()
	fences := 0
	coord := fhCoordinator(a, victim, &fences, "mtl")
	coord.RunOnce(ctx)
	if fences != 0 {
		t.Fatalf("premise: the fencer fired %d times during the hold", fences)
	}

	if err := b.DB.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'mtl'`,
		`{"name":"mtl","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`); err != nil {
		t.Fatal(err)
	}
	fhPutVM(t, b, "late", victim.Name, "restart-any")
	victim.Virt.SetState("late", libvirtfake.StateRunning)
	if err := b.DB.Execute(ctx, `DELETE FROM leader_election WHERE key = 'failover'`); err != nil {
		t.Fatal(err)
	}
	fhFailVictim(t, victim, a, b)

	succFences := 0
	var proofsAtFence int
	succ := failover.NewCoordinator(b.Name, b.DB)
	succ.Gate = quorateGate{}
	succ.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		if h.Name == victim.Name {
			succFences++
			proofsAtFence = len(proofsFor(t, b, "mtl")) + len(proofsFor(t, b, "late"))
			victim.Virt.SetState("mtl", libvirtfake.StateShutdown)
			victim.Virt.SetState("late", libvirtfake.StateShutdown)
		}
		return fence.Result{Method: "fleet-test", Success: true}
	})
	succ.RunOnce(ctx)
	succ.RunOnce(ctx)

	if succFences != 1 {
		t.Fatalf("the successor fenced %s %d times, want once", victim.Name, succFences)
	}
	if proofsAtFence != 0 {
		t.Fatalf("%d recovery proofs existed before the fence; nothing may be recovered while its old copy may run", proofsAtFence)
	}
	for _, vm := range []string{"mtl", "late"} {
		if fhRunning(t, victim, vm) {
			t.Fatalf("%s still runs on the fenced victim", vm)
		}
		rec, _ := corrosion.GetVM(ctx, b.DB, vm)
		if rec == nil || rec.HostName == victim.Name || rec.State != "pending" {
			t.Fatalf("%s = %+v, want it pending on a survivor", vm, rec)
		}
		if got := proofsFor(t, b, vm); len(got) != 1 {
			t.Fatalf("%s has %d recovery proofs, want exactly 1: %v", vm, len(got), got)
		}
	}
	if fhOpen(t, b, victim.Name) {
		t.Fatalf("%s still open after the fence", fenceHeldCode)
	}
}

// TestFleet_AHeldHostThatComesBackIsActiveAndUntouched: the victim's daemon
// returns; a quorum sees it healthy, it goes back to active, the condition
// resolves, and nothing was fenced or restarted.
func TestFleet_AHeldHostThatComesBackIsActiveAndUntouched(t *testing.T) {
	_, a, b, victim := fhCluster(t)
	ctx := context.Background()
	fences := 0
	coord := fhCoordinator(a, victim, &fences, "mtl")
	coord.RunOnce(ctx)
	now := time.Now().UTC()
	for _, o := range []*Node{a, b} {
		if err := o.DB.Execute(ctx, `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			VALUES (?, ?, 'healthy', 0, ?, ?)`, o.Name, victim.Name, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	coord.RunOnce(ctx)
	coord.RunOnce(ctx)
	if st := fhHostState(t, b, victim.Name); st != "active" {
		t.Fatalf("%s is %q after it came back, want active", victim.Name, st)
	}
	if fhOpen(t, b, victim.Name) {
		t.Fatalf("%s still open on an active host", fenceHeldCode)
	}
	if fences != 0 || !fhRunning(t, victim, "mtl") {
		t.Fatalf("fences=%d, mtl running=%v; a host that came back must be untouched", fences, fhRunning(t, victim, "mtl"))
	}
}

// needsFenceOn records on host, through n, a workload that needs host's fence
// and is never moved: a restart-same VM on a host-local disk, held for its
// host after the fence. A scenario whose subject is when or whether a fence
// runs adds it, since a host with nothing to recover is not fenced.
func needsFenceOn(t *testing.T, n *Node, host string) {
	t.Helper()
	name := "held-for-" + host
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"` + name + `","cpu":1,"memory_mib":256,"on_host_failure":"restart-same"}`,
	}, nil, []corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: host,
		Path: "/var/lib/litevirt/disks/" + name + ".qcow2", SizeBytes: 1 << 30, StorageType: "local"}}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// TestFleet_AHoldReplicatesAsOneEntry: on independent replicas, every peer
// applies the hold's 'offline' and its ha.fence_held together: no peer ever
// reads the host offline without the condition, which would have it cache the
// host as terminal. What this pins is that a receiver accepts the combined
// entry; that it is one entry is TestFenceHeld_TheHoldIsOneEntry's.
func TestFleet_AHoldReplicatesAsOneEntry(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2610})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	fhPutVM(t, a, "mtl", victim.Name, "none")
	c.WaitConverged(t, convergeTimeout)
	fhFailVictim(t, victim, a, b)
	c.WaitConverged(t, convergeTimeout)
	fences := 0
	fhCoordinator(a, victim, &fences, "mtl").RunOnce(context.Background())
	if fences != 0 {
		t.Fatalf("premise: fenced %d times", fences)
	}
	eventually(t, convergeTimeout, b.Name+" to apply the hold", func() bool {
		h, err := corrosion.GetHost(context.Background(), b.DB, victim.Name)
		return err == nil && h != nil && h.State == "offline"
	})
	if !fhOpen(t, b, victim.Name) {
		t.Fatalf("%s reads %s offline without its %s", b.Name, victim.Name, fenceHeldCode)
	}
}
