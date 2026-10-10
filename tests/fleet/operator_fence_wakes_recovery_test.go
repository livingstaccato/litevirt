// Fleet scenario: lab drill S5. A successful fence recorded by anyone — here
// an operator's `lv host fence` — wakes the recovery of the lease-holding
// coordinator that had itself tried and failed to fence the same host.
package fleet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fence"
)

// waitNextWallSecond sleeps into the next wall-clock second. fencing_log rows
// carry second precision and a failed attempt wins a same-second tie, so an
// operator fence must land in a later second than the failed one to be the
// newest — as it was by minutes in the drill.
func waitNextWallSecond() {
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 20*time.Millisecond)))
}

// TestFleet_OperatorFenceAfterLeadersFailedFence_RecoversInOneCycle: the
// leader's own fence of d fails (in the drill, the lab had no SSH identity),
// leaving d 'offline' with its workloads on it. An operator then fences d
// successfully from the same node. The leader, still holding the lease and
// never restarted, recovers vm on its very next cycle from the operator's
// record, without fencing d again, and vm runs in exactly one place.
//
// The existing TestFleet_OperatorFence_RecoveryResumesExactlyOnce has the
// operator fence land before the leader's first cycle, so the leader never
// held a failed fence of its own. Here the order is the drill's.
//
// Mutation M1 (adopt): fenceAuthorityChanged answers false — the leader's
// cached failed fence hides the operator's record and vm stays on d.
func TestFleet_OperatorFenceAfterLeadersFailedFence_RecoversInOneCycle(t *testing.T) {
	ctx := context.Background()
	vm := "vm-s5"
	c, a, b, cc, _, d := crashFleet(t, 2745, vm)
	voters := []*Node{a, b, cc}
	ledger := watchClaims(t, c)
	// d fences over SSH, as node-2 did in the drill: a failed SSH fence is
	// refused by the split-brain guard (best-effort, the harness default,
	// would proceed anyway).
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: d.Name, FenceStrategy: "ssh"}); err != nil {
		t.Fatalf("configure %s fence strategy ssh: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, voters...)

	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	var coordFences atomic.Int32
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.ByNode[a.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		coordFences.Add(1)
		return fence.Result{Method: "ssh", Success: false, Detail: "ssh: no identity"}
	})
	a.Server.SetFenceExecutor(func(context.Context, fence.HostConfig) fence.Result { return sshOff })

	// The leader's own fence fails first.
	cs.Tick(ctx, a)
	if n := coordFences.Load(); n != 1 {
		t.Fatalf("fixture: the leader ran %d fences of %s, want its one failed fence", n, d.Name)
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	if got := hostStateOn(t, a, d.Name); got != "offline" {
		t.Fatalf("fixture: %s is %q after the leader's failed fence, want offline", d.Name, got)
	}
	if v := vmOn(t, a, vm); v.HostName != d.Name || v.PendingActionID != "" {
		t.Fatalf("fixture: a failed fence moved %s: %+v", vm, v)
	}
	// The leader keeps the lease and cycles; nothing changes for d.
	clock.Advance(5 * time.Second)
	cs.Tick(ctx, a)

	// Then the operator's fence succeeds.
	waitNextWallSecond()
	if _, err := c.SelfClient(a).FenceHost(ctx, &pb.FenceHostRequest{Name: d.Name, Confirmed: true}); err != nil {
		t.Fatalf("lv host fence %s: %v", d.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, voters...)

	// Inside the leader's retry backoff, so only the operator's record can
	// authorise what follows.
	clock.Advance(10 * time.Second)
	for _, n := range voters {
		PublishHealth(t, n, d.Name, streakSince(2*time.Minute), clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, voters...)

	// ONE cycle.
	cs.Tick(ctx, a)
	decided := vmOn(t, a, vm)
	if decided.PendingActionID == "" || decided.HostName == d.Name {
		t.Fatalf("one leader cycle after the operator's fence of %s, %s is still on it: %+v", d.Name, vm, decided)
	}
	for i := 0; i < 3; i++ {
		clock.Advance(contentionPoll)
		cs.Tick(ctx, a)
	}
	if n := coordFences.Load(); n != 1 {
		t.Errorf("the leader fenced %s %d time(s), want only its first failed fence: it adopts the operator's", d.Name, n)
	}
	c.WaitConverged(t, convergeTimeout, voters...)
	claimReconciler(t, c.Node(decided.HostName)).ReconcileOnce(ctx)
	out := checkClaimSafety(t, ledger, a, vm, c.Nodes)
	if len(out.Running) != 1 || out.Running[0] != decided.HostName {
		t.Errorf("%s runs on %v, want exactly the decided destination %s", vm, out.Running, decided.HostName)
	}
	if v := vmOn(t, a, vm); v.HostName != decided.HostName {
		t.Errorf("%s moved again to %s after its recovery to %s: the recovery ran more than once", vm, v.HostName, decided.HostName)
	}
}
