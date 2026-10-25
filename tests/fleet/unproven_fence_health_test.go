package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
)

// unprovenFenceCond is what host's ha.recovery.unproven_fence says through
// n's `lv health` (GetClusterHealth): listed open, and its evidence.
func unprovenFenceCond(t *testing.T, c *Cluster, n *Node, host string) (open bool, detail, remedy string, workloads []string) {
	t.Helper()
	resp, err := c.SelfClient(n).GetClusterHealth(context.Background(), &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth on %s: %v", n.Name, err)
	}
	for _, cond := range resp.GetConditions() {
		if cond.GetCode() != failover.CondRecoveryUnprovenFence || cond.GetSubjectId() != host || cond.GetLifecycle() == "resolved" {
			continue
		}
		var ev struct {
			Detail    string   `json:"detail"`
			Workloads []string `json:"workloads"`
			Remedy    string   `json:"remedy"`
		}
		if err := json.Unmarshal([]byte(cond.GetEvidence()), &ev); err != nil {
			t.Fatalf("%s evidence %q: %v", failover.CondRecoveryUnprovenFence, cond.GetEvidence(), err)
		}
		return true, ev.Detail, ev.Remedy, ev.Workloads
	}
	return false, "", "", nil
}

// TestFleet_AnUnprovenFenceHoldIsInLvHealth: the rc9 lab's F1b and F3. A
// coordinator on a's SSH power-off of the victim, which the remote shell
// confirmed, holds the victim's VM, because the victim does not trust a
// confirmed SSH power-off. `lv health` on ANOTHER node (b) lists
// ha.recovery.unproven_fence for the victim, naming the reason, the held VM
// and the way out: fence-confirm, and the trust opt-in for later fences. The
// operator confirms the victim off through b; the coordinator recovers the
// VM, and the condition resolves on b's replica.
//
// Multi-node by construction: the hold is a's coordinator's, decided on two
// observers' failure reports, and read back through b's replica.
//
// Mutations: drop raiseUnproven — b lists nothing, red; drop the resolve in
// resumeFromConfirmation and the settle sweep's pending case — it stays open
// on b after the VM moved, red.
func TestFleet_AnUnprovenFenceHoldIsInLvHealth(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2812})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: victim.Name, FenceStrategy: "ssh"}); err != nil {
		t.Fatal(err)
	}
	insertVM(t, a, "vm-held", victim.Name)
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(victim)
	// The observers' runs began well before the operator's confirmation, so
	// it stands: they watched the host stay down across it.
	runStart := clock.Now().Add(-time.Minute)
	PublishHealthRun(t, a, victim.Name, 5, runStart, clock.Now())
	PublishHealthRun(t, b, victim.Name, 5, runStart, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)

	cs := c.NewCoordinators(clock)
	for _, n := range c.Nodes {
		cs.ByNode[n.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "ssh", Success: true, Detail: "litevirt-fence-armed [path=managed]"}
		})
	}
	tick := func(i int) {
		clock.Advance(20 * time.Second)
		now := clock.Now()
		PublishHealthRun(t, a, victim.Name, 6+i, runStart, now)
		PublishHealthRun(t, b, victim.Name, 6+i, runStart, now)
		c.WaitConverged(t, convergeTimeout, a, b)
		cs.Tick(ctx, a)
		c.WaitConverged(t, convergeTimeout, a, b)
	}
	cs.Tick(ctx, a)
	for i := 0; i < 2; i++ {
		tick(i)
	}
	if vm := vmOn(t, b, "vm-held"); vm == nil || vm.HostName != victim.Name {
		t.Fatalf("setup: vm-held on b's replica = %+v, want held on %s", vm, victim.Name)
	}
	open, detail, remedy, workloads := unprovenFenceCond(t, c, b, victim.Name)
	if !open {
		t.Fatalf("`lv health` on %s does not list %s for %s", b.Name, failover.CondRecoveryUnprovenFence, victim.Name)
	}
	if !strings.Contains(detail, "not proof "+victim.Name+" is off") || len(workloads) != 1 || workloads[0] != "vm/vm-held" {
		t.Errorf("evidence does not name the reason and the held VM: detail %q, workloads %v", detail, workloads)
	}
	for _, want := range []string{"`lv host fence-confirm " + victim.Name + "`", "`lv host config " + victim.Name + " --trust-ssh-poweroff`"} {
		if !strings.Contains(remedy, want) {
			t.Errorf("remedy does not name %q: %q", want, remedy)
		}
	}

	mustFenceConfirm(t, b, victim.Name)
	c.WaitConverged(t, convergeTimeout, a, b)
	for i := 2; i < 4; i++ {
		tick(i)
	}
	if vm := vmOn(t, b, "vm-held"); vm == nil || vm.HostName == victim.Name {
		t.Fatalf("vm-held on b's replica = %+v, want it recovered after fence-confirm", vm)
	}
	if open, _, _, _ := unprovenFenceCond(t, c, b, victim.Name); open {
		t.Fatalf("`lv health` on %s still lists %s for %s after the recovery", b.Name, failover.CondRecoveryUnprovenFence, victim.Name)
	}
}

// TestFleet_TrustIsNeverRetroactiveAcrossALeaderChange: the rc9 lab's A3,
// across a leader change. a's coordinator judges the victim's confirmed SSH
// power-off untrusted and holds its VM. The operator then sets the victim to
// trust a confirmed SSH power-off, through b, and the lease passes to b, whose
// coordinator never judged the fence and resumes it from the record. It must
// use the decision recorded with the fence, not the label as it reads now:
// the VM stays held until fence-confirm, and the condition stays open.
//
// Mutation: judge a resumed fence by the host's label again — b recovers the
// VM on the old fence, red.
func TestFleet_TrustIsNeverRetroactiveAcrossALeaderChange(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2813})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: victim.Name, FenceStrategy: "ssh"}); err != nil {
		t.Fatal(err)
	}
	insertVM(t, a, "vm-held", victim.Name)
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(victim)
	runStart := clock.Now().Add(-time.Minute)
	publish := func(i int) {
		now := clock.Now()
		PublishHealthRun(t, a, victim.Name, 5+i, runStart, now)
		PublishHealthRun(t, b, victim.Name, 5+i, runStart, now)
		c.WaitConverged(t, convergeTimeout, a, b)
	}
	publish(0)
	cs := c.NewCoordinators(clock)
	for _, n := range c.Nodes {
		cs.ByNode[n.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "ssh", Success: true, Detail: "litevirt-fence-armed [path=managed]"}
		})
	}
	cs.Tick(ctx, a)
	c.WaitConverged(t, convergeTimeout, a, b)
	if vm := vmOn(t, b, "vm-held"); vm == nil || vm.HostName != victim.Name {
		t.Fatalf("setup: vm-held = %+v, want held on %s", vm, victim.Name)
	}

	trustSSHPoweroffOn(t, c, b, victim, a, b)
	// a stops; its lease runs out, and b's coordinator takes over.
	for i := 1; i <= 4; i++ {
		clock.Advance(30 * time.Second)
		publish(i)
		cs.Tick(ctx, b)
		c.WaitConverged(t, convergeTimeout, a, b)
	}
	if vm := vmOn(t, b, "vm-held"); vm == nil || vm.HostName != victim.Name {
		t.Fatalf("vm-held = %+v: b recovered it on a fence a judged untrusted, after the trust was set", vm)
	}
	if open, _, _, _ := unprovenFenceCond(t, c, b, victim.Name); !open {
		t.Fatalf("`lv health` on %s does not list %s while the recovery is still held", b.Name, failover.CondRecoveryUnprovenFence)
	}

	mustFenceConfirm(t, b, victim.Name)
	c.WaitConverged(t, convergeTimeout, a, b)
	for i := 5; i <= 6; i++ {
		clock.Advance(20 * time.Second)
		publish(i)
		cs.Tick(ctx, b)
		c.WaitConverged(t, convergeTimeout, a, b)
	}
	if vm := vmOn(t, b, "vm-held"); vm == nil || vm.HostName == victim.Name {
		t.Fatalf("vm-held = %+v, want it recovered after fence-confirm", vm)
	}
}

// TestFleet_AFailedSSHFenceHoldIsInLvHealth: the rc9 lab's F1a. The victim,
// fenced only over SSH, is powered off from outside, so a's coordinator's SSH
// fence cannot reach it and its VM is held, retried with backoff. `lv health`
// on b lists ha.recovery.unproven_fence for it with the failure and the way
// out; after fence-confirm through b the VM is recovered and the condition
// resolves on b's replica.
//
// Mutation: drop the raise from the failed-fence branch — b lists nothing,
// red.
func TestFleet_AFailedSSHFenceHoldIsInLvHealth(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2814})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: victim.Name, FenceStrategy: "ssh"}); err != nil {
		t.Fatal(err)
	}
	insertVM(t, a, "vm-off", victim.Name)
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(victim)
	runStart := clock.Now().Add(-time.Minute)
	cs := c.NewCoordinators(clock)
	for _, n := range c.Nodes {
		cs.ByNode[n.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
			return fence.Result{Method: "ssh", Detail: "ssh: connect to host port 22: No route to host [path=managed]"}
		})
	}
	tick := func(i int) {
		clock.Advance(20 * time.Second)
		now := clock.Now()
		PublishHealthRun(t, a, victim.Name, 5+i, runStart, now)
		PublishHealthRun(t, b, victim.Name, 5+i, runStart, now)
		c.WaitConverged(t, convergeTimeout, a, b)
		cs.Tick(ctx, a)
		c.WaitConverged(t, convergeTimeout, a, b)
	}
	for i := 0; i < 2; i++ {
		tick(i)
	}
	if vm := vmOn(t, b, "vm-off"); vm == nil || vm.HostName != victim.Name {
		t.Fatalf("setup: vm-off = %+v, want held on %s", vm, victim.Name)
	}
	open, detail, remedy, workloads := unprovenFenceCond(t, c, b, victim.Name)
	if !open {
		t.Fatalf("`lv health` on %s does not list %s for %s", b.Name, failover.CondRecoveryUnprovenFence, victim.Name)
	}
	if !strings.Contains(detail, "No route to host") || len(workloads) != 1 || workloads[0] != "vm/vm-off" ||
		!strings.Contains(remedy, "`lv host fence-confirm "+victim.Name+"`") {
		t.Errorf("evidence: detail %q, workloads %v, remedy %q", detail, workloads, remedy)
	}

	mustFenceConfirm(t, b, victim.Name)
	c.WaitConverged(t, convergeTimeout, a, b)
	for i := 2; i < 4; i++ {
		tick(i)
	}
	if vm := vmOn(t, b, "vm-off"); vm == nil || vm.HostName == victim.Name {
		t.Fatalf("vm-off = %+v, want it recovered after fence-confirm", vm)
	}
	if open, _, _, _ := unprovenFenceCond(t, c, b, victim.Name); open {
		t.Fatalf("`lv health` on %s still lists %s after the recovery", b.Name, failover.CondRecoveryUnprovenFence)
	}
}

// TestFleet_ADeclinedOperatorFenceIsInLvHealth: the rc10 lab's A5. An
// operator fences the victim (`lv host fence --confirmed`, over SSH, on a host
// that trusts a confirmed SSH power-off) before any observer has watched it
// stay down. a's coordinator finds the recorded fence, which does not stand
// (every observer's failing run began after it), and declines it: the VM is
// held and never recovered on it. `lv health` on ANOTHER node (b) lists
// ha.recovery.unproven_fence for the victim, naming the declined fence and
// both ways out, fence-confirm and undrain. The operator undrains the victim
// through b; the coordinator fences it afresh for the outage, recovers the
// VM, and the condition resolves on b's replica.
//
// Multi-node by construction: the decline rests on two observers' failure
// reports, the hold is a's coordinator's, and it is read back through b.
//
// Mutation: no raise in noteResumeDeclined — b lists nothing, red.
func TestFleet_ADeclinedOperatorFenceIsInLvHealth(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2815})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: victim.Name, FenceStrategy: "ssh"}); err != nil {
		t.Fatal(err)
	}
	trustSSHPoweroffOn(t, c, a, victim)
	insertVM(t, a, "vm-declined", victim.Name)
	c.WaitConverged(t, convergeTimeout)
	clock := NewVirtualClock(time.Now().UTC())

	// The operator's fence lands while the victim still answers everyone.
	a.Server.SetFenceExecutor(func(context.Context, fence.HostConfig) fence.Result { return sshOff })
	if _, err := c.SelfClient(a).FenceHost(ctx, &pb.FenceHostRequest{Name: victim.Name, Confirmed: true}); err != nil {
		t.Fatalf("lv host fence %s: %v", victim.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(victim)

	// The observers' failing runs begin only after the fence.
	clock.Advance(30 * time.Second)
	runStart := clock.Now()
	cs := c.NewCoordinators(clock)
	var fences atomic.Int32
	for _, n := range c.Nodes {
		cs.ByNode[n.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
			fences.Add(1)
			return fence.Result{Method: "ssh", Success: true, Detail: "litevirt-fence-armed [path=managed]"}
		})
	}
	seq := 5
	tick := func() {
		clock.Advance(20 * time.Second)
		seq++
		PublishHealthRun(t, a, victim.Name, seq, runStart, clock.Now())
		PublishHealthRun(t, b, victim.Name, seq, runStart, clock.Now())
		c.WaitConverged(t, convergeTimeout, a, b)
		cs.Tick(ctx, a)
		c.WaitConverged(t, convergeTimeout, a, b)
	}
	for i := 0; i < 3; i++ {
		tick()
	}
	if vm := vmOn(t, b, "vm-declined"); vm == nil || vm.HostName != victim.Name {
		t.Fatalf("vm-declined on b's replica = %+v: a recorded fence that does not stand recovered it", vm)
	}
	if n := fences.Load(); n != 0 {
		t.Fatalf("the coordinator fenced %s %d time(s) over a declined recorded fence", victim.Name, n)
	}
	open, detail, remedy, workloads := unprovenFenceCond(t, c, b, victim.Name)
	if !open {
		t.Fatalf("`lv health` on %s does not list %s for %s, whose recorded fence was declined", b.Name, failover.CondRecoveryUnprovenFence, victim.Name)
	}
	if !strings.Contains(detail, "no longer stands") || len(workloads) != 1 || workloads[0] != "vm/vm-declined" {
		t.Errorf("evidence does not name the declined fence and the held VM: detail %q, workloads %v", detail, workloads)
	}
	for _, want := range []string{"`lv host fence-confirm " + victim.Name + "`", "`lv host undrain " + victim.Name + "`"} {
		if !strings.Contains(remedy, want) {
			t.Errorf("remedy does not name %q: %q", want, remedy)
		}
	}

	if _, err := c.SelfClient(b).UndrainHost(ctx, &pb.UndrainHostRequest{Name: victim.Name}); err != nil {
		t.Fatalf("lv host undrain %s: %v", victim.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	for i := 0; i < 20 && fences.Load() == 0; i++ {
		tick()
	}
	for i := 0; i < 3; i++ {
		tick()
	}
	if fences.Load() == 0 {
		t.Fatalf("the coordinator did not fence %s afresh after the undrain", victim.Name)
	}
	if vm := vmOn(t, b, "vm-declined"); vm == nil || vm.HostName == victim.Name {
		t.Fatalf("vm-declined = %+v, want it recovered on the fresh fence after the undrain", vm)
	}
	if open, _, _, _ := unprovenFenceCond(t, c, b, victim.Name); open {
		t.Fatalf("`lv health` on %s still lists %s after the hold ended", b.Name, failover.CondRecoveryUnprovenFence)
	}
}
