package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// TestFleet_FenceSSH_BestEffortRowlessTargetIsHeld: with
// release_2026_12_v1 latched, node-2 has published no fence ssh row, and it
// fences by best-effort (the default). The coordinator's own agent refuses
// the unpinned path, and the production fence.Execute turns that refusal into
// a failed fence, not best-effort's assumed success: nothing reached node-2,
// so its VM stays recorded there on every replica, the fence is recorded
// partial with the ways out, and the one stall alert names the held VM and the
// ways out: power node-2 off and `lv host fence-confirm node-2`, or give it
// ipmi or redfish.
//
// Mutation: count a refused lenient fence as best-effort's assumed success
// (fence.sshNotAttempted) — vm-victim is rescheduled, red.
func TestFleet_FenceSSH_BestEffortRowlessTargetIsHeld(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, fs := fenceSSHFleet(t, 3, 2621)
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	syncAll(t, fs[a.Name], fs[b.Name])
	c.WaitConverged(t, convergeTimeout)
	syncAll(t, fs[a.Name], fs[b.Name])
	if _, ok, err := corrosion.GetHostFenceSSH(ctx, a.DB, victim.Name); err != nil || ok {
		t.Fatalf("precondition: %s holds a fence ssh row for %s (%v %v)", a.Name, victim.Name, ok, err)
	}
	if h, err := corrosion.GetHost(ctx, a.DB, victim.Name); err != nil || h == nil ||
		fence.ResolveStrategy(h.FenceStrategy) != "best-effort" {
		t.Fatalf("precondition: %s fences by %+v (%v), want best-effort", victim.Name, h, err)
	}
	insertVM(t, a, "vm-victim", victim.Name)
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(victim)
	runStart := clock.Now()
	PublishHealthRun(t, a, victim.Name, 5, runStart, clock.Now())
	PublishHealthRun(t, b, victim.Name, 5, runStart, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)

	cs := c.NewCoordinators(clock)
	var mu sync.Mutex
	var results []fence.Result
	var reasons []string
	for _, n := range c.Nodes {
		coord := cs.ByNode[n.Name]
		coord.FenceSSH = fs[n.Name].agent.FenceConfig
		coord.SetFencer(func(ctx context.Context, h fence.HostConfig) fence.Result {
			r := fence.Execute(ctx, h) // refused: dials nothing
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
			return r
		})
		coord.OnRecoveryStalled = func(host, _, reason string, _ int, _ time.Time) {
			if host == victim.Name {
				mu.Lock()
				reasons = append(reasons, reason)
				mu.Unlock()
			}
		}
	}
	cs.Tick(ctx, a)
	// Hold it past the stall alert's bound, re-publishing the observers'
	// view as their checkers would.
	for i := 0; i < 4; i++ {
		clock.Advance(20 * time.Second)
		now := clock.Now()
		PublishHealthRun(t, a, victim.Name, 6+i, runStart, now)
		PublishHealthRun(t, b, victim.Name, 6+i, runStart, now)
		c.WaitConverged(t, convergeTimeout, a, b)
		cs.Tick(ctx, a)
	}

	mu.Lock()
	gotResults, gotReasons := append([]fence.Result(nil), results...), append([]string(nil), reasons...)
	mu.Unlock()
	if len(gotResults) == 0 {
		t.Fatal("no fence of node-2 ran; this proves nothing")
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		if vm := vmOn(t, n, "vm-victim"); vm == nil || vm.HostName != victim.Name {
			t.Fatalf("vm-victim on %s's replica: %+v, want it still on %s", n.Name, vm, victim.Name)
		}
		rows, err := n.DB.Query(ctx, `SELECT method, result, detail FROM fencing_log WHERE host_name = ?`, victim.Name)
		if err != nil || len(rows) == 0 {
			t.Fatalf("%s: fencing_log of %s = %v (%v), want the refused fence", n.Name, victim.Name, rows, err)
		}
		for _, r := range rows {
			if r.String("result") != fence.LogPartial || !strings.Contains(r.String("detail"), "lv host fence-confirm "+victim.Name) {
				t.Fatalf("%s: fencing_log row %v, want partial naming fence-confirm", n.Name, r)
			}
		}
	}
	for _, r := range gotResults {
		if r.Success || r.Method != "best-effort-ssh" || !strings.Contains(r.Detail, "has published no fence ssh row") {
			t.Fatalf("fence of %s = %+v, want a refused best-effort failure", victim.Name, r)
		}
	}
	if len(gotReasons) == 0 {
		t.Fatalf("no stall alert named %s", victim.Name)
	}
	for _, want := range []string{"lv host fence-confirm " + victim.Name, "ipmi or redfish", "held: vm/vm-victim"} {
		if !strings.Contains(gotReasons[len(gotReasons)-1], want) {
			t.Fatalf("stall reason %q does not name %q", gotReasons[len(gotReasons)-1], want)
		}
	}
}
