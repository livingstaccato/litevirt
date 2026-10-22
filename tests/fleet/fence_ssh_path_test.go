package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/fencessh"
)

// TestFleet_FenceSSH_CoordinatorFencesOverTheDecidedPath: a coordinator's
// fence of a failed host carries the path the coordinator's own agent decided
// from its own replica of the victim's row — managed toward a victim that
// accepts the managed key, pinned toward one that does not, and refused in
// managed mode toward one that does not — and never the unpinned legacy path
// for a host that has published.
//
// Mutation: leave Coordinator.FenceSSH unused at the fence (fenceSSHPath) —
// every fence carries the zero (unpinned legacy) path, red.
func TestFleet_FenceSSH_CoordinatorFencesOverTheDecidedPath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		accepting bool
		mode      string
		path      string
		refused   bool
	}{
		{"accepting victim, auto: managed", true, fencessh.ModeAuto, fence.SSHPathManaged, false},
		{"non-accepting victim, auto: pinned", false, fencessh.ModeAuto, fence.SSHPathPinned, false},
		{"non-accepting victim, managed: refused", false, fencessh.ModeManaged, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			c, fs := fenceSSHFleetWith(t, 3, 2617, func(name string) bool { return name != "node-2" || tc.accepting },
				func(string) string { return tc.mode })
			a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			publishAndRender(t, c, fs)
			insertVM(t, a, "vm-victim", victim.Name)
			c.WaitConverged(t, convergeTimeout)
			c.Isolate(victim)
			PublishHealth(t, a, victim.Name, 5, clock.Now())
			PublishHealth(t, b, victim.Name, 5, clock.Now())
			c.WaitConverged(t, convergeTimeout, a, b)

			cs := c.NewCoordinators(clock)
			for _, n := range c.Nodes {
				cs.ByNode[n.Name].FenceSSH = fs[n.Name].agent.FenceConfig
			}
			cs.Tick(ctx, a)
			f := cs.Fences()
			if len(f) != 1 || f[0].Target != victim.Name {
				t.Fatalf("fences = %+v, want one of %s", f, victim.Name)
			}
			got := f[0].SSH
			switch {
			case tc.refused:
				if got.Refusal == "" || !strings.Contains(got.Refusal, "does not accept the managed fence key") {
					t.Fatalf("fence path = %+v, want a refusal", got)
				}
			default:
				if got.Refusal != "" || got.Path != tc.path || got.HostKeyAlias != fencessh.Alias(victim.Name) {
					t.Fatalf("fence path = %+v, want %q pinned to %s", got, tc.path, victim.Name)
				}
				if tc.path == fence.SSHPathManaged && got.BindAddress != fs[a.Name].ip {
					t.Fatalf("managed fence binds to %q, want %s's certificate address %s", got.BindAddress, a.Name, fs[a.Name].ip)
				}
			}
		})
	}
}

// TestFleet_FenceSSH_OperatorFenceUsesTheDecidedPath: `lv host fence` runs on
// whichever node receives it, and that node's agent decides the path from its
// own replica, as the coordinator's does.
//
// Mutation: drop SSH from FenceHost's HostConfig — the fence carries the
// unpinned legacy path, red.
func TestFleet_FenceSSH_OperatorFenceUsesTheDecidedPath(t *testing.T) {
	ctx := context.Background()
	c, fs := fenceSSHFleet(t, 3, 2618)
	publishAndRender(t, c, fs)
	a := c.Nodes[1]
	a.Server.SetFenceSSH(fs[a.Name].agent)
	var got fence.HostConfig
	a.Server.SetFenceExecutor(func(_ context.Context, h fence.HostConfig) fence.Result {
		got = h
		return fence.Result{Method: "fleet-test", Success: true}
	})
	if _, err := c.SelfClient(a).FenceHost(ctx, &pb.FenceHostRequest{Name: "node-2", Confirmed: true}); err != nil {
		t.Fatalf("FenceHost: %v", err)
	}
	if got.Name != "node-2" || got.SSH.Path != fence.SSHPathManaged || got.SSH.BindAddress != fs[a.Name].ip ||
		got.SSH.HostKeyAlias != fencessh.Alias("node-2") {
		t.Fatalf("FenceHost fenced %q over %+v, want node-2 over the managed path from %s", got.Name, got.SSH, fs[a.Name].ip)
	}
}
